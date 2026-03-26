use cove_cspp::CsppStore as _;
use cove_cspp::master_key_crypto;
use cove_device::cloud_storage::CloudStorage;
use cove_device::keychain::Keychain;
use cove_device::passkey::PasskeyAccess;
use cove_util::ResultExt as _;
use tracing::{info, warn};
use zeroize::Zeroizing;

use super::cloud_inventory::CloudWalletInventory;
use super::wallets::{
    NamespaceMatchOutcome, all_local_wallets, discover_or_create_prf_key, download_wallet_backup,
    obtain_prf_key, persist_enabled_cloud_backup_state, restore_single_wallet,
    try_match_namespace_with_passkey, upload_all_wallets,
};
use cove_device::keychain::CSPP_NAMESPACE_ID_KEY;

use super::{
    CloudBackupError, CloudBackupReconcileMessage as Message, CloudBackupRestoreReport,
    CloudBackupState, CloudBackupWalletItem, CloudBackupWalletStatus, RustCloudBackupManager,
};
use crate::database::Database;
use crate::database::global_config::CloudBackup;
use crate::wallet::metadata::WalletMetadata;

impl RustCloudBackupManager {
    pub(crate) fn do_sync_unsynced_wallets(&self) -> Result<(), CloudBackupError> {
        let namespace = self.current_namespace_id()?;
        info!("Sync: listing cloud wallet backups for namespace {namespace}");
        let cloud = CloudStorage::global();
        let wallet_record_ids =
            cloud.list_wallet_backups(namespace).map_err_str(CloudBackupError::Cloud)?;
        let inventory = CloudWalletInventory::load(&wallet_record_ids);

        info!(
            "Sync: found {} wallet(s) in cloud (including pending)",
            inventory.cloud_wallet_count()
        );
        let unsynced = inventory.unsynced_local_wallets();

        if unsynced.is_empty() {
            info!("Sync: all wallets already synced");
            return Ok(());
        }

        info!("Sync: {} wallet(s) need backup", unsynced.len());
        self.do_backup_wallets(&unsynced)
    }

    pub(crate) fn do_fetch_cloud_only_wallets(
        &self,
    ) -> Result<Vec<CloudBackupWalletItem>, CloudBackupError> {
        let namespace = self.current_namespace_id()?;
        let cloud = CloudStorage::global();
        let wallet_record_ids =
            cloud.list_wallet_backups(namespace.clone()).map_err_str(CloudBackupError::Cloud)?;

        let db = Database::global();
        let local_record_ids: std::collections::HashSet<_> = all_local_wallets(&db)
            .iter()
            .map(|wallet| cove_cspp::backup_data::wallet_record_id(wallet.id.as_ref()))
            .collect();

        let orphan_ids: Vec<_> = wallet_record_ids
            .iter()
            .filter(|record_id| !local_record_ids.contains(*record_id))
            .collect();

        if orphan_ids.is_empty() {
            return Ok(Vec::new());
        }

        let cspp = cove_cspp::Cspp::new(Keychain::global().clone());
        let master_key = cspp
            .get_or_create_master_key()
            .map_err_prefix("master key", CloudBackupError::Internal)?;

        let critical_key = Zeroizing::new(master_key.critical_data_key());
        let mut items = Vec::new();

        for record_id in orphan_ids {
            let metadata: WalletMetadata =
                match download_wallet_backup(cloud, &namespace, record_id, &critical_key) {
                    Ok(wallet) => wallet.metadata,
                    Err(error) => {
                        warn!("Failed to load cloud-only wallet {record_id}: {error}");
                        continue;
                    }
                };

            items.push(CloudBackupWalletItem {
                name: metadata.name,
                network: metadata.network,
                wallet_mode: metadata.wallet_mode,
                wallet_type: metadata.wallet_type,
                fingerprint: metadata.master_fingerprint.as_ref().map(|fp| fp.as_uppercase()),
                status: CloudBackupWalletStatus::DeletedFromDevice,
                record_id: record_id.clone(),
            });
        }

        Ok(items)
    }

    pub(crate) fn do_restore_cloud_wallet(&self, record_id: &str) -> Result<(), CloudBackupError> {
        let namespace = self.current_namespace_id()?;
        let cloud = CloudStorage::global();
        let cspp = cove_cspp::Cspp::new(Keychain::global().clone());
        let master_key = cspp
            .get_or_create_master_key()
            .map_err_prefix("master key", CloudBackupError::Internal)?;
        let critical_key = Zeroizing::new(master_key.critical_data_key());

        let db = Database::global();
        let mut existing_fingerprints: Vec<_> = all_local_wallets(&db)
            .iter()
            .filter_map(|wallet| {
                wallet
                    .master_fingerprint
                    .as_ref()
                    .map(|fp| (**fp, wallet.network, wallet.wallet_mode))
            })
            .collect();

        restore_single_wallet(
            cloud,
            &namespace,
            record_id,
            &critical_key,
            &mut existing_fingerprints,
        )?;
        info!("Restored cloud wallet {record_id}");
        Ok(())
    }

    pub(crate) fn do_delete_cloud_wallet(&self, record_id: &str) -> Result<(), CloudBackupError> {
        let namespace = self.current_namespace_id()?;
        let cloud = CloudStorage::global();

        cloud
            .delete_wallet_backup(namespace.clone(), record_id.to_string())
            .map_err_str(CloudBackupError::Cloud)?;
        self.remove_pending_uploads(&namespace, std::iter::once(record_id.to_string()))?;

        let wallet_record_ids =
            cloud.list_wallet_backups(namespace).map_err_str(CloudBackupError::Cloud)?;
        let wallet_count = wallet_record_ids.len() as u32;
        let db = Database::global();
        let last_sync = match db.global_config.cloud_backup() {
            CloudBackup::Enabled { last_sync, .. } | CloudBackup::Unverified { last_sync, .. } => {
                last_sync
            }
            CloudBackup::Disabled => None,
        };
        let _ = db.global_config.set_cloud_backup(&CloudBackup::Enabled {
            last_sync,
            wallet_count: Some(wallet_count),
        });

        info!("Deleted cloud wallet {record_id}");
        Ok(())
    }

    /// Re-upload all local wallets to cloud
    ///
    /// Reuses the master key from keychain (no passkey interaction needed)
    pub(crate) fn do_reupload_all_wallets(&self) -> Result<(), CloudBackupError> {
        info!("Re-uploading all wallets to cloud");

        let namespace = self.current_namespace_id()?;
        let cspp = cove_cspp::Cspp::new(Keychain::global().clone());
        let master_key = cspp
            .get_or_create_master_key()
            .map_err_prefix("master key", CloudBackupError::Internal)?;

        let critical_key = Zeroizing::new(master_key.critical_data_key());
        let cloud = CloudStorage::global();
        let db = Database::global();

        let uploaded_record_ids = upload_all_wallets(cloud, &namespace, &critical_key, &db)?;
        persist_enabled_cloud_backup_state(&db, uploaded_record_ids.len() as u32)?;
        self.enqueue_pending_uploads(&namespace, uploaded_record_ids)?;

        Ok(())
    }

    pub(crate) fn do_enable_cloud_backup(&self) -> Result<(), CloudBackupError> {
        self.send(Message::StateChanged(CloudBackupState::Enabling));

        let passkey = PasskeyAccess::global();
        if !passkey.is_prf_supported() {
            return Err(CloudBackupError::NotSupported(
                "PRF extension not supported on this device".into(),
            ));
        }

        let keychain = Keychain::global();
        let cspp = cove_cspp::Cspp::new(keychain.clone());
        let cloud = CloudStorage::global();

        let has_local_master_key = cspp
            .load_master_key_from_store()
            .map_err_prefix("load local master key", CloudBackupError::Internal)?
            .is_some();

        if has_local_master_key {
            return self.do_enable_cloud_backup_create_new();
        }

        // no local master key — check iCloud for existing namespaces to recover
        let namespaces = cloud
            .list_namespaces()
            .map_err(|e| CloudBackupError::Cloud(format!(
                "could not check for existing cloud backups, please try again when iCloud is available: {e}"
            )))?;

        if namespaces.is_empty() {
            return self.do_enable_cloud_backup_create_new();
        }

        info!("Enable: found {} existing namespace(s), attempting recovery", namespaces.len());

        match try_match_namespace_with_passkey(cloud, passkey, &namespaces)? {
            NamespaceMatchOutcome::Matched(matched) => {
                self.complete_recovery(keychain, cloud, &cspp, matched)
            }

            NamespaceMatchOutcome::UserDeclined => {
                info!("Enable: user cancelled passkey picker during namespace matching");
                self.send(Message::PasskeyDiscoveryCancelled);
                self.send(Message::StateChanged(CloudBackupState::Disabled));
                Ok(())
            }

            NamespaceMatchOutcome::NoMatch => {
                info!("Enable: passkey didn't match existing backups, asking user to confirm");
                self.send(Message::ExistingBackupFound);
                self.send(Message::StateChanged(CloudBackupState::Disabled));
                Ok(())
            }

            NamespaceMatchOutcome::Inconclusive => Err(CloudBackupError::Cloud(
                "could not verify all cloud backups, please try again when iCloud is available"
                    .into(),
            )),

            NamespaceMatchOutcome::UnsupportedVersions => Err(CloudBackupError::Internal(
                "some cloud backups use a newer format, please update the app to access all backups"
                    .into(),
            )),
        }
    }

    /// Complete recovery from a matched cloud namespace
    fn complete_recovery(
        &self,
        keychain: &Keychain,
        cloud: &CloudStorage,
        cspp: &cove_cspp::Cspp<Keychain>,
        matched: super::wallets::NamespaceMatch,
    ) -> Result<(), CloudBackupError> {
        info!("Enable: recovered namespace {}", matched.namespace_id);

        cspp.save_master_key(&matched.master_key)
            .map_err_prefix("save recovered master key", CloudBackupError::Internal)?;
        cove_cspp::reset_master_key_cache();

        let critical_key = Zeroizing::new(matched.master_key.critical_data_key());
        let db = Database::global();
        let uploaded_wallet_record_ids =
            upload_all_wallets(cloud, &matched.namespace_id, &critical_key, &db)?;

        // get accurate wallet count from cloud (includes pre-existing + uploaded)
        let wallet_count = cloud
            .list_wallet_backups(matched.namespace_id.clone())
            .map(|ids| ids.len() as u32)
            .unwrap_or(uploaded_wallet_record_ids.len() as u32);

        // persist credentials AFTER uploads succeed
        keychain
            .save_cspp_passkey_and_namespace(
                &matched.credential_id,
                matched.prf_salt,
                &matched.namespace_id,
            )
            .map_err_prefix("save cspp credentials", CloudBackupError::Internal)?;

        persist_enabled_cloud_backup_state(&db, wallet_count)?;
        self.enqueue_pending_uploads(&matched.namespace_id, uploaded_wallet_record_ids)?;

        self.send(Message::EnableComplete);
        self.send(Message::StateChanged(CloudBackupState::Enabled));
        info!("Cloud backup enabled (recovered existing namespace)");
        Ok(())
    }

    /// Create a new cloud backup from scratch — no recovery attempt
    ///
    /// Called directly when `do_enable_cloud_backup` determines no recovery is needed,
    /// or via `do_enable_cloud_backup_force_new` when the user confirms creating a
    /// new backup after being warned about existing ones
    pub(crate) fn do_enable_cloud_backup_create_new(&self) -> Result<(), CloudBackupError> {
        let passkey = PasskeyAccess::global();
        let keychain = Keychain::global();

        info!("Enable: getting master key");
        let cspp = cove_cspp::Cspp::new(keychain.clone());
        let master_key = cspp
            .get_or_create_master_key()
            .map_err_prefix("master key", CloudBackupError::Internal)?;

        let namespace_id = master_key.namespace_id();
        info!("Enable: namespace_id={namespace_id}, getting passkey");
        let (prf_key, prf_salt) = match discover_or_create_prf_key(keychain, passkey) {
            Ok(result) => result,
            Err(CloudBackupError::PasskeyDiscoveryCancelled) => {
                self.send(Message::PasskeyDiscoveryCancelled);
                self.send(Message::StateChanged(CloudBackupState::Disabled));
                return Ok(());
            }
            Err(e) => return Err(e),
        };

        info!("Enable: passkey created, uploading backup");
        self.enable_cloud_backup_with_prf_key(keychain, &master_key, prf_key, prf_salt)
    }

    /// Same as `do_enable_cloud_backup_create_new` but skips passkey discovery,
    /// going straight to passkey registration
    pub(super) fn do_enable_cloud_backup_no_discovery(&self) -> Result<(), CloudBackupError> {
        let passkey = PasskeyAccess::global();
        let keychain = Keychain::global();

        info!("Enable (no discovery): getting master key");
        let cspp = cove_cspp::Cspp::new(keychain.clone());
        let master_key = cspp
            .get_or_create_master_key()
            .map_err_prefix("master key", CloudBackupError::Internal)?;

        let namespace_id = master_key.namespace_id();
        info!("Enable (no discovery): namespace_id={namespace_id}, creating passkey");
        let (prf_key, prf_salt) = obtain_prf_key(keychain, passkey)?;

        info!("Enable (no discovery): passkey created, uploading backup");
        self.enable_cloud_backup_with_prf_key(keychain, &master_key, prf_key, prf_salt)
    }

    pub(super) fn do_restore_from_cloud_backup(&self) -> Result<(), CloudBackupError> {
        self.send(Message::StateChanged(CloudBackupState::Restoring));

        let cloud = CloudStorage::global();
        let keychain = Keychain::global();
        let cspp = cove_cspp::Cspp::new(keychain.clone());

        // passkey matching first, local master key as fallback
        let passkey = PasskeyAccess::global();
        let (master_key, namespace_id) = match self.restore_via_passkey_matching(cloud, passkey) {
            Ok(matched) => {
                cspp.save_master_key(&matched.master_key)
                    .map_err_prefix("save master key", CloudBackupError::Internal)?;
                cove_cspp::reset_master_key_cache();

                keychain
                    .save_cspp_passkey_and_namespace(
                        &matched.credential_id,
                        matched.prf_salt,
                        &matched.namespace_id,
                    )
                    .map_err_prefix("save cspp credentials", CloudBackupError::Internal)?;

                (matched.master_key, matched.namespace_id)
            }
            Err(CloudBackupError::PasskeyMismatch) => {
                info!("Restore: passkey didn't match, trying local master key fallback");
                self.try_restore_from_local_master_key(cloud, &cspp)
                    .ok_or(CloudBackupError::PasskeyMismatch)?
            }
            Err(e) => return Err(e),
        };

        // download and restore wallets
        let wallet_record_ids =
            cloud.list_wallet_backups(namespace_id.clone()).map_err_str(CloudBackupError::Cloud)?;

        let total = wallet_record_ids.len() as u32;
        let critical_key = Zeroizing::new(master_key.critical_data_key());
        let mut report = CloudBackupRestoreReport {
            wallets_restored: 0,
            wallets_failed: 0,
            failed_wallet_errors: Vec::new(),
        };

        let mut existing_fingerprints = crate::backup::import::collect_existing_fingerprints()
            .map_err_prefix("collect fingerprints", CloudBackupError::Internal)?;

        for (index, record_id) in wallet_record_ids.iter().enumerate() {
            match restore_single_wallet(
                cloud,
                &namespace_id,
                record_id,
                &critical_key,
                &mut existing_fingerprints,
            ) {
                Ok(()) => report.wallets_restored += 1,
                Err(error) => {
                    warn!("Failed to restore wallet {record_id}: {error}");
                    report.wallets_failed += 1;
                    report.failed_wallet_errors.push(error.to_string());
                }
            }

            self.send(Message::ProgressUpdated { completed: (index + 1) as u32, total });
        }

        if report.wallets_restored == 0 && report.wallets_failed > 0 {
            self.send(Message::RestoreComplete(report));
            return Err(CloudBackupError::Internal("all wallets failed to restore".into()));
        }

        let wallet_count = report.wallets_restored;
        let now = jiff::Timestamp::now().as_second().try_into().unwrap_or(0);
        let db = Database::global();
        db.global_config
            .set_cloud_backup(&CloudBackup::Enabled {
                last_sync: Some(now),
                wallet_count: Some(wallet_count),
            })
            .map_err_prefix("persist cloud backup state", CloudBackupError::Internal)?;

        self.send(Message::RestoreComplete(report));
        self.send(Message::StateChanged(CloudBackupState::Enabled));

        info!("Cloud backup restore complete");
        Ok(())
    }

    fn enable_cloud_backup_with_prf_key(
        &self,
        keychain: &Keychain,
        master_key: &cove_cspp::master_key::MasterKey,
        prf_key: [u8; 32],
        prf_salt: [u8; 32],
    ) -> Result<(), CloudBackupError> {
        let namespace_id = master_key.namespace_id();
        let cloud = CloudStorage::global();

        let encrypted_master =
            master_key_crypto::encrypt_master_key(master_key, &prf_key, &prf_salt)
                .map_err_str(CloudBackupError::Crypto)?;
        let master_json =
            serde_json::to_vec(&encrypted_master).map_err_str(CloudBackupError::Internal)?;

        info!("Enable: uploading master key");
        cloud
            .upload_master_key_backup(namespace_id.clone(), master_json)
            .map_err_str(CloudBackupError::Cloud)?;

        info!("Enable: uploading wallets");
        let critical_key = Zeroizing::new(master_key.critical_data_key());
        let db = Database::global();
        let uploaded_wallet_record_ids =
            upload_all_wallets(cloud, &namespace_id, &critical_key, &db)?;

        info!("Enable: persisting cloud backup state");
        keychain
            .save(CSPP_NAMESPACE_ID_KEY.into(), namespace_id.clone())
            .map_err_prefix("save namespace_id", CloudBackupError::Internal)?;
        persist_enabled_cloud_backup_state(&db, uploaded_wallet_record_ids.len() as u32)?;
        self.enqueue_pending_uploads(
            &namespace_id,
            std::iter::once(super::cspp_master_key_record_id()).chain(uploaded_wallet_record_ids),
        )?;

        self.send(Message::EnableComplete);
        self.send(Message::StateChanged(CloudBackupState::Enabled));
        info!("Cloud backup enabled successfully");
        Ok(())
    }

    /// Try to restore using a local master key from keychain
    ///
    /// Returns `Some((master_key, namespace_id))` if a local master key exists
    /// and the cloud namespace has wallets. Returns `None` to fall through
    /// to passkey-based matching
    fn try_restore_from_local_master_key(
        &self,
        cloud: &CloudStorage,
        cspp: &cove_cspp::Cspp<Keychain>,
    ) -> Option<(cove_cspp::master_key::MasterKey, String)> {
        let master_key = cspp.load_master_key_from_store().ok()??;
        let namespace_id = master_key.namespace_id();

        let has_wallets = cloud
            .list_wallet_backups(namespace_id.clone())
            .map(|ids| !ids.is_empty())
            .unwrap_or(false);

        if has_wallets {
            info!("Restore: found local master key with wallets, namespace_id={namespace_id}");
            Some((master_key, namespace_id))
        } else {
            info!(
                "Restore: local master key found but no wallets in cloud, falling through to passkey matching"
            );
            None
        }
    }

    /// Restore via passkey-based namespace matching (fresh device path)
    fn restore_via_passkey_matching(
        &self,
        cloud: &CloudStorage,
        passkey: &PasskeyAccess,
    ) -> Result<super::wallets::NamespaceMatch, CloudBackupError> {
        let namespaces = cloud.list_namespaces().map_err_str(CloudBackupError::Cloud)?;
        if namespaces.is_empty() {
            return Err(CloudBackupError::Internal("no cloud backup namespaces found".into()));
        }

        info!("Restore: authenticating with passkey across {} namespace(s)", namespaces.len());

        match try_match_namespace_with_passkey(cloud, passkey, &namespaces)? {
            NamespaceMatchOutcome::Matched(m) => {
                info!("Restore: matched namespace {}", m.namespace_id);
                Ok(m)
            }
            NamespaceMatchOutcome::UserDeclined | NamespaceMatchOutcome::NoMatch => {
                Err(CloudBackupError::PasskeyMismatch)
            }
            NamespaceMatchOutcome::Inconclusive => Err(CloudBackupError::Cloud(
                "could not download all cloud backups, please try again when iCloud is available"
                    .into(),
            )),
            NamespaceMatchOutcome::UnsupportedVersions => Err(CloudBackupError::Internal(
                "some cloud backups use a newer format, please update the app".into(),
            )),
        }
    }
}
