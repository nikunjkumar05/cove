use cove_cspp::master_key_crypto;
use cove_device::cloud_storage::CloudStorage;
use cove_device::keychain::{CSPP_NAMESPACE_ID_KEY, Keychain};
use cove_device::passkey::PasskeyAccess;
use cove_util::ResultExt as _;
use tracing::{info, warn};
use zeroize::Zeroizing;

use super::cloud_inventory::CloudWalletInventory;
use super::wallets::{
    DownloadedWalletBackup, NamespaceMatchOutcome, UnpersistedPrfKey, all_local_wallets,
    create_new_prf_key, discover_or_create_prf_key_without_persisting, download_wallet_backup,
    persist_enabled_cloud_backup_state, persist_enabled_cloud_backup_state_reset_verification,
    restore_downloaded_wallet_for_restore, restore_single_wallet, try_match_namespace_with_passkey,
    upload_all_wallets,
};

use super::{
    CloudBackupError, CloudBackupReconcileMessage as Message, CloudBackupRestoreProgress,
    CloudBackupRestoreReport, CloudBackupRestoreStage, CloudBackupStatus, CloudBackupWalletItem,
    CloudBackupWalletStatus, PendingEnableSession, RustCloudBackupManager,
};
use crate::database::Database;
use crate::database::cloud_backup::{PersistedCloudBackupState, PersistedCloudBackupStatus};
use crate::wallet::metadata::WalletMetadata;

const CLOUD_ONLY_FETCH_RECOVERY_MESSAGE: &str =
    "Cloud backup needs verification before wallets not on this device can be loaded";
const CLOUD_ONLY_RESTORE_RECOVERY_MESSAGE: &str =
    "Cloud backup needs verification before this wallet can be restored";
const RECREATE_MANIFEST_RECOVERY_MESSAGE: &str =
    "Cloud backup needs verification before the backup index can be recreated";

impl RustCloudBackupManager {
    fn send_restore_progress(
        &self,
        operation_id: u64,
        stage: CloudBackupRestoreStage,
        completed: u32,
        total: Option<u32>,
    ) -> Result<(), CloudBackupError> {
        self.set_restore_progress_for_restore_operation(
            operation_id,
            Some(CloudBackupRestoreProgress { stage, completed, total }),
        )
    }

    pub(crate) fn do_sync_unsynced_wallets(&self) -> Result<(), CloudBackupError> {
        let namespace = self.current_namespace_id()?;
        info!("Sync: listing cloud wallet backups for namespace {namespace}");
        let cloud = CloudStorage::global();
        let wallet_record_ids =
            cloud.list_wallet_backups(namespace).map_err_str(CloudBackupError::Cloud)?;
        let inventory = CloudWalletInventory::load(&wallet_record_ids)?;

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
        let local_record_ids: std::collections::HashSet<_> = all_local_wallets(&db)?
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
        let master_key = load_master_key_for_cloud_action(&cspp, || {
            self.recover_local_master_key_from_cloud_without_discovery(
                &namespace,
                CLOUD_ONLY_FETCH_RECOVERY_MESSAGE,
            )
        })?;

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
        let master_key = load_master_key_for_cloud_action(&cspp, || {
            self.recover_local_master_key_from_cloud(
                &namespace,
                CLOUD_ONLY_RESTORE_RECOVERY_MESSAGE,
            )
        })?;
        let critical_key = Zeroizing::new(master_key.critical_data_key());

        let db = Database::global();
        let mut existing_fingerprints: Vec<_> = all_local_wallets(&db)?
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
        if let Ok(mut current) = db.cloud_backup_state.get() {
            current.wallet_count = Some(wallet_count);
            let _ = self.persist_cloud_backup_state(
                &current,
                "persist cloud backup state after deleting cloud wallet",
            );
        }

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
        let master_key = load_master_key_for_cloud_action(&cspp, || {
            self.recover_local_master_key_from_cloud_without_discovery(
                &namespace,
                RECREATE_MANIFEST_RECOVERY_MESSAGE,
            )
        })?;

        let critical_key = Zeroizing::new(master_key.critical_data_key());
        let cloud = CloudStorage::global();
        let db = Database::global();

        let uploaded_record_ids = upload_all_wallets(cloud, &namespace, &critical_key, &db)?;
        persist_enabled_cloud_backup_state(&db, uploaded_record_ids.len() as u32)?;
        self.enqueue_pending_uploads(&namespace, uploaded_record_ids)?;

        Ok(())
    }

    pub(crate) fn do_enable_cloud_backup(&self) -> Result<(), CloudBackupError> {
        self.clear_pending_enable_session();
        self.set_progress(None);
        self.set_restore_progress(None);
        self.set_restore_report(None);
        self.set_status(CloudBackupStatus::Enabling);

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
                self.set_progress(None);
                self.set_restore_progress(None);
                self.set_status(CloudBackupStatus::Disabled);
                Ok(())
            }

            NamespaceMatchOutcome::NoMatch => {
                info!("Enable: passkey didn't match existing backups, asking user to confirm");
                self.send(Message::ExistingBackupFound);
                self.set_progress(None);
                self.set_restore_progress(None);
                self.set_status(CloudBackupStatus::Disabled);
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

        persist_enabled_cloud_backup_state_reset_verification(&db, wallet_count)?;
        self.enqueue_pending_uploads(&matched.namespace_id, uploaded_wallet_record_ids)?;

        self.set_progress(None);
        self.set_restore_progress(None);
        self.set_status(CloudBackupStatus::Enabled);
        info!("Cloud backup enabled (recovered existing namespace)");
        Ok(())
    }

    /// Create a new cloud backup from scratch — no recovery attempt
    ///
    /// Called directly when `do_enable_cloud_backup` determines no recovery is needed,
    /// or via `do_enable_cloud_backup_force_new` when the user confirms creating a
    /// new backup after being warned about existing ones
    pub(crate) fn do_enable_cloud_backup_create_new(&self) -> Result<(), CloudBackupError> {
        self.clear_pending_enable_session();
        let passkey = PasskeyAccess::global();
        let keychain = Keychain::global();

        info!("Enable: getting master key");
        let cspp = cove_cspp::Cspp::new(keychain.clone());
        let master_key = cspp
            .get_or_create_master_key()
            .map_err_prefix("master key", CloudBackupError::Internal)?;

        let namespace_id = master_key.namespace_id();
        info!("Enable: namespace_id={namespace_id}, getting passkey");
        let passkey = match discover_or_create_prf_key_without_persisting(passkey) {
            Ok(result) => result,
            Err(CloudBackupError::PasskeyDiscoveryCancelled) => {
                self.send(Message::PasskeyDiscoveryCancelled);
                self.set_progress(None);
                self.set_restore_progress(None);
                self.set_status(CloudBackupStatus::Disabled);
                return Ok(());
            }
            Err(e) => return Err(e),
        };

        info!("Enable: passkey created, uploading backup");
        self.enable_cloud_backup_with_passkey_material(
            keychain,
            Zeroizing::new(master_key),
            Zeroizing::new(passkey),
        )
    }

    pub(crate) fn do_enable_cloud_backup_force_new(&self) -> Result<(), CloudBackupError> {
        let keychain = Keychain::global();

        if let Some(pending) = self.take_pending_enable_session() {
            let (master_key, passkey) = pending.into_parts();
            info!("Enable: committing pending create-first cloud backup");
            return self.enable_cloud_backup_with_passkey_material(keychain, master_key, passkey);
        }

        self.do_enable_cloud_backup_create_new()
    }

    /// Same as `do_enable_cloud_backup_create_new` but skips passkey discovery,
    /// going straight to passkey registration
    pub(super) fn do_enable_cloud_backup_no_discovery(&self) -> Result<(), CloudBackupError> {
        let passkey = PasskeyAccess::global();
        let keychain = Keychain::global();
        let cloud = CloudStorage::global();
        self.clear_pending_enable_session();

        let cspp = cove_cspp::Cspp::new(keychain.clone());
        let has_local_master_key = cspp
            .load_master_key_from_store()
            .map_err_prefix("load local master key", CloudBackupError::Internal)?
            .is_some();
        let existing_namespaces = if has_local_master_key {
            Vec::new()
        } else {
            cloud.list_namespaces().map_err(|e| {
                CloudBackupError::Cloud(format!(
                    "could not check for existing cloud backups, please try again when iCloud is available: {e}"
                ))
            })?
        };

        info!("Enable (no discovery): getting master key");
        let master_key = cspp
            .get_or_create_master_key()
            .map_err_prefix("master key", CloudBackupError::Internal)?;

        let namespace_id = master_key.namespace_id();
        info!("Enable (no discovery): namespace_id={namespace_id}, creating passkey");
        let passkey = match create_new_prf_key(passkey, "Creating new passkey") {
            Ok(result) => result,
            Err(CloudBackupError::PasskeyDiscoveryCancelled) => {
                self.send(Message::PasskeyDiscoveryCancelled);
                self.set_progress(None);
                self.set_restore_progress(None);
                self.set_status(CloudBackupStatus::Disabled);
                return Ok(());
            }
            Err(error) => return Err(error),
        };

        if !has_local_master_key && !existing_namespaces.is_empty() {
            info!(
                "Enable (no discovery): created passkey with {} existing namespace(s), waiting for confirmation",
                existing_namespaces.len()
            );
            self.replace_pending_enable_session(PendingEnableSession::new(master_key, passkey));
            self.send(Message::ExistingBackupFound);
            self.set_progress(None);
            self.set_restore_progress(None);
            self.set_status(CloudBackupStatus::Disabled);
            return Ok(());
        }

        info!("Enable (no discovery): passkey created, uploading backup");
        self.enable_cloud_backup_with_passkey_material(
            keychain,
            Zeroizing::new(master_key),
            Zeroizing::new(passkey),
        )
    }

    pub(super) fn do_restore_from_cloud_backup(
        &self,
        operation_id: u64,
    ) -> Result<(), CloudBackupError> {
        self.set_progress(None);
        self.set_restore_progress(None);
        self.set_restore_report(None);
        self.set_status_for_restore_operation(operation_id, CloudBackupStatus::Restoring)?;
        self.send_restore_progress(operation_id, CloudBackupRestoreStage::Finding, 0, None)?;

        let cloud = CloudStorage::global();
        let keychain = Keychain::global();
        let cspp = cove_cspp::Cspp::new(keychain.clone());

        // passkey matching first, local master key as fallback
        let passkey = PasskeyAccess::global();
        let (master_key, namespace_id) = match self.restore_via_passkey_matching(cloud, passkey) {
            Ok(matched) => {
                self.ensure_current_restore_operation(operation_id)?;
                cspp.save_master_key(&matched.master_key)
                    .map_err_prefix("save master key", CloudBackupError::Internal)?;

                self.ensure_current_restore_operation(operation_id)?;
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
                self.ensure_current_restore_operation(operation_id)?;
                restore_from_local_master_key_fallback(cloud, keychain, &cspp)?
            }
            Err(e) => return Err(e),
        };

        // download and restore wallets
        self.ensure_current_restore_operation(operation_id)?;
        let wallet_record_ids =
            cloud.list_wallet_backups(namespace_id.clone()).map_err_str(CloudBackupError::Cloud)?;

        let critical_key = Zeroizing::new(master_key.critical_data_key());
        let mut report = CloudBackupRestoreReport {
            wallets_restored: 0,
            wallets_failed: 0,
            failed_wallet_errors: Vec::new(),
        };

        let mut existing_fingerprints = crate::backup::import::collect_existing_fingerprints()
            .map_err_prefix("collect fingerprints", CloudBackupError::Internal)?;

        let downloaded_wallets = self.download_wallets_for_restore(
            operation_id,
            cloud,
            &namespace_id,
            &wallet_record_ids,
            &critical_key,
            &mut report,
        )?;
        let restore_total = downloaded_wallets.len() as u32;

        self.send_restore_progress(
            operation_id,
            CloudBackupRestoreStage::Restoring,
            0,
            Some(restore_total),
        )?;

        for (index, (record_id, wallet)) in downloaded_wallets.iter().enumerate() {
            self.ensure_current_restore_operation(operation_id)?;
            match restore_downloaded_wallet_for_restore(wallet, &mut existing_fingerprints) {
                Ok(()) => report.wallets_restored += 1,
                Err(error) => {
                    warn!("Failed to restore wallet {record_id}: {error}");
                    report.wallets_failed += 1;
                    report.failed_wallet_errors.push(error.to_string());
                }
            }

            self.send_restore_progress(
                operation_id,
                CloudBackupRestoreStage::Restoring,
                (index + 1) as u32,
                Some(restore_total),
            )?;
        }

        if report.wallets_restored == 0 && report.wallets_failed > 0 {
            self.set_restore_progress_for_restore_operation(operation_id, None)?;
            self.set_restore_report_for_restore_operation(operation_id, Some(report))?;
            return Err(CloudBackupError::Internal("all wallets failed to restore".into()));
        }

        let wallet_count = report.wallets_restored;
        let now = jiff::Timestamp::now().as_second().try_into().unwrap_or(0);
        let state = PersistedCloudBackupState {
            status: PersistedCloudBackupStatus::Enabled,
            last_sync: Some(now),
            wallet_count: Some(wallet_count),
            last_verified_at: None,
            last_verification_requested_at: None,
            last_verification_dismissed_at: None,
        };
        self.persist_cloud_backup_state_for_restore_operation(
            operation_id,
            &state,
            "persist restored cloud backup state",
        )?;

        self.set_restore_progress_for_restore_operation(operation_id, None)?;
        self.set_restore_report_for_restore_operation(operation_id, Some(report))?;
        self.set_status_for_restore_operation(operation_id, CloudBackupStatus::Enabled)?;

        info!("Cloud backup restore complete");
        Ok(())
    }

    fn download_wallets_for_restore(
        &self,
        operation_id: u64,
        cloud: &CloudStorage,
        namespace_id: &str,
        wallet_record_ids: &[String],
        critical_key: &[u8; 32],
        report: &mut CloudBackupRestoreReport,
    ) -> Result<Vec<(String, DownloadedWalletBackup)>, CloudBackupError> {
        let total = wallet_record_ids.len() as u32;

        self.send_restore_progress(
            operation_id,
            CloudBackupRestoreStage::Downloading,
            0,
            Some(total),
        )?;

        let mut downloaded_wallets = Vec::with_capacity(wallet_record_ids.len());

        for (index, record_id) in wallet_record_ids.iter().enumerate() {
            self.ensure_current_restore_operation(operation_id)?;
            match download_wallet_backup(cloud, namespace_id, record_id, critical_key) {
                Ok(wallet) => downloaded_wallets.push((record_id.clone(), wallet)),
                Err(error) => {
                    warn!("Failed to download wallet {record_id}: {error}");
                    report.wallets_failed += 1;
                    report.failed_wallet_errors.push(error.to_string());
                }
            }

            self.send_restore_progress(
                operation_id,
                CloudBackupRestoreStage::Downloading,
                (index + 1) as u32,
                Some(total),
            )?;
        }

        Ok(downloaded_wallets)
    }

    fn enable_cloud_backup_with_passkey_material(
        &self,
        keychain: &Keychain,
        master_key: Zeroizing<cove_cspp::master_key::MasterKey>,
        passkey: Zeroizing<UnpersistedPrfKey>,
    ) -> Result<(), CloudBackupError> {
        let namespace_id = master_key.namespace_id();
        let cloud = CloudStorage::global();

        let encrypted_master =
            master_key_crypto::encrypt_master_key(&master_key, &passkey.prf_key, &passkey.prf_salt)
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
            .save_cspp_passkey_and_namespace(
                &passkey.credential_id,
                passkey.prf_salt,
                &namespace_id,
            )
            .map_err_prefix("save cspp credentials", CloudBackupError::Internal)?;
        persist_enabled_cloud_backup_state_reset_verification(
            &db,
            uploaded_wallet_record_ids.len() as u32,
        )?;
        self.enqueue_pending_uploads(
            &namespace_id,
            std::iter::once(super::cspp_master_key_record_id()).chain(uploaded_wallet_record_ids),
        )?;

        self.set_progress(None);
        self.set_restore_progress(None);
        self.set_status(CloudBackupStatus::Enabled);
        info!("Cloud backup enabled successfully");
        Ok(())
    }

    /// Restore via passkey-based namespace matching (fresh device path)
    ///
    /// Tries the selected passkey across all downloaded namespaces. If it
    /// doesn't match any of them, returns `PasskeyMismatch` so the caller can
    /// try local master key fallback or prompt the user to try a different
    /// passkey
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

fn persist_namespace_id<S>(store: &S, namespace_id: &str) -> Result<(), CloudBackupError>
where
    S: cove_cspp::CsppStore,
    S::Error: std::fmt::Display,
{
    store
        .save(CSPP_NAMESPACE_ID_KEY.into(), namespace_id.to_owned())
        .map_err_prefix("save namespace_id", CloudBackupError::Internal)
}

fn try_restore_from_local_master_key<S>(
    cloud: &CloudStorage,
    cspp: &cove_cspp::Cspp<S>,
) -> Option<(cove_cspp::master_key::MasterKey, String)>
where
    S: cove_cspp::CsppStore,
    S::Error: std::fmt::Display,
{
    let master_key = cspp.load_master_key_from_store().ok()??;
    let namespace_id = master_key.namespace_id();

    let has_wallets =
        cloud.list_wallet_backups(namespace_id.clone()).map(|ids| !ids.is_empty()).unwrap_or(false);

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

fn restore_from_local_master_key_fallback<S>(
    cloud: &CloudStorage,
    store: &S,
    cspp: &cove_cspp::Cspp<S>,
) -> Result<(cove_cspp::master_key::MasterKey, String), CloudBackupError>
where
    S: cove_cspp::CsppStore,
    S::Error: std::fmt::Display,
{
    let (master_key, namespace_id) =
        try_restore_from_local_master_key(cloud, cspp).ok_or(CloudBackupError::PasskeyMismatch)?;
    persist_namespace_id(store, &namespace_id)?;
    Ok((master_key, namespace_id))
}

fn load_master_key_for_cloud_action<S, F>(
    cspp: &cove_cspp::Cspp<S>,
    recover_missing: F,
) -> Result<cove_cspp::master_key::MasterKey, CloudBackupError>
where
    S: cove_cspp::CsppStore,
    F: FnOnce() -> Result<cove_cspp::master_key::MasterKey, CloudBackupError>,
{
    match cspp
        .load_master_key_from_store()
        .map_err_prefix("load local master key", CloudBackupError::Internal)?
    {
        Some(master_key) => Ok(master_key),
        None => recover_missing(),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Mutex as StdMutex;
    use std::sync::{Arc, OnceLock};

    use cove_cspp::CsppStore;
    use cove_cspp::backup_data::wallet_filename_from_record_id;
    use cove_device::cloud_storage::{CloudStorage, CloudStorageAccess, CloudStorageError};
    use cove_device::keychain::{
        CSPP_CREDENTIAL_ID_KEY, CSPP_NAMESPACE_ID_KEY, CSPP_PRF_SALT_KEY, Keychain, KeychainAccess,
    };
    use cove_device::passkey::{
        DiscoveredPasskeyResult, PasskeyAccess, PasskeyCredentialPresence, PasskeyError,
        PasskeyProvider,
    };
    use parking_lot::Mutex;
    use strum::IntoEnumIterator as _;

    use super::*;
    use crate::database::Database;
    use crate::database::cloud_backup::{PersistedCloudBackupState, PersistedCloudBackupStatus};
    use crate::manager::cloud_backup_manager::{DeepVerificationResult, VerificationFailureKind};
    use crate::network::Network;
    use crate::wallet::metadata::WalletMode;

    #[derive(Debug, Default)]
    struct MockStore {
        entries: Mutex<HashMap<String, String>>,
        save_count: Mutex<usize>,
    }

    #[derive(Debug, Clone)]
    struct MockStoreHandle(Arc<MockStore>);

    impl cove_cspp::CsppStore for MockStoreHandle {
        type Error = String;

        fn save(&self, key: String, value: String) -> Result<(), Self::Error> {
            *self.0.save_count.lock() += 1;
            self.0.entries.lock().insert(key, value);
            Ok(())
        }

        fn get(&self, key: String) -> Option<String> {
            self.0.entries.lock().get(&key).cloned()
        }

        fn delete(&self, key: String) -> bool {
            self.0.entries.lock().remove(&key).is_some()
        }
    }

    type MockDiscoverResult = Result<(Vec<u8>, Vec<u8>), PasskeyError>;

    #[derive(Debug, Clone, Default)]
    struct MockKeychain {
        entries: Arc<Mutex<HashMap<String, String>>>,
    }

    impl MockKeychain {
        fn reset(&self) {
            self.entries.lock().clear();
        }
    }

    impl KeychainAccess for MockKeychain {
        fn save(
            &self,
            key: String,
            value: String,
        ) -> Result<(), cove_device::keychain::KeychainError> {
            self.entries.lock().insert(key, value);
            Ok(())
        }

        fn get(&self, key: String) -> Option<String> {
            self.entries.lock().get(&key).cloned()
        }

        fn delete(&self, key: String) -> bool {
            self.entries.lock().remove(&key).is_some()
        }
    }

    #[derive(Debug, Default)]
    struct MockCloudState {
        wallet_files: HashMap<String, Vec<String>>,
        master_key_backups: HashMap<String, Vec<u8>>,
        upload_master_key_error: Option<CloudStorageError>,
        upload_wallet_backup_error: Option<CloudStorageError>,
        reflect_uploaded_wallets_in_listing: bool,
        uploaded_wallet_backups: Vec<(String, String)>,
    }

    #[derive(Debug, Clone, Default)]
    struct MockCloudStorage {
        state: Arc<Mutex<MockCloudState>>,
    }

    impl MockCloudStorage {
        fn reset(&self) {
            *self.state.lock() = MockCloudState::default();
        }

        fn set_wallet_files(&self, namespace: String, wallet_files: Vec<String>) {
            self.state.lock().wallet_files.insert(namespace, wallet_files);
        }

        fn set_master_key_backup(&self, namespace: String, backup: Vec<u8>) {
            self.state.lock().master_key_backups.insert(namespace, backup);
        }

        fn fail_master_key_upload(&self, message: &str) {
            self.state.lock().upload_master_key_error =
                Some(CloudStorageError::UploadFailed(message.into()));
        }

        fn fail_wallet_backup_upload(&self, message: &str) {
            self.state.lock().upload_wallet_backup_error =
                Some(CloudStorageError::UploadFailed(message.into()));
        }

        fn set_reflect_uploaded_wallets_in_listing(&self, enabled: bool) {
            self.state.lock().reflect_uploaded_wallets_in_listing = enabled;
        }

        fn uploaded_wallet_backup_count(&self) -> usize {
            self.state.lock().uploaded_wallet_backups.len()
        }
    }

    impl CloudStorageAccess for MockCloudStorage {
        fn upload_master_key_backup(
            &self,
            _namespace: String,
            _data: Vec<u8>,
        ) -> Result<(), CloudStorageError> {
            if let Some(error) = self.state.lock().upload_master_key_error.clone() {
                return Err(error);
            }

            Ok(())
        }

        fn upload_wallet_backup(
            &self,
            namespace: String,
            record_id: String,
            _data: Vec<u8>,
        ) -> Result<(), CloudStorageError> {
            if let Some(error) = self.state.lock().upload_wallet_backup_error.clone() {
                return Err(error);
            }

            self.state.lock().uploaded_wallet_backups.push((namespace, record_id));
            Ok(())
        }

        fn download_master_key_backup(
            &self,
            namespace: String,
        ) -> Result<Vec<u8>, CloudStorageError> {
            self.state
                .lock()
                .master_key_backups
                .get(&namespace)
                .cloned()
                .ok_or(CloudStorageError::NotFound(namespace))
        }

        fn download_wallet_backup(
            &self,
            namespace: String,
            record_id: String,
        ) -> Result<Vec<u8>, CloudStorageError> {
            Err(CloudStorageError::NotFound(format!("{namespace}/{record_id}")))
        }

        fn delete_wallet_backup(
            &self,
            _namespace: String,
            _record_id: String,
        ) -> Result<(), CloudStorageError> {
            Ok(())
        }

        fn list_namespaces(&self) -> Result<Vec<String>, CloudStorageError> {
            Ok(self.state.lock().wallet_files.keys().cloned().collect())
        }

        fn list_wallet_files(&self, namespace: String) -> Result<Vec<String>, CloudStorageError> {
            let state = self.state.lock();
            let mut wallet_files = state.wallet_files.get(&namespace).cloned().unwrap_or_default();

            if state.reflect_uploaded_wallets_in_listing {
                for (uploaded_namespace, record_id) in &state.uploaded_wallet_backups {
                    if uploaded_namespace == &namespace {
                        let filename = wallet_filename_from_record_id(record_id);
                        if !wallet_files.contains(&filename) {
                            wallet_files.push(filename);
                        }
                    }
                }
            }

            Ok(wallet_files)
        }

        fn is_backup_uploaded(
            &self,
            _namespace: String,
            _record_id: String,
        ) -> Result<bool, CloudStorageError> {
            Ok(true)
        }
    }

    #[derive(Debug, Clone)]
    struct MockPasskeyProviderImpl {
        discover_result: Arc<Mutex<MockDiscoverResult>>,
    }

    impl Default for MockPasskeyProviderImpl {
        fn default() -> Self {
            Self { discover_result: Arc::new(Mutex::new(Err(PasskeyError::NoCredentialFound))) }
        }
    }

    impl MockPasskeyProviderImpl {
        fn reset(&self) {
            *self.discover_result.lock() = Err(PasskeyError::NoCredentialFound);
        }

        fn set_discover_result(&self, result: Result<DiscoveredPasskeyResult, PasskeyError>) {
            *self.discover_result.lock() =
                result.map(|value| (value.prf_output, value.credential_id));
        }
    }

    impl PasskeyProvider for MockPasskeyProviderImpl {
        fn create_passkey(
            &self,
            _rp_id: String,
            _user_id: Vec<u8>,
            _challenge: Vec<u8>,
        ) -> Result<Vec<u8>, PasskeyError> {
            Err(PasskeyError::CreationFailed("unexpected create_passkey call".into()))
        }

        fn authenticate_with_prf(
            &self,
            _rp_id: String,
            _credential_id: Vec<u8>,
            _prf_salt: Vec<u8>,
            _challenge: Vec<u8>,
        ) -> Result<Vec<u8>, PasskeyError> {
            Err(PasskeyError::AuthenticationFailed("unexpected authenticate_with_prf call".into()))
        }

        fn discover_and_authenticate_with_prf(
            &self,
            _rp_id: String,
            _prf_salt: Vec<u8>,
            _challenge: Vec<u8>,
        ) -> Result<DiscoveredPasskeyResult, PasskeyError> {
            self.discover_result.lock().clone().map(|(prf_output, credential_id)| {
                DiscoveredPasskeyResult { prf_output, credential_id }
            })
        }

        fn is_prf_supported(&self) -> bool {
            true
        }

        fn check_passkey_presence(
            &self,
            _rp_id: String,
            _credential_id: Vec<u8>,
        ) -> PasskeyCredentialPresence {
            PasskeyCredentialPresence::Present
        }
    }

    struct TestGlobals {
        keychain: MockKeychain,
        cloud: MockCloudStorage,
        passkey: MockPasskeyProviderImpl,
    }

    impl TestGlobals {
        fn init() -> Self {
            let keychain = MockKeychain::default();
            let cloud = MockCloudStorage::default();
            let passkey = MockPasskeyProviderImpl::default();

            let _ = Keychain::new(Box::new(keychain.clone()));
            let _ = CloudStorage::new(Box::new(cloud.clone()));
            let _ = PasskeyAccess::new(Box::new(passkey.clone()));

            Self { keychain, cloud, passkey }
        }

        fn reset(&self) {
            self.keychain.reset();
            self.cloud.reset();
            self.passkey.reset();
            cove_cspp::Cspp::<Keychain>::clear_cached_master_key();
        }
    }

    fn test_globals() -> &'static TestGlobals {
        static GLOBALS: OnceLock<TestGlobals> = OnceLock::new();
        GLOBALS.get_or_init(TestGlobals::init)
    }

    fn test_lock() -> &'static StdMutex<()> {
        static LOCK: OnceLock<StdMutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| StdMutex::new(()))
    }

    fn clear_local_wallets() {
        let wallets = Database::global().wallets();
        for network in Network::iter() {
            for mode in WalletMode::iter() {
                wallets.save_all_wallets(network, mode, Vec::new()).unwrap();
            }
        }
    }

    fn reset_cloud_backup_test_state(manager: &RustCloudBackupManager, globals: &TestGlobals) {
        globals.reset();
        clear_local_wallets();
        manager.debug_reset_cloud_backup_state();
    }

    fn prepare_deep_verify_with_unsynced_wallet(
        manager: &RustCloudBackupManager,
        globals: &TestGlobals,
    ) -> crate::wallet::metadata::WalletMetadata {
        reset_cloud_backup_test_state(manager, globals);

        let master_key = cove_cspp::master_key::MasterKey::generate();
        let namespace = master_key.namespace_id();
        let prf_key = [7u8; 32];
        let prf_salt = [9u8; 32];
        let credential_id = vec![1, 2, 3, 4];
        let encrypted_master =
            cove_cspp::master_key_crypto::encrypt_master_key(&master_key, &prf_key, &prf_salt)
                .unwrap();

        globals.cloud.set_master_key_backup(
            namespace.clone(),
            serde_json::to_vec(&encrypted_master).unwrap(),
        );
        globals.cloud.set_reflect_uploaded_wallets_in_listing(false);
        globals.passkey.set_discover_result(Ok(DiscoveredPasskeyResult {
            prf_output: prf_key.to_vec(),
            credential_id,
        }));

        let keychain = Keychain::global();
        keychain.save(CSPP_NAMESPACE_ID_KEY.into(), namespace).unwrap();
        cove_cspp::Cspp::new(keychain.clone()).save_master_key(&master_key).unwrap();

        manager
            .persist_cloud_backup_state(
                &PersistedCloudBackupState {
                    status: PersistedCloudBackupStatus::Enabled,
                    ..PersistedCloudBackupState::default()
                },
                "set cloud backup enabled for test",
            )
            .unwrap();

        let mut metadata = crate::wallet::metadata::WalletMetadata::preview_new();
        metadata.wallet_type = crate::wallet::metadata::WalletType::WatchOnly;
        Database::global()
            .wallets()
            .save_all_wallets(metadata.network, metadata.wallet_mode, vec![metadata.clone()])
            .unwrap();

        metadata
    }

    #[test]
    fn cloud_action_uses_existing_master_key_without_recovery() {
        let store = Arc::new(MockStore::default());
        let cspp = cove_cspp::Cspp::new(MockStoreHandle(store));
        let expected = cove_cspp::master_key::MasterKey::generate();
        cspp.save_master_key(&expected).unwrap();

        let recovered = load_master_key_for_cloud_action(&cspp, || {
            Err(CloudBackupError::RecoveryRequired("unexpected".into()))
        })
        .unwrap();

        assert_eq!(recovered.as_bytes(), expected.as_bytes());
    }

    #[test]
    fn cloud_action_does_not_create_master_key_when_missing() {
        let store = Arc::new(MockStore::default());
        let cspp = cove_cspp::Cspp::new(MockStoreHandle(store.clone()));

        let result = load_master_key_for_cloud_action(&cspp, || {
            Err(CloudBackupError::RecoveryRequired("needs recovery".into()))
        });

        assert!(matches!(
            result,
            Err(CloudBackupError::RecoveryRequired(message)) if message == "needs recovery"
        ));
        assert!(cspp.load_master_key_from_store().unwrap().is_none());
        assert_eq!(*store.save_count.lock(), 0);
    }

    #[test]
    fn local_master_key_fallback_persists_namespace_id() {
        let _guard = test_lock().lock().unwrap();
        let globals = test_globals();
        globals.reset();

        let store = Arc::new(MockStore::default());
        let store_handle = MockStoreHandle(store.clone());
        let cspp = cove_cspp::Cspp::new(store_handle.clone());
        let expected = cove_cspp::master_key::MasterKey::generate();
        let namespace_id = expected.namespace_id();
        cspp.save_master_key(&expected).unwrap();
        globals.cloud.set_wallet_files(namespace_id.clone(), vec!["wallet-test.json".into()]);

        let (restored, restored_namespace) =
            restore_from_local_master_key_fallback(CloudStorage::global(), &store_handle, &cspp)
                .unwrap();

        assert_eq!(restored.as_bytes(), expected.as_bytes());
        assert_eq!(restored_namespace, namespace_id.clone());
        assert_eq!(
            store_handle.get(CSPP_NAMESPACE_ID_KEY.into()).as_deref(),
            Some(namespace_id.as_str())
        );
    }

    #[test]
    fn failed_create_new_enable_does_not_persist_passkey_metadata() {
        let _guard = test_lock().lock().unwrap();
        let globals = test_globals();
        globals.reset();
        globals.cloud.fail_master_key_upload("boom");
        globals.passkey.set_discover_result(Ok(DiscoveredPasskeyResult {
            prf_output: vec![7; 32],
            credential_id: vec![1, 2, 3],
        }));

        let manager = RustCloudBackupManager::init();
        let error = manager.do_enable_cloud_backup_create_new().unwrap_err();
        assert!(
            matches!(error, CloudBackupError::Cloud(message) if message.contains("upload failed: boom"))
        );

        let keychain = Keychain::global();
        assert!(keychain.get(CSPP_CREDENTIAL_ID_KEY.into()).is_none());
        assert!(keychain.get(CSPP_PRF_SALT_KEY.into()).is_none());
        assert!(keychain.get(CSPP_NAMESPACE_ID_KEY.into()).is_none());
    }

    #[test]
    fn reupload_all_wallets_does_not_create_master_key_for_existing_namespace() {
        let _guard = test_lock().lock().unwrap();
        let globals = test_globals();
        globals.reset();

        Keychain::global().save(CSPP_NAMESPACE_ID_KEY.into(), "existing-namespace".into()).unwrap();

        let manager = RustCloudBackupManager::init();
        let error = manager.do_reupload_all_wallets().unwrap_err();

        assert!(matches!(
            error,
            CloudBackupError::RecoveryRequired(message)
                if message == RECREATE_MANIFEST_RECOVERY_MESSAGE
        ));

        let cspp = cove_cspp::Cspp::new(Keychain::global().clone());
        assert!(cspp.load_master_key_from_store().unwrap().is_none());
    }

    #[test]
    fn backup_wallets_does_not_create_master_key_or_upload_when_missing() {
        let _guard = test_lock().lock().unwrap();
        let globals = test_globals();
        globals.reset();

        let namespace = "existing-namespace";
        Keychain::global().save(CSPP_NAMESPACE_ID_KEY.into(), namespace.into()).unwrap();

        let manager = RustCloudBackupManager::init();
        let mut metadata = WalletMetadata::preview_new();
        metadata.wallet_type = crate::wallet::metadata::WalletType::WatchOnly;

        let error = manager.do_backup_wallets(&[metadata]).unwrap_err();

        assert!(matches!(
            error,
            CloudBackupError::RecoveryRequired(message)
                if message == "Cloud backup needs verification before wallets can be uploaded"
        ));

        let cspp = cove_cspp::Cspp::new(Keychain::global().clone());
        assert!(cspp.load_master_key_from_store().unwrap().is_none());
        assert_eq!(globals.cloud.uploaded_wallet_backup_count(), 0);
    }

    #[test]
    fn deep_verify_fails_when_auto_sync_upload_fails() {
        let _guard = test_lock().lock().unwrap();
        let globals = test_globals();
        let manager = RustCloudBackupManager::init();
        let metadata = prepare_deep_verify_with_unsynced_wallet(&manager, globals);
        let record_id = cove_cspp::backup_data::wallet_record_id(metadata.id.as_ref());
        globals.cloud.fail_wallet_backup_upload("upload failed");

        let result = manager.deep_verify_cloud_backup(true);

        match result {
            DeepVerificationResult::Failed(failure) => {
                assert_eq!(failure.kind, VerificationFailureKind::Retry);
                assert_eq!(
                    failure.message,
                    "failed to auto-sync missing wallet backups: cloud storage error: upload failed: upload failed"
                );
                let detail = failure.detail.expect("expected detail on retry failure");
                assert_eq!(detail.not_backed_up.len(), 1);
                assert_eq!(detail.not_backed_up[0].record_id, record_id);
            }
            other => panic!("expected retry failure, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn deep_verify_fails_when_relist_still_misses_uploaded_wallet() {
        let _guard = test_lock().lock().unwrap();
        cove_tokio::init();
        let globals = test_globals();
        let manager = RustCloudBackupManager::init();
        let metadata = prepare_deep_verify_with_unsynced_wallet(&manager, globals);

        let result = manager.deep_verify_cloud_backup(true);

        match result {
            DeepVerificationResult::Failed(failure) => {
                assert_eq!(failure.kind, VerificationFailureKind::Retry);
                assert_eq!(
                    failure.message,
                    "1 local wallet backup(s) are still missing in iCloud after auto-sync"
                );
                let detail = failure.detail.expect("expected detail on retry failure");
                assert_eq!(detail.not_backed_up.len(), 1);
                assert_eq!(
                    detail.not_backed_up[0].record_id,
                    cove_cspp::backup_data::wallet_record_id(metadata.id.as_ref())
                );
            }
            other => panic!("expected retry failure, got {other:?}"),
        }

        assert_eq!(globals.cloud.uploaded_wallet_backup_count(), 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn deep_verify_succeeds_after_auto_sync_relist_confirms_wallet() {
        let _guard = test_lock().lock().unwrap();
        cove_tokio::init();
        let globals = test_globals();
        let manager = RustCloudBackupManager::init();
        let metadata = prepare_deep_verify_with_unsynced_wallet(&manager, globals);
        globals.cloud.set_reflect_uploaded_wallets_in_listing(true);

        let result = manager.deep_verify_cloud_backup(true);

        match result {
            DeepVerificationResult::Verified(report) => {
                let detail = report.detail.expect("expected verification detail");
                assert_eq!(detail.backed_up.len(), 1);
                assert!(detail.not_backed_up.is_empty());
                assert_eq!(
                    detail.backed_up[0].record_id,
                    cove_cspp::backup_data::wallet_record_id(metadata.id.as_ref())
                );
            }
            other => panic!("expected verified result, got {other:?}"),
        }

        assert_eq!(globals.cloud.uploaded_wallet_backup_count(), 1);
    }
}
