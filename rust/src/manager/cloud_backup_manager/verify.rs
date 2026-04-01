mod passkey_auth;
mod session;
mod wrapper_repair;

use cove_cspp::CsppStore as _;
use cove_cspp::backup_data::EncryptedWalletBackup;
use cove_cspp::master_key::MasterKey;
use cove_cspp::master_key_crypto;
use cove_cspp::wallet_crypto;
use cove_device::cloud_storage::{CloudStorage, CloudStorageError};
use cove_device::keychain::{CSPP_CREDENTIAL_ID_KEY, CSPP_PRF_SALT_KEY, Keychain};
use cove_device::passkey::PasskeyAccess;
use cove_util::ResultExt as _;
use tracing::{error, info, warn};
use zeroize::Zeroizing;

use self::passkey_auth::{PasskeyAuthOutcome, PasskeyAuthPolicy, authenticate_with_policy};
use self::session::VerificationSession;
use self::wrapper_repair::{WrapperRepairOperation, WrapperRepairStrategy};
use super::wallets::{count_all_wallets, persist_enabled_cloud_backup_state};
use super::{
    CloudBackupDetailResult, CloudBackupError, CloudBackupStatus, DeepVerificationFailure,
    DeepVerificationReport, DeepVerificationResult, PendingVerificationCompletion,
    RustCloudBackupManager, VerificationFailureKind,
};
use crate::database::Database;
use crate::database::cloud_backup::{PersistedCloudBackupState, PersistedCloudBackupStatus};
use crate::manager::cloud_backup_detail_manager::{RecoveryState, VerificationState};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IntegrityDowngrade {
    Unverified,
}

enum PendingWalletVerificationOutcome {
    Verified,
    Failed,
    Unsupported,
}

impl RustCloudBackupManager {
    /// Background startup health check for cloud backup integrity
    ///
    /// Verifies the master key is in the keychain and backup files exist in iCloud.
    /// Returns None if everything is OK, Some(warning) if there's a problem
    pub(super) fn verify_backup_integrity_impl(&self) -> Option<String> {
        let state = self.state.read().status.clone();
        if !matches!(state, CloudBackupStatus::Enabled | CloudBackupStatus::PasskeyMissing) {
            return None;
        }

        let mut issues: Vec<&str> = Vec::new();

        let keychain = Keychain::global();
        let cspp = cove_cspp::Cspp::new(keychain.clone());
        if !cspp.has_master_key() {
            issues.push("master key not found in keychain");
        }

        let mut downgrade = None;
        let has_prf_salt = keychain.get(CSPP_PRF_SALT_KEY.into()).is_some();
        let stored_credential_id = load_stored_credential_id(keychain);

        // keep launch integrity checks non-interactive so app startup never presents passkey UI
        if stored_credential_id.is_none() {
            issues
                .push("passkey credential not found — open Cloud Backup in Settings to re-verify");
            downgrade = Some(IntegrityDowngrade::Unverified);
        }
        if !has_prf_salt {
            issues.push("passkey salt not found — open Cloud Backup in Settings to re-verify");
            downgrade = Some(IntegrityDowngrade::Unverified);
        }

        let namespace = match self.current_namespace_id() {
            Ok(ns) => ns,
            Err(_) => {
                issues.push("namespace_id not found in keychain");
                self.persist_integrity_downgrade(downgrade);
                return Some(issues.join("; "));
            }
        };

        let cloud = CloudStorage::global();
        if issues.is_empty() {
            match cloud.list_wallet_backups(namespace) {
                Ok(wallet_record_ids) => {
                    let db = Database::global();
                    let local_count = match count_all_wallets(&db) {
                        Ok(local_count) => local_count,
                        Err(error) => {
                            warn!("Backup integrity: local wallet count failed: {error}");
                            issues.push("local wallet inventory could not be read");
                            0
                        }
                    };
                    let cloud_count = wallet_record_ids.len() as u32;

                    if local_count > cloud_count {
                        info!(
                            "Backup integrity: {local_count} local wallets vs {cloud_count} in cloud, auto-syncing"
                        );
                        if let Err(error) = self.do_sync_unsynced_wallets() {
                            error!("Backup integrity: auto-sync failed: {error}");
                            issues.push("some wallets are not backed up");
                        }
                    }
                }
                Err(error) => {
                    warn!("Backup integrity: wallet list check failed: {error}");
                }
            }
        }

        if issues.is_empty() {
            info!("Backup integrity check passed");
            None
        } else {
            self.persist_integrity_downgrade(downgrade);
            let message = issues.join("; ");
            error!("Backup integrity issues: {message}");
            Some(message)
        }
    }

    /// Deep verification of cloud backup integrity
    ///
    /// Checks state, runs do_deep_verify, wraps errors, persists result
    pub(crate) fn deep_verify_cloud_backup(
        &self,
        force_discoverable: bool,
    ) -> DeepVerificationResult {
        let state = self.state.read().status.clone();
        if !matches!(state, CloudBackupStatus::Enabled | CloudBackupStatus::PasskeyMissing) {
            return DeepVerificationResult::NotEnabled;
        }

        self.clear_pending_verification_completion();
        let result = match self.do_deep_verify_cloud_backup(force_discoverable) {
            Ok(result) => result,
            Err(error) => {
                error!("Deep verification unexpected error: {error}");
                DeepVerificationResult::Failed(DeepVerificationFailure {
                    kind: VerificationFailureKind::Retry,
                    message: error.to_string(),
                    detail: None,
                })
            }
        };

        self.persist_verification_result(&result);
        result
    }

    pub(crate) fn persist_verification_result(&self, result: &DeepVerificationResult) {
        let current = RustCloudBackupManager::load_persisted_state();
        if matches!(current.status, PersistedCloudBackupStatus::Disabled) {
            return;
        }

        let mut new_state = current.clone();
        match result {
            DeepVerificationResult::Verified(_) => {
                new_state.status = PersistedCloudBackupStatus::Enabled;
                new_state.last_verified_at =
                    Some(jiff::Timestamp::now().as_second().try_into().unwrap_or(0));
            }
            DeepVerificationResult::AwaitingUploadConfirmation(_) => return,
            DeepVerificationResult::PasskeyConfirmed(_) => return,
            DeepVerificationResult::PasskeyMissing(_) => {
                new_state.status = PersistedCloudBackupStatus::PasskeyMissing;
            }
            DeepVerificationResult::UserCancelled(_) | DeepVerificationResult::Failed(_) => {
                new_state.status = PersistedCloudBackupStatus::Unverified;
            }
            DeepVerificationResult::NotEnabled => return,
        };

        if current != new_state
            && let Err(error) =
                self.persist_cloud_backup_state(&new_state, "persist verification state")
        {
            error!("Failed to persist verification state: {error}");
        }
    }

    pub(crate) fn finalize_pending_verification_if_ready(&self) {
        let Some(completion) = self.pending_verification_completion() else { return };

        if !self.pending_verification_uploads_confirmed(&completion) {
            return;
        }

        match self.finalize_pending_verification(completion.clone()) {
            Ok(report) => self.apply_verified_report(report),
            Err(failure) => self.apply_failed_verification(failure),
        }

        self.clear_pending_verification_completion();
    }

    pub(crate) fn mark_verification_required_after_wallet_change(&self) {
        let current = RustCloudBackupManager::load_persisted_state();

        match current.status {
            PersistedCloudBackupStatus::Enabled | PersistedCloudBackupStatus::Unverified => {
                let Some(mut new_state) =
                    downgrade_cloud_backup_state(&current, IntegrityDowngrade::Unverified)
                else {
                    return;
                };

                new_state.last_verification_requested_at =
                    Some(jiff::Timestamp::now().as_second().try_into().unwrap_or(0));

                if let Err(error) = self.persist_cloud_backup_state(
                    &new_state,
                    "mark cloud backup unverified after wallet change",
                ) {
                    error!("Failed to mark cloud backup unverified after wallet change: {error}");
                }
            }
            PersistedCloudBackupStatus::PasskeyMissing | PersistedCloudBackupStatus::Disabled => {}
        }
    }

    pub(crate) fn do_repair_passkey_wrapper(&self) -> Result<(), CloudBackupError> {
        self.do_repair_passkey_wrapper_with_strategy(WrapperRepairStrategy::DiscoverOrCreate)
    }

    pub(crate) fn do_repair_passkey_wrapper_no_discovery(&self) -> Result<(), CloudBackupError> {
        self.do_repair_passkey_wrapper_with_strategy(WrapperRepairStrategy::CreateNew)
    }

    fn do_repair_passkey_wrapper_with_strategy(
        &self,
        strategy: WrapperRepairStrategy,
    ) -> Result<(), CloudBackupError> {
        let keychain = Keychain::global();
        let cspp = cove_cspp::Cspp::new(keychain.clone());
        let cloud = CloudStorage::global();
        let passkey = PasskeyAccess::global();
        let namespace = self.current_namespace_id()?;

        let local_master_key = cspp
            .load_master_key_from_store()
            .map_err_prefix("load local master key", CloudBackupError::Internal)?
            .ok_or_else(|| CloudBackupError::Internal("no local master key".into()))?;

        let wallet_record_ids = match cloud.list_wallet_backups(namespace.clone()) {
            Ok(ids) => ids,
            Err(CloudStorageError::NotFound(_)) => Vec::new(),
            Err(error) => {
                return Err(CloudBackupError::Cloud(format!("list wallet backups: {error}")));
            }
        };

        let repair = WrapperRepairOperation::new(self, keychain, cloud, passkey, &namespace);
        repair
            .run(&local_master_key, &wallet_record_ids, strategy)
            .map_err(|error| error.into_cloud_backup_error())?;

        info!("Repaired cloud master key wrapper with repaired passkey association");
        Ok(())
    }

    pub(crate) fn finalize_passkey_repair(&self) -> Result<(), CloudBackupError> {
        let namespace = self.current_namespace_id()?;
        let cloud = CloudStorage::global();
        let wallet_record_ids =
            cloud.list_wallet_backups(namespace).map_err_str(CloudBackupError::Cloud)?;

        persist_enabled_cloud_backup_state(&Database::global(), wallet_record_ids.len() as u32)?;
        self.set_status(CloudBackupStatus::Enabled);

        match self.refresh_cloud_backup_detail() {
            Some(CloudBackupDetailResult::Success(detail)) => {
                self.set_detail(Some(detail));
            }
            Some(CloudBackupDetailResult::AccessError(error)) => {
                warn!("Failed to refresh detail after passkey repair: {error}");
            }
            None => {}
        }

        Ok(())
    }

    fn pending_verification_uploads_confirmed(
        &self,
        completion: &PendingVerificationCompletion,
    ) -> bool {
        let pending = Database::global()
            .cloud_upload_queue
            .get()
            .ok()
            .flatten()
            .map(|queue| queue.items)
            .unwrap_or_default();

        let listed_ids = CloudStorage::global()
            .list_wallet_backups(completion.namespace_id().to_string())
            .ok()
            .map(|ids| ids.into_iter().collect::<std::collections::HashSet<_>>())
            .unwrap_or_default();

        completion.record_ids().iter().all(|record_id| {
            if listed_ids.contains(record_id) {
                return true;
            }

            let pending_item = pending.iter().find(|item| {
                item.namespace_id == completion.namespace_id() && item.record_id == *record_id
            });

            pending_item.is_some_and(|item| item.is_confirmed())
        })
    }

    fn finalize_pending_verification(
        &self,
        completion: PendingVerificationCompletion,
    ) -> Result<DeepVerificationReport, DeepVerificationFailure> {
        let cspp = cove_cspp::Cspp::new(Keychain::global().clone());
        let master_key = cspp
            .load_master_key_from_store()
            .map_err_prefix("load local master key", CloudBackupError::Internal)
            .map_err(|error| self.pending_verification_failure(&completion, error.to_string()))?
            .ok_or_else(|| {
                self.pending_verification_failure(&completion, "no local master key available")
            })?;

        let critical_key = Zeroizing::new(master_key.critical_data_key());
        let mut report = completion.report().clone();

        for record_id in completion.record_ids() {
            match self.verify_pending_wallet_backup(&completion, record_id, &critical_key)? {
                PendingWalletVerificationOutcome::Verified => report.wallets_verified += 1,
                PendingWalletVerificationOutcome::Failed => report.wallets_failed += 1,
                PendingWalletVerificationOutcome::Unsupported => report.wallets_unsupported += 1,
            }
        }

        report.detail = self.pending_verification_detail(&completion);
        Ok(report)
    }

    fn verify_pending_wallet_backup(
        &self,
        completion: &PendingVerificationCompletion,
        record_id: &str,
        critical_key: &[u8; 32],
    ) -> Result<PendingWalletVerificationOutcome, DeepVerificationFailure> {
        let cloud = CloudStorage::global();
        let download = cloud
            .download_wallet_backup(completion.namespace_id().to_string(), record_id.to_string());
        let wallet_json = match download {
            Ok(wallet_json) => wallet_json,
            Err(error) => {
                warn!("Pending verification: failed to download wallet {record_id}: {error}");
                return Ok(PendingWalletVerificationOutcome::Failed);
            }
        };

        let encrypted: EncryptedWalletBackup =
            serde_json::from_slice(&wallet_json).map_err(|error| {
                self.pending_verification_failure(
                    completion,
                    format!("deserialize wallet {record_id}: {error}"),
                )
            })?;

        if encrypted.version != 1 {
            return Ok(PendingWalletVerificationOutcome::Unsupported);
        }

        match wallet_crypto::decrypt_wallet_backup(&encrypted, critical_key) {
            Ok(_) => Ok(PendingWalletVerificationOutcome::Verified),
            Err(error) => {
                warn!("Pending verification: failed to decrypt wallet {record_id}: {error}");
                Ok(PendingWalletVerificationOutcome::Failed)
            }
        }
    }

    fn pending_verification_detail(
        &self,
        completion: &PendingVerificationCompletion,
    ) -> Option<super::CloudBackupDetail> {
        match self.refresh_cloud_backup_detail() {
            Some(CloudBackupDetailResult::Success(detail)) => Some(detail),
            Some(CloudBackupDetailResult::AccessError(error)) => {
                warn!("Pending verification: failed to refresh detail: {error}");
                completion.report().detail.clone()
            }
            None => completion.report().detail.clone(),
        }
    }

    fn pending_verification_failure(
        &self,
        completion: &PendingVerificationCompletion,
        message: impl Into<String>,
    ) -> DeepVerificationFailure {
        DeepVerificationFailure {
            kind: VerificationFailureKind::Retry,
            message: message.into(),
            detail: self.pending_verification_detail(completion),
        }
    }

    pub(crate) fn apply_verified_report(&self, report: DeepVerificationReport) {
        self.persist_verification_result(&DeepVerificationResult::Verified(report.clone()));
        if let Some(detail) = &report.detail {
            self.set_detail(Some(detail.clone()));
        }
        self.set_verification(VerificationState::Verified(report));
        self.set_recovery(RecoveryState::Idle);
    }

    pub(crate) fn apply_failed_verification(&self, failure: DeepVerificationFailure) {
        self.persist_verification_result(&DeepVerificationResult::Failed(failure.clone()));
        if let Some(detail) = failure.detail.clone() {
            self.set_detail(Some(detail));
        }
        self.set_verification(VerificationState::Failed(failure));
    }

    pub(crate) fn do_deep_verify_cloud_backup(
        &self,
        force_discoverable: bool,
    ) -> Result<DeepVerificationResult, CloudBackupError> {
        VerificationSession::new(self, force_discoverable)?.run()
    }

    pub(crate) fn recover_local_master_key_from_cloud(
        &self,
        namespace: &str,
        recovery_message: &str,
    ) -> Result<MasterKey, CloudBackupError> {
        self.recover_local_master_key_from_cloud_with_policy(
            namespace,
            recovery_message,
            PasskeyAuthPolicy::StoredThenDiscover,
        )
    }

    pub(crate) fn recover_local_master_key_from_cloud_without_discovery(
        &self,
        namespace: &str,
        recovery_message: &str,
    ) -> Result<MasterKey, CloudBackupError> {
        self.recover_local_master_key_from_cloud_with_policy(
            namespace,
            recovery_message,
            PasskeyAuthPolicy::StoredOnly,
        )
    }

    fn recover_local_master_key_from_cloud_with_policy(
        &self,
        namespace: &str,
        recovery_message: &str,
        auth_policy: PasskeyAuthPolicy,
    ) -> Result<MasterKey, CloudBackupError> {
        let keychain = Keychain::global();
        let cspp = cove_cspp::Cspp::new(keychain.clone());
        let cloud = CloudStorage::global();
        let passkey = PasskeyAccess::global();

        let master_json = match cloud.download_master_key_backup(namespace.to_string()) {
            Ok(json) => json,
            Err(CloudStorageError::NotFound(_)) => {
                return Err(CloudBackupError::RecoveryRequired(recovery_message.into()));
            }
            Err(error) => {
                return Err(CloudBackupError::Cloud(format!(
                    "download master key backup: {error}",
                )));
            }
        };

        let encrypted: cove_cspp::backup_data::EncryptedMasterKeyBackup =
            serde_json::from_slice(&master_json).map_err_str(CloudBackupError::Internal)?;
        if encrypted.version != 1 {
            let version = encrypted.version;
            return Err(CloudBackupError::Internal(format!(
                "master key backup version {version} is not supported",
            )));
        }

        let authenticated =
            match authenticate_with_policy(keychain, passkey, &encrypted.prf_salt, auth_policy)? {
                PasskeyAuthOutcome::Authenticated(result) => result,
                PasskeyAuthOutcome::UserCancelled => {
                    return Err(CloudBackupError::Passkey("user cancelled".into()));
                }
                PasskeyAuthOutcome::NoCredentialFound => {
                    return Err(CloudBackupError::RecoveryRequired(recovery_message.into()));
                }
            };

        let master_key = master_key_crypto::decrypt_master_key(&encrypted, &authenticated.prf_key)
            .map_err(|_| match auth_policy {
                PasskeyAuthPolicy::StoredOnly => {
                    CloudBackupError::RecoveryRequired(recovery_message.into())
                }
                PasskeyAuthPolicy::StoredThenDiscover | PasskeyAuthPolicy::DiscoverOnly => {
                    CloudBackupError::Passkey(
                        "selected passkey didn't unlock this cloud backup".into(),
                    )
                }
            })?;

        keychain
            .save_cspp_passkey(&authenticated.credential_id, encrypted.prf_salt)
            .map_err_prefix("save cspp credentials", CloudBackupError::Internal)?;
        cspp.save_master_key(&master_key)
            .map_err_prefix("save recovered master key", CloudBackupError::Internal)?;

        info!("Recovered local master key from cloud");
        Ok(master_key)
    }
}

impl RustCloudBackupManager {
    fn persist_integrity_downgrade(&self, downgrade: Option<IntegrityDowngrade>) {
        let Some(downgrade) = downgrade else {
            return;
        };

        info!("Cloud backup integrity: applying downgrade={downgrade:?}");

        let current = RustCloudBackupManager::load_persisted_state();
        let Some(new_state) = downgrade_cloud_backup_state(&current, downgrade) else {
            return;
        };

        if let Err(error) =
            self.persist_cloud_backup_state(&new_state, "persist backup integrity state")
        {
            error!("Failed to persist backup integrity state: {error}");
        };
    }
}

pub(super) fn load_stored_credential_id(keychain: &Keychain) -> Option<Vec<u8>> {
    keychain.get(CSPP_CREDENTIAL_ID_KEY.into()).and_then(|hex_str| {
        hex::decode(hex_str)
            .inspect_err(|error| warn!("Failed to decode stored credential_id: {error}"))
            .ok()
    })
}

fn downgrade_cloud_backup_state(
    current: &PersistedCloudBackupState,
    downgrade: IntegrityDowngrade,
) -> Option<PersistedCloudBackupState> {
    match downgrade {
        IntegrityDowngrade::Unverified => match current.status {
            PersistedCloudBackupStatus::Enabled => Some(PersistedCloudBackupState {
                status: PersistedCloudBackupStatus::Unverified,
                ..current.clone()
            }),
            PersistedCloudBackupStatus::Unverified => Some(current.clone()),
            PersistedCloudBackupStatus::PasskeyMissing | PersistedCloudBackupStatus::Disabled => {
                None
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn downgrade_state_marks_enabled_as_unverified() {
        let current = PersistedCloudBackupState {
            status: PersistedCloudBackupStatus::Enabled,
            last_sync: Some(5),
            wallet_count: Some(2),
            last_verified_at: Some(21),
            ..PersistedCloudBackupState::default()
        };

        let updated =
            downgrade_cloud_backup_state(&current, IntegrityDowngrade::Unverified).unwrap();

        assert_eq!(
            updated,
            PersistedCloudBackupState {
                status: PersistedCloudBackupStatus::Unverified,
                last_sync: Some(5),
                wallet_count: Some(2),
                last_verified_at: Some(21),
                ..PersistedCloudBackupState::default()
            }
        );
    }

    #[test]
    fn downgrade_state_keeps_passkey_missing_when_only_unverified_requested() {
        let current = PersistedCloudBackupState {
            status: PersistedCloudBackupStatus::PasskeyMissing,
            last_sync: Some(11),
            wallet_count: Some(4),
            last_verified_at: Some(22),
            ..PersistedCloudBackupState::default()
        };

        let updated = downgrade_cloud_backup_state(&current, IntegrityDowngrade::Unverified);

        assert!(updated.is_none());
    }
}
