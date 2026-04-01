use tracing::error;

use super::cloud_backup_manager::{
    CLOUD_BACKUP_MANAGER, CloudBackupError, CloudBackupManagerAction, CloudBackupReconcileMessage,
    CloudBackupWalletItem, DeepVerificationFailure, DeepVerificationReport, DeepVerificationResult,
    RustCloudBackupManager,
};

type Action = CloudBackupManagerAction;

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum RecoveryAction {
    RecreateManifest,
    ReinitializeBackup,
    RepairPasskey,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum VerificationState {
    Idle,
    Verifying,
    Verified(DeepVerificationReport),
    PasskeyConfirmed,
    Failed(DeepVerificationFailure),
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum SyncState {
    Idle,
    Syncing,
    Failed(String),
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum RecoveryState {
    Idle,
    Recovering(RecoveryAction),
    Failed { action: RecoveryAction, error: String },
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum CloudOnlyState {
    NotFetched,
    Loading,
    Loaded { wallets: Vec<CloudBackupWalletItem> },
    Failed { error: String },
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum CloudOnlyOperation {
    Idle,
    Operating { record_id: String },
    Failed { error: String },
}

#[uniffi::export]
impl RustCloudBackupManager {
    #[uniffi::method]
    pub fn dispatch(&self, action: Action) {
        match action {
            Action::EnableCloudBackup => self.enable_cloud_backup(),
            Action::EnableCloudBackupForceNew => self.enable_cloud_backup_force_new(),
            Action::EnableCloudBackupNoDiscovery => self.enable_cloud_backup_no_discovery(),
            Action::DiscardPendingEnableCloudBackup => {
                self.discard_pending_enable_cloud_backup();
            }
            Action::RestoreFromCloudBackup => self.restore_from_cloud_backup(),
            Action::CancelRestore => self.cancel_restore(),
            Action::StartVerification => self.start_verification(),
            Action::StartVerificationDiscoverable => self.start_verification_discoverable(),
            Action::DismissVerificationPrompt => self.dismiss_verification_prompt(),
            Action::RecreateManifest => {
                CLOUD_BACKUP_MANAGER.clone().spawn_recovery(RecoveryAction::RecreateManifest);
            }
            Action::ReinitializeBackup => {
                CLOUD_BACKUP_MANAGER.clone().spawn_recovery(RecoveryAction::ReinitializeBackup);
            }
            Action::RepairPasskey => {
                CLOUD_BACKUP_MANAGER.clone().spawn_repair_passkey(false);
            }
            Action::RepairPasskeyNoDiscovery => {
                CLOUD_BACKUP_MANAGER.clone().spawn_repair_passkey(true);
            }
            Action::SyncUnsynced => CLOUD_BACKUP_MANAGER.clone().spawn_sync(),
            Action::FetchCloudOnly => CLOUD_BACKUP_MANAGER.clone().spawn_fetch_cloud_only(),
            Action::RestoreCloudWallet { record_id } => {
                CLOUD_BACKUP_MANAGER.clone().spawn_restore_cloud_wallet(record_id);
            }
            Action::DeleteCloudWallet { record_id } => {
                CLOUD_BACKUP_MANAGER.clone().spawn_delete_cloud_wallet(record_id);
            }
            Action::RefreshDetail => CLOUD_BACKUP_MANAGER.clone().spawn_refresh_detail(),
        }
    }
}

impl RustCloudBackupManager {
    fn start_verification(&self) {
        if let Err(error) = self.dismiss_verification_prompt_impl() {
            error!("Failed to dismiss verification prompt before verification: {error}");
        }
        CLOUD_BACKUP_MANAGER.clone().spawn_verification(false);
    }

    fn start_verification_discoverable(&self) {
        if let Err(error) = self.dismiss_verification_prompt_impl() {
            error!("Failed to dismiss verification prompt before verification: {error}");
        }
        CLOUD_BACKUP_MANAGER.clone().spawn_verification(true);
    }

    fn dismiss_verification_prompt(&self) {
        if let Err(error) = self.dismiss_verification_prompt_impl() {
            error!("Failed to dismiss verification prompt: {error}");
        }
    }

    fn spawn_verification(self: std::sync::Arc<Self>, force_discoverable: bool) {
        cove_tokio::task::spawn_blocking(move || {
            self.handle_start_verification(force_discoverable)
        });
    }

    fn spawn_recovery(self: std::sync::Arc<Self>, action: RecoveryAction) {
        cove_tokio::task::spawn_blocking(move || self.handle_recovery(action));
    }

    fn spawn_repair_passkey(self: std::sync::Arc<Self>, no_discovery: bool) {
        cove_tokio::task::spawn_blocking(move || self.handle_repair_passkey(no_discovery));
    }

    fn spawn_sync(self: std::sync::Arc<Self>) {
        cove_tokio::task::spawn_blocking(move || self.handle_sync());
    }

    fn spawn_fetch_cloud_only(self: std::sync::Arc<Self>) {
        cove_tokio::task::spawn_blocking(move || self.handle_fetch_cloud_only());
    }

    fn spawn_restore_cloud_wallet(self: std::sync::Arc<Self>, record_id: String) {
        cove_tokio::task::spawn_blocking(move || self.handle_restore_cloud_wallet(&record_id));
    }

    fn spawn_delete_cloud_wallet(self: std::sync::Arc<Self>, record_id: String) {
        cove_tokio::task::spawn_blocking(move || self.handle_delete_cloud_wallet(&record_id));
    }

    fn spawn_refresh_detail(self: std::sync::Arc<Self>) {
        cove_tokio::task::spawn_blocking(move || self.handle_refresh_detail());
    }

    fn handle_start_verification(&self, force_discoverable: bool) {
        self.clear_pending_verification_completion();
        self.set_verification(VerificationState::Verifying);

        let result = self.deep_verify_cloud_backup(force_discoverable);

        match result {
            DeepVerificationResult::Verified(report) => {
                self.apply_verified_report(report);
            }
            DeepVerificationResult::AwaitingUploadConfirmation(report) => {
                if let Some(detail) = report.detail {
                    self.set_detail(Some(detail));
                }
            }
            DeepVerificationResult::PasskeyConfirmed(detail) => {
                if let Some(detail) = detail {
                    self.set_detail(Some(detail));
                }
                self.set_verification(VerificationState::PasskeyConfirmed);
            }
            DeepVerificationResult::PasskeyMissing(detail) => {
                if let Some(detail) = detail {
                    self.set_detail(Some(detail));
                }
                self.set_verification(VerificationState::Idle);
                self.set_recovery(RecoveryState::Idle);
            }
            DeepVerificationResult::UserCancelled(detail) => {
                if let Some(detail) = detail {
                    self.set_detail(Some(detail));
                }
                self.set_verification(VerificationState::Cancelled);
            }
            DeepVerificationResult::NotEnabled => {}
            DeepVerificationResult::Failed(failure) => {
                self.apply_failed_verification(failure);
            }
        }
    }

    fn handle_recovery(&self, action: RecoveryAction) {
        self.set_recovery(RecoveryState::Recovering(action.clone()));

        let result = match &action {
            RecoveryAction::RecreateManifest => self.do_reupload_all_wallets(),
            RecoveryAction::ReinitializeBackup => self.do_enable_cloud_backup(),
            RecoveryAction::RepairPasskey => self.do_repair_passkey_wrapper(),
        };

        match result {
            Ok(()) => {
                self.set_recovery(RecoveryState::Idle);
                self.handle_start_verification(false);
            }
            Err(CloudBackupError::UnsupportedPasskeyProvider) => {
                self.set_recovery(RecoveryState::Idle);
                self.set_status(RustCloudBackupManager::status_for_operation_error(
                    &CloudBackupError::UnsupportedPasskeyProvider,
                ));
            }
            Err(error) => {
                self.set_recovery(RecoveryState::Failed { action, error: error.to_string() });
            }
        }
    }

    fn handle_repair_passkey(&self, no_discovery: bool) {
        self.set_recovery(RecoveryState::Recovering(RecoveryAction::RepairPasskey));

        let result = if no_discovery {
            self.do_repair_passkey_wrapper_no_discovery()
        } else {
            self.do_repair_passkey_wrapper()
        };

        match result {
            Ok(()) => {
                if let Err(error) = self.finalize_passkey_repair() {
                    self.set_recovery(RecoveryState::Failed {
                        action: RecoveryAction::RepairPasskey,
                        error: error.to_string(),
                    });
                    return;
                }

                self.set_recovery(RecoveryState::Idle);
                self.set_verification(VerificationState::Idle);
            }
            Err(CloudBackupError::PasskeyDiscoveryCancelled) => {
                self.set_recovery(RecoveryState::Idle);
                self.send(CloudBackupReconcileMessage::PasskeyDiscoveryCancelled);
            }
            Err(CloudBackupError::UnsupportedPasskeyProvider) => {
                self.set_recovery(RecoveryState::Idle);
                self.set_status(RustCloudBackupManager::status_for_operation_error(
                    &CloudBackupError::UnsupportedPasskeyProvider,
                ));
            }
            Err(error) => {
                self.set_recovery(RecoveryState::Failed {
                    action: RecoveryAction::RepairPasskey,
                    error: error.to_string(),
                });
            }
        }
    }

    fn handle_sync(&self) {
        self.set_sync(SyncState::Syncing);

        match self.do_sync_unsynced_wallets() {
            Ok(()) => {
                self.handle_refresh_detail();
                self.set_sync(SyncState::Idle);
            }
            Err(error) => {
                self.set_sync(SyncState::Failed(error.to_string()));
            }
        }
    }

    fn handle_fetch_cloud_only(&self) {
        self.set_cloud_only(CloudOnlyState::Loading);
        self.set_cloud_only_operation(CloudOnlyOperation::Idle);

        match self.do_fetch_cloud_only_wallets() {
            Ok(items) => {
                self.set_cloud_only(CloudOnlyState::Loaded { wallets: items });
            }
            Err(error) => {
                error!("Failed to fetch cloud-only wallets: {error}");
                self.set_cloud_only(CloudOnlyState::Failed { error: error.to_string() });
            }
        }
    }

    fn handle_restore_cloud_wallet(&self, record_id: &str) {
        self.set_cloud_only_operation(CloudOnlyOperation::Operating {
            record_id: record_id.to_string(),
        });

        match self.do_restore_cloud_wallet(record_id) {
            Ok(()) => {
                self.set_cloud_only_operation(CloudOnlyOperation::Idle);

                let mut cloud_only = self.state.read().cloud_only.clone();
                if let CloudOnlyState::Loaded { wallets } = &mut cloud_only {
                    wallets.retain(|wallet| wallet.record_id != record_id);
                }
                self.set_cloud_only(cloud_only);
                self.handle_refresh_detail();
            }
            Err(error) => {
                self.set_cloud_only_operation(CloudOnlyOperation::Failed {
                    error: error.to_string(),
                });
            }
        }
    }

    fn handle_delete_cloud_wallet(&self, record_id: &str) {
        self.set_cloud_only_operation(CloudOnlyOperation::Operating {
            record_id: record_id.to_string(),
        });

        match self.do_delete_cloud_wallet(record_id) {
            Ok(()) => {
                self.set_cloud_only_operation(CloudOnlyOperation::Idle);

                let mut cloud_only = self.state.read().cloud_only.clone();
                if let CloudOnlyState::Loaded { wallets } = &mut cloud_only {
                    wallets.retain(|wallet| wallet.record_id != record_id);
                }
                self.set_cloud_only(cloud_only);
                self.handle_refresh_detail();
            }
            Err(error) => {
                self.set_cloud_only_operation(CloudOnlyOperation::Failed {
                    error: error.to_string(),
                });
            }
        }
    }

    fn handle_refresh_detail(&self) {
        if let Some(result) = self.refresh_cloud_backup_detail() {
            match result {
                super::cloud_backup_manager::CloudBackupDetailResult::Success(detail) => {
                    self.set_detail(Some(detail));
                }
                super::cloud_backup_manager::CloudBackupDetailResult::AccessError(error) => {
                    error!("Failed to refresh detail: {error}");
                }
            }
        }
    }
}
