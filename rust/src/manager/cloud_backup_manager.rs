mod cloud_inventory;
mod ops;
mod pending;
mod verify;
mod wallets;

use std::path::Path;
use std::sync::{
    Arc, LazyLock,
    atomic::{AtomicBool, AtomicU64, Ordering},
};

use cove_cspp::CsppStore as _;
use cove_cspp::backup_data::MASTER_KEY_RECORD_ID;
use cove_util::ResultExt as _;
use flume::{Receiver, Sender};
use parking_lot::{Mutex, RwLock};
use tokio::sync::Notify;
use tracing::{error, info, warn};
use zeroize::Zeroizing;

use cove_device::keychain::{
    CSPP_CREDENTIAL_ID_KEY, CSPP_NAMESPACE_ID_KEY, CSPP_PRF_SALT_KEY, Keychain,
};
use cove_types::network::Network;

use crate::backup::model::DescriptorPair as LocalDescriptorPair;
use crate::database::Database;
use crate::database::cloud_backup::{PersistedCloudBackupState, PersistedCloudBackupStatus};
use crate::wallet::metadata::{WalletId, WalletMode as LocalWalletMode, WalletType};

use self::wallets::{UnpersistedPrfKey, all_local_wallets, count_all_wallets};
use super::cloud_backup_detail_manager::{
    CloudOnlyOperation, CloudOnlyState, RecoveryState, SyncState, VerificationState,
};

type LocalWalletSecret = crate::backup::model::WalletSecret;

const PASSKEY_RP_ID: &str = "covebitcoinwallet.com";
type Message = CloudBackupReconcileMessage;

pub static CLOUD_BACKUP_MANAGER: LazyLock<Arc<RustCloudBackupManager>> =
    LazyLock::new(RustCloudBackupManager::init);

#[derive(Debug, Clone, Hash, Eq, PartialEq, uniffi::Enum)]
pub enum CloudBackupStatus {
    Disabled,
    Enabling,
    Restoring,
    Enabled,
    PasskeyMissing,
    UnsupportedPasskeyProvider,
    Error(String),
}

#[derive(Debug, Clone, uniffi::Enum)]
pub enum CloudBackupManagerAction {
    EnableCloudBackup,
    EnableCloudBackupForceNew,
    EnableCloudBackupNoDiscovery,
    DiscardPendingEnableCloudBackup,
    RestoreFromCloudBackup,
    CancelRestore,
    StartVerification,
    StartVerificationDiscoverable,
    DismissVerificationPrompt,
    RecreateManifest,
    ReinitializeBackup,
    RepairPasskey,
    RepairPasskeyNoDiscovery,
    SyncUnsynced,
    FetchCloudOnly,
    RestoreCloudWallet { record_id: String },
    DeleteCloudWallet { record_id: String },
    RefreshDetail,
}

#[derive(Debug, Clone, uniffi::Enum)]
pub enum CloudBackupReconcileMessage {
    StatusChanged(CloudBackupStatus),
    ProgressChanged(Option<CloudBackupProgress>),
    RestoreProgressChanged(Option<CloudBackupRestoreProgress>),
    RestoreReportChanged(Option<CloudBackupRestoreReport>),
    SyncErrorChanged(Option<String>),
    VerificationPromptChanged(bool),
    VerificationMetadataChanged(CloudBackupVerificationMetadata),
    PendingUploadVerificationChanged(bool),
    DetailChanged(Option<CloudBackupDetail>),
    VerificationChanged(VerificationState),
    SyncChanged(SyncState),
    RecoveryChanged(RecoveryState),
    CloudOnlyChanged(CloudOnlyState),
    CloudOnlyOperationChanged(CloudOnlyOperation),
    ExistingBackupFound,
    PasskeyDiscoveryCancelled,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct CloudBackupRestoreReport {
    pub wallets_restored: u32,
    pub wallets_failed: u32,
    pub failed_wallet_errors: Vec<String>,
}

#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq, uniffi::Record)]
pub struct CloudBackupProgress {
    pub completed: u32,
    pub total: u32,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, uniffi::Enum)]
pub enum CloudBackupRestoreStage {
    Finding,
    Downloading,
    Restoring,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, uniffi::Record)]
pub struct CloudBackupRestoreProgress {
    pub stage: CloudBackupRestoreStage,
    pub completed: u32,
    pub total: Option<u32>,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, uniffi::Enum)]
pub enum CloudBackupWalletStatus {
    BackedUp,
    NotBackedUp,
    DeletedFromDevice,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, uniffi::Record)]
pub struct CloudBackupWalletItem {
    pub name: String,
    pub network: Network,
    pub wallet_mode: LocalWalletMode,
    pub wallet_type: WalletType,
    pub fingerprint: Option<String>,
    pub status: CloudBackupWalletStatus,
    /// Deterministic cloud record ID for the wallet backup represented by this item
    pub record_id: String,
}

#[derive(Debug, Clone, uniffi::Enum)]
pub enum CloudBackupDetailResult {
    Success(CloudBackupDetail),
    AccessError(String),
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct CloudBackupDetail {
    pub last_sync: Option<u64>,
    pub backed_up: Vec<CloudBackupWalletItem>,
    pub not_backed_up: Vec<CloudBackupWalletItem>,
    /// Number of wallets in the cloud that aren't on this device
    pub cloud_only_count: u32,
}

#[derive(Debug, Clone, uniffi::Enum)]
pub enum DeepVerificationResult {
    Verified(DeepVerificationReport),
    AwaitingUploadConfirmation(DeepVerificationReport),
    PasskeyConfirmed(Option<CloudBackupDetail>),
    PasskeyMissing(Option<CloudBackupDetail>),
    UserCancelled(Option<CloudBackupDetail>),
    NotEnabled,
    Failed(DeepVerificationFailure),
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct DeepVerificationReport {
    /// Cloud master key PRF wrapping was repaired
    pub master_key_wrapper_repaired: bool,
    /// Local keychain was repaired from verified cloud master key
    pub local_master_key_repaired: bool,
    /// credential_id was recovered via discoverable auth
    pub credential_recovered: bool,
    pub wallets_verified: u32,
    pub wallets_failed: u32,
    /// Wallet backups with unsupported version (newer format, skipped)
    pub wallets_unsupported: u32,
    /// May be None if wallet list was missing but master key verified
    pub detail: Option<CloudBackupDetail>,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, uniffi::Enum)]
pub enum CloudBackupVerificationMetadata {
    NotConfigured,
    ConfiguredNeverVerified,
    Verified(u64),
    NeedsVerification,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct DeepVerificationFailure {
    pub kind: VerificationFailureKind,
    pub message: String,
    pub detail: Option<CloudBackupDetail>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum VerificationFailureKind {
    /// Transient iCloud/network/passkey error — safe to retry
    Retry,
    /// Manifest missing, master key verified intact — recreate from local wallets
    RecreateManifest { warning: String },
    /// No verified cloud or local master key available — full re-enable needed
    ReinitializeBackup { warning: String },
    /// Backup uses a newer format — do not overwrite
    UnsupportedVersion,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct CloudBackupState {
    pub status: CloudBackupStatus,
    pub progress: Option<CloudBackupProgress>,
    pub restore_progress: Option<CloudBackupRestoreProgress>,
    pub restore_report: Option<CloudBackupRestoreReport>,
    pub sync_error: Option<String>,
    pub has_pending_upload_verification: bool,
    pub should_prompt_verification: bool,
    pub verification_metadata: CloudBackupVerificationMetadata,
    pub detail: Option<CloudBackupDetail>,
    pub verification: VerificationState,
    pub sync: SyncState,
    pub recovery: RecoveryState,
    pub cloud_only: CloudOnlyState,
    pub cloud_only_operation: CloudOnlyOperation,
}

impl Default for CloudBackupState {
    fn default() -> Self {
        Self {
            status: CloudBackupStatus::Disabled,
            progress: None,
            restore_progress: None,
            restore_report: None,
            sync_error: None,
            has_pending_upload_verification: false,
            should_prompt_verification: false,
            verification_metadata: CloudBackupVerificationMetadata::NotConfigured,
            detail: None,
            verification: VerificationState::Idle,
            sync: SyncState::Idle,
            recovery: RecoveryState::Idle,
            cloud_only: CloudOnlyState::NotFetched,
            cloud_only_operation: CloudOnlyOperation::Idle,
        }
    }
}

pub(crate) struct PendingEnableSession {
    master_key: Zeroizing<cove_cspp::master_key::MasterKey>,
    passkey: Zeroizing<UnpersistedPrfKey>,
}

#[derive(Debug, Clone)]
pub(crate) struct PendingVerificationCompletion {
    report: DeepVerificationReport,
    namespace_id: String,
    record_ids: Vec<String>,
}

impl std::fmt::Debug for PendingEnableSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingEnableSession").finish_non_exhaustive()
    }
}

impl PendingEnableSession {
    fn new(master_key: cove_cspp::master_key::MasterKey, passkey: UnpersistedPrfKey) -> Self {
        Self { master_key: Zeroizing::new(master_key), passkey: Zeroizing::new(passkey) }
    }

    fn into_parts(
        self,
    ) -> (Zeroizing<cove_cspp::master_key::MasterKey>, Zeroizing<UnpersistedPrfKey>) {
        (self.master_key, self.passkey)
    }
}

impl PendingVerificationCompletion {
    fn new(report: DeepVerificationReport, namespace_id: String, record_ids: Vec<String>) -> Self {
        Self { report, namespace_id, record_ids }
    }

    pub(crate) fn report(&self) -> &DeepVerificationReport {
        &self.report
    }

    pub(crate) fn namespace_id(&self) -> &str {
        &self.namespace_id
    }

    pub(crate) fn record_ids(&self) -> &[String] {
        &self.record_ids
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum CloudBackupError {
    #[error("not supported: {0}")]
    NotSupported(String),

    #[error("passkey provider does not support PRF for Cloud Backup")]
    UnsupportedPasskeyProvider,

    #[error("{0}")]
    RecoveryRequired(String),

    #[error("passkey error: {0}")]
    Passkey(String),

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("cloud storage error: {0}")]
    Cloud(String),

    #[error("internal error: {0}")]
    Internal(String),

    #[error("Passkey didn't match any backups, please try a new one")]
    PasskeyMismatch,

    #[error("user cancelled passkey discovery")]
    PasskeyDiscoveryCancelled,

    #[error("restore cancelled")]
    Cancelled,
}

#[derive(Debug, Clone, uniffi::Error, thiserror::Error)]
#[uniffi::export(Display)]
pub enum CatastrophicRecoveryError {
    #[error("{0}")]
    Failure(String),
}

#[uniffi::export(callback_interface)]
pub trait CloudBackupManagerReconciler: Send + Sync + std::fmt::Debug + 'static {
    fn reconcile(&self, message: CloudBackupReconcileMessage);
}

#[derive(Clone, Debug, uniffi::Object)]
pub struct RustCloudBackupManager {
    pub state: Arc<RwLock<CloudBackupState>>,
    pub reconciler: Sender<Message>,
    pub reconcile_receiver: Arc<Receiver<Message>>,
    pending_enable_session: Arc<Mutex<Option<PendingEnableSession>>>,
    pending_verification_completion: Arc<Mutex<Option<PendingVerificationCompletion>>>,
    pending_upload_verifier_running: Arc<AtomicBool>,
    pending_upload_verifier_wakeup: Arc<Notify>,
    restore_operation_id: Arc<AtomicU64>,
    restore_operation_gate: Arc<Mutex<()>>,
}

impl RustCloudBackupManager {
    fn load_persisted_state() -> PersistedCloudBackupState {
        Database::global().cloud_backup_state.get().unwrap_or_else(|error| {
            error!("Failed to load cloud backup state: {error}");
            PersistedCloudBackupState::default()
        })
    }

    pub(crate) fn runtime_status_for(state: &PersistedCloudBackupState) -> CloudBackupStatus {
        match state.status {
            PersistedCloudBackupStatus::Disabled => CloudBackupStatus::Disabled,
            PersistedCloudBackupStatus::Enabled | PersistedCloudBackupStatus::Unverified => {
                CloudBackupStatus::Enabled
            }
            PersistedCloudBackupStatus::PasskeyMissing => CloudBackupStatus::PasskeyMissing,
        }
    }

    pub(crate) fn status_for_operation_error(error: &CloudBackupError) -> CloudBackupStatus {
        match error {
            CloudBackupError::UnsupportedPasskeyProvider => {
                CloudBackupStatus::UnsupportedPasskeyProvider
            }
            other => CloudBackupStatus::Error(other.to_string()),
        }
    }

    fn init() -> Arc<Self> {
        let (sender, receiver) = flume::bounded(1000);

        Self {
            state: Arc::new(RwLock::new(CloudBackupState::default())),
            reconciler: sender,
            reconcile_receiver: Arc::new(receiver),
            pending_enable_session: Arc::new(Mutex::new(None)),
            pending_verification_completion: Arc::new(Mutex::new(None)),
            pending_upload_verifier_running: Arc::new(AtomicBool::new(false)),
            pending_upload_verifier_wakeup: Arc::new(Notify::new()),
            restore_operation_id: Arc::new(AtomicU64::new(0)),
            restore_operation_gate: Arc::new(Mutex::new(())),
        }
        .into()
    }

    fn verification_metadata_for(
        db_state: &PersistedCloudBackupState,
    ) -> CloudBackupVerificationMetadata {
        if db_state.is_unverified() {
            return CloudBackupVerificationMetadata::NeedsVerification;
        }

        if !db_state.is_configured() {
            return CloudBackupVerificationMetadata::NotConfigured;
        }

        match db_state.last_verified_at {
            Some(last_verified_at) => CloudBackupVerificationMetadata::Verified(last_verified_at),
            None => CloudBackupVerificationMetadata::ConfiguredNeverVerified,
        }
    }

    fn load_persisted_flags() -> (CloudBackupVerificationMetadata, bool) {
        let db_state = Self::load_persisted_state();
        (Self::verification_metadata_for(&db_state), db_state.should_prompt_verification())
    }

    pub(super) fn send(&self, message: Message) {
        if let Err(error) = self.reconciler.send(message) {
            error!("unable to send cloud backup message: {error:?}");
        }
    }

    fn set_and_notify_field<T>(
        &self,
        value: T,
        field: impl FnOnce(&mut CloudBackupState) -> &mut T,
        notify: fn(T) -> Message,
    ) where
        T: PartialEq + Clone,
    {
        {
            let mut state = self.state.write();
            let slot = field(&mut state);
            if *slot == value {
                return;
            }

            *slot = value.clone();
        }

        self.send(notify(value));
    }

    pub(super) fn set_status(&self, status: CloudBackupStatus) {
        self.set_and_notify_field(status, |state| &mut state.status, Message::StatusChanged);
    }

    pub(super) fn set_progress(&self, progress: Option<CloudBackupProgress>) {
        self.set_and_notify_field(progress, |state| &mut state.progress, Message::ProgressChanged);
    }

    pub(super) fn set_restore_progress(&self, progress: Option<CloudBackupRestoreProgress>) {
        self.set_and_notify_field(
            progress,
            |state| &mut state.restore_progress,
            Message::RestoreProgressChanged,
        );
    }

    pub(super) fn set_restore_report(&self, report: Option<CloudBackupRestoreReport>) {
        self.set_and_notify_field(
            report,
            |state| &mut state.restore_report,
            Message::RestoreReportChanged,
        );
    }

    pub(super) fn set_sync_error(&self, sync_error: Option<String>) {
        self.set_and_notify_field(
            sync_error,
            |state| &mut state.sync_error,
            Message::SyncErrorChanged,
        );
    }

    pub(super) fn refresh_persisted_flags(&self) {
        let (verification_metadata, should_prompt_verification) = Self::load_persisted_flags();

        let (metadata_changed, prompt_changed) = {
            let mut state = self.state.write();

            let metadata_changed = state.verification_metadata != verification_metadata;
            if metadata_changed {
                state.verification_metadata = verification_metadata.clone();
            }

            let prompt_changed = state.should_prompt_verification != should_prompt_verification;
            if prompt_changed {
                state.should_prompt_verification = should_prompt_verification;
            }

            (metadata_changed, prompt_changed)
        };

        if metadata_changed {
            self.send(Message::VerificationMetadataChanged(verification_metadata));
        }

        if prompt_changed {
            self.send(Message::VerificationPromptChanged(should_prompt_verification));
        }
    }

    pub(super) fn set_pending_upload_verification(&self, pending: bool) {
        self.set_and_notify_field(
            pending,
            |state| &mut state.has_pending_upload_verification,
            Message::PendingUploadVerificationChanged,
        );
    }

    pub(super) fn set_detail(&self, detail: Option<CloudBackupDetail>) {
        self.set_and_notify_field(detail, |state| &mut state.detail, Message::DetailChanged);
    }

    pub(super) fn set_verification(&self, verification: VerificationState) {
        self.set_and_notify_field(
            verification,
            |state| &mut state.verification,
            Message::VerificationChanged,
        );
    }

    pub(super) fn set_sync(&self, sync: SyncState) {
        self.set_and_notify_field(sync, |state| &mut state.sync, Message::SyncChanged);
    }

    pub(super) fn set_recovery(&self, recovery: RecoveryState) {
        self.set_and_notify_field(recovery, |state| &mut state.recovery, Message::RecoveryChanged);
    }

    pub(super) fn set_cloud_only(&self, cloud_only: CloudOnlyState) {
        self.set_and_notify_field(
            cloud_only,
            |state| &mut state.cloud_only,
            Message::CloudOnlyChanged,
        );
    }

    pub(super) fn set_cloud_only_operation(&self, cloud_only_operation: CloudOnlyOperation) {
        self.set_and_notify_field(
            cloud_only_operation,
            |state| &mut state.cloud_only_operation,
            Message::CloudOnlyOperationChanged,
        );
    }

    fn next_restore_operation_id(&self) -> u64 {
        let _gate = self.restore_operation_gate.lock();
        self.restore_operation_id.fetch_add(1, Ordering::AcqRel) + 1
    }

    fn invalidate_restore_operation(&self) {
        let _gate = self.restore_operation_gate.lock();
        self.restore_operation_id.fetch_add(1, Ordering::AcqRel);
    }

    pub(crate) fn ensure_current_restore_operation(
        &self,
        operation_id: u64,
    ) -> Result<(), CloudBackupError> {
        // only use this as a preflight read
        // side-effecting restore work must use the locked helpers below so
        // cancellation can't race between the check and the write
        if self.restore_operation_id.load(Ordering::Acquire) == operation_id {
            return Ok(());
        }

        Err(CloudBackupError::Cancelled)
    }

    pub(crate) fn set_status_for_restore_operation(
        &self,
        operation_id: u64,
        status: CloudBackupStatus,
    ) -> Result<(), CloudBackupError> {
        self.with_current_restore_operation(operation_id, |this| this.set_status(status))
    }

    pub(crate) fn set_restore_progress_for_restore_operation(
        &self,
        operation_id: u64,
        progress: Option<CloudBackupRestoreProgress>,
    ) -> Result<(), CloudBackupError> {
        self.with_current_restore_operation(operation_id, |this| {
            this.set_restore_progress(progress)
        })
    }

    pub(crate) fn set_restore_report_for_restore_operation(
        &self,
        operation_id: u64,
        report: Option<CloudBackupRestoreReport>,
    ) -> Result<(), CloudBackupError> {
        self.with_current_restore_operation(operation_id, |this| this.set_restore_report(report))
    }

    fn with_current_restore_operation<T>(
        &self,
        operation_id: u64,
        update: impl FnOnce(&Self) -> T,
    ) -> Result<T, CloudBackupError> {
        let _gate = self.restore_operation_gate.lock();
        if self.restore_operation_id.load(Ordering::Acquire) != operation_id {
            return Err(CloudBackupError::Cancelled);
        }

        Ok(update(self))
    }

    fn with_current_restore_operation_result<T>(
        &self,
        operation_id: u64,
        update: impl FnOnce(&Self) -> Result<T, CloudBackupError>,
    ) -> Result<T, CloudBackupError> {
        let _gate = self.restore_operation_gate.lock();
        if self.restore_operation_id.load(Ordering::Acquire) != operation_id {
            return Err(CloudBackupError::Cancelled);
        }

        update(self)
    }

    pub(crate) fn persist_cloud_backup_state(
        &self,
        state: &PersistedCloudBackupState,
        context: &str,
    ) -> Result<(), CloudBackupError> {
        Database::global()
            .cloud_backup_state
            .set(state)
            .map_err(|error| CloudBackupError::Internal(format!("{context}: {error}")))?;

        self.set_status(Self::runtime_status_for(state));
        self.refresh_persisted_flags();

        Ok(())
    }

    pub(crate) fn persist_cloud_backup_state_for_restore_operation(
        &self,
        operation_id: u64,
        state: &PersistedCloudBackupState,
        context: &str,
    ) -> Result<(), CloudBackupError> {
        self.with_current_restore_operation_result(operation_id, |this| {
            Database::global()
                .cloud_backup_state
                .set(state)
                .map_err(|error| CloudBackupError::Internal(format!("{context}: {error}")))?;
            this.set_status(Self::runtime_status_for(state));
            this.refresh_persisted_flags();
            Ok(())
        })
    }

    pub(crate) fn dismiss_verification_prompt_impl(&self) -> Result<(), CloudBackupError> {
        let mut state = Self::load_persisted_state();
        if state.last_verification_requested_at.is_none() {
            return Ok(());
        }

        state.last_verification_dismissed_at =
            Some(jiff::Timestamp::now().as_second().try_into().unwrap_or(0));

        self.persist_cloud_backup_state(&state, "persist cloud backup prompt dismissal")
    }

    fn current_namespace_id(&self) -> Result<String, CloudBackupError> {
        let keychain = Keychain::global();
        keychain
            .get(CSPP_NAMESPACE_ID_KEY.into())
            .ok_or_else(|| CloudBackupError::Internal("namespace_id not found in keychain".into()))
    }

    pub(crate) fn replace_pending_enable_session(&self, session: PendingEnableSession) {
        *self.pending_enable_session.lock() = Some(session);
    }

    pub(crate) fn take_pending_enable_session(&self) -> Option<PendingEnableSession> {
        self.pending_enable_session.lock().take()
    }

    pub(crate) fn clear_pending_enable_session(&self) {
        self.pending_enable_session.lock().take();
    }

    pub(crate) fn replace_pending_verification_completion(
        &self,
        completion: PendingVerificationCompletion,
    ) {
        *self.pending_verification_completion.lock() = Some(completion);
    }

    pub(crate) fn pending_verification_completion(&self) -> Option<PendingVerificationCompletion> {
        self.pending_verification_completion.lock().clone()
    }

    pub(crate) fn clear_pending_verification_completion(&self) {
        self.pending_verification_completion.lock().take();
    }

    fn start_background_operation<F>(
        self: Arc<Self>,
        operation_name: &str,
        entering_status: Option<CloudBackupStatus>,
        work: F,
    ) where
        F: FnOnce(Arc<Self>) -> Result<(), CloudBackupError> + Send + 'static,
    {
        if let Some(status) = entering_status.clone() {
            let (
                progress_changed,
                restore_progress_changed,
                restore_report_changed,
                status_changed,
            ) = {
                let mut state = self.state.write();
                let current_status = state.status.clone();
                if matches!(
                    current_status,
                    CloudBackupStatus::Enabling | CloudBackupStatus::Restoring
                ) {
                    warn!("{operation_name} called while {current_status:?}, ignoring");
                    return;
                }

                let progress_changed = state.progress.take().is_some();
                let restore_progress_changed = state.restore_progress.take().is_some();
                let restore_report_changed =
                    matches!(status, CloudBackupStatus::Enabling | CloudBackupStatus::Restoring)
                        && state.restore_report.take().is_some();
                let status_changed = state.status != status;
                if status_changed {
                    state.status = status.clone();
                }

                (progress_changed, restore_progress_changed, restore_report_changed, status_changed)
            };

            if progress_changed {
                self.send(Message::ProgressChanged(None));
            }
            if restore_progress_changed {
                self.send(Message::RestoreProgressChanged(None));
            }
            if restore_report_changed {
                self.send(Message::RestoreReportChanged(None));
            }
            if status_changed {
                self.send(Message::StatusChanged(status));
            }
        } else {
            let status = self.state.read().status.clone();
            if matches!(status, CloudBackupStatus::Enabling | CloudBackupStatus::Restoring) {
                warn!("{operation_name} called while {status:?}, ignoring");
                return;
            }
        }

        let operation_name = operation_name.to_owned();
        cove_tokio::task::spawn_blocking(move || {
            if let Err(error) = work(self.clone()) {
                error!("{operation_name} failed: {error}");
                self.set_progress(None);
                self.set_restore_progress(None);
                self.set_status(Self::status_for_operation_error(&error));
            }
        });
    }
}

#[uniffi::export]
impl RustCloudBackupManager {
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        CLOUD_BACKUP_MANAGER.clone()
    }

    pub fn listen_for_updates(&self, reconciler: Box<dyn CloudBackupManagerReconciler>) {
        let reconcile_receiver = self.reconcile_receiver.clone();

        std::thread::spawn(move || {
            while let Ok(field) = reconcile_receiver.recv() {
                reconciler.reconcile(field);
            }
        });
    }

    pub fn current_status(&self) -> CloudBackupStatus {
        self.state.read().status.clone()
    }

    pub fn state(&self) -> CloudBackupState {
        let mut state = self.state.read().clone();
        let (verification_metadata, should_prompt_verification) = Self::load_persisted_flags();
        state.verification_metadata = verification_metadata;
        state.should_prompt_verification = should_prompt_verification;
        state.has_pending_upload_verification = self.has_pending_cloud_upload_verification();
        state
    }

    /// Number of wallets in the cloud backup
    pub fn backup_wallet_count(&self) -> Option<u32> {
        let db = Database::global();
        let current = Self::load_persisted_state();

        match current.wallet_count {
            Some(count) => Some(count),
            None if current.is_configured() => match count_all_wallets(&db) {
                Ok(count) => {
                    let _ = db.cloud_backup_state.set(&current.with_wallet_count(Some(count)));
                    Some(count)
                }
                Err(error) => {
                    warn!("Failed to derive cloud backup wallet count: {error}");
                    None
                }
            },
            None => None,
        }
    }

    /// Read persisted cloud backup state from DB and update in-memory state
    ///
    /// Called after bootstrap completes so the UI reflects the correct state
    /// even before the reconciler has delivered its first message
    pub fn sync_persisted_state(&self) {
        let db_state = Self::load_persisted_state();
        self.set_status(Self::runtime_status_for(&db_state));
        self.refresh_persisted_flags();
        self.set_pending_upload_verification(self.has_pending_cloud_upload_verification());
    }

    /// Check if cloud backup is enabled, used as nav guard
    pub fn is_cloud_backup_enabled(&self) -> bool {
        Self::load_persisted_state().is_configured()
    }

    /// Whether the persisted cloud backup state is unverified
    pub fn is_cloud_backup_unverified(&self) -> bool {
        Self::load_persisted_state().is_unverified()
    }

    /// Whether the persisted cloud backup passkey is missing
    pub fn is_cloud_backup_passkey_missing(&self) -> bool {
        Self::load_persisted_state().is_passkey_missing()
    }

    pub fn has_pending_cloud_upload_verification(&self) -> bool {
        Database::global()
            .cloud_upload_queue
            .get()
            .ok()
            .flatten()
            .is_some_and(|queue| queue.has_unconfirmed())
    }

    pub fn resume_pending_cloud_upload_verification(&self) {
        self.start_pending_upload_verification_loop();
    }

    /// Reset local cloud backup state (keychain + DB) without touching iCloud
    ///
    /// Debug-only: pair with Swift-side iCloud wipe for full reset
    pub fn debug_reset_cloud_backup_state(&self) {
        let keychain = Keychain::global();
        keychain.delete(CSPP_NAMESPACE_ID_KEY.to_string());
        keychain.delete(CSPP_CREDENTIAL_ID_KEY.to_string());
        keychain.delete(CSPP_PRF_SALT_KEY.to_string());
        self.clear_pending_enable_session();

        // also delete the master key so next enable starts clean
        let cspp = cove_cspp::Cspp::new(keychain.clone());
        cspp.delete_master_key();

        let db = Database::global();
        let _ = db.cloud_backup_state.delete();
        let _ = db.cloud_upload_queue.delete();

        self.clear_pending_verification_completion();
        self.set_progress(None);
        self.set_restore_progress(None);
        self.set_restore_report(None);
        self.set_sync_error(None);
        self.refresh_persisted_flags();
        self.set_pending_upload_verification(false);
        self.set_detail(None);
        self.set_verification(VerificationState::Idle);
        self.set_sync(SyncState::Idle);
        self.set_recovery(RecoveryState::Idle);
        self.set_cloud_only(CloudOnlyState::NotFetched);
        self.set_cloud_only_operation(CloudOnlyOperation::Idle);
        self.set_status(CloudBackupStatus::Disabled);
        info!("Debug: reset cloud backup local state (including master key)");
    }

    /// Background startup health check for cloud backup integrity
    pub fn verify_backup_integrity(&self) -> Option<String> {
        self.verify_backup_integrity_impl()
    }

    /// Back up a newly created wallet, fire-and-forget
    ///
    /// Returns immediately if cloud backup isn't enabled (e.g. during restore)
    pub fn backup_new_wallet(&self, metadata: crate::wallet::metadata::WalletMetadata) {
        let status = self.state.read().status.clone();
        if !matches!(status, CloudBackupStatus::Enabled | CloudBackupStatus::PasskeyMissing) {
            return;
        }

        let this = CLOUD_BACKUP_MANAGER.clone();
        cove_tokio::task::spawn_blocking(move || {
            if let Err(error) = this.do_backup_wallets(&[metadata]) {
                warn!("Failed to backup new wallet, retrying full sync: {error}");
                if let Err(error) = this.do_sync_unsynced_wallets() {
                    error!("Retry sync also failed: {error}");
                    this.set_sync_error(Some(error.to_string()));
                }
            }
        });
    }
}

impl RustCloudBackupManager {
    pub(crate) fn enable_cloud_backup(&self) {
        CLOUD_BACKUP_MANAGER.clone().start_background_operation(
            "enable_cloud_backup",
            Some(CloudBackupStatus::Enabling),
            |this| this.do_enable_cloud_backup(),
        );
    }

    pub(crate) fn enable_cloud_backup_force_new(&self) {
        CLOUD_BACKUP_MANAGER.clone().start_background_operation(
            "enable_cloud_backup_force_new",
            Some(CloudBackupStatus::Enabling),
            |this| this.do_enable_cloud_backup_force_new(),
        );
    }

    pub(crate) fn enable_cloud_backup_no_discovery(&self) {
        CLOUD_BACKUP_MANAGER.clone().start_background_operation(
            "enable_cloud_backup_no_discovery",
            Some(CloudBackupStatus::Enabling),
            |this| this.do_enable_cloud_backup_no_discovery(),
        );
    }

    pub(crate) fn discard_pending_enable_cloud_backup(&self) {
        if self.take_pending_enable_session().is_some() {
            cove_cspp::Cspp::new(Keychain::global().clone()).delete_master_key();
        }
    }

    pub(crate) fn cancel_restore(&self) {
        let status = self.state.read().status.clone();
        if !matches!(status, CloudBackupStatus::Restoring) {
            return;
        }

        self.invalidate_restore_operation();
        self.set_progress(None);
        self.set_restore_progress(None);
        self.set_restore_report(None);
        self.set_status(Self::runtime_status_for(&Self::load_persisted_state()));
        info!("restore_from_cloud_backup: cancelled active restore");
    }

    pub(crate) fn restore_from_cloud_backup(&self) {
        info!("restore_from_cloud_backup: spawning restore task");
        let this = CLOUD_BACKUP_MANAGER.clone();
        {
            let status = this.state.read().status.clone();
            if matches!(status, CloudBackupStatus::Enabling | CloudBackupStatus::Restoring) {
                warn!("restore_from_cloud_backup called while {status:?}, ignoring");
                return;
            }
        }

        let operation_id = this.next_restore_operation_id();
        cove_tokio::task::spawn_blocking(move || {
            info!("restore_from_cloud_backup: task started");
            match this.do_restore_from_cloud_backup(operation_id) {
                Ok(()) => {}
                Err(CloudBackupError::Cancelled) => {
                    info!("restore_from_cloud_backup: task cancelled");
                }
                Err(error) => {
                    error!("restore_from_cloud_backup failed: {error}");
                    this.set_progress(None);
                    this.set_restore_progress(None);
                    this.set_status(Self::status_for_operation_error(&error));
                }
            }
        });
    }
}

/// Reset local state for the database-encryption-key-mismatch recovery flow
///
/// Removes wallet keychain items, deletes local databases, then reinitializes
/// the database handle so bootstrap can start from a clean state
#[uniffi::export]
pub fn reset_local_data_for_catastrophic_recovery() -> Result<(), CatastrophicRecoveryError> {
    wipe_local_data_for_catastrophic_recovery()?;
    reinit_database_after_catastrophic_recovery()
}

fn wipe_local_data_for_catastrophic_recovery() -> Result<(), CatastrophicRecoveryError> {
    use crate::database::migration::log_remove_file;

    wipe_wallet_keychain_items_for_catastrophic_recovery()?;

    let root = &*cove_common::consts::ROOT_DATA_DIR;

    log_remove_file(&root.join("cove.encrypted.db"));
    log_remove_file(&root.join("cove.db"));

    if let Ok(entries) = std::fs::read_dir(root) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            if name.to_string_lossy().starts_with("bdk_wallet") {
                log_remove_file(&entry.path());
            }
        }
    }

    let wallet_dir = &*cove_common::consts::WALLET_DATA_DIR;
    if wallet_dir.exists()
        && let Err(error) = std::fs::remove_dir_all(wallet_dir)
    {
        error!("Failed to remove wallet data dir: {error}");
    }

    Ok(())
}

fn reinit_database_after_catastrophic_recovery() -> Result<(), CatastrophicRecoveryError> {
    crate::database::wallet_data::DATABASE_CONNECTIONS.write().clear();
    Database::try_reinit()
        .map_err_prefix("reinitialize database", CatastrophicRecoveryError::Failure)
}

#[uniffi::export]
pub fn cspp_master_key_record_id() -> String {
    MASTER_KEY_RECORD_ID.to_string()
}

#[uniffi::export]
pub fn cspp_master_key_filename() -> String {
    cove_cspp::backup_data::master_key_filename()
}

#[uniffi::export]
pub fn cspp_wallet_filename_from_record_id(record_id: String) -> String {
    cove_cspp::backup_data::wallet_filename_from_record_id(&record_id)
}

#[uniffi::export]
pub fn cspp_wallet_file_prefix() -> String {
    cove_cspp::backup_data::WALLET_FILE_PREFIX.to_string()
}

#[uniffi::export]
pub fn cspp_namespaces_subdirectory() -> String {
    cove_cspp::backup_data::NAMESPACES_SUBDIRECTORY.to_string()
}

fn wipe_wallet_keychain_items_for_catastrophic_recovery() -> Result<(), CatastrophicRecoveryError> {
    let keychain = Keychain::global();
    let wallet_ids = catastrophic_wipe_wallet_ids(
        persisted_wallet_ids_for_catastrophic_wipe(),
        &cove_common::consts::WALLET_DATA_DIR,
    );
    let mut failed_wallet_ids = Vec::new();

    for wallet_id in wallet_ids {
        if !keychain.delete_wallet_items(&wallet_id) {
            failed_wallet_ids.push(wallet_id.to_string());
        }
    }

    if failed_wallet_ids.is_empty() {
        return Ok(());
    }

    let failed_wallet_ids = failed_wallet_ids.join(", ");
    error!("Failed to delete wallet keychain items for: {failed_wallet_ids}");
    Err(CatastrophicRecoveryError::Failure(format!(
        "failed to delete wallet keychain items for: {failed_wallet_ids}"
    )))
}

fn persisted_wallet_ids_for_catastrophic_wipe() -> Option<Vec<WalletId>> {
    let Some(db_swap) = crate::database::DATABASE.get() else {
        warn!("Database not initialized, deriving wipe wallet ids from wallet data dir");
        return None;
    };

    let db = db_swap.load();
    match all_local_wallets(&db) {
        Ok(wallets) => Some(wallets.into_iter().map(|wallet| wallet.id).collect()),
        Err(error) => {
            warn!(
                "Failed to read wallet ids for catastrophic recovery, deriving from wallet data dir: {error}"
            );
            None
        }
    }
}

fn catastrophic_wipe_wallet_ids(
    persisted_wallet_ids: Option<Vec<WalletId>>,
    wallet_data_dir: &Path,
) -> Vec<WalletId> {
    if let Some(wallet_ids) = persisted_wallet_ids {
        return wallet_ids;
    }

    wallet_ids_from_wallet_data_dir(wallet_data_dir)
}

fn wallet_ids_from_wallet_data_dir(wallet_data_dir: &Path) -> Vec<WalletId> {
    let mut wallet_ids = std::collections::BTreeSet::new();
    let entries = match std::fs::read_dir(wallet_data_dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Vec::new(),
        Err(error) => {
            warn!("Failed to read wallet data dir during catastrophic wipe: {error}");
            return Vec::new();
        }
    };

    for entry in entries.flatten() {
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if !file_type.is_dir() {
            continue;
        }

        let file_name = entry.file_name();
        let Some(wallet_id) = file_name.to_str() else {
            continue;
        };
        wallet_ids.insert(wallet_id.to_owned());
    }

    wallet_ids.into_iter().map(WalletId::from).collect()
}

#[cfg(test)]
pub(crate) fn cloud_backup_test_lock() -> &'static parking_lot::Mutex<()> {
    static LOCK: std::sync::OnceLock<parking_lot::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(parking_lot::Mutex::default)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_lock() -> &'static parking_lot::Mutex<()> {
        super::cloud_backup_test_lock()
    }

    #[test]
    fn convert_cloud_secret_mnemonic() {
        let secret = cove_cspp::backup_data::WalletSecret::Mnemonic("abandon".into());
        let result = wallets::convert_cloud_secret(&secret);
        assert!(matches!(result, LocalWalletSecret::Mnemonic(ref m) if m == "abandon"));
    }

    #[test]
    fn convert_cloud_secret_tap_signer() {
        let secret = cove_cspp::backup_data::WalletSecret::TapSignerBackup(vec![1, 2, 3]);
        let result = wallets::convert_cloud_secret(&secret);
        assert!(matches!(result, LocalWalletSecret::TapSignerBackup(ref b) if b == &[1, 2, 3]));
    }

    #[test]
    fn convert_cloud_secret_descriptor_to_none() {
        let secret = cove_cspp::backup_data::WalletSecret::Descriptor("wpkh(...)".into());
        let result = wallets::convert_cloud_secret(&secret);
        assert!(matches!(result, LocalWalletSecret::None));
    }

    #[test]
    fn convert_cloud_secret_watch_only_to_none() {
        let result =
            wallets::convert_cloud_secret(&cove_cspp::backup_data::WalletSecret::WatchOnly);
        assert!(matches!(result, LocalWalletSecret::None));
    }

    #[test]
    fn restore_progress_updates_state() {
        let _guard = test_lock().lock();
        let manager = RustCloudBackupManager::init();
        let progress = CloudBackupRestoreProgress {
            stage: CloudBackupRestoreStage::Downloading,
            completed: 1,
            total: Some(2),
        };

        manager.set_restore_progress(Some(progress.clone()));

        assert_eq!(manager.state.read().restore_progress, Some(progress));
    }

    #[test]
    fn verification_metadata_is_not_configured_when_backup_is_disabled() {
        let db_state = PersistedCloudBackupState::default();

        assert_eq!(
            RustCloudBackupManager::verification_metadata_for(&db_state),
            CloudBackupVerificationMetadata::NotConfigured,
        );
    }

    #[test]
    fn verification_metadata_is_configured_never_verified_without_timestamp() {
        let db_state = PersistedCloudBackupState {
            status: PersistedCloudBackupStatus::Enabled,
            ..PersistedCloudBackupState::default()
        };

        assert_eq!(
            RustCloudBackupManager::verification_metadata_for(&db_state),
            CloudBackupVerificationMetadata::ConfiguredNeverVerified,
        );
    }

    #[test]
    fn verification_metadata_is_verified_with_timestamp() {
        let db_state = PersistedCloudBackupState {
            status: PersistedCloudBackupStatus::Enabled,
            last_verified_at: Some(21),
            ..PersistedCloudBackupState::default()
        };

        assert_eq!(
            RustCloudBackupManager::verification_metadata_for(&db_state),
            CloudBackupVerificationMetadata::Verified(21),
        );
    }

    #[test]
    fn verification_metadata_is_needs_verification_when_unverified() {
        let db_state = PersistedCloudBackupState {
            status: PersistedCloudBackupStatus::Unverified,
            last_verified_at: Some(21),
            ..PersistedCloudBackupState::default()
        };

        assert_eq!(
            RustCloudBackupManager::verification_metadata_for(&db_state),
            CloudBackupVerificationMetadata::NeedsVerification,
        );
    }

    #[test]
    fn restore_complete_clears_restore_progress() {
        let _guard = test_lock().lock();
        let manager = RustCloudBackupManager::init();
        manager.set_restore_progress(Some(CloudBackupRestoreProgress {
            stage: CloudBackupRestoreStage::Restoring,
            completed: 1,
            total: Some(2),
        }));
        manager.set_restore_progress(None);
        manager.set_restore_report(Some(CloudBackupRestoreReport {
            wallets_restored: 1,
            wallets_failed: 0,
            failed_wallet_errors: Vec::new(),
        }));

        assert!(manager.state.read().restore_progress.is_none());
    }

    #[test]
    fn terminal_status_clears_restore_progress_and_keeps_report() {
        let _guard = test_lock().lock();
        let manager = RustCloudBackupManager::init();
        let report = CloudBackupRestoreReport {
            wallets_restored: 0,
            wallets_failed: 2,
            failed_wallet_errors: vec!["download failed".into()],
        };

        manager.set_restore_progress(Some(CloudBackupRestoreProgress {
            stage: CloudBackupRestoreStage::Restoring,
            completed: 1,
            total: Some(2),
        }));
        manager.set_restore_progress(None);
        manager.set_restore_report(Some(report.clone()));
        manager.set_status(CloudBackupStatus::Error("all wallets failed".into()));

        let state = manager.state.read();
        assert!(state.restore_progress.is_none());
        assert_eq!(state.restore_report, Some(report));
    }

    #[test]
    fn unsupported_passkey_provider_maps_to_typed_status() {
        assert_eq!(
            RustCloudBackupManager::status_for_operation_error(
                &CloudBackupError::UnsupportedPasskeyProvider,
            ),
            CloudBackupStatus::UnsupportedPasskeyProvider,
        );
    }

    #[test]
    fn stale_restore_operation_cannot_update_restore_progress() {
        let _guard = test_lock().lock();
        let manager = RustCloudBackupManager::init();
        let stale_operation_id = manager.next_restore_operation_id();
        let current_operation_id = manager.next_restore_operation_id();
        let progress = CloudBackupRestoreProgress {
            stage: CloudBackupRestoreStage::Downloading,
            completed: 1,
            total: Some(3),
        };

        let error = manager
            .set_restore_progress_for_restore_operation(stale_operation_id, Some(progress.clone()))
            .unwrap_err();

        assert!(matches!(error, CloudBackupError::Cancelled));
        assert_eq!(manager.state.read().restore_progress, None);

        manager
            .set_restore_progress_for_restore_operation(
                current_operation_id,
                Some(progress.clone()),
            )
            .unwrap();

        assert_eq!(manager.state.read().restore_progress, Some(progress));
    }

    #[test]
    fn stale_restore_operation_cannot_update_status() {
        let _guard = test_lock().lock();
        let manager = RustCloudBackupManager::init();
        let stale_operation_id = manager.next_restore_operation_id();
        let current_operation_id = manager.next_restore_operation_id();

        let error = manager
            .set_status_for_restore_operation(stale_operation_id, CloudBackupStatus::Restoring)
            .unwrap_err();

        assert!(matches!(error, CloudBackupError::Cancelled));
        assert_eq!(manager.state.read().status, CloudBackupStatus::Disabled);

        manager
            .set_status_for_restore_operation(current_operation_id, CloudBackupStatus::Restoring)
            .unwrap();

        assert_eq!(manager.state.read().status, CloudBackupStatus::Restoring);
    }

    #[test]
    fn stale_restore_operation_cannot_update_restore_report() {
        let _guard = test_lock().lock();
        let manager = RustCloudBackupManager::init();
        let stale_operation_id = manager.next_restore_operation_id();
        let current_operation_id = manager.next_restore_operation_id();
        let report = CloudBackupRestoreReport {
            wallets_restored: 1,
            wallets_failed: 0,
            failed_wallet_errors: Vec::new(),
        };

        let error = manager
            .set_restore_report_for_restore_operation(stale_operation_id, Some(report.clone()))
            .unwrap_err();

        assert!(matches!(error, CloudBackupError::Cancelled));
        assert_eq!(manager.state.read().restore_report, None);

        manager
            .set_restore_report_for_restore_operation(current_operation_id, Some(report.clone()))
            .unwrap();

        assert_eq!(manager.state.read().restore_report, Some(report));
    }

    #[test]
    fn stale_restore_operation_cannot_persist_cloud_backup_state() {
        let _guard = test_lock().lock();
        let manager = RustCloudBackupManager::init();
        let db = Database::global();
        db.cloud_backup_state.set(&PersistedCloudBackupState::default()).unwrap();
        manager.set_status(CloudBackupStatus::Disabled);

        let stale_operation_id = manager.next_restore_operation_id();
        let current_operation_id = manager.next_restore_operation_id();
        let persisted_state = PersistedCloudBackupState {
            status: PersistedCloudBackupStatus::Enabled,
            ..PersistedCloudBackupState::default()
        };

        let error = manager
            .persist_cloud_backup_state_for_restore_operation(
                stale_operation_id,
                &persisted_state,
                "test stale restore persist",
            )
            .unwrap_err();

        assert!(matches!(error, CloudBackupError::Cancelled));
        assert_eq!(db.cloud_backup_state.get().unwrap(), PersistedCloudBackupState::default());
        assert_eq!(manager.state.read().status, CloudBackupStatus::Disabled);

        manager
            .persist_cloud_backup_state_for_restore_operation(
                current_operation_id,
                &persisted_state,
                "test current restore persist",
            )
            .unwrap();

        assert_eq!(db.cloud_backup_state.get().unwrap(), persisted_state);
        assert_eq!(manager.state.read().status, CloudBackupStatus::Enabled);
    }

    #[test]
    fn invalidated_restore_operation_becomes_cancelled() {
        let _guard = test_lock().lock();
        let manager = RustCloudBackupManager::init();
        let operation_id = manager.next_restore_operation_id();

        manager.invalidate_restore_operation();

        let error = manager.ensure_current_restore_operation(operation_id).unwrap_err();
        assert!(matches!(error, CloudBackupError::Cancelled));
    }

    #[test]
    fn stale_restore_operation_does_not_run_locked_update() {
        let _guard = test_lock().lock();
        let manager = RustCloudBackupManager::init();
        let stale_operation_id = manager.next_restore_operation_id();
        manager.next_restore_operation_id();
        let mut ran = false;

        let error = manager
            .with_current_restore_operation_result(stale_operation_id, |_| {
                ran = true;
                Ok(())
            })
            .unwrap_err();

        assert!(matches!(error, CloudBackupError::Cancelled));
        assert!(!ran);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn start_background_operation_claims_enabling_synchronously() {
        let _guard = test_lock().lock();
        cove_tokio::init();
        let manager = RustCloudBackupManager::init();
        manager.debug_reset_cloud_backup_state();

        manager.clone().start_background_operation(
            "first_enable",
            Some(CloudBackupStatus::Enabling),
            |_| Ok(()),
        );

        assert_eq!(manager.state.read().status, CloudBackupStatus::Enabling);
        manager.debug_reset_cloud_backup_state();
    }

    #[test]
    fn catastrophic_wipe_wallet_ids_prefers_persisted_wallet_ids() {
        let dir = TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join("wallet-from-dir")).unwrap();

        let wallet_ids = catastrophic_wipe_wallet_ids(
            Some(vec![WalletId::from("wallet-from-db".to_string())]),
            dir.path(),
        );

        assert_eq!(wallet_ids, vec![WalletId::from("wallet-from-db".to_string())]);
    }

    #[test]
    fn catastrophic_wipe_wallet_ids_falls_back_to_wallet_data_dir() {
        let dir = TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join("wallet-from-dir")).unwrap();
        std::fs::create_dir_all(dir.path().join("wallet-two")).unwrap();

        let wallet_ids = catastrophic_wipe_wallet_ids(None, dir.path());

        assert_eq!(
            wallet_ids,
            vec![
                WalletId::from("wallet-from-dir".to_string()),
                WalletId::from("wallet-two".to_string()),
            ]
        );
    }

    #[test]
    fn wallet_ids_from_wallet_data_dir_uses_directory_names() {
        let dir = TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join("AbCd123")).unwrap();
        std::fs::create_dir_all(dir.path().join("wallet-two")).unwrap();
        std::fs::write(dir.path().join("bdk_wallet_abcd123.db"), "").unwrap();

        let wallet_ids = wallet_ids_from_wallet_data_dir(dir.path());

        assert_eq!(
            wallet_ids,
            vec![WalletId::from("AbCd123".to_string()), WalletId::from("wallet-two".to_string()),],
        );
    }

    #[test]
    fn wallet_ids_from_wallet_data_dir_returns_empty_for_missing_dir() {
        let dir = TempDir::new().unwrap();
        let wallet_ids = wallet_ids_from_wallet_data_dir(&dir.path().join("missing"));

        assert!(wallet_ids.is_empty());
    }
}
