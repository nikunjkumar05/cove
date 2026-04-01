use cove_device::cloud_storage::CloudStorage;
use tracing::{error, info, warn};

use super::super::RustCloudBackupManager;
use crate::database::Database;
use crate::database::cloud_backup::{
    CloudUploadKind, CloudUploadQueueTable, PendingCloudUploadItem, PendingCloudUploadQueue,
};

enum BlobCheckResult {
    Confirmed,
    NotYetUploaded,
    Failed(String),
}

pub(super) struct PendingUploadVerifier<'a>(pub(super) &'a RustCloudBackupManager);

impl PendingUploadVerifier<'_> {
    pub(super) fn run_once(&self) -> bool {
        let db = Database::global();
        let table = &db.cloud_upload_queue;
        let queue = match table.get() {
            Ok(queue) => queue,
            Err(error) => {
                error!("Pending upload verification: failed to read queue: {error}");
                return true;
            }
        };

        let Some(mut queue) = queue else {
            self.send_pending_state(false);
            return false;
        };

        if let Some(should_continue) = self.handle_terminal_state(table, &queue) {
            return should_continue;
        }

        self.verify_blobs(&mut queue);

        if let Err(error) = table.set(&queue) {
            error!("Pending upload verification: failed to persist queue: {error}");
            return true;
        }

        self.0.finalize_pending_verification_if_ready();
        self.finish_pass(&queue)
    }

    fn handle_terminal_state(
        &self,
        table: &CloudUploadQueueTable,
        queue: &PendingCloudUploadQueue,
    ) -> Option<bool> {
        if queue.items.is_empty() {
            if let Err(error) = table.delete() {
                error!("Pending upload verification: failed to delete empty queue: {error}");
                return Some(true);
            }

            self.send_pending_state(false);
            return Some(false);
        }

        if !queue.has_unconfirmed() {
            self.send_pending_state(false);
            return Some(false);
        }

        None
    }

    fn verify_blobs(&self, queue: &mut PendingCloudUploadQueue) {
        let cloud = CloudStorage::global();
        let checked_at: u64 = jiff::Timestamp::now().as_second().try_into().unwrap_or(0);
        for item in &mut queue.items {
            if item.kind != CloudUploadKind::BackupBlob || item.is_confirmed() {
                continue;
            }

            let result = self.check_blob(cloud, &item.namespace_id, &item.record_id);
            Self::apply_blob_result(item, checked_at, &result);
            self.log_blob_result(item, &result);
        }
    }

    fn check_blob(
        &self,
        cloud: &CloudStorage,
        namespace_id: &str,
        record_id: &str,
    ) -> BlobCheckResult {
        match cloud.is_backup_uploaded(namespace_id.to_string(), record_id.to_string()) {
            Ok(true) => BlobCheckResult::Confirmed,
            Ok(false) => BlobCheckResult::NotYetUploaded,
            Err(error) => BlobCheckResult::Failed(error.to_string()),
        }
    }

    fn apply_blob_result(
        item: &mut PendingCloudUploadItem,
        checked_at: u64,
        result: &BlobCheckResult,
    ) {
        match result {
            BlobCheckResult::Confirmed => item.confirm(checked_at),
            BlobCheckResult::NotYetUploaded | BlobCheckResult::Failed(_) => {
                item.mark_checked(checked_at)
            }
        }
    }

    fn log_blob_result(&self, item: &PendingCloudUploadItem, result: &BlobCheckResult) {
        match result {
            BlobCheckResult::Confirmed => {
                let elapsed_secs =
                    item.confirmed_at().unwrap_or_default().saturating_sub(item.enqueued_at);
                info!(
                    "Pending upload verification: confirmed record_id={} elapsed={elapsed_secs}s attempts={}",
                    item.record_id,
                    item.attempt_count()
                );
            }
            BlobCheckResult::NotYetUploaded => {
                let last_checked_at = item.last_checked_at().unwrap_or_default();
                info!(
                    "Pending upload verification: not yet uploaded record_id={} checked_at={last_checked_at} attempts={}",
                    item.record_id,
                    item.attempt_count()
                );
            }
            BlobCheckResult::Failed(error) => {
                let last_checked_at = item.last_checked_at().unwrap_or_default();
                warn!(
                    "Pending upload verification: check failed record_id={} checked_at={last_checked_at} error={error} attempts={}",
                    item.record_id,
                    item.attempt_count()
                );
            }
        }
    }

    fn finish_pass(&self, queue: &PendingCloudUploadQueue) -> bool {
        let has_unconfirmed = queue.has_unconfirmed();
        if has_unconfirmed {
            let unconfirmed = queue.items.iter().filter(|item| !item.is_confirmed()).count();
            self.send_pending_state(true);
            info!("Pending upload verification: still pending count={unconfirmed}");
        } else {
            self.send_pending_state(false);
            info!("Pending upload verification: all blobs confirmed");
        }

        has_unconfirmed
    }

    fn send_pending_state(&self, pending: bool) {
        self.0.set_pending_upload_verification(pending);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_blob_result_confirms_blob() {
        let mut blob = PendingCloudUploadItem {
            kind: CloudUploadKind::BackupBlob,
            namespace_id: "ns-1".into(),
            record_id: "wallet-a".into(),
            enqueued_at: 10,
            verification: crate::database::cloud_backup::CloudUploadVerificationState::Pending {
                attempt_count: 0,
                last_checked_at: None,
            },
        };

        PendingUploadVerifier::apply_blob_result(&mut blob, 20, &BlobCheckResult::Confirmed);

        assert_eq!(blob.confirmed_at(), Some(20));
        assert_eq!(blob.last_checked_at(), None);
        assert_eq!(blob.attempt_count(), 0);
    }

    #[test]
    fn apply_blob_result_tracks_pending_blob() {
        let mut blob = PendingCloudUploadItem {
            kind: CloudUploadKind::BackupBlob,
            namespace_id: "ns-1".into(),
            record_id: "wallet-a".into(),
            enqueued_at: 10,
            verification: crate::database::cloud_backup::CloudUploadVerificationState::Pending {
                attempt_count: 0,
                last_checked_at: None,
            },
        };

        PendingUploadVerifier::apply_blob_result(&mut blob, 20, &BlobCheckResult::NotYetUploaded);

        assert_eq!(blob.confirmed_at(), None);
        assert_eq!(blob.last_checked_at(), Some(20));
        assert_eq!(blob.attempt_count(), 1);
    }

    #[test]
    fn apply_blob_result_tracks_failed_blob() {
        let mut blob = PendingCloudUploadItem {
            kind: CloudUploadKind::BackupBlob,
            namespace_id: "ns-1".into(),
            record_id: "wallet-a".into(),
            enqueued_at: 10,
            verification: crate::database::cloud_backup::CloudUploadVerificationState::Pending {
                attempt_count: 0,
                last_checked_at: None,
            },
        };

        PendingUploadVerifier::apply_blob_result(
            &mut blob,
            20,
            &BlobCheckResult::Failed("boom".into()),
        );

        assert_eq!(blob.confirmed_at(), None);
        assert_eq!(blob.last_checked_at(), Some(20));
        assert_eq!(blob.attempt_count(), 1);
    }
}
