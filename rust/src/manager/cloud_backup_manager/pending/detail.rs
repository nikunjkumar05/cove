use std::collections::HashSet;

use cove_device::cloud_storage::{CloudStorage, CloudStorageError};
use tracing::info;

use super::super::cloud_inventory::CloudWalletInventory;
use super::super::{
    CLOUD_BACKUP_MANAGER, CloudBackupDetail, CloudBackupDetailResult, CloudBackupStatus,
    RustCloudBackupManager,
};
use crate::database::Database;
use crate::database::cloud_backup::CloudUploadKind;

impl RustCloudBackupManager {
    /// List wallet backups in the current namespace and build detail
    ///
    /// Returns None if disabled. On NotFound, re-uploads all wallets automatically.
    /// On other errors, returns AccessError so the UI can offer a re-upload button
    pub(crate) fn refresh_cloud_backup_detail(&self) -> Option<CloudBackupDetailResult> {
        let status = self.state.read().status.clone();
        if !matches!(status, CloudBackupStatus::Enabled | CloudBackupStatus::PasskeyMissing) {
            info!("refresh_cloud_backup_detail: skipping, status={status:?}");
            return None;
        }

        let namespace = match self.current_namespace_id() {
            Ok(ns) => ns,
            Err(error) => return Some(CloudBackupDetailResult::AccessError(error.to_string())),
        };

        info!("refresh_cloud_backup_detail: listing wallets for namespace {namespace}");
        let cloud = CloudStorage::global();
        let wallet_record_ids = match cloud.list_wallet_backups(namespace) {
            Ok(ids) => ids,
            Err(CloudStorageError::NotFound(_)) => {
                info!("No wallet backups found in namespace, re-uploading all wallets");
                if let Err(error) = self.do_reupload_all_wallets() {
                    return Some(CloudBackupDetailResult::AccessError(format!(
                        "Failed to re-upload wallets: {error}"
                    )));
                }

                match cloud.list_wallet_backups(self.current_namespace_id().unwrap_or_default()) {
                    Ok(ids) => ids,
                    Err(error) => {
                        return Some(CloudBackupDetailResult::AccessError(error.to_string()));
                    }
                }
            }
            Err(error) => return Some(CloudBackupDetailResult::AccessError(error.to_string())),
        };

        info!(
            "refresh_cloud_backup_detail: found {} wallet record(s) in cloud",
            wallet_record_ids.len()
        );

        let listed: HashSet<_> = wallet_record_ids.iter().cloned().collect();
        cleanup_confirmed_pending_blobs(&listed);

        match build_detail_from_wallet_ids(&wallet_record_ids) {
            Ok(detail) => Some(CloudBackupDetailResult::Success(detail)),
            Err(error) => Some(CloudBackupDetailResult::AccessError(error.to_string())),
        }
    }
}

/// Remove confirmed pending blobs that now appear in the cloud listing
pub(crate) fn cleanup_confirmed_pending_blobs(listed_ids: &HashSet<String>) {
    let db = Database::global();
    let table = &db.cloud_upload_queue;
    let mut queue = match table.get() {
        Ok(Some(p)) => p,
        _ => return,
    };
    let namespace_id = match CLOUD_BACKUP_MANAGER.current_namespace_id() {
        Ok(namespace_id) => namespace_id,
        Err(_) => return,
    };

    let before = queue.items.len();
    queue.cleanup_listed(CloudUploadKind::BackupBlob, &namespace_id, listed_ids);

    if queue.items.len() < before {
        if queue.items.is_empty() {
            let _ = table.delete();
            CLOUD_BACKUP_MANAGER.set_pending_upload_verification(false);
        } else {
            let _ = table.set(&queue);
        }
    }
}

/// Build a CloudBackupDetail from wallet record IDs by comparing against local wallets
pub(crate) fn build_detail_from_wallet_ids(
    wallet_record_ids: &[String],
) -> Result<CloudBackupDetail, super::super::CloudBackupError> {
    Ok(CloudWalletInventory::load(wallet_record_ids)?.build_detail())
}
