use std::collections::HashSet;

use cove_cspp::backup_data::wallet_record_id;

use super::{
    CloudBackupDetail, CloudBackupError, CloudBackupWalletItem, CloudBackupWalletStatus,
    cspp_master_key_record_id,
};
use crate::database::Database;
use crate::database::cloud_backup::{
    CloudUploadKind, PendingCloudUploadItem, PersistedCloudBackupStatus,
};
use crate::manager::cloud_backup_manager::wallets::all_local_wallets;
use crate::wallet::metadata::WalletMetadata;

pub(super) struct CloudWalletInventory {
    last_sync: Option<u64>,
    local_wallets: Vec<WalletMetadata>,
    cloud_wallet_record_ids: HashSet<String>,
}

impl CloudWalletInventory {
    pub(super) fn load(wallet_record_ids: &[String]) -> Result<Self, CloudBackupError> {
        let db = Database::global();
        let local_wallets = all_local_wallets(&db)?;
        let last_sync = last_sync(&db);
        let cloud_wallet_record_ids = merged_cloud_wallet_record_ids(&db, wallet_record_ids);

        Ok(Self::new(last_sync, local_wallets, cloud_wallet_record_ids))
    }

    pub(super) fn load_strict(wallet_record_ids: &[String]) -> Result<Self, CloudBackupError> {
        let db = Database::global();
        let local_wallets = all_local_wallets(&db)?;
        let last_sync = last_sync(&db);
        let cloud_wallet_record_ids = listed_cloud_wallet_record_ids(wallet_record_ids, &[], false);

        Ok(Self::new(last_sync, local_wallets, cloud_wallet_record_ids))
    }

    fn new(
        last_sync: Option<u64>,
        local_wallets: Vec<WalletMetadata>,
        cloud_wallet_record_ids: HashSet<String>,
    ) -> Self {
        Self { last_sync, local_wallets, cloud_wallet_record_ids }
    }

    pub(super) fn cloud_wallet_count(&self) -> usize {
        self.cloud_wallet_record_ids.len()
    }

    pub(super) fn unsynced_local_wallets(&self) -> Vec<WalletMetadata> {
        self.local_wallets
            .iter()
            .filter(|wallet| {
                !self.cloud_wallet_record_ids.contains(&wallet_record_id(wallet.id.as_ref()))
            })
            .cloned()
            .collect()
    }

    pub(super) fn build_detail(&self) -> CloudBackupDetail {
        let local_record_ids: HashSet<_> =
            self.local_wallets.iter().map(|wallet| wallet_record_id(wallet.id.as_ref())).collect();

        let mut backed_up = Vec::new();
        let mut not_backed_up = Vec::new();

        for wallet in &self.local_wallets {
            let record_id = wallet_record_id(wallet.id.as_ref());
            let status = if self.cloud_wallet_record_ids.contains(&record_id) {
                CloudBackupWalletStatus::BackedUp
            } else {
                CloudBackupWalletStatus::NotBackedUp
            };

            let item = local_wallet_item(wallet, status);

            match item.status {
                CloudBackupWalletStatus::BackedUp => backed_up.push(item),
                CloudBackupWalletStatus::NotBackedUp => not_backed_up.push(item),
                CloudBackupWalletStatus::DeletedFromDevice => {}
            }
        }

        let cloud_only_count = self
            .cloud_wallet_record_ids
            .iter()
            .filter(|record_id| !local_record_ids.contains(*record_id))
            .count() as u32;

        CloudBackupDetail { last_sync: self.last_sync, backed_up, not_backed_up, cloud_only_count }
    }
}

fn last_sync(db: &Database) -> Option<u64> {
    let state = db.cloud_backup_state.get().ok()?;
    match state.status {
        PersistedCloudBackupStatus::Disabled => None,
        PersistedCloudBackupStatus::Enabled
        | PersistedCloudBackupStatus::Unverified
        | PersistedCloudBackupStatus::PasskeyMissing => state.last_sync,
    }
}

pub(super) fn merged_cloud_wallet_record_ids(
    db: &Database,
    wallet_record_ids: &[String],
) -> HashSet<String> {
    let pending_items =
        db.cloud_upload_queue.get().ok().flatten().map(|queue| queue.items).unwrap_or_default();

    listed_cloud_wallet_record_ids(wallet_record_ids, &pending_items, true)
}

fn listed_cloud_wallet_record_ids(
    wallet_record_ids: &[String],
    pending_items: &[PendingCloudUploadItem],
    include_pending_uploads: bool,
) -> HashSet<String> {
    let mut cloud_wallet_record_ids: HashSet<_> = wallet_record_ids.iter().cloned().collect();

    if include_pending_uploads {
        merge_pending_wallet_record_ids(&mut cloud_wallet_record_ids, pending_items);
    }

    cloud_wallet_record_ids
}

fn merge_pending_wallet_record_ids(
    cloud_wallet_record_ids: &mut HashSet<String>,
    pending_items: &[PendingCloudUploadItem],
) {
    let master_key_id = cspp_master_key_record_id();
    for item in pending_items {
        if item.kind == CloudUploadKind::BackupBlob && item.record_id != master_key_id {
            cloud_wallet_record_ids.insert(item.record_id.clone());
        }
    }
}

fn local_wallet_item(
    wallet: &WalletMetadata,
    status: CloudBackupWalletStatus,
) -> CloudBackupWalletItem {
    CloudBackupWalletItem {
        name: wallet.name.clone(),
        network: wallet.network,
        wallet_mode: wallet.wallet_mode,
        wallet_type: wallet.wallet_type,
        fingerprint: wallet.master_fingerprint.as_ref().map(|fp| fp.as_uppercase()),
        status,
        record_id: wallet_record_id(wallet.id.as_ref()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::cloud_backup::CloudUploadVerificationState;

    #[test]
    fn merge_pending_wallet_record_ids_skips_master_key() {
        let mut cloud_wallet_record_ids = HashSet::from(["wallet-a".to_string()]);
        let pending_blobs = vec![
            PendingCloudUploadItem {
                kind: CloudUploadKind::BackupBlob,
                namespace_id: "ns-1".into(),
                record_id: cspp_master_key_record_id(),
                enqueued_at: 0,
                verification: CloudUploadVerificationState::Pending {
                    attempt_count: 0,
                    last_checked_at: None,
                },
            },
            PendingCloudUploadItem {
                kind: CloudUploadKind::BackupBlob,
                namespace_id: "ns-1".into(),
                record_id: "wallet-b".to_string(),
                enqueued_at: 0,
                verification: CloudUploadVerificationState::Pending {
                    attempt_count: 0,
                    last_checked_at: None,
                },
            },
        ];

        merge_pending_wallet_record_ids(&mut cloud_wallet_record_ids, &pending_blobs);

        assert!(cloud_wallet_record_ids.contains("wallet-a"));
        assert!(cloud_wallet_record_ids.contains("wallet-b"));
        assert!(!cloud_wallet_record_ids.contains(&cspp_master_key_record_id()));
    }

    #[test]
    fn inventory_build_detail_preserves_wallet_statuses() {
        let wallet_a = WalletMetadata::preview_new();
        let mut wallet_b = WalletMetadata::preview_new();
        wallet_b.name = "Wallet B".into();

        let cloud_wallet_record_ids = HashSet::from([wallet_record_id(wallet_a.id.as_ref())]);
        let inventory = CloudWalletInventory::new(
            Some(42),
            vec![wallet_a.clone(), wallet_b.clone()],
            cloud_wallet_record_ids,
        );

        let detail = inventory.build_detail();

        assert_eq!(detail.last_sync, Some(42));
        assert_eq!(detail.backed_up.len(), 1);
        assert_eq!(detail.not_backed_up.len(), 1);
        assert_eq!(detail.backed_up[0].record_id, wallet_record_id(wallet_a.id.as_ref()));
        assert_eq!(detail.not_backed_up[0].record_id, wallet_record_id(wallet_b.id.as_ref()));
    }

    #[test]
    fn inventory_unsynced_local_wallets_uses_merged_cloud_ids() {
        let wallet_a = WalletMetadata::preview_new();
        let mut wallet_b = WalletMetadata::preview_new();
        wallet_b.name = "Wallet B".into();

        let cloud_wallet_record_ids = HashSet::from([wallet_record_id(wallet_a.id.as_ref())]);
        let inventory = CloudWalletInventory::new(
            None,
            vec![wallet_a, wallet_b.clone()],
            cloud_wallet_record_ids,
        );

        let unsynced = inventory.unsynced_local_wallets();

        assert_eq!(unsynced.len(), 1);
        assert_eq!(unsynced[0].id, wallet_b.id);
    }

    #[test]
    fn listed_cloud_wallet_record_ids_can_ignore_pending_uploads() {
        let wallet_a = WalletMetadata::preview_new();
        let wallet_b = WalletMetadata::preview_new();
        let pending_items = vec![PendingCloudUploadItem {
            kind: CloudUploadKind::BackupBlob,
            namespace_id: "ns-1".into(),
            record_id: wallet_record_id(wallet_b.id.as_ref()),
            enqueued_at: 0,
            verification: CloudUploadVerificationState::Pending {
                attempt_count: 0,
                last_checked_at: None,
            },
        }];

        let strict_ids = listed_cloud_wallet_record_ids(
            &[wallet_record_id(wallet_a.id.as_ref())],
            &pending_items,
            false,
        );

        assert!(strict_ids.contains(&wallet_record_id(wallet_a.id.as_ref())));
        assert!(!strict_ids.contains(&wallet_record_id(wallet_b.id.as_ref())));
    }
}
