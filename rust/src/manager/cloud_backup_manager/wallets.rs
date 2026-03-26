use std::str::FromStr as _;

use cove_cspp::CsppStore as _;
use cove_cspp::backup_data::{
    DescriptorPair, EncryptedWalletBackup, WalletEntry, WalletMode,
    WalletSecret as CloudWalletSecret, wallet_record_id,
};
use cove_cspp::master_key_crypto;
use cove_cspp::wallet_crypto;
use cove_device::cloud_storage::CloudStorage;
use cove_device::keychain::Keychain;
use cove_device::passkey::PasskeyAccess;
use cove_types::network::Network;
use cove_util::ResultExt as _;
use rand::RngExt as _;
use strum::IntoEnumIterator as _;
use tracing::{info, warn};
use zeroize::Zeroizing;

use cove_device::keychain::{CSPP_CREDENTIAL_ID_KEY, CSPP_PRF_SALT_KEY};

use super::{
    CloudBackupError, LocalDescriptorPair, LocalWalletMode, LocalWalletSecret, RP_ID,
    RustCloudBackupManager,
};
use crate::database::Database;
use crate::database::global_config::CloudBackup;
use crate::wallet::metadata::{WalletMetadata, WalletType};

pub(super) struct UnpersistedPrfKey {
    pub(super) prf_key: [u8; 32],
    pub(super) prf_salt: [u8; 32],
    pub(super) credential_id: Vec<u8>,
}

pub(super) struct DownloadedWalletBackup {
    pub(super) metadata: WalletMetadata,
    pub(super) entry: WalletEntry,
}

impl RustCloudBackupManager {
    /// Upload wallets to cloud and update local cache
    pub(super) fn do_backup_wallets(
        &self,
        wallets: &[crate::wallet::metadata::WalletMetadata],
    ) -> Result<(), CloudBackupError> {
        if wallets.is_empty() {
            return Ok(());
        }

        let namespace = self.current_namespace_id()?;
        let cspp = cove_cspp::Cspp::new(Keychain::global().clone());
        let master_key = cspp
            .get_or_create_master_key()
            .map_err_prefix("master key", CloudBackupError::Internal)?;

        let critical_key = Zeroizing::new(master_key.critical_data_key());
        let cloud = CloudStorage::global();
        let mut uploaded_record_ids = Vec::with_capacity(wallets.len());

        for (index, metadata) in wallets.iter().enumerate() {
            info!("Backup: uploading wallet {}/{} '{}'", index + 1, wallets.len(), metadata.name);
            let entry = build_wallet_entry(metadata, metadata.wallet_mode)?;
            let encrypted = wallet_crypto::encrypt_wallet_entry(&entry, &critical_key)
                .map_err_str(CloudBackupError::Crypto)?;

            let record_id = wallet_record_id(metadata.id.as_ref());
            let wallet_json =
                serde_json::to_vec(&encrypted).map_err_str(CloudBackupError::Internal)?;

            cloud
                .upload_wallet_backup(namespace.clone(), record_id.clone(), wallet_json)
                .map_err_str(CloudBackupError::Cloud)?;
            uploaded_record_ids.push(record_id);
            info!("Backup: wallet {}/{} uploaded", index + 1, wallets.len());
        }

        let db = Database::global();
        self.enqueue_pending_uploads(&namespace, uploaded_record_ids)?;

        let previous_count = match db.global_config.cloud_backup() {
            CloudBackup::Enabled { wallet_count: Some(count), .. }
            | CloudBackup::Unverified { wallet_count: Some(count), .. } => count,
            _ => 0,
        };
        let wallet_count = previous_count + wallets.len() as u32;
        persist_enabled_cloud_backup_state(&db, wallet_count)?;

        info!("Backed up {} wallet(s) to cloud", wallets.len());
        Ok(())
    }
}

/// Create a passkey and authenticate with PRF without persisting to keychain
///
/// Used by the wrapper-repair path where we need to defer persistence until
/// after the cloud upload succeeds
pub(super) fn create_prf_key_without_persisting(
    passkey: &PasskeyAccess,
) -> Result<UnpersistedPrfKey, CloudBackupError> {
    create_new_prf_key(passkey, "Creating new passkey for wrapper repair")
}

#[allow(dead_code)]
pub(super) struct NamespaceMatch {
    pub(super) namespace_id: String,
    pub(super) master_key: cove_cspp::master_key::MasterKey,
    pub(super) prf_key: [u8; 32],
    pub(super) prf_salt: [u8; 32],
    pub(super) credential_id: Vec<u8>,
}

pub(super) enum NamespaceMatchOutcome {
    /// User's passkey decrypted a namespace's master key
    Matched(NamespaceMatch),
    /// User cancelled the picker or biometric, or no credentials on device
    UserDeclined,
    /// All downloaded v1 backups tried, none matched, no issues
    NoMatch,
    /// Some namespaces couldn't be downloaded — result is inconclusive
    Inconclusive,
    /// Some/all namespaces had unsupported version — app may be too old
    UnsupportedVersions,
}

/// Try to match a discovered passkey against cloud namespaces
///
/// Downloads all encrypted master keys, then does a discovery auth with the first
/// v1 backup's salt. If that doesn't match, does targeted auth against remaining
/// namespaces with each one's own salt (one biometric per additional namespace)
pub(super) fn try_match_namespace_with_passkey(
    cloud: &CloudStorage,
    passkey: &PasskeyAccess,
    namespaces: &[String],
) -> Result<NamespaceMatchOutcome, CloudBackupError> {
    if namespaces.is_empty() {
        return Ok(NamespaceMatchOutcome::NoMatch);
    }

    // download all encrypted master key backups
    let mut downloaded: Vec<(String, cove_cspp::backup_data::EncryptedMasterKeyBackup)> =
        Vec::with_capacity(namespaces.len());
    let mut had_download_failures = false;
    let mut had_unsupported_versions = false;

    for ns in namespaces {
        let master_json = match cloud.download_master_key_backup(ns.clone()) {
            Ok(json) => json,
            Err(error) => {
                warn!("Failed to download master key for namespace {ns}: {error}");
                had_download_failures = true;
                continue;
            }
        };

        let encrypted: cove_cspp::backup_data::EncryptedMasterKeyBackup =
            match serde_json::from_slice(&master_json) {
                Ok(e) => e,
                Err(error) => {
                    warn!("Failed to deserialize master key for namespace {ns}: {error}");
                    had_download_failures = true;
                    continue;
                }
            };

        if encrypted.version != 1 {
            had_unsupported_versions = true;
            continue;
        }

        downloaded.push((ns.clone(), encrypted));
    }

    if downloaded.is_empty() {
        return if had_download_failures {
            Ok(NamespaceMatchOutcome::Inconclusive)
        } else {
            Ok(NamespaceMatchOutcome::UnsupportedVersions)
        };
    }

    // discovery auth with first downloaded backup's salt
    let first_prf_salt = downloaded[0].1.prf_salt;

    let discovered = match passkey.discover_and_authenticate_with_prf(
        RP_ID.to_string(),
        first_prf_salt.to_vec(),
        random_challenge(),
    ) {
        Ok(result) => result,
        Err(cove_device::passkey::PasskeyError::UserCancelled)
        | Err(cove_device::passkey::PasskeyError::NoCredentialFound) => {
            return Ok(NamespaceMatchOutcome::UserDeclined);
        }
        Err(error) => return Err(CloudBackupError::Passkey(error.to_string())),
    };

    let prf_key = prf_output_to_key(discovered.prf_output)?;

    // try first backup
    if let Ok(master_key) = master_key_crypto::decrypt_master_key(&downloaded[0].1, &prf_key) {
        return Ok(NamespaceMatchOutcome::Matched(NamespaceMatch {
            namespace_id: downloaded[0].0.clone(),
            master_key,
            prf_key,
            prf_salt: first_prf_salt,
            credential_id: discovered.credential_id,
        }));
    }

    // try remaining with targeted auth using each namespace's own salt
    for (ns, encrypted) in &downloaded[1..] {
        let ns_prf_output = match passkey.authenticate_with_prf(
            RP_ID.to_string(),
            discovered.credential_id.clone(),
            encrypted.prf_salt.to_vec(),
            random_challenge(),
        ) {
            Ok(output) => output,
            Err(cove_device::passkey::PasskeyError::UserCancelled) => {
                return Ok(NamespaceMatchOutcome::UserDeclined);
            }
            Err(error) => {
                warn!("Targeted auth failed for namespace {ns}: {error}");
                continue;
            }
        };

        let ns_prf_key = match prf_output_to_key(ns_prf_output) {
            Ok(key) => key,
            Err(_) => continue,
        };

        if let Ok(master_key) = master_key_crypto::decrypt_master_key(encrypted, &ns_prf_key) {
            return Ok(NamespaceMatchOutcome::Matched(NamespaceMatch {
                namespace_id: ns.clone(),
                master_key,
                prf_key: ns_prf_key,
                prf_salt: encrypted.prf_salt,
                credential_id: discovered.credential_id.clone(),
            }));
        }
    }

    // none matched
    if had_download_failures {
        Ok(NamespaceMatchOutcome::Inconclusive)
    } else if had_unsupported_versions {
        Ok(NamespaceMatchOutcome::UnsupportedVersions)
    } else {
        Ok(NamespaceMatchOutcome::NoMatch)
    }
}

/// Encrypt and hand off all local wallets to the given namespace
pub(super) fn upload_all_wallets(
    cloud: &CloudStorage,
    namespace: &str,
    critical_key: &[u8; 32],
    db: &Database,
) -> Result<Vec<String>, CloudBackupError> {
    let mut uploaded_record_ids = Vec::new();

    for metadata in all_local_wallets(db) {
        let entry = build_wallet_entry(&metadata, metadata.wallet_mode)?;
        let encrypted = wallet_crypto::encrypt_wallet_entry(&entry, critical_key)
            .map_err_str(CloudBackupError::Crypto)?;

        let record_id = wallet_record_id(metadata.id.as_ref());
        let wallet_json = serde_json::to_vec(&encrypted).map_err_str(CloudBackupError::Internal)?;

        cloud
            .upload_wallet_backup(namespace.to_string(), record_id.clone(), wallet_json)
            .map_err_str(CloudBackupError::Cloud)?;

        uploaded_record_ids.push(record_id);
    }

    Ok(uploaded_record_ids)
}

pub(super) fn persist_enabled_cloud_backup_state(
    db: &Database,
    wallet_count: u32,
) -> Result<(), CloudBackupError> {
    let now = jiff::Timestamp::now().as_second().try_into().unwrap_or(0);
    db.global_config
        .set_cloud_backup(&CloudBackup::Enabled {
            last_sync: Some(now),
            wallet_count: Some(wallet_count),
        })
        .map_err_prefix("persist cloud backup state", CloudBackupError::Internal)
}

/// All local wallets across every network and mode
pub(super) fn all_local_wallets(db: &Database) -> Vec<WalletMetadata> {
    Network::iter()
        .flat_map(|network| {
            LocalWalletMode::iter()
                .flat_map(move |mode| db.wallets.get_all(network, mode).unwrap_or_default())
        })
        .collect()
}

pub(super) fn count_all_wallets(db: &Database) -> u32 {
    all_local_wallets(db).len() as u32
}

pub(super) fn restore_single_wallet(
    cloud: &CloudStorage,
    namespace: &str,
    record_id: &str,
    critical_key: &[u8; 32],
    existing_fingerprints: &mut Vec<(
        crate::wallet::fingerprint::Fingerprint,
        Network,
        LocalWalletMode,
    )>,
) -> Result<(), CloudBackupError> {
    let wallet = download_wallet_backup(cloud, namespace, record_id, critical_key)?;

    if should_skip_duplicate_wallet(&wallet.metadata, existing_fingerprints) {
        return Ok(());
    }

    restore_downloaded_wallet(&wallet.metadata, &wallet.entry)?;
    remember_restored_wallet_fingerprint(&wallet.metadata, existing_fingerprints);

    Ok(())
}

/// Create a fresh passkey and authenticate with PRF to get the wrapping key
///
/// Always creates a new passkey — the enable flow re-encrypts everything,
/// so there's no benefit to reusing stale cached credentials (which may
/// reference a passkey deleted from the user's password manager)
pub(super) fn obtain_prf_key(
    keychain: &Keychain,
    passkey: &PasskeyAccess,
) -> Result<([u8; 32], [u8; 32]), CloudBackupError> {
    keychain.delete(CSPP_CREDENTIAL_ID_KEY.to_string());
    keychain.delete(CSPP_PRF_SALT_KEY.to_string());

    let unpersisted = create_new_prf_key(passkey, "Creating new passkey")?;

    keychain
        .save_cspp_passkey(&unpersisted.credential_id, unpersisted.prf_salt)
        .map_err_prefix("save cspp credentials", CloudBackupError::Internal)?;

    Ok((unpersisted.prf_key, unpersisted.prf_salt))
}

/// Try to discover an existing passkey, fall back to creating a new one
///
/// Shows the full passkey picker (including 1Password). If the user picks
/// an existing passkey, uses it with a fresh random salt. If the user cancels
/// or no credentials are available, creates a new passkey via obtain_prf_key
pub(super) fn discover_or_create_prf_key(
    keychain: &Keychain,
    passkey: &PasskeyAccess,
) -> Result<([u8; 32], [u8; 32]), CloudBackupError> {
    info!("Attempting passkey discovery before creating new");
    let prf_salt: [u8; 32] = rand::rng().random();

    match passkey.discover_and_authenticate_with_prf(
        RP_ID.to_string(),
        prf_salt.to_vec(),
        random_challenge(),
    ) {
        Ok(discovered) => {
            let prf_key = prf_output_to_key(discovered.prf_output)?;

            info!("Discovered existing passkey, reusing");
            keychain.delete(CSPP_CREDENTIAL_ID_KEY.to_string());
            keychain.delete(CSPP_PRF_SALT_KEY.to_string());
            keychain
                .save_cspp_passkey(&discovered.credential_id, prf_salt)
                .map_err_prefix("save cspp credentials", CloudBackupError::Internal)?;

            Ok((prf_key, prf_salt))
        }
        Err(cove_device::passkey::PasskeyError::UserCancelled) => {
            info!("User cancelled passkey discovery");
            Err(CloudBackupError::PasskeyDiscoveryCancelled)
        }
        Err(cove_device::passkey::PasskeyError::NoCredentialFound) => {
            info!("No existing passkey found, creating new");
            obtain_prf_key(keychain, passkey)
        }
        Err(error) => {
            warn!("Discovery failed ({error}), falling back to create");
            obtain_prf_key(keychain, passkey)
        }
    }
}

pub(super) fn download_wallet_backup(
    cloud: &CloudStorage,
    namespace: &str,
    record_id: &str,
    critical_key: &[u8; 32],
) -> Result<DownloadedWalletBackup, CloudBackupError> {
    let wallet_json = cloud
        .download_wallet_backup(namespace.to_string(), record_id.to_string())
        .map_err(|e| CloudBackupError::Cloud(format!("download {record_id}: {e}")))?;

    let encrypted: EncryptedWalletBackup = serde_json::from_slice(&wallet_json)
        .map_err_prefix("deserialize wallet", CloudBackupError::Internal)?;

    if encrypted.version != 1 {
        let version = encrypted.version;
        return Err(CloudBackupError::Internal(format!(
            "unsupported wallet backup version: {version}",
        )));
    }

    let entry = wallet_crypto::decrypt_wallet_backup(&encrypted, critical_key)
        .map_err_prefix("decrypt wallet", CloudBackupError::Crypto)?;
    let metadata = serde_json::from_value(entry.metadata.clone())
        .map_err_prefix("parse wallet metadata", CloudBackupError::Internal)?;

    Ok(DownloadedWalletBackup { metadata, entry })
}

fn create_new_prf_key(
    passkey: &PasskeyAccess,
    log_message: &str,
) -> Result<UnpersistedPrfKey, CloudBackupError> {
    info!("{log_message}");
    let prf_salt: [u8; 32] = rand::rng().random();
    let credential_id = passkey
        .create_passkey(
            RP_ID.to_string(),
            rand::rng().random::<[u8; 16]>().to_vec(),
            random_challenge(),
        )
        .map_err_str(CloudBackupError::Passkey)?;

    let prf_output = passkey
        .authenticate_with_prf(
            RP_ID.to_string(),
            credential_id.clone(),
            prf_salt.to_vec(),
            random_challenge(),
        )
        .map_err_str(CloudBackupError::Passkey)?;

    Ok(UnpersistedPrfKey { prf_key: prf_output_to_key(prf_output)?, prf_salt, credential_id })
}

fn prf_output_to_key(prf_output: Vec<u8>) -> Result<[u8; 32], CloudBackupError> {
    prf_output
        .try_into()
        .map_err(|_| CloudBackupError::Internal("PRF output is not 32 bytes".into()))
}

fn random_challenge() -> Vec<u8> {
    rand::rng().random::<[u8; 32]>().to_vec()
}

fn should_skip_duplicate_wallet(
    metadata: &WalletMetadata,
    existing_fingerprints: &[(crate::wallet::fingerprint::Fingerprint, Network, LocalWalletMode)],
) -> bool {
    if crate::backup::import::is_wallet_duplicate(metadata, existing_fingerprints)
        .inspect_err(|e| warn!("is_wallet_duplicate check failed for {}: {e}", metadata.name))
        .unwrap_or(false)
    {
        info!("Skipping duplicate wallet {}", metadata.name);
        true
    } else {
        false
    }
}

fn restore_downloaded_wallet(
    metadata: &WalletMetadata,
    entry: &WalletEntry,
) -> Result<(), CloudBackupError> {
    let backup_model = crate::backup::model::WalletBackup {
        metadata: entry.metadata.clone(),
        secret: convert_cloud_secret(&entry.secret),
        descriptors: entry.descriptors.as_ref().map(|descriptors| LocalDescriptorPair {
            external: descriptors.external.clone(),
            internal: descriptors.internal.clone(),
        }),
        xpub: entry.xpub.clone(),
        labels_jsonl: None,
    };

    match &backup_model.secret {
        LocalWalletSecret::Mnemonic(words) => {
            let mnemonic = bip39::Mnemonic::from_str(words)
                .map_err_prefix("invalid mnemonic", CloudBackupError::Internal)?;

            crate::backup::import::restore_mnemonic_wallet(metadata, mnemonic).map_err(
                |(error, _)| {
                    CloudBackupError::Internal(format!("restore mnemonic wallet: {error}"))
                },
            )?;
        }
        _ => {
            crate::backup::import::restore_descriptor_wallet(metadata, &backup_model).map_err(
                |(error, _)| {
                    CloudBackupError::Internal(format!("restore descriptor wallet: {error}"))
                },
            )?;
        }
    }

    Ok(())
}

fn remember_restored_wallet_fingerprint(
    metadata: &WalletMetadata,
    existing_fingerprints: &mut Vec<(
        crate::wallet::fingerprint::Fingerprint,
        Network,
        LocalWalletMode,
    )>,
) {
    if let Some(fingerprint) = &metadata.master_fingerprint {
        existing_fingerprints.push((**fingerprint, metadata.network, metadata.wallet_mode));
    }
}

pub(super) fn convert_cloud_secret(secret: &CloudWalletSecret) -> LocalWalletSecret {
    match secret {
        CloudWalletSecret::Mnemonic(mnemonic) => LocalWalletSecret::Mnemonic(mnemonic.clone()),
        CloudWalletSecret::TapSignerBackup(backup) => {
            LocalWalletSecret::TapSignerBackup(backup.clone())
        }
        CloudWalletSecret::Descriptor(_) | CloudWalletSecret::WatchOnly => LocalWalletSecret::None,
    }
}

pub(super) fn build_wallet_entry(
    metadata: &crate::wallet::metadata::WalletMetadata,
    mode: LocalWalletMode,
) -> Result<WalletEntry, CloudBackupError> {
    let keychain = Keychain::global();
    let id = &metadata.id;
    let name = &metadata.name;

    let secret = match metadata.wallet_type {
        WalletType::Hot => match keychain.get_wallet_key(id) {
            Ok(Some(mnemonic)) => CloudWalletSecret::Mnemonic(mnemonic.to_string()),
            Ok(None) => {
                return Err(CloudBackupError::Internal(format!(
                    "hot wallet '{name}' has no mnemonic"
                )));
            }
            Err(error) => {
                return Err(CloudBackupError::Internal(format!(
                    "failed to get mnemonic for '{name}': {error}"
                )));
            }
        },
        WalletType::Cold => {
            let is_tap_signer = metadata
                .hardware_metadata
                .as_ref()
                .is_some_and(|hardware| hardware.is_tap_signer());

            if is_tap_signer {
                match keychain.get_tap_signer_backup(id) {
                    Ok(Some(backup)) => CloudWalletSecret::TapSignerBackup(backup),
                    Ok(None) => {
                        warn!("Tap signer wallet '{name}' has no backup, exporting without it");
                        CloudWalletSecret::WatchOnly
                    }
                    Err(error) => {
                        return Err(CloudBackupError::Internal(format!(
                            "failed to read tap signer backup for '{name}': {error}"
                        )));
                    }
                }
            } else {
                CloudWalletSecret::WatchOnly
            }
        }
        WalletType::XpubOnly | WalletType::WatchOnly => CloudWalletSecret::WatchOnly,
    };

    let xpub = match keychain.get_wallet_xpub(id) {
        Ok(Some(xpub)) => Some(xpub.to_string()),
        Ok(None) => None,
        Err(error) => {
            return Err(CloudBackupError::Internal(format!(
                "failed to read xpub for '{name}': {error}"
            )));
        }
    };

    let descriptors = match keychain.get_public_descriptor(id) {
        Ok(Some((external, internal))) => {
            Some(DescriptorPair { external: external.to_string(), internal: internal.to_string() })
        }
        Ok(None) => None,
        Err(error) => {
            return Err(CloudBackupError::Internal(format!(
                "failed to read descriptors for '{name}': {error}"
            )));
        }
    };

    let metadata_value = serde_json::to_value(metadata)
        .map_err_prefix("serialize metadata", CloudBackupError::Internal)?;

    let wallet_mode = match mode {
        LocalWalletMode::Main => WalletMode::Main,
        LocalWalletMode::Decoy => WalletMode::Decoy,
    };

    Ok(WalletEntry {
        wallet_id: id.to_string(),
        secret,
        metadata: metadata_value,
        descriptors,
        xpub,
        wallet_mode,
    })
}
