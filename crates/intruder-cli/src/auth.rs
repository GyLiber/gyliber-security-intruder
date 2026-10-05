use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use intruder_policy::{CampaignDocument, SignedCampaignDocument, SignedTargetDocument, TargetDocument};
use intruder_signing::{
    DocumentKind, KeyRole, PublicKeyFile, RevisionFloor, SigningKeyFile, TrustPolicy, TrustedKey,
    TRUST_POLICY_SCHEMA_VERSION, sign_envelope,
};
use serde::{Serialize, de::DeserializeOwned};
use zeroize::Zeroizing;

use crate::CliError;

pub const DEFAULT_DOCUMENT_VALIDITY_SECONDS: u64 = 86_400;
pub const DEFAULT_TRUST_VALIDITY_SECONDS: u64 = 604_800;
const MAX_DOCUMENT_VALIDITY_SECONDS: u64 = 2_592_000;
const MAX_TRUST_VALIDITY_SECONDS: u64 = 31_536_000;

pub fn load_json<T>(path: &Path) -> Result<T, CliError>
where
    T: DeserializeOwned,
{
    let bytes = fs::read(path)?;
    Ok(serde_json::from_slice(&bytes)?)
}

pub fn write_json_new<T>(path: &Path, value: &T) -> Result<(), CliError>
where
    T: Serialize,
{
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    write_bytes_new(path, &bytes, false)
}

pub fn write_private_key_new(path: &Path, key: &SigningKeyFile) -> Result<(), CliError> {
    let mut bytes = Zeroizing::new(serde_json::to_vec_pretty(key)?);
    bytes.push(b'\n');
    write_bytes_new(path, &bytes, true)
}

fn write_bytes_new(path: &Path, bytes: &[u8], private: bool) -> Result<(), CliError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);

    #[cfg(unix)]
    if private {
        options.mode(0o600);
    }

    #[cfg(not(unix))]
    let _ = private;

    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

pub fn unix_now() -> Result<u64, CliError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| CliError::ClockBeforeUnixEpoch)
}

pub fn document_expiry(now: u64, valid_for_seconds: u64) -> Result<u64, CliError> {
    checked_expiry(
        now,
        valid_for_seconds,
        MAX_DOCUMENT_VALIDITY_SECONDS,
        "signed document",
    )
}

pub fn trust_expiry(now: u64, valid_for_seconds: u64) -> Result<u64, CliError> {
    checked_expiry(
        now,
        valid_for_seconds,
        MAX_TRUST_VALIDITY_SECONDS,
        "trust policy",
    )
}

fn checked_expiry(
    now: u64,
    valid_for_seconds: u64,
    maximum: u64,
    purpose: &'static str,
) -> Result<u64, CliError> {
    if valid_for_seconds == 0 || valid_for_seconds > maximum {
        return Err(CliError::InvalidValidityWindow {
            purpose,
            seconds: valid_for_seconds,
            maximum,
        });
    }
    now.checked_add(valid_for_seconds)
        .ok_or(CliError::ValidityWindowOverflow)
}

pub fn bootstrap_lab_trust(
    public_key: &PublicKeyFile,
    target_id: &str,
    campaign_id: &str,
    target_minimum_revision: u64,
    campaign_minimum_revision: u64,
    now: u64,
    valid_for_seconds: u64,
) -> Result<TrustPolicy, CliError> {
    public_key.validate()?;
    let not_after_unix = trust_expiry(now, valid_for_seconds)?;
    let policy = TrustPolicy {
        schema_version: TRUST_POLICY_SCHEMA_VERSION,
        keys: vec![TrustedKey {
            key_id: public_key.key_id.clone(),
            algorithm: public_key.algorithm,
            public_key_hex: public_key.public_key_hex.clone(),
            roles: vec![
                KeyRole::TargetSigner,
                KeyRole::CampaignSigner,
                KeyRole::EvidenceSigner,
            ],
            not_before_unix: now,
            not_after_unix,
            revoked_at_unix: None,
        }],
        revision_floors: vec![
            RevisionFloor {
                document_kind: DocumentKind::Target,
                document_id: target_id.to_owned(),
                minimum_revision: target_minimum_revision,
            },
            RevisionFloor {
                document_kind: DocumentKind::Campaign,
                document_id: campaign_id.to_owned(),
                minimum_revision: campaign_minimum_revision,
            },
        ],
    };
    policy.validate()?;
    Ok(policy)
}

pub fn sign_target(
    target: &TargetDocument,
    key: &SigningKeyFile,
    revision: u64,
    now: u64,
    valid_for_seconds: u64,
) -> Result<SignedTargetDocument, CliError> {
    target.validate()?;
    key.validate()?;
    let expires_at = document_expiry(now, valid_for_seconds)?;
    Ok(sign_envelope(
        target.clone(),
        DocumentKind::Target,
        target.target.target_id.clone(),
        revision,
        now,
        now,
        expires_at,
        key,
    )?)
}

pub fn sign_campaign(
    target: &TargetDocument,
    campaign: &CampaignDocument,
    key: &SigningKeyFile,
    now: u64,
    valid_for_seconds: u64,
) -> Result<SignedCampaignDocument, CliError> {
    target.validate()?;
    campaign.validate_against(target)?;
    key.validate()?;
    let expires_at = document_expiry(now, valid_for_seconds)?;
    Ok(sign_envelope(
        campaign.clone(),
        DocumentKind::Campaign,
        campaign.campaign_id.clone(),
        u64::from(campaign.campaign_version),
        now,
        now,
        expires_at,
        key,
    )?)
}
