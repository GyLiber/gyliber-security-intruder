//! Redacted evidence records and deterministic integrity envelopes.

pub use intruder_core::Verdict;
use intruder_signing::{
    DocumentKind, KeyRole, SignedEnvelope, SigningError, TrustPolicy, verify_envelope,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

const EVIDENCE_HASH_DOMAIN: &[u8] = b"gyliber-security-intruder:evidence:v1";
pub const EVIDENCE_SCHEMA_VERSION: u16 = 1;
pub const BUNDLE_MANIFEST_SCHEMA_VERSION: u16 = 1;

/// Explicit statement of what data class an evidence record is allowed to contain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceHandling {
    /// Metadata only: no response body and no header values.
    MetadataOnlyNoValues,
}

/// Typed expectation used by the v0.1.0 baseline oracle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceExpectation {
    HttpStatus { status_code: u16 },
}

/// Typed observation persisted by the v0.1.0 baseline probe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceObservation {
    HttpMetadata {
        status_code: u16,
        content_length: Option<u64>,
        header_names: Vec<String>,
    },
}

/// Redacted evidence record.
///
/// This v0.1.0 schema intentionally has no fields for response bodies, request
/// bodies, cookies, authorization material, or header values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceRecord {
    schema_version: u16,
    target_id: String,
    test_case_id: String,
    handling: EvidenceHandling,
    verdict: Verdict,
    expected: EvidenceExpectation,
    observed: EvidenceObservation,
}

impl EvidenceRecord {
    /// Construct a metadata-only HTTP evidence record.
    ///
    /// Header names are normalized into deterministic sorted/deduplicated order
    /// before integrity sealing.
    #[must_use]
    pub fn http_metadata(
        target_id: impl Into<String>,
        test_case_id: impl Into<String>,
        verdict: Verdict,
        expected_status: u16,
        observed_status: u16,
        content_length: Option<u64>,
        header_names: impl IntoIterator<Item = String>,
    ) -> Self {
        let mut header_names = header_names.into_iter().collect::<Vec<_>>();
        header_names.sort_unstable();
        header_names.dedup();

        Self {
            schema_version: EVIDENCE_SCHEMA_VERSION,
            target_id: target_id.into(),
            test_case_id: test_case_id.into(),
            handling: EvidenceHandling::MetadataOnlyNoValues,
            verdict,
            expected: EvidenceExpectation::HttpStatus {
                status_code: expected_status,
            },
            observed: EvidenceObservation::HttpMetadata {
                status_code: observed_status,
                content_length,
                header_names,
            },
        }
    }

    #[must_use]
    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }

    #[must_use]
    pub fn target_id(&self) -> &str {
        &self.target_id
    }

    #[must_use]
    pub fn test_case_id(&self) -> &str {
        &self.test_case_id
    }

    #[must_use]
    pub const fn handling(&self) -> EvidenceHandling {
        self.handling
    }

    #[must_use]
    pub const fn verdict(&self) -> Verdict {
        self.verdict
    }

    #[must_use]
    pub const fn verdict_label(&self) -> &'static str {
        match self.verdict {
            Verdict::Pass => "PASS",
            Verdict::Fail => "FAIL",
            Verdict::NotApplicable => "NOT_APPLICABLE",
            Verdict::NotTested => "NOT_TESTED",
            Verdict::NotArmed => "NOT_ARMED",
        }
    }

    #[must_use]
    pub const fn expected(&self) -> &EvidenceExpectation {
        &self.expected
    }

    #[must_use]
    pub const fn observed(&self) -> &EvidenceObservation {
        &self.observed
    }
}

/// Hash algorithm identifier stored alongside evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IntegrityAlgorithm {
    Sha256,
}

/// Integrity metadata for one evidence record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntegrityManifest {
    algorithm: IntegrityAlgorithm,
    digest_hex: String,
}

impl IntegrityManifest {
    #[must_use]
    pub const fn algorithm(&self) -> IntegrityAlgorithm {
        self.algorithm
    }

    #[must_use]
    pub fn digest_hex(&self) -> &str {
        &self.digest_hex
    }
}

/// Evidence plus a deterministic integrity digest.
///
/// The digest covers the schema serialization of the redacted record and a
/// GyLiber-specific domain separator. It is an integrity check, not a signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedEvidence {
    record: EvidenceRecord,
    integrity: IntegrityManifest,
}

impl SealedEvidence {
    /// Serialize and seal a redacted evidence record.
    ///
    /// # Errors
    ///
    /// Returns `EvidenceError` when JSON serialization fails.
    pub fn seal(record: EvidenceRecord) -> Result<Self, EvidenceError> {
        let digest_hex = evidence_digest(&record)?;
        Ok(Self {
            record,
            integrity: IntegrityManifest {
                algorithm: IntegrityAlgorithm::Sha256,
                digest_hex,
            },
        })
    }

    /// Recompute and compare the evidence digest.
    ///
    /// # Errors
    ///
    /// Returns `EvidenceError::IntegrityMismatch` when the record no longer
    /// matches its sealed digest, or a serialization error if verification
    /// cannot reproduce the serialized record.
    pub fn verify(&self) -> Result<(), EvidenceError> {
        let digest_hex = evidence_digest(&self.record)?;
        if self.integrity.algorithm != IntegrityAlgorithm::Sha256
            || self.integrity.digest_hex != digest_hex
        {
            return Err(EvidenceError::IntegrityMismatch);
        }
        Ok(())
    }

    #[must_use]
    pub const fn record(&self) -> &EvidenceRecord {
        &self.record
    }

    #[must_use]
    pub const fn integrity(&self) -> &IntegrityManifest {
        &self.integrity
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleFileDigest {
    path: String,
    sha256: String,
}

impl BundleFileDigest {
    #[must_use]
    pub fn from_bytes(path: impl Into<String>, bytes: &[u8]) -> Self {
        Self {
            path: path.into(),
            sha256: content_sha256_hex(bytes),
        }
    }

    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    #[must_use]
    pub fn sha256(&self) -> &str {
        &self.sha256
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleManifest {
    schema_version: u16,
    run_id: String,
    target_id: String,
    campaign_id: String,
    campaign_version: u32,
    tool_version: String,
    source_commit: String,
    files: Vec<BundleFileDigest>,
}

impl BundleManifest {
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        run_id: impl Into<String>,
        target_id: impl Into<String>,
        campaign_id: impl Into<String>,
        campaign_version: u32,
        tool_version: impl Into<String>,
        source_commit: impl Into<String>,
        files: Vec<BundleFileDigest>,
    ) -> Self {
        Self {
            schema_version: BUNDLE_MANIFEST_SCHEMA_VERSION,
            run_id: run_id.into(),
            target_id: target_id.into(),
            campaign_id: campaign_id.into(),
            campaign_version,
            tool_version: tool_version.into(),
            source_commit: source_commit.into(),
            files,
        }
    }

    /// Validate manifest identity and file-digest invariants.
    ///
    /// # Errors
    ///
    /// Returns an error for unsupported schema versions, empty identifiers,
    /// invalid campaign versions, unsafe/duplicate paths, or malformed SHA-256
    /// digests.
    pub fn validate(&self) -> Result<(), EvidenceError> {
        if self.schema_version != BUNDLE_MANIFEST_SCHEMA_VERSION {
            return Err(EvidenceError::UnsupportedBundleManifestSchema(
                self.schema_version,
            ));
        }
        for (field, value) in [
            ("run_id", self.run_id.as_str()),
            ("target_id", self.target_id.as_str()),
            ("campaign_id", self.campaign_id.as_str()),
            ("tool_version", self.tool_version.as_str()),
            ("source_commit", self.source_commit.as_str()),
        ] {
            if value.trim().is_empty() {
                return Err(EvidenceError::MissingBundleManifestField(field));
            }
        }
        if self.campaign_version == 0 {
            return Err(EvidenceError::InvalidBundleCampaignVersion);
        }
        if self.files.is_empty() {
            return Err(EvidenceError::EmptyBundleManifest);
        }

        for (index, file) in self.files.iter().enumerate() {
            if !is_safe_bundle_path(&file.path) {
                return Err(EvidenceError::UnsafeBundlePath(file.path.clone()));
            }
            if !is_sha256_hex(&file.sha256) {
                return Err(EvidenceError::MalformedBundleDigest(file.path.clone()));
            }
            if self.files[..index]
                .iter()
                .any(|prior| prior.path == file.path)
            {
                return Err(EvidenceError::DuplicateBundlePath(file.path.clone()));
            }
        }

        Ok(())
    }

    #[must_use]
    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    #[must_use]
    pub fn target_id(&self) -> &str {
        &self.target_id
    }

    #[must_use]
    pub fn campaign_id(&self) -> &str {
        &self.campaign_id
    }

    #[must_use]
    pub const fn campaign_version(&self) -> u32 {
        self.campaign_version
    }

    #[must_use]
    pub fn tool_version(&self) -> &str {
        &self.tool_version
    }

    #[must_use]
    pub fn source_commit(&self) -> &str {
        &self.source_commit
    }

    #[must_use]
    pub fn files(&self) -> &[BundleFileDigest] {
        &self.files
    }
}

pub type SignedBundleManifest = SignedEnvelope<BundleManifest>;

/// Verify a signed evidence-bundle manifest and bind the envelope to the run.
///
/// # Errors
///
/// Returns an error when the evidence signer is untrusted/expired/revoked, the
/// Ed25519 signature is invalid, the envelope is the wrong document kind or
/// run ID, or the manifest itself is malformed.
pub fn verify_signed_bundle_manifest<'a>(
    signed: &'a SignedBundleManifest,
    trust_policy: &TrustPolicy,
    now_unix: u64,
) -> Result<&'a BundleManifest, EvidenceError> {
    if signed.document_kind() != DocumentKind::EvidenceManifest {
        return Err(EvidenceError::SignedManifestKindMismatch);
    }

    verify_envelope(signed, trust_policy, now_unix, KeyRole::EvidenceSigner)?;
    let manifest = signed.payload();
    manifest.validate()?;

    if signed.document_id() != manifest.run_id {
        return Err(EvidenceError::SignedManifestRunIdMismatch {
            envelope_id: signed.document_id().to_owned(),
            manifest_run_id: manifest.run_id.clone(),
        });
    }

    Ok(manifest)
}

/// Verify one bundle file against a validated manifest entry.
///
/// # Errors
///
/// Returns an error if the named path is absent or its SHA-256 digest differs.
pub fn verify_bundle_file(
    manifest: &BundleManifest,
    path: &str,
    bytes: &[u8],
) -> Result<(), EvidenceError> {
    let file = manifest
        .files
        .iter()
        .find(|file| file.path == path)
        .ok_or_else(|| EvidenceError::BundlePathNotManifested(path.to_owned()))?;
    let actual = content_sha256_hex(bytes);
    if file.sha256 != actual {
        return Err(EvidenceError::BundleDigestMismatch {
            path: path.to_owned(),
        });
    }
    Ok(())
}

fn is_safe_bundle_path(path: &str) -> bool {
    !path.is_empty()
        && path != "."
        && path != ".."
        && !path.contains('/')
        && !path.contains('\\')
        && !path.contains('\0')
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[derive(Debug, Error)]
pub enum EvidenceError {
    #[error(transparent)]
    Signing(#[from] SigningError),
    #[error("unsupported bundle manifest schema: {0}")]
    UnsupportedBundleManifestSchema(u16),
    #[error("bundle manifest field is required: {0}")]
    MissingBundleManifestField(&'static str),
    #[error("bundle manifest campaign version must be positive")]
    InvalidBundleCampaignVersion,
    #[error("bundle manifest must contain at least one file")]
    EmptyBundleManifest,
    #[error("unsafe bundle path: {0}")]
    UnsafeBundlePath(String),
    #[error("duplicate bundle path: {0}")]
    DuplicateBundlePath(String),
    #[error("malformed SHA-256 digest for bundle path: {0}")]
    MalformedBundleDigest(String),
    #[error("signed bundle manifest uses the wrong document kind")]
    SignedManifestKindMismatch,
    #[error("signed manifest run id mismatch: envelope {envelope_id}, manifest {manifest_run_id}")]
    SignedManifestRunIdMismatch {
        envelope_id: String,
        manifest_run_id: String,
    },
    #[error("bundle path is not present in signed manifest: {0}")]
    BundlePathNotManifested(String),
    #[error("bundle digest verification failed: {path}")]
    BundleDigestMismatch { path: String },
    #[error("evidence serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("evidence integrity verification failed")]
    IntegrityMismatch,
}

/// Return a standard lowercase SHA-256 digest for arbitrary bytes.
#[must_use]
pub fn content_sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    lower_hex(digest.as_ref())
}

fn evidence_digest(record: &EvidenceRecord) -> Result<String, EvidenceError> {
    let serialized = serde_json::to_vec(record)?;
    let mut hasher = Sha256::new();
    hasher.update(EVIDENCE_HASH_DOMAIN);
    hasher.update([0]);
    hasher.update(serialized);
    let digest = hasher.finalize();
    Ok(lower_hex(digest.as_ref()))
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> EvidenceRecord {
        EvidenceRecord::http_metadata(
            "fixture-secure",
            "baseline-health",
            Verdict::Pass,
            204,
            204,
            Some(0),
            [
                "x-gyliber-fixture".to_owned(),
                "content-length".to_owned(),
                "x-gyliber-fixture".to_owned(),
            ],
        )
    }

    #[test]
    fn content_hash_matches_standard_sha256() {
        assert_eq!(
            content_sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sealing_is_deterministic() -> Result<(), EvidenceError> {
        let first = SealedEvidence::seal(record())?;
        let second = SealedEvidence::seal(record())?;

        assert_eq!(first.integrity(), second.integrity());
        assert_eq!(first.integrity().digest_hex().len(), 64);
        first.verify()
    }

    #[test]
    fn header_names_are_sorted_and_deduplicated() {
        let record = record();
        assert!(matches!(
            record.observed(),
            EvidenceObservation::HttpMetadata { header_names, .. }
                if header_names == &vec![
                    "content-length".to_owned(),
                    "x-gyliber-fixture".to_owned()
                ]
        ));
    }

    #[test]
    fn tampering_is_detected() -> Result<(), EvidenceError> {
        let mut sealed = SealedEvidence::seal(record())?;
        sealed.record.verdict = Verdict::Fail;

        assert!(matches!(
            sealed.verify(),
            Err(EvidenceError::IntegrityMismatch)
        ));
        Ok(())
    }

    fn signing_trust(public: intruder_signing::PublicKeyFile) -> intruder_signing::TrustPolicy {
        intruder_signing::TrustPolicy {
            schema_version: intruder_signing::TRUST_POLICY_SCHEMA_VERSION,
            keys: vec![intruder_signing::TrustedKey {
                key_id: public.key_id,
                algorithm: public.algorithm,
                public_key_hex: public.public_key_hex,
                roles: vec![intruder_signing::KeyRole::EvidenceSigner],
                not_before_unix: 1_799_999_000,
                not_after_unix: 1_800_100_000,
                revoked_at_unix: None,
            }],
            revision_floors: Vec::new(),
        }
    }

    fn manifest() -> BundleManifest {
        BundleManifest::new(
            "run-001",
            "fixture-secure",
            "baseline-health",
            1,
            "0.2.0",
            "abc123",
            vec![
                BundleFileDigest::from_bytes("report.json", b"{\"ok\":true}\n"),
                BundleFileDigest::from_bytes("report.txt", b"PASS\n"),
                BundleFileDigest::from_bytes("run.json", b"{\"run\":\"run-001\"}\n"),
            ],
        )
    }

    #[test]
    fn signed_bundle_manifest_authenticates_files() -> Result<(), Box<dyn std::error::Error>> {
        const NOW: u64 = 1_800_000_000;
        let (private, public) = intruder_signing::generate_keypair("evidence-authority")?;
        let trust = signing_trust(public);
        let signed = intruder_signing::sign_envelope(
            manifest(),
            intruder_signing::DocumentKind::EvidenceManifest,
            "run-001",
            1,
            NOW - 10,
            NOW - 10,
            NOW + 1_000,
            &private,
        )?;

        let verified = verify_signed_bundle_manifest(&signed, &trust, NOW)?;
        verify_bundle_file(verified, "report.txt", b"PASS\n")?;
        Ok(())
    }

    #[test]
    fn signed_bundle_manifest_detects_file_tampering() -> Result<(), Box<dyn std::error::Error>> {
        const NOW: u64 = 1_800_000_000;
        let (private, public) = intruder_signing::generate_keypair("evidence-authority")?;
        let trust = signing_trust(public);
        let signed = intruder_signing::sign_envelope(
            manifest(),
            intruder_signing::DocumentKind::EvidenceManifest,
            "run-001",
            1,
            NOW - 10,
            NOW - 10,
            NOW + 1_000,
            &private,
        )?;

        let verified = verify_signed_bundle_manifest(&signed, &trust, NOW)?;
        assert!(matches!(
            verify_bundle_file(verified, "report.txt", b"FAIL\n"),
            Err(EvidenceError::BundleDigestMismatch { .. })
        ));
        Ok(())
    }

    #[test]
    fn serialized_evidence_contains_no_body_or_header_values() -> Result<(), EvidenceError> {
        let sealed = SealedEvidence::seal(record())?;
        let json = serde_json::to_string(&sealed)?;

        assert!(!json.contains("response_body"));
        assert!(!json.contains("authorization"));
        assert!(!json.contains("cookie"));
        assert!(json.contains("x-gyliber-fixture"));
        Ok(())
    }
}
