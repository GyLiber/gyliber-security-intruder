//! Redacted evidence records and deterministic integrity envelopes.

pub use intruder_core::Verdict;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

const EVIDENCE_HASH_DOMAIN: &[u8] = b"gyliber-security-intruder:evidence:v1";
pub const EVIDENCE_SCHEMA_VERSION: u16 = 1;

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

#[derive(Debug, Error)]
pub enum EvidenceError {
    #[error("evidence serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("evidence integrity verification failed")]
    IntegrityMismatch,
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
