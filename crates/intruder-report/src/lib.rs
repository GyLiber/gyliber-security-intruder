//! Human and machine-readable reporting contracts.

use intruder_evidence::{EvidenceError, EvidenceExpectation, EvidenceObservation, SealedEvidence};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunReport {
    run_id: String,
    evidence: Vec<SealedEvidence>,
}

impl RunReport {
    #[must_use]
    pub fn new(run_id: impl Into<String>, evidence: Vec<SealedEvidence>) -> Self {
        Self {
            run_id: run_id.into(),
            evidence,
        }
    }

    /// Verify every sealed evidence record before report emission.
    ///
    /// # Errors
    ///
    /// Returns `EvidenceError` when any record fails integrity verification.
    pub fn verify(&self) -> Result<(), EvidenceError> {
        for evidence in &self.evidence {
            evidence.verify()?;
        }
        Ok(())
    }

    /// Render a concise human-readable report after integrity verification.
    ///
    /// # Errors
    ///
    /// Returns `EvidenceError` when any record fails integrity verification.
    pub fn render_human(&self) -> Result<String, EvidenceError> {
        self.verify()?;

        let mut output = String::new();
        output.push_str("GyLiber Security Intruder Run Report\n");
        output.push_str("run_id: ");
        output.push_str(&self.run_id);
        output.push('\n');
        output.push_str("evidence_records: ");
        output.push_str(&self.evidence.len().to_string());
        output.push('\n');

        for sealed in &self.evidence {
            let record = sealed.record();
            let expectation = expectation_label(record.expected());
            let observation = observation_label(record.observed());

            output.push_str("- target=");
            output.push_str(record.target_id());
            output.push_str(" test=");
            output.push_str(record.test_case_id());
            output.push_str(" verdict=");
            output.push_str(record.verdict_label());
            output.push_str(" expected=");
            output.push_str(&expectation);
            output.push_str(" observed=");
            output.push_str(&observation);
            output.push_str(" sha256=");
            output.push_str(sealed.integrity().digest_hex());
            output.push('\n');
        }

        Ok(output)
    }

    #[must_use]
    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    #[must_use]
    pub fn evidence(&self) -> &[SealedEvidence] {
        &self.evidence
    }
}

fn expectation_label(expectation: &EvidenceExpectation) -> String {
    match expectation {
        EvidenceExpectation::HttpStatus { status_code } => {
            format!("HTTP_STATUS:{status_code}")
        }
    }
}

fn observation_label(observation: &EvidenceObservation) -> String {
    match observation {
        EvidenceObservation::HttpMetadata { status_code, .. } => {
            format!("HTTP_STATUS:{status_code}")
        }
    }
}

#[cfg(test)]
mod tests {
    use intruder_evidence::{EvidenceRecord, SealedEvidence, Verdict};

    use super::*;

    fn sealed(verdict: Verdict, observed_status: u16) -> Result<SealedEvidence, EvidenceError> {
        SealedEvidence::seal(EvidenceRecord::http_metadata(
            "fixture-secure",
            "baseline-health",
            verdict,
            204,
            observed_status,
            Some(0),
            ["content-length".to_owned()],
        ))
    }

    #[test]
    fn human_report_contains_verified_run_summary() -> Result<(), EvidenceError> {
        let report = RunReport::new("run-0001", vec![sealed(Verdict::Pass, 204)?]);
        let human = report.render_human()?;

        assert!(human.contains("GyLiber Security Intruder Run Report"));
        assert!(human.contains("run_id: run-0001"));
        assert!(human.contains("verdict=PASS"));
        assert!(human.contains("expected=HTTP_STATUS:204"));
        assert!(human.contains("observed=HTTP_STATUS:204"));
        assert!(human.contains("sha256="));
        Ok(())
    }

    #[test]
    fn report_preserves_multiple_verdicts() -> Result<(), EvidenceError> {
        let report = RunReport::new(
            "run-0002",
            vec![sealed(Verdict::Pass, 204)?, sealed(Verdict::Fail, 500)?],
        );

        assert_eq!(report.evidence().len(), 2);
        report.verify()
    }
}
