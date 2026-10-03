//! Human and machine-readable reporting contracts.

use intruder_evidence::EvidenceRecord;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunReport {
    pub run_id: String,
    pub evidence: Vec<EvidenceRecord>,
}
