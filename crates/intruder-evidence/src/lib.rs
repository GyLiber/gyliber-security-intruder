//! Evidence model. Persistence and hashing arrive after the safety boundary is established.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceRecord {
    pub target_id: String,
    pub test_case_id: String,
    pub expected: String,
    pub observed: String,
}
