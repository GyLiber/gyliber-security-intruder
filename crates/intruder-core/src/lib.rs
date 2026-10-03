//! Core domain types and safety invariants for GyLiber Security Intruder.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Deployment classification used to select safety policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Environment {
    Lab,
    Staging,
    Canary,
    Production,
}

/// Stable verdict dimensions. A single aggregate "security score" is intentionally avoided.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Verdict {
    Pass,
    Fail,
    NotApplicable,
    NotTested,
    NotArmed,
}

/// Centrally enforced execution budget.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SafetyBudget {
    pub max_total_requests: u32,
    pub max_requests_per_second: u32,
    pub max_concurrent_requests: u16,
    pub max_request_body_bytes: u64,
    pub max_response_body_bytes: u64,
    pub max_execution_seconds: u64,
    pub max_redirects: u8,
    pub max_auth_attempts: u16,
}

impl SafetyBudget {
    /// Conservative production baseline for v0.1.0.
    #[must_use]
    pub const fn production_baseline() -> Self {
        Self {
            max_total_requests: 50,
            max_requests_per_second: 2,
            max_concurrent_requests: 2,
            max_request_body_bytes: 16 * 1024,
            max_response_body_bytes: 256 * 1024,
            max_execution_seconds: 60,
            max_redirects: 3,
            max_auth_attempts: 3,
        }
    }

    /// Reject obviously unsafe or unusable budget definitions.
    pub fn validate(&self) -> Result<(), CoreError> {
        if self.max_total_requests == 0 {
            return Err(CoreError::InvalidBudget(
                "max_total_requests must be positive",
            ));
        }
        if self.max_requests_per_second == 0 {
            return Err(CoreError::InvalidBudget(
                "max_requests_per_second must be positive",
            ));
        }
        if self.max_concurrent_requests == 0 {
            return Err(CoreError::InvalidBudget(
                "max_concurrent_requests must be positive",
            ));
        }
        if self.max_execution_seconds == 0 {
            return Err(CoreError::InvalidBudget(
                "max_execution_seconds must be positive",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CoreError {
    #[error("invalid safety budget: {0}")]
    InvalidBudget(&'static str),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_budget_is_valid() -> Result<(), CoreError> {
        SafetyBudget::production_baseline().validate()
    }

    #[test]
    fn zero_request_budget_is_rejected() {
        let budget = SafetyBudget {
            max_total_requests: 0,
            ..SafetyBudget::production_baseline()
        };
        assert!(matches!(
            budget.validate(),
            Err(CoreError::InvalidBudget(
                "max_total_requests must be positive"
            ))
        ));
    }
}
