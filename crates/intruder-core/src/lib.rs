//! Core domain types and safety invariants for `GyLiber` Security Intruder.

use std::collections::BTreeSet;

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
    ///
    /// # Errors
    ///
    /// Returns `CoreError::InvalidBudget` when a required execution limit is zero.
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

/// Fail-closed execution stop state.
///
/// Missing or unreadable external kill-switch state must be converted into an active
/// stop before constructing this value. This type only models an already-resolved snapshot.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct KillSwitchState {
    pub global_active: bool,
    pub disabled_targets: BTreeSet<String>,
    pub cancelled_campaigns: BTreeSet<String>,
}

impl KillSwitchState {
    /// Verify that a target and campaign are not stopped.
    ///
    /// # Errors
    ///
    /// Returns a `CoreError` whenever global, target, or campaign stop state is active.
    pub fn authorize(&self, target_id: &str, campaign_id: &str) -> Result<(), CoreError> {
        if self.global_active {
            return Err(CoreError::GlobalKillSwitchActive);
        }
        if self.disabled_targets.contains(target_id) {
            return Err(CoreError::TargetKillSwitchActive(target_id.to_owned()));
        }
        if self.cancelled_campaigns.contains(campaign_id) {
            return Err(CoreError::CampaignCancelled(campaign_id.to_owned()));
        }
        Ok(())
    }
}

/// Mutable accounting state for centrally enforced request budgets.
///
/// The future HTTP executor must reserve capacity here before opening a request and
/// release concurrent capacity when the request completes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetTracker {
    budget: SafetyBudget,
    total_requests: u32,
    concurrent_requests: u16,
    auth_attempts: u16,
}

impl BudgetTracker {
    /// Create a tracker after validating its immutable limits.
    ///
    /// # Errors
    ///
    /// Returns `CoreError` when the supplied budget is structurally invalid.
    pub fn new(budget: SafetyBudget) -> Result<Self, CoreError> {
        budget.validate()?;
        Ok(Self {
            budget,
            total_requests: 0,
            concurrent_requests: 0,
            auth_attempts: 0,
        })
    }

    /// Reserve one request before execution.
    ///
    /// # Errors
    ///
    /// Returns `CoreError` without changing counters when total or concurrent request
    /// capacity has been exhausted.
    pub fn try_start_request(&mut self) -> Result<(), CoreError> {
        if self.total_requests >= self.budget.max_total_requests {
            return Err(CoreError::RequestBudgetExhausted {
                limit: self.budget.max_total_requests,
            });
        }
        if self.concurrent_requests >= self.budget.max_concurrent_requests {
            return Err(CoreError::ConcurrentRequestBudgetExhausted {
                limit: self.budget.max_concurrent_requests,
            });
        }

        self.total_requests += 1;
        self.concurrent_requests += 1;
        Ok(())
    }

    /// Release one concurrent request slot after completion.
    pub fn finish_request(&mut self) {
        self.concurrent_requests = self.concurrent_requests.saturating_sub(1);
    }

    /// Reserve one authentication attempt before execution.
    ///
    /// # Errors
    ///
    /// Returns `CoreError` without changing the counter when the authentication-attempt
    /// budget has been exhausted.
    pub fn try_record_auth_attempt(&mut self) -> Result<(), CoreError> {
        if self.auth_attempts >= self.budget.max_auth_attempts {
            return Err(CoreError::AuthAttemptBudgetExhausted {
                limit: self.budget.max_auth_attempts,
            });
        }

        self.auth_attempts += 1;
        Ok(())
    }

    #[must_use]
    pub const fn total_requests(&self) -> u32 {
        self.total_requests
    }

    #[must_use]
    pub const fn concurrent_requests(&self) -> u16 {
        self.concurrent_requests
    }

    #[must_use]
    pub const fn auth_attempts(&self) -> u16 {
        self.auth_attempts
    }

    #[must_use]
    pub const fn budget(&self) -> &SafetyBudget {
        &self.budget
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CoreError {
    #[error("invalid safety budget: {0}")]
    InvalidBudget(&'static str),
    #[error("global kill switch is active")]
    GlobalKillSwitchActive,
    #[error("target kill switch is active: {0}")]
    TargetKillSwitchActive(String),
    #[error("campaign has been cancelled: {0}")]
    CampaignCancelled(String),
    #[error("total request budget exhausted at {limit}")]
    RequestBudgetExhausted { limit: u32 },
    #[error("concurrent request budget exhausted at {limit}")]
    ConcurrentRequestBudgetExhausted { limit: u16 },
    #[error("authentication-attempt budget exhausted at {limit}")]
    AuthAttemptBudgetExhausted { limit: u16 },
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

    #[test]
    fn global_kill_switch_stops_every_execution() {
        let state = KillSwitchState {
            global_active: true,
            ..KillSwitchState::default()
        };

        assert_eq!(
            state.authorize("command-center-production", "baseline"),
            Err(CoreError::GlobalKillSwitchActive)
        );
    }

    #[test]
    fn target_kill_switch_is_scoped() -> Result<(), CoreError> {
        let mut state = KillSwitchState::default();
        state
            .disabled_targets
            .insert("command-center-production".to_owned());

        assert!(matches!(
            state.authorize("command-center-production", "baseline"),
            Err(CoreError::TargetKillSwitchActive(target))
                if target == "command-center-production"
        ));
        state.authorize("command-center-staging", "baseline")
    }

    #[test]
    fn campaign_cancellation_is_scoped() -> Result<(), CoreError> {
        let mut state = KillSwitchState::default();
        state
            .cancelled_campaigns
            .insert("deep-assessment".to_owned());

        assert!(matches!(
            state.authorize("command-center-staging", "deep-assessment"),
            Err(CoreError::CampaignCancelled(campaign)) if campaign == "deep-assessment"
        ));
        state.authorize("command-center-staging", "baseline")
    }

    #[test]
    fn request_budget_stops_before_counter_overflow() -> Result<(), CoreError> {
        let budget = SafetyBudget {
            max_total_requests: 1,
            max_concurrent_requests: 1,
            ..SafetyBudget::production_baseline()
        };
        let mut tracker = BudgetTracker::new(budget)?;

        tracker.try_start_request()?;
        tracker.finish_request();

        assert_eq!(tracker.total_requests(), 1);
        assert!(matches!(
            tracker.try_start_request(),
            Err(CoreError::RequestBudgetExhausted { limit: 1 })
        ));
        assert_eq!(tracker.total_requests(), 1);
        Ok(())
    }

    #[test]
    fn concurrent_budget_stops_second_in_flight_request() -> Result<(), CoreError> {
        let budget = SafetyBudget {
            max_total_requests: 2,
            max_concurrent_requests: 1,
            ..SafetyBudget::production_baseline()
        };
        let mut tracker = BudgetTracker::new(budget)?;

        tracker.try_start_request()?;
        assert!(matches!(
            tracker.try_start_request(),
            Err(CoreError::ConcurrentRequestBudgetExhausted { limit: 1 })
        ));
        assert_eq!(tracker.total_requests(), 1);
        assert_eq!(tracker.concurrent_requests(), 1);
        Ok(())
    }

    #[test]
    fn auth_attempt_budget_is_enforced() -> Result<(), CoreError> {
        let budget = SafetyBudget {
            max_auth_attempts: 1,
            ..SafetyBudget::production_baseline()
        };
        let mut tracker = BudgetTracker::new(budget)?;

        tracker.try_record_auth_attempt()?;
        assert!(matches!(
            tracker.try_record_auth_attempt(),
            Err(CoreError::AuthAttemptBudgetExhausted { limit: 1 })
        ));
        assert_eq!(tracker.auth_attempts(), 1);
        Ok(())
    }
}
