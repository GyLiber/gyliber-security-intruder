//! Non-bypassable production networking boundary.
//!
//! All future production outbound HTTP execution must pass through the execution
//! gate before opening a socket. The gate combines target authorization,
//! kill-switch evaluation, and central budget reservation.

use std::net::IpAddr;

use intruder_core::{BudgetTracker, CoreError, KillSwitchState};
use intruder_policy::{PolicyError, Target};
use thiserror::Error;
use url::Url;

#[derive(Debug)]
pub struct TargetGate<'a> {
    target: &'a Target,
}

impl<'a> TargetGate<'a> {
    #[must_use]
    pub const fn new(target: &'a Target) -> Self {
        Self { target }
    }

    /// Apply the target policy to a candidate outbound URL.
    ///
    /// # Errors
    ///
    /// Returns TargetGateError when the candidate is outside the enrolled
    /// target boundary or the target definition itself is invalid.
    pub fn authorize(&self, candidate: &Url) -> Result<(), TargetGateError> {
        self.target.authorize_url(candidate)?;
        Ok(())
    }

    /// Apply the target network policy to one resolved destination address.
    ///
    /// # Errors
    ///
    /// Returns TargetGateError when the address is outside the enrolled
    /// target's permitted network class.
    pub fn authorize_resolved_ip(&self, address: IpAddr) -> Result<(), TargetGateError> {
        self.target.authorize_resolved_ip(address)?;
        Ok(())
    }
}

/// Composite execution boundary used before any outbound request.
///
/// A request permit is issued only after the target, kill-switch snapshot, and
/// budget all authorize the operation.
#[derive(Debug)]
pub struct ExecutionGate<'a> {
    target: &'a Target,
    campaign_id: &'a str,
    kill_switches: &'a KillSwitchState,
    budget: &'a mut BudgetTracker,
}

impl<'a> ExecutionGate<'a> {
    #[must_use]
    pub fn new(
        target: &'a Target,
        campaign_id: &'a str,
        kill_switches: &'a KillSwitchState,
        budget: &'a mut BudgetTracker,
    ) -> Self {
        Self {
            target,
            campaign_id,
            kill_switches,
            budget,
        }
    }

    /// Authorize and reserve capacity for one outbound request.
    ///
    /// # Errors
    ///
    /// Returns ExecutionGateError when execution is stopped, the URL is outside
    /// target policy, or request capacity is exhausted.
    pub fn begin_request(&mut self, candidate: &Url) -> Result<RequestPermit<'_>, ExecutionGateError> {
        self.kill_switches
            .authorize(&self.target.target_id, self.campaign_id)?;
        TargetGate::new(self.target).authorize(candidate)?;
        self.budget.try_start_request()?;

        Ok(RequestPermit {
            target: self.target,
            budget: self.budget,
            finished: false,
        })
    }
}

/// In-flight request reservation.
///
/// Dropping a permit automatically releases the concurrent-request slot. Total
/// request consumption remains counted, because capacity was reserved for the
/// attempted request.
#[derive(Debug)]
pub struct RequestPermit<'a> {
    target: &'a Target,
    budget: &'a mut BudgetTracker,
    finished: bool,
}

impl RequestPermit<'_> {
    /// Re-authorize each resolved address before a connection is opened.
    ///
    /// # Errors
    ///
    /// Returns TargetGateError when DNS resolution yields a destination outside
    /// the target's permitted network class.
    pub fn authorize_resolved_ip(&self, address: IpAddr) -> Result<(), TargetGateError> {
        TargetGate::new(self.target).authorize_resolved_ip(address)
    }

    /// Release the concurrent-request slot explicitly.
    pub fn finish(mut self) {
        self.release();
    }

    fn release(&mut self) {
        if !self.finished {
            self.budget.finish_request();
            self.finished = true;
        }
    }
}

impl Drop for RequestPermit<'_> {
    fn drop(&mut self) {
        self.release();
    }
}

#[derive(Debug, Error)]
pub enum TargetGateError {
    #[error(transparent)]
    Policy(#[from] PolicyError),
}

#[derive(Debug, Error)]
pub enum ExecutionGateError {
    #[error(transparent)]
    Core(#[from] CoreError),
    #[error(transparent)]
    Target(#[from] TargetGateError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use intruder_core::{Environment, SafetyBudget};

    fn target(environment: Environment, allow_private_networks: bool) -> Target {
        Target {
            target_id: "fixture".to_owned(),
            environment,
            allowed_hosts: vec!["localhost".to_owned()],
            allowed_schemes: vec!["http".to_owned()],
            allowed_path_prefixes: vec!["/".to_owned()],
            allow_private_networks,
            budget: SafetyBudget::production_baseline(),
        }
    }

    #[test]
    fn gate_rejects_non_enrolled_host() -> Result<(), Box<dyn std::error::Error>> {
        let candidate = Url::parse("http://example.com/")?;
        assert!(
            TargetGate::new(&target(Environment::Lab, true))
                .authorize(&candidate)
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn gate_rejects_private_resolution_for_production() -> Result<(), Box<dyn std::error::Error>> {
        let address = "127.0.0.1".parse()?;
        assert!(
            TargetGate::new(&target(Environment::Production, false))
                .authorize_resolved_ip(address)
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn execution_gate_stops_before_budget_on_global_kill() -> Result<(), Box<dyn std::error::Error>> {
        let target = target(Environment::Lab, true);
        let mut budget = BudgetTracker::new(target.budget.clone())?;
        let switches = KillSwitchState {
            global_active: true,
            ..KillSwitchState::default()
        };
        let candidate = Url::parse("http://localhost/")?;

        let mut gate = ExecutionGate::new(&target, "baseline", &switches, &mut budget);
        assert!(matches!(
            gate.begin_request(&candidate),
            Err(ExecutionGateError::Core(CoreError::GlobalKillSwitchActive))
        ));
        assert_eq!(budget.total_requests(), 0);
        Ok(())
    }

    #[test]
    fn execution_gate_rejects_url_before_budget_reservation() -> Result<(), Box<dyn std::error::Error>>
    {
        let target = target(Environment::Lab, true);
        let mut budget = BudgetTracker::new(target.budget.clone())?;
        let switches = KillSwitchState::default();
        let candidate = Url::parse("http://example.com/")?;

        let mut gate = ExecutionGate::new(&target, "baseline", &switches, &mut budget);
        assert!(matches!(
            gate.begin_request(&candidate),
            Err(ExecutionGateError::Target(_))
        ));
        assert_eq!(budget.total_requests(), 0);
        Ok(())
    }

    #[test]
    fn permit_releases_concurrency_on_drop() -> Result<(), Box<dyn std::error::Error>> {
        let mut target = target(Environment::Lab, true);
        target.budget.max_concurrent_requests = 1;
        let mut budget = BudgetTracker::new(target.budget.clone())?;
        let switches = KillSwitchState::default();
        let candidate = Url::parse("http://localhost/")?;

        {
            let mut gate = ExecutionGate::new(&target, "baseline", &switches, &mut budget);
            let permit = gate.begin_request(&candidate)?;
            permit.authorize_resolved_ip("127.0.0.1".parse()?)?;
        }

        assert_eq!(budget.total_requests(), 1);
        assert_eq!(budget.concurrent_requests(), 0);
        Ok(())
    }

    #[test]
    fn permit_blocks_forbidden_resolution() -> Result<(), Box<dyn std::error::Error>> {
        let target = target(Environment::Production, false);
        let mut budget = BudgetTracker::new(target.budget.clone())?;
        let switches = KillSwitchState::default();
        let candidate = Url::parse("http://localhost/")?;

        let mut gate = ExecutionGate::new(&target, "baseline", &switches, &mut budget);
        let permit = gate.begin_request(&candidate)?;
        assert!(permit
            .authorize_resolved_ip("127.0.0.1".parse()?)
            .is_err());
        Ok(())
    }
}
