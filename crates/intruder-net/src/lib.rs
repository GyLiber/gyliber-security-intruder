//! Non-bypassable production networking boundary.
//!
//! The v0.1.0 implementation begins with destination authorization. DNS,
//! redirect and concrete HTTP execution are added in subsequent commits.

use std::net::IpAddr;

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
    /// Returns [`TargetGateError`] when the candidate is outside the enrolled
    /// target boundary or the target definition itself is invalid.
    pub fn authorize(&self, candidate: &Url) -> Result<(), TargetGateError> {
        self.target.authorize_url(candidate)?;
        Ok(())
    }

    /// Apply the target network policy to one resolved destination address.
    ///
    /// # Errors
    ///
    /// Returns [`TargetGateError`] when the address is outside the enrolled
    /// target's permitted network class.
    pub fn authorize_resolved_ip(&self, address: IpAddr) -> Result<(), TargetGateError> {
        self.target.authorize_resolved_ip(address)?;
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum TargetGateError {
    #[error(transparent)]
    Policy(#[from] PolicyError),
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
}
