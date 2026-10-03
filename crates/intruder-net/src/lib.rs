//! Non-bypassable production networking boundary.
//!
//! The v0.1.0 implementation begins with destination authorization. DNS,
//! redirect and concrete HTTP execution are added in subsequent commits.

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

    /// Apply the target policy to a candidate outbound destination.
    ///
    /// # Errors
    ///
    /// Returns [`TargetGateError`] when the candidate is outside the enrolled
    /// target boundary or the target definition itself is invalid.
    pub fn authorize(&self, candidate: &Url) -> Result<(), TargetGateError> {
        self.target.authorize_url(candidate)?;
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

    #[test]
    fn gate_rejects_non_enrolled_host() -> Result<(), Box<dyn std::error::Error>> {
        let target = Target {
            target_id: "fixture".to_owned(),
            environment: Environment::Lab,
            allowed_hosts: vec!["localhost".to_owned()],
            allowed_schemes: vec!["http".to_owned()],
            allowed_path_prefixes: vec!["/".to_owned()],
            budget: SafetyBudget::production_baseline(),
        };
        let candidate = Url::parse("http://example.com/")?;

        assert!(TargetGate::new(&target).authorize(&candidate).is_err());
        Ok(())
    }
}
