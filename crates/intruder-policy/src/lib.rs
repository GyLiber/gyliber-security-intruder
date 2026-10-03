//! Typed target-enrollment and authorization policy.

use intruder_core::{Environment, SafetyBudget};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

/// Immutable logical target definition. Raw arbitrary URLs are not an execution interface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Target {
    pub target_id: String,
    pub environment: Environment,
    pub allowed_hosts: Vec<String>,
    pub allowed_schemes: Vec<String>,
    pub allowed_path_prefixes: Vec<String>,
    pub budget: SafetyBudget,
}

impl Target {
    pub fn validate(&self) -> Result<(), PolicyError> {
        if self.target_id.trim().is_empty() {
            return Err(PolicyError::MissingTargetId);
        }
        if self.allowed_hosts.is_empty() {
            return Err(PolicyError::NoAllowedHosts);
        }
        if self.allowed_schemes.is_empty() {
            return Err(PolicyError::NoAllowedSchemes);
        }
        self.budget.validate().map_err(PolicyError::InvalidBudget)
    }

    pub fn authorize_url(&self, candidate: &Url) -> Result<(), PolicyError> {
        self.validate()?;

        let scheme = candidate.scheme();
        if !self
            .allowed_schemes
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(scheme))
        {
            return Err(PolicyError::SchemeDenied(scheme.to_owned()));
        }

        let host = candidate.host_str().ok_or(PolicyError::MissingHost)?;
        if !self
            .allowed_hosts
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(host))
        {
            return Err(PolicyError::HostDenied(host.to_owned()));
        }

        let path = candidate.path();
        if !self.allowed_path_prefixes.is_empty()
            && !self
                .allowed_path_prefixes
                .iter()
                .any(|prefix| path.starts_with(prefix))
        {
            return Err(PolicyError::PathDenied(path.to_owned()));
        }

        Ok(())
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PolicyError {
    #[error("target id is required")]
    MissingTargetId,
    #[error("target must enroll at least one host")]
    NoAllowedHosts,
    #[error("target must enroll at least one scheme")]
    NoAllowedSchemes,
    #[error("target URL has no host")]
    MissingHost,
    #[error("scheme is not authorized: {0}")]
    SchemeDenied(String),
    #[error("host is not authorized: {0}")]
    HostDenied(String),
    #[error("path is not authorized: {0}")]
    PathDenied(String),
    #[error(transparent)]
    InvalidBudget(#[from] intruder_core::CoreError),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target() -> Target {
        Target {
            target_id: "fixture-secure".to_owned(),
            environment: Environment::Lab,
            allowed_hosts: vec!["127.0.0.1".to_owned()],
            allowed_schemes: vec!["http".to_owned()],
            allowed_path_prefixes: vec!["/health".to_owned()],
            budget: SafetyBudget::production_baseline(),
        }
    }

    #[test]
    fn allows_exact_enrolled_destination() -> Result<(), Box<dyn std::error::Error>> {
        let url = Url::parse("http://127.0.0.1/health")?;
        target().authorize_url(&url)?;
        Ok(())
    }

    #[test]
    fn rejects_arbitrary_host() -> Result<(), Box<dyn std::error::Error>> {
        let url = Url::parse("http://example.com/health")?;
        assert!(matches!(
            target().authorize_url(&url),
            Err(PolicyError::HostDenied(_))
        ));
        Ok(())
    }

    #[test]
    fn rejects_unapproved_path() -> Result<(), Box<dyn std::error::Error>> {
        let url = Url::parse("http://127.0.0.1/admin")?;
        assert!(matches!(
            target().authorize_url(&url),
            Err(PolicyError::PathDenied(_))
        ));
        Ok(())
    }
}
