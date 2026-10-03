//! Typed target-enrollment and authorization policy.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

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
    /// Whether a LAB/STAGING target may resolve to loopback, private, or link-local space.
    pub allow_private_networks: bool,
    pub budget: SafetyBudget,
}

impl Target {
    /// Validate the structural safety requirements of an enrolled target.
    ///
    /// # Errors
    ///
    /// Returns a [`PolicyError`] when the target identifier, allowlists, network
    /// permissions, or execution budget do not satisfy the minimum enrollment contract.
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
        if self.allow_private_networks
            && matches!(
                self.environment,
                Environment::Canary | Environment::Production
            )
        {
            return Err(PolicyError::PrivateNetworksForbiddenForEnvironment(
                self.environment,
            ));
        }
        self.budget.validate().map_err(PolicyError::InvalidBudget)
    }

    /// Authorize a candidate URL against the declared scheme, host, and path scope.
    ///
    /// # Errors
    ///
    /// Returns a [`PolicyError`] when the target definition is invalid or the
    /// candidate URL falls outside an enrolled scheme, host, or path boundary.
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

    /// Authorize one resolved network destination.
    ///
    /// Public internet targets accept only globally routable unicast destinations.
    /// LAB/STAGING targets may additionally accept local-network destinations when
    /// `allow_private_networks` is explicitly enabled. Known cloud metadata endpoints
    /// and non-routable special-purpose destinations are always denied.
    ///
    /// # Errors
    ///
    /// Returns a [`PolicyError`] when the target definition is invalid or the resolved
    /// address falls outside the target's permitted network class.
    pub fn authorize_resolved_ip(&self, address: IpAddr) -> Result<(), PolicyError> {
        self.validate()?;

        match classify_address(address) {
            AddressClass::PublicInternet => Ok(()),
            AddressClass::LocalNetwork if self.allow_private_networks => Ok(()),
            AddressClass::LocalNetwork | AddressClass::Forbidden => {
                Err(PolicyError::NetworkDestinationDenied(address))
            }
        }
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
    #[error("private-network enrollment is forbidden for {0:?} targets")]
    PrivateNetworksForbiddenForEnvironment(Environment),
    #[error("resolved network destination is not authorized: {0}")]
    NetworkDestinationDenied(IpAddr),
    #[error(transparent)]
    InvalidBudget(#[from] intruder_core::CoreError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AddressClass {
    PublicInternet,
    LocalNetwork,
    Forbidden,
}

fn classify_address(address: IpAddr) -> AddressClass {
    match address {
        IpAddr::V4(address) => classify_ipv4(address),
        IpAddr::V6(address) => classify_ipv6(address),
    }
}

fn classify_ipv4(address: Ipv4Addr) -> AddressClass {
    let octets = address.octets();

    if is_known_metadata_endpoint(IpAddr::V4(address))
        || matches!(
            octets,
            [0 | 224..=255, ..]
                | [192, 0, 0 | 2, ..]
                | [192, 88, 99, ..]
                | [198, 18..=19, ..]
                | [198, 51, 100, ..]
                | [203, 0, 113, ..]
        )
    {
        return AddressClass::Forbidden;
    }

    if matches!(
        octets,
        [10 | 127, ..]
            | [100, 64..=127, ..]
            | [169, 254, ..]
            | [172, 16..=31, ..]
            | [192, 168, ..]
    ) {
        return AddressClass::LocalNetwork;
    }

    AddressClass::PublicInternet
}

fn classify_ipv6(address: Ipv6Addr) -> AddressClass {
    if let Some(mapped) = address.to_ipv4_mapped() {
        return classify_ipv4(mapped);
    }

    if is_known_metadata_endpoint(IpAddr::V6(address))
        || address.is_unspecified()
        || address.is_multicast()
        || is_ipv6_documentation(address)
    {
        return AddressClass::Forbidden;
    }

    if address.is_loopback() || is_ipv6_unique_local(address) || is_ipv6_link_local(address) {
        return AddressClass::LocalNetwork;
    }

    AddressClass::PublicInternet
}

fn is_ipv6_unique_local(address: Ipv6Addr) -> bool {
    (address.segments()[0] & 0xfe00) == 0xfc00
}

fn is_ipv6_link_local(address: Ipv6Addr) -> bool {
    (address.segments()[0] & 0xffc0) == 0xfe80
}

fn is_ipv6_documentation(address: Ipv6Addr) -> bool {
    let segments = address.segments();
    segments[0] == 0x2001 && segments[1] == 0x0db8
}

fn is_known_metadata_endpoint(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => matches!(
            address.octets(),
            [169, 254, 169, 254] | [169, 254, 170, 2] | [100, 100, 100, 200]
        ),
        IpAddr::V6(address) => address.segments() == [0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(environment: Environment, allow_private_networks: bool) -> Target {
        Target {
            target_id: "fixture-secure".to_owned(),
            environment,
            allowed_hosts: vec!["127.0.0.1".to_owned()],
            allowed_schemes: vec!["http".to_owned()],
            allowed_path_prefixes: vec!["/health".to_owned()],
            allow_private_networks,
            budget: SafetyBudget::production_baseline(),
        }
    }

    #[test]
    fn allows_exact_enrolled_destination() -> Result<(), Box<dyn std::error::Error>> {
        let url = Url::parse("http://127.0.0.1/health")?;
        target(Environment::Lab, true).authorize_url(&url)?;
        Ok(())
    }

    #[test]
    fn rejects_arbitrary_host() -> Result<(), Box<dyn std::error::Error>> {
        let url = Url::parse("http://example.com/health")?;
        assert!(matches!(
            target(Environment::Lab, true).authorize_url(&url),
            Err(PolicyError::HostDenied(_))
        ));
        Ok(())
    }

    #[test]
    fn rejects_unapproved_path() -> Result<(), Box<dyn std::error::Error>> {
        let url = Url::parse("http://127.0.0.1/admin")?;
        assert!(matches!(
            target(Environment::Lab, true).authorize_url(&url),
            Err(PolicyError::PathDenied(_))
        ));
        Ok(())
    }

    #[test]
    fn production_cannot_enable_private_networks() {
        assert!(matches!(
            target(Environment::Production, true).validate(),
            Err(PolicyError::PrivateNetworksForbiddenForEnvironment(
                Environment::Production
            ))
        ));
    }

    #[test]
    fn production_accepts_public_unicast() -> Result<(), Box<dyn std::error::Error>> {
        let address = "8.8.8.8".parse()?;
        target(Environment::Production, false).authorize_resolved_ip(address)?;
        Ok(())
    }

    #[test]
    fn production_rejects_private_and_loopback() -> Result<(), Box<dyn std::error::Error>> {
        for address in ["10.0.0.1", "127.0.0.1", "192.168.1.10", "::1"] {
            let address = address.parse()?;
            assert!(matches!(
                target(Environment::Production, false).authorize_resolved_ip(address),
                Err(PolicyError::NetworkDestinationDenied(_))
            ));
        }
        Ok(())
    }

    #[test]
    fn lab_requires_explicit_private_network_permission() -> Result<(), Box<dyn std::error::Error>>
    {
        let address = "127.0.0.1".parse()?;
        assert!(matches!(
            target(Environment::Lab, false).authorize_resolved_ip(address),
            Err(PolicyError::NetworkDestinationDenied(_))
        ));
        target(Environment::Lab, true).authorize_resolved_ip(address)?;
        Ok(())
    }

    #[test]
    fn metadata_endpoints_are_always_denied() -> Result<(), Box<dyn std::error::Error>> {
        for address in [
            "169.254.169.254",
            "169.254.170.2",
            "100.100.100.200",
            "fd00:ec2::254",
        ] {
            let address = address.parse()?;
            assert!(matches!(
                target(Environment::Lab, true).authorize_resolved_ip(address),
                Err(PolicyError::NetworkDestinationDenied(_))
            ));
        }
        Ok(())
    }

    #[test]
    fn documentation_and_multicast_ranges_are_denied() -> Result<(), Box<dyn std::error::Error>> {
        for address in [
            "192.0.2.1",
            "198.51.100.1",
            "203.0.113.1",
            "2001:db8::1",
            "224.0.0.1",
        ] {
            let address = address.parse()?;
            assert!(matches!(
                target(Environment::Lab, true).authorize_resolved_ip(address),
                Err(PolicyError::NetworkDestinationDenied(_))
            ));
        }
        Ok(())
    }
}
