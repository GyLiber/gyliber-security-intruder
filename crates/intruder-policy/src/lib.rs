//! Typed target-enrollment and authorization policy.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use intruder_core::{Environment, SafetyBudget};
use intruder_signing::{
    DocumentKind, KeyRole, SignedEnvelope, SigningError, TrustPolicy, verify_envelope,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

pub const TARGET_SCHEMA_VERSION: u16 = 1;
pub const CAMPAIGN_SCHEMA_VERSION: u16 = 1;

/// Immutable logical target definition. Raw arbitrary URLs are not an execution interface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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

/// Versioned external target document for v0.1.0.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetDocument {
    pub schema_version: u16,
    pub target: Target,
}

impl TargetDocument {
    /// Validate the schema version and enrolled target policy.
    ///
    /// # Errors
    ///
    /// Returns an error when the document schema is unsupported or the
    /// contained target violates enrollment policy.
    pub fn validate(&self) -> Result<(), PolicyError> {
        if self.schema_version != TARGET_SCHEMA_VERSION {
            return Err(PolicyError::UnsupportedTargetSchemaVersion(
                self.schema_version,
            ));
        }

        self.target.validate()
    }
}

/// Probe families armed in the v0.1.0 campaign contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProbeKind {
    HttpHeadStatus,
}

/// Strict configuration for one v0.1.0 baseline probe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignProbe {
    pub kind: ProbeKind,
    pub candidate_url: Url,
    pub expected_status: u16,
}

impl CampaignProbe {
    #[must_use]
    pub const fn kind(&self) -> ProbeKind {
        self.kind
    }

    #[must_use]
    pub const fn expected_status(&self) -> u16 {
        self.expected_status
    }

    #[must_use]
    pub const fn candidate_url(&self) -> &Url {
        &self.candidate_url
    }
}

/// Versioned external campaign document for v0.1.0.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignDocument {
    pub schema_version: u16,
    pub campaign_id: String,
    pub campaign_version: u32,
    pub target_id: String,
    pub test_case_id: String,
    pub probe: CampaignProbe,
}

impl CampaignDocument {
    /// Validate the campaign and bind it to one enrolled target document.
    ///
    /// # Errors
    ///
    /// Returns an error when schema/version identifiers are invalid, the
    /// campaign targets a different enrollment, the expected HTTP status is
    /// invalid, or the candidate URL escapes target policy.
    pub fn validate_against(&self, target: &TargetDocument) -> Result<(), PolicyError> {
        target.validate()?;

        if self.schema_version != CAMPAIGN_SCHEMA_VERSION {
            return Err(PolicyError::UnsupportedCampaignSchemaVersion(
                self.schema_version,
            ));
        }
        if self.campaign_id.trim().is_empty() {
            return Err(PolicyError::MissingCampaignId);
        }
        if self.campaign_version == 0 {
            return Err(PolicyError::InvalidCampaignVersion);
        }
        if self.target_id.trim().is_empty() {
            return Err(PolicyError::MissingCampaignTargetId);
        }
        if self.test_case_id.trim().is_empty() {
            return Err(PolicyError::MissingTestCaseId);
        }
        if self.target_id != target.target.target_id {
            return Err(PolicyError::CampaignTargetMismatch {
                campaign_target_id: self.target_id.clone(),
                enrolled_target_id: target.target.target_id.clone(),
            });
        }
        if !(100..=599).contains(&self.probe.expected_status) {
            return Err(PolicyError::InvalidExpectedHttpStatus(
                self.probe.expected_status,
            ));
        }

        target.target.authorize_url(&self.probe.candidate_url)
    }
}

pub type SignedTargetDocument = SignedEnvelope<TargetDocument>;
pub type SignedCampaignDocument = SignedEnvelope<CampaignDocument>;

#[derive(Debug, Clone, Copy)]
pub struct VerifiedTarget<'a> {
    document: &'a TargetDocument,
}

impl<'a> VerifiedTarget<'a> {
    #[must_use]
    pub const fn document(self) -> &'a TargetDocument {
        self.document
    }
}

#[derive(Debug, Clone, Copy)]
pub struct VerifiedCampaign<'a> {
    document: &'a CampaignDocument,
}

impl<'a> VerifiedCampaign<'a> {
    #[must_use]
    pub const fn document(self) -> &'a CampaignDocument {
        self.document
    }
}

/// Verify a signed target envelope and bind the signature to the target ID.
///
/// # Errors
///
/// Returns an error when the cryptographic envelope is untrusted, expired,
/// revoked, rolled back, the wrong document kind, or its signed identity does
/// not match the target payload.
pub fn verify_signed_target<'a>(
    signed: &'a SignedTargetDocument,
    trust_policy: &TrustPolicy,
    now_unix: u64,
) -> Result<VerifiedTarget<'a>, PolicyError> {
    if signed.document_kind() != DocumentKind::Target {
        return Err(PolicyError::SignedDocumentKindMismatch {
            expected: DocumentKind::Target,
            actual: signed.document_kind(),
        });
    }

    verify_envelope(signed, trust_policy, now_unix, KeyRole::TargetSigner)?;

    let document = signed.payload();
    document.validate()?;
    if signed.document_id() != document.target.target_id {
        return Err(PolicyError::SignedDocumentIdMismatch {
            envelope_id: signed.document_id().to_owned(),
            payload_id: document.target.target_id.clone(),
        });
    }

    Ok(VerifiedTarget { document })
}

/// Verify a signed campaign and bind it to one verified target.
///
/// # Errors
///
/// Returns an error when the campaign signature is untrusted, its identity or
/// revision does not match the payload, or the campaign is invalid for the
/// verified target.
pub fn verify_signed_campaign<'a>(
    signed: &'a SignedCampaignDocument,
    target: VerifiedTarget<'_>,
    trust_policy: &TrustPolicy,
    now_unix: u64,
) -> Result<VerifiedCampaign<'a>, PolicyError> {
    if signed.document_kind() != DocumentKind::Campaign {
        return Err(PolicyError::SignedDocumentKindMismatch {
            expected: DocumentKind::Campaign,
            actual: signed.document_kind(),
        });
    }

    verify_envelope(signed, trust_policy, now_unix, KeyRole::CampaignSigner)?;

    let document = signed.payload();
    if signed.document_id() != document.campaign_id {
        return Err(PolicyError::SignedDocumentIdMismatch {
            envelope_id: signed.document_id().to_owned(),
            payload_id: document.campaign_id.clone(),
        });
    }
    if signed.revision() != u64::from(document.campaign_version) {
        return Err(PolicyError::SignedCampaignRevisionMismatch {
            envelope_revision: signed.revision(),
            campaign_version: document.campaign_version,
        });
    }

    document.validate_against(target.document())?;
    Ok(VerifiedCampaign { document })
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PolicyError {
    #[error(transparent)]
    Signing(#[from] SigningError),
    #[error("signed document kind mismatch: expected {expected:?}, found {actual:?}")]
    SignedDocumentKindMismatch {
        expected: DocumentKind,
        actual: DocumentKind,
    },
    #[error("signed document id mismatch: envelope {envelope_id}, payload {payload_id}")]
    SignedDocumentIdMismatch {
        envelope_id: String,
        payload_id: String,
    },
    #[error(
        "signed campaign revision {envelope_revision} does not match campaign version {campaign_version}"
    )]
    SignedCampaignRevisionMismatch {
        envelope_revision: u64,
        campaign_version: u32,
    },
    #[error("unsupported target schema version: {0}")]
    UnsupportedTargetSchemaVersion(u16),
    #[error("unsupported campaign schema version: {0}")]
    UnsupportedCampaignSchemaVersion(u16),
    #[error("campaign id is required")]
    MissingCampaignId,
    #[error("campaign version must be positive")]
    InvalidCampaignVersion,
    #[error("campaign target id is required")]
    MissingCampaignTargetId,
    #[error("campaign test-case id is required")]
    MissingTestCaseId,
    #[error(
        "campaign target {campaign_target_id} does not match enrolled target {enrolled_target_id}"
    )]
    CampaignTargetMismatch {
        campaign_target_id: String,
        enrolled_target_id: String,
    },
    #[error("expected HTTP status is outside 100..=599: {0}")]
    InvalidExpectedHttpStatus(u16),
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
        [10 | 127, ..] | [100, 64..=127, ..] | [169, 254, ..] | [172, 16..=31, ..] | [192, 168, ..]
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
    fn target_document() -> TargetDocument {
        TargetDocument {
            schema_version: TARGET_SCHEMA_VERSION,
            target: target(Environment::Lab, true),
        }
    }

    fn campaign_document() -> Result<CampaignDocument, url::ParseError> {
        Ok(CampaignDocument {
            schema_version: CAMPAIGN_SCHEMA_VERSION,
            campaign_id: "baseline-health".to_owned(),
            campaign_version: 1,
            target_id: "fixture-secure".to_owned(),
            test_case_id: "baseline-health-status".to_owned(),
            probe: CampaignProbe {
                kind: ProbeKind::HttpHeadStatus,
                candidate_url: Url::parse("http://127.0.0.1/health")?,
                expected_status: 204,
            },
        })
    }

    #[test]
    fn versioned_campaign_binds_to_enrolled_target() -> Result<(), Box<dyn std::error::Error>> {
        campaign_document()?.validate_against(&target_document())?;
        Ok(())
    }

    #[test]
    fn campaign_rejects_mismatched_target() -> Result<(), Box<dyn std::error::Error>> {
        let mut campaign = campaign_document()?;
        campaign.target_id = "different-target".to_owned();

        assert!(matches!(
            campaign.validate_against(&target_document()),
            Err(PolicyError::CampaignTargetMismatch { .. })
        ));
        Ok(())
    }

    #[test]
    fn campaign_rejects_invalid_expected_status() -> Result<(), Box<dyn std::error::Error>> {
        let mut campaign = campaign_document()?;
        campaign.probe.expected_status = 99;

        assert_eq!(
            campaign.validate_against(&target_document()),
            Err(PolicyError::InvalidExpectedHttpStatus(99))
        );
        Ok(())
    }
    fn signing_trust(public: intruder_signing::PublicKeyFile) -> intruder_signing::TrustPolicy {
        intruder_signing::TrustPolicy {
            schema_version: intruder_signing::TRUST_POLICY_SCHEMA_VERSION,
            keys: vec![intruder_signing::TrustedKey {
                key_id: public.key_id,
                algorithm: public.algorithm,
                public_key_hex: public.public_key_hex,
                roles: vec![
                    intruder_signing::KeyRole::TargetSigner,
                    intruder_signing::KeyRole::CampaignSigner,
                ],
                not_before_unix: 1_799_999_000,
                not_after_unix: 1_800_100_000,
                revoked_at_unix: None,
            }],
            revision_floors: vec![
                intruder_signing::RevisionFloor {
                    document_kind: intruder_signing::DocumentKind::Target,
                    document_id: "fixture-secure".to_owned(),
                    minimum_revision: 1,
                },
                intruder_signing::RevisionFloor {
                    document_kind: intruder_signing::DocumentKind::Campaign,
                    document_id: "baseline-health".to_owned(),
                    minimum_revision: 1,
                },
            ],
        }
    }

    #[test]
    fn signed_target_and_campaign_bind_to_payload_identity()
    -> Result<(), Box<dyn std::error::Error>> {
        const NOW: u64 = 1_800_000_000;
        let (private, public) = intruder_signing::generate_keypair("fixture-authority")?;
        let trust = signing_trust(public);
        let target = target_document();
        let signed_target = intruder_signing::sign_envelope(
            target,
            intruder_signing::DocumentKind::Target,
            "fixture-secure",
            1,
            NOW - 10,
            NOW - 10,
            NOW + 1_000,
            &private,
        )?;
        let verified_target = verify_signed_target(&signed_target, &trust, NOW)?;

        let campaign = campaign_document()?;
        let signed_campaign = intruder_signing::sign_envelope(
            campaign,
            intruder_signing::DocumentKind::Campaign,
            "baseline-health",
            1,
            NOW - 10,
            NOW - 10,
            NOW + 1_000,
            &private,
        )?;
        let verified_campaign =
            verify_signed_campaign(&signed_campaign, verified_target, &trust, NOW)?;

        assert_eq!(verified_campaign.document().campaign_id, "baseline-health");
        Ok(())
    }

    #[test]
    fn signed_campaign_revision_must_match_payload_version()
    -> Result<(), Box<dyn std::error::Error>> {
        const NOW: u64 = 1_800_000_000;
        let (private, public) = intruder_signing::generate_keypair("fixture-authority")?;
        let mut trust = signing_trust(public);
        trust.revision_floors[1].minimum_revision = 2;

        let signed_target = intruder_signing::sign_envelope(
            target_document(),
            intruder_signing::DocumentKind::Target,
            "fixture-secure",
            1,
            NOW - 10,
            NOW - 10,
            NOW + 1_000,
            &private,
        )?;
        let verified_target = verify_signed_target(&signed_target, &trust, NOW)?;

        let signed_campaign = intruder_signing::sign_envelope(
            campaign_document()?,
            intruder_signing::DocumentKind::Campaign,
            "baseline-health",
            2,
            NOW - 10,
            NOW - 10,
            NOW + 1_000,
            &private,
        )?;

        assert!(matches!(
            verify_signed_campaign(&signed_campaign, verified_target, &trust, NOW),
            Err(PolicyError::SignedCampaignRevisionMismatch {
                envelope_revision: 2,
                campaign_version: 1,
            })
        ));
        Ok(())
    }
}
