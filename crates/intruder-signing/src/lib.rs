//! Cryptographic authorization and authenticity primitives.
//!
//! v0.2.0 signs canonical, domain-separated envelopes with Ed25519. Target and
//! campaign authorization additionally requires an explicit minimum revision
//! in the trust policy so a valid but stale document cannot silently roll back
//! authorization state.

use std::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

const ENVELOPE_SIGNATURE_DOMAIN: &[u8] = b"gyliber-security-intruder:signed-envelope:v1";
pub const SIGNED_ENVELOPE_SCHEMA_VERSION: u16 = 1;
pub const KEY_FILE_SCHEMA_VERSION: u16 = 1;
pub const TRUST_POLICY_SCHEMA_VERSION: u16 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DocumentKind {
    Target,
    Campaign,
    EvidenceManifest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum KeyRole {
    TargetSigner,
    CampaignSigner,
    EvidenceSigner,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SignatureAlgorithm {
    Ed25519,
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct SigningKeyFile {
    schema_version: u16,
    key_id: String,
    secret_key_hex: String,
}

impl fmt::Debug for SigningKeyFile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SigningKeyFile")
            .field("schema_version", &self.schema_version)
            .field("key_id", &self.key_id)
            .field("secret_key_hex", &"[REDACTED]")
            .finish()
    }
}

impl SigningKeyFile {
    /// Validate the private key-file schema and Ed25519 secret bytes.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsupported schema, empty key ID, or malformed
    /// secret-key encoding.
    pub fn validate(&self) -> Result<(), SigningError> {
        validate_signing_key_file(self)
    }

    #[must_use]
    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }

    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicKeyFile {
    pub schema_version: u16,
    pub key_id: String,
    pub algorithm: SignatureAlgorithm,
    pub public_key_hex: String,
}

impl PublicKeyFile {
    /// Validate the public key-file schema and Ed25519 public key.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsupported schema, empty key ID, unsupported
    /// algorithm, or malformed public-key encoding.
    pub fn validate(&self) -> Result<(), SigningError> {
        if self.schema_version != KEY_FILE_SCHEMA_VERSION {
            return Err(SigningError::UnsupportedKeyFileSchema(self.schema_version));
        }
        validate_identifier(&self.key_id)?;
        if self.algorithm != SignatureAlgorithm::Ed25519 {
            return Err(SigningError::UnsupportedSignatureAlgorithm);
        }
        parse_public_key(&self.public_key_hex)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedKey {
    pub key_id: String,
    pub algorithm: SignatureAlgorithm,
    pub public_key_hex: String,
    pub roles: Vec<KeyRole>,
    pub not_before_unix: u64,
    pub not_after_unix: u64,
    pub revoked_at_unix: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevisionFloor {
    pub document_kind: DocumentKind,
    pub document_id: String,
    pub minimum_revision: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustPolicy {
    pub schema_version: u16,
    pub keys: Vec<TrustedKey>,
    pub revision_floors: Vec<RevisionFloor>,
}

impl TrustPolicy {
    /// Validate trust-policy structure and embedded public keys.
    ///
    /// # Errors
    ///
    /// Returns an error for unsupported schemas, duplicate identities/floors,
    /// invalid validity windows, missing roles, or malformed public keys.
    pub fn validate(&self) -> Result<(), SigningError> {
        if self.schema_version != TRUST_POLICY_SCHEMA_VERSION {
            return Err(SigningError::UnsupportedTrustPolicySchema(
                self.schema_version,
            ));
        }

        for (index, key) in self.keys.iter().enumerate() {
            validate_identifier(&key.key_id)?;
            if key.roles.is_empty() {
                return Err(SigningError::TrustedKeyHasNoRoles(key.key_id.clone()));
            }
            if key.not_before_unix >= key.not_after_unix {
                return Err(SigningError::InvalidTrustedKeyWindow(key.key_id.clone()));
            }
            parse_public_key(&key.public_key_hex)?;
            if self.keys[..index]
                .iter()
                .any(|prior| prior.key_id == key.key_id)
            {
                return Err(SigningError::DuplicateTrustedKey(key.key_id.clone()));
            }
        }

        for (index, floor) in self.revision_floors.iter().enumerate() {
            validate_identifier(&floor.document_id)?;
            if floor.minimum_revision == 0 {
                return Err(SigningError::InvalidRevisionFloor {
                    document_kind: floor.document_kind,
                    document_id: floor.document_id.clone(),
                });
            }
            if self.revision_floors[..index].iter().any(|prior| {
                prior.document_kind == floor.document_kind && prior.document_id == floor.document_id
            }) {
                return Err(SigningError::DuplicateRevisionFloor {
                    document_kind: floor.document_kind,
                    document_id: floor.document_id.clone(),
                });
            }
        }

        Ok(())
    }

    fn trusted_key(&self, key_id: &str) -> Result<&TrustedKey, SigningError> {
        self.keys
            .iter()
            .find(|key| key.key_id == key_id)
            .ok_or_else(|| SigningError::UntrustedKey(key_id.to_owned()))
    }

    fn minimum_revision(&self, kind: DocumentKind, document_id: &str) -> Result<u64, SigningError> {
        self.revision_floors
            .iter()
            .find(|floor| floor.document_kind == kind && floor.document_id == document_id)
            .map(|floor| floor.minimum_revision)
            .ok_or_else(|| SigningError::MissingRevisionFloor {
                document_kind: kind,
                document_id: document_id.to_owned(),
            })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureBlock {
    algorithm: SignatureAlgorithm,
    signature_hex: String,
}

impl SignatureBlock {
    #[must_use]
    pub const fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }

    #[must_use]
    pub fn signature_hex(&self) -> &str {
        &self.signature_hex
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedEnvelope<T> {
    envelope_schema_version: u16,
    document_kind: DocumentKind,
    document_id: String,
    revision: u64,
    key_id: String,
    issued_at_unix: u64,
    not_before_unix: u64,
    expires_at_unix: u64,
    payload: T,
    signature: SignatureBlock,
}

impl<T> SignedEnvelope<T> {
    #[must_use]
    pub const fn envelope_schema_version(&self) -> u16 {
        self.envelope_schema_version
    }

    #[must_use]
    pub const fn document_kind(&self) -> DocumentKind {
        self.document_kind
    }

    #[must_use]
    pub fn document_id(&self) -> &str {
        &self.document_id
    }

    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    #[must_use]
    pub const fn issued_at_unix(&self) -> u64 {
        self.issued_at_unix
    }

    #[must_use]
    pub const fn not_before_unix(&self) -> u64 {
        self.not_before_unix
    }

    #[must_use]
    pub const fn expires_at_unix(&self) -> u64 {
        self.expires_at_unix
    }

    #[must_use]
    pub const fn payload(&self) -> &T {
        &self.payload
    }

    #[must_use]
    pub const fn signature(&self) -> &SignatureBlock {
        &self.signature
    }
}

#[derive(Serialize)]
struct UnsignedEnvelope<'a, T> {
    envelope_schema_version: u16,
    document_kind: DocumentKind,
    document_id: &'a str,
    revision: u64,
    key_id: &'a str,
    issued_at_unix: u64,
    not_before_unix: u64,
    expires_at_unix: u64,
    payload: &'a T,
}

/// Generate a new Ed25519 keypair using operating-system entropy.
///
/// # Errors
///
/// Returns an error when the key identifier is empty or the operating
/// system cannot provide cryptographically secure random bytes.
pub fn generate_keypair(
    key_id: impl Into<String>,
) -> Result<(SigningKeyFile, PublicKeyFile), SigningError> {
    let key_id = key_id.into();
    validate_identifier(&key_id)?;

    let mut secret = [0_u8; 32];
    getrandom::fill(&mut secret).map_err(|error| SigningError::Entropy(error.to_string()))?;
    let signing_key = SigningKey::from_bytes(&secret);
    secret.zeroize();

    let public_key = signing_key.verifying_key().to_bytes();
    let private = SigningKeyFile {
        schema_version: KEY_FILE_SCHEMA_VERSION,
        key_id: key_id.clone(),
        secret_key_hex: lower_hex(signing_key.as_bytes()),
    };
    let public = PublicKeyFile {
        schema_version: KEY_FILE_SCHEMA_VERSION,
        key_id,
        algorithm: SignatureAlgorithm::Ed25519,
        public_key_hex: lower_hex(&public_key),
    };

    Ok((private, public))
}

/// Verify that a private signing key corresponds to a currently trusted public
/// key and is authorized for the requested role.
///
/// This is intended as a preflight before an operation whose output must be
/// signed, so trust misconfiguration is detected before side effects occur.
///
/// # Errors
///
/// Returns an error if the private key is malformed, absent from the trust
/// policy, outside its current validity window, revoked, assigned the wrong
/// role, or does not match the trusted public key bytes.
pub fn authorize_signing_key(
    key: &SigningKeyFile,
    trust_policy: &TrustPolicy,
    now_unix: u64,
    required_role: KeyRole,
) -> Result<(), SigningError> {
    key.validate()?;
    trust_policy.validate()?;

    let trusted_key = trust_policy.trusted_key(key.key_id())?;
    if !trusted_key.roles.contains(&required_role) {
        return Err(SigningError::RoleNotAuthorized {
            key_id: key.key_id().to_owned(),
            role: required_role,
        });
    }
    if now_unix < trusted_key.not_before_unix || now_unix > trusted_key.not_after_unix {
        return Err(SigningError::TrustedKeyOutsideValidity(
            key.key_id().to_owned(),
        ));
    }
    if trusted_key
        .revoked_at_unix
        .is_some_and(|revoked_at| now_unix >= revoked_at)
    {
        return Err(SigningError::TrustedKeyRevoked(key.key_id().to_owned()));
    }

    let signing_key = parse_signing_key(&key.secret_key_hex)?;
    let trusted_public = parse_public_key(&trusted_key.public_key_hex)?;
    if signing_key.verifying_key() != trusted_public {
        return Err(SigningError::SigningKeyDoesNotMatchTrustedPublic(
            key.key_id().to_owned(),
        ));
    }

    Ok(())
}

/// Sign one canonical, domain-separated authorization envelope.
///
/// # Errors
///
/// Returns an error for malformed key material, invalid revision/time
/// metadata, or canonical serialization failure.
#[allow(clippy::too_many_arguments)]
pub fn sign_envelope<T>(
    payload: T,
    document_kind: DocumentKind,
    document_id: impl Into<String>,
    revision: u64,
    issued_at_unix: u64,
    not_before_unix: u64,
    expires_at_unix: u64,
    key: &SigningKeyFile,
) -> Result<SignedEnvelope<T>, SigningError>
where
    T: Serialize,
{
    validate_signing_key_file(key)?;
    let document_id = document_id.into();
    validate_envelope_metadata(
        &document_id,
        revision,
        issued_at_unix,
        not_before_unix,
        expires_at_unix,
    )?;

    let signing_key = parse_signing_key(&key.secret_key_hex)?;
    let unsigned = UnsignedEnvelope {
        envelope_schema_version: SIGNED_ENVELOPE_SCHEMA_VERSION,
        document_kind,
        document_id: &document_id,
        revision,
        key_id: &key.key_id,
        issued_at_unix,
        not_before_unix,
        expires_at_unix,
        payload: &payload,
    };
    let message = signature_input(&unsigned)?;
    let signature = signing_key.sign(&message);

    Ok(SignedEnvelope {
        envelope_schema_version: SIGNED_ENVELOPE_SCHEMA_VERSION,
        document_kind,
        document_id,
        revision,
        key_id: key.key_id.clone(),
        issued_at_unix,
        not_before_unix,
        expires_at_unix,
        payload,
        signature: SignatureBlock {
            algorithm: SignatureAlgorithm::Ed25519,
            signature_hex: lower_hex(&signature.to_bytes()),
        },
    })
}

/// Verify trust role, validity, revocation, rollback floor, and signature.
///
/// # Errors
///
/// Returns an error when any structural, trust-policy, temporal, rollback, or
/// Ed25519 verification check fails.
pub fn verify_envelope<T>(
    envelope: &SignedEnvelope<T>,
    trust_policy: &TrustPolicy,
    now_unix: u64,
    required_role: KeyRole,
) -> Result<(), SigningError>
where
    T: Serialize,
{
    trust_policy.validate()?;

    if envelope.envelope_schema_version != SIGNED_ENVELOPE_SCHEMA_VERSION {
        return Err(SigningError::UnsupportedEnvelopeSchema(
            envelope.envelope_schema_version,
        ));
    }
    validate_envelope_metadata(
        &envelope.document_id,
        envelope.revision,
        envelope.issued_at_unix,
        envelope.not_before_unix,
        envelope.expires_at_unix,
    )?;

    if now_unix < envelope.not_before_unix {
        return Err(SigningError::EnvelopeNotYetValid {
            not_before_unix: envelope.not_before_unix,
            now_unix,
        });
    }
    if now_unix > envelope.expires_at_unix {
        return Err(SigningError::EnvelopeExpired {
            expires_at_unix: envelope.expires_at_unix,
            now_unix,
        });
    }

    let trusted_key = trust_policy.trusted_key(&envelope.key_id)?;
    if !trusted_key.roles.contains(&required_role) {
        return Err(SigningError::RoleNotAuthorized {
            key_id: envelope.key_id.clone(),
            role: required_role,
        });
    }
    let trust_time = match envelope.document_kind {
        DocumentKind::EvidenceManifest => envelope.issued_at_unix,
        DocumentKind::Target | DocumentKind::Campaign => now_unix,
    };
    if envelope.issued_at_unix < trusted_key.not_before_unix
        || trust_time > trusted_key.not_after_unix
    {
        return Err(SigningError::TrustedKeyOutsideValidity(
            envelope.key_id.clone(),
        ));
    }
    if trusted_key
        .revoked_at_unix
        .is_some_and(|revoked_at| trust_time >= revoked_at)
    {
        return Err(SigningError::TrustedKeyRevoked(envelope.key_id.clone()));
    }

    if matches!(
        envelope.document_kind,
        DocumentKind::Target | DocumentKind::Campaign
    ) {
        let minimum_revision =
            trust_policy.minimum_revision(envelope.document_kind, &envelope.document_id)?;
        if envelope.revision < minimum_revision {
            return Err(SigningError::RevisionRollback {
                document_kind: envelope.document_kind,
                document_id: envelope.document_id.clone(),
                revision: envelope.revision,
                minimum_revision,
            });
        }
    }

    if envelope.signature.algorithm != SignatureAlgorithm::Ed25519
        || trusted_key.algorithm != SignatureAlgorithm::Ed25519
    {
        return Err(SigningError::UnsupportedSignatureAlgorithm);
    }

    let public_key = parse_public_key(&trusted_key.public_key_hex)?;
    let signature_bytes = decode_hex::<64>(&envelope.signature.signature_hex)?;
    let signature = Signature::from_bytes(&signature_bytes);
    let unsigned = UnsignedEnvelope {
        envelope_schema_version: envelope.envelope_schema_version,
        document_kind: envelope.document_kind,
        document_id: &envelope.document_id,
        revision: envelope.revision,
        key_id: &envelope.key_id,
        issued_at_unix: envelope.issued_at_unix,
        not_before_unix: envelope.not_before_unix,
        expires_at_unix: envelope.expires_at_unix,
        payload: &envelope.payload,
    };
    let message = signature_input(&unsigned)?;

    public_key
        .verify_strict(&message, &signature)
        .map_err(|_| SigningError::SignatureVerificationFailed)
}

/// Serialize the supported JSON subset into deterministic canonical bytes.
///
/// Object keys are sorted lexicographically, array order is preserved, and
/// floating-point numbers are rejected.
///
/// # Errors
///
/// Returns an error if serialization fails or a floating-point JSON number is
/// encountered.
pub fn canonical_json_bytes<T>(value: &T) -> Result<Vec<u8>, SigningError>
where
    T: Serialize,
{
    let value = serde_json::to_value(value)?;
    let mut output = Vec::new();
    write_canonical_json(&value, &mut output)?;
    Ok(output)
}

fn signature_input<T>(unsigned: &UnsignedEnvelope<'_, T>) -> Result<Vec<u8>, SigningError>
where
    T: Serialize,
{
    let canonical = canonical_json_bytes(unsigned)?;
    let mut message = Vec::with_capacity(ENVELOPE_SIGNATURE_DOMAIN.len() + 1 + canonical.len());
    message.extend_from_slice(ENVELOPE_SIGNATURE_DOMAIN);
    message.push(0);
    message.extend_from_slice(&canonical);
    Ok(message)
}

fn write_canonical_json(value: &Value, output: &mut Vec<u8>) -> Result<(), SigningError> {
    match value {
        Value::Null => output.extend_from_slice(b"null"),
        Value::Bool(true) => output.extend_from_slice(b"true"),
        Value::Bool(false) => output.extend_from_slice(b"false"),
        Value::Number(number) => {
            if number.as_i64().is_none() && number.as_u64().is_none() {
                return Err(SigningError::UnsupportedCanonicalNumber);
            }
            output.extend_from_slice(number.to_string().as_bytes());
        }
        Value::String(string) => output.extend_from_slice(&serde_json::to_vec(string)?),
        Value::Array(values) => {
            output.push(b'[');
            for (index, item) in values.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                write_canonical_json(item, output)?;
            }
            output.push(b']');
        }
        Value::Object(object) => {
            let mut keys = object.keys().collect::<Vec<_>>();
            keys.sort_unstable();
            output.push(b'{');
            for (index, key) in keys.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                output.extend_from_slice(&serde_json::to_vec(key)?);
                output.push(b':');
                if let Some(item) = object.get(*key) {
                    write_canonical_json(item, output)?;
                }
            }
            output.push(b'}');
        }
    }

    Ok(())
}

fn validate_signing_key_file(key: &SigningKeyFile) -> Result<(), SigningError> {
    if key.schema_version != KEY_FILE_SCHEMA_VERSION {
        return Err(SigningError::UnsupportedKeyFileSchema(key.schema_version));
    }
    validate_identifier(&key.key_id)?;
    parse_signing_key(&key.secret_key_hex)?;
    Ok(())
}

fn validate_envelope_metadata(
    document_id: &str,
    revision: u64,
    issued_at_unix: u64,
    not_before_unix: u64,
    expires_at_unix: u64,
) -> Result<(), SigningError> {
    validate_identifier(document_id)?;
    if revision == 0 {
        return Err(SigningError::InvalidEnvelopeRevision);
    }
    if issued_at_unix > not_before_unix || not_before_unix >= expires_at_unix {
        return Err(SigningError::InvalidEnvelopeWindow);
    }
    Ok(())
}

fn validate_identifier(value: &str) -> Result<(), SigningError> {
    if value.trim().is_empty() {
        return Err(SigningError::MissingIdentifier);
    }
    Ok(())
}

fn parse_signing_key(secret_key_hex: &str) -> Result<SigningKey, SigningError> {
    let mut secret = decode_hex::<32>(secret_key_hex)?;
    let signing_key = SigningKey::from_bytes(&secret);
    secret.zeroize();
    Ok(signing_key)
}

fn parse_public_key(public_key_hex: &str) -> Result<VerifyingKey, SigningError> {
    let bytes = decode_hex::<32>(public_key_hex)?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| SigningError::MalformedPublicKey)
}

fn decode_hex<const N: usize>(value: &str) -> Result<[u8; N], SigningError> {
    if value.len() != N * 2 {
        return Err(SigningError::MalformedHex);
    }

    let bytes = value.as_bytes();
    let mut decoded = [0_u8; N];
    for (index, slot) in decoded.iter_mut().enumerate() {
        let high = hex_nibble(bytes[index * 2])?;
        let low = hex_nibble(bytes[index * 2 + 1])?;
        *slot = (high << 4) | low;
    }
    Ok(decoded)
}

fn hex_nibble(value: u8) -> Result<u8, SigningError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(SigningError::MalformedHex),
    }
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SigningError {
    #[error("identifier must not be empty")]
    MissingIdentifier,
    #[error("unsupported signing-key file schema: {0}")]
    UnsupportedKeyFileSchema(u16),
    #[error("unsupported trust-policy schema: {0}")]
    UnsupportedTrustPolicySchema(u16),
    #[error("unsupported signed-envelope schema: {0}")]
    UnsupportedEnvelopeSchema(u16),
    #[error("unsupported signature algorithm")]
    UnsupportedSignatureAlgorithm,
    #[error("operating-system entropy failed: {0}")]
    Entropy(String),
    #[error("malformed hexadecimal key or signature material")]
    MalformedHex,
    #[error("malformed Ed25519 public key")]
    MalformedPublicKey,
    #[error("signed envelope revision must be positive")]
    InvalidEnvelopeRevision,
    #[error("signed envelope time window is invalid")]
    InvalidEnvelopeWindow,
    #[error("signed envelope is not valid until {not_before_unix}, current time is {now_unix}")]
    EnvelopeNotYetValid { not_before_unix: u64, now_unix: u64 },
    #[error("signed envelope expired at {expires_at_unix}, current time is {now_unix}")]
    EnvelopeExpired { expires_at_unix: u64, now_unix: u64 },
    #[error("untrusted signing key: {0}")]
    UntrustedKey(String),
    #[error("trusted key has no roles: {0}")]
    TrustedKeyHasNoRoles(String),
    #[error("trusted key validity window is invalid: {0}")]
    InvalidTrustedKeyWindow(String),
    #[error("trusted key appears more than once: {0}")]
    DuplicateTrustedKey(String),
    #[error("trusted key is outside its validity window: {0}")]
    TrustedKeyOutsideValidity(String),
    #[error("trusted key has been revoked: {0}")]
    TrustedKeyRevoked(String),
    #[error("key {key_id} is not authorized for role {role:?}")]
    RoleNotAuthorized { key_id: String, role: KeyRole },
    #[error("missing revision floor for {document_kind:?} document {document_id}")]
    MissingRevisionFloor {
        document_kind: DocumentKind,
        document_id: String,
    },
    #[error("invalid revision floor for {document_kind:?} document {document_id}")]
    InvalidRevisionFloor {
        document_kind: DocumentKind,
        document_id: String,
    },
    #[error("duplicate revision floor for {document_kind:?} document {document_id}")]
    DuplicateRevisionFloor {
        document_kind: DocumentKind,
        document_id: String,
    },
    #[error(
        "{document_kind:?} document {document_id} revision {revision} is below minimum {minimum_revision}"
    )]
    RevisionRollback {
        document_kind: DocumentKind,
        document_id: String,
        revision: u64,
        minimum_revision: u64,
    },
    #[error("private key does not match trusted public key for id: {0}")]
    SigningKeyDoesNotMatchTrustedPublic(String),
    #[error("Ed25519 signature verification failed")]
    SignatureVerificationFailed,
    #[error("canonical JSON does not permit floating-point numbers")]
    UnsupportedCanonicalNumber,
    #[error("canonical JSON serialization failed: {0}")]
    Serialization(String),
}

impl From<serde_json::Error> for SigningError {
    fn from(error: serde_json::Error) -> Self {
        Self::Serialization(error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use serde::Serialize;

    use super::*;

    const NOW: u64 = 1_800_000_000;

    #[derive(Debug, Clone, PartialEq, Eq, Serialize)]
    struct FixtureDocument {
        id: String,
        count: u64,
        enabled: bool,
    }

    fn fixture() -> FixtureDocument {
        FixtureDocument {
            id: "fixture-local".to_owned(),
            count: 7,
            enabled: true,
        }
    }

    fn fixed_key(key_id: &str, byte: u8) -> SigningKeyFile {
        SigningKeyFile {
            schema_version: KEY_FILE_SCHEMA_VERSION,
            key_id: key_id.to_owned(),
            secret_key_hex: lower_hex(&[byte; 32]),
        }
    }

    fn public_for(key: &SigningKeyFile) -> Result<PublicKeyFile, SigningError> {
        let signing_key = parse_signing_key(&key.secret_key_hex)?;
        Ok(PublicKeyFile {
            schema_version: KEY_FILE_SCHEMA_VERSION,
            key_id: key.key_id.clone(),
            algorithm: SignatureAlgorithm::Ed25519,
            public_key_hex: lower_hex(&signing_key.verifying_key().to_bytes()),
        })
    }

    fn trust_for(
        key: &SigningKeyFile,
        role: KeyRole,
        kind: DocumentKind,
        document_id: &str,
        minimum_revision: u64,
    ) -> Result<TrustPolicy, SigningError> {
        let public = public_for(key)?;
        Ok(TrustPolicy {
            schema_version: TRUST_POLICY_SCHEMA_VERSION,
            keys: vec![TrustedKey {
                key_id: public.key_id,
                algorithm: public.algorithm,
                public_key_hex: public.public_key_hex,
                roles: vec![role],
                not_before_unix: NOW - 100,
                not_after_unix: NOW + 10_000,
                revoked_at_unix: None,
            }],
            revision_floors: vec![RevisionFloor {
                document_kind: kind,
                document_id: document_id.to_owned(),
                minimum_revision,
            }],
        })
    }

    fn signed_target(
        key: &SigningKeyFile,
        revision: u64,
    ) -> Result<SignedEnvelope<FixtureDocument>, SigningError> {
        sign_envelope(
            fixture(),
            DocumentKind::Target,
            "fixture-local",
            revision,
            NOW - 10,
            NOW - 10,
            NOW + 1_000,
            key,
        )
    }

    #[test]
    fn canonical_json_sorts_object_keys() -> Result<(), SigningError> {
        #[derive(Serialize)]
        struct OutOfOrder<'a> {
            zeta: u64,
            alpha: &'a str,
        }

        let canonical = canonical_json_bytes(&OutOfOrder {
            zeta: 2,
            alpha: "first",
        })?;
        assert_eq!(
            String::from_utf8(canonical)
                .map_err(|error| SigningError::Serialization(error.to_string()))?,
            r#"{"alpha":"first","zeta":2}"#
        );
        Ok(())
    }

    #[test]
    fn signing_key_preflight_requires_matching_trusted_public_key() -> Result<(), SigningError> {
        let key = fixed_key("evidence-key", 11);
        let other = fixed_key("evidence-key", 12);
        let public = public_for(&other)?;
        let trust = TrustPolicy {
            schema_version: TRUST_POLICY_SCHEMA_VERSION,
            keys: vec![TrustedKey {
                key_id: public.key_id,
                algorithm: public.algorithm,
                public_key_hex: public.public_key_hex,
                roles: vec![KeyRole::EvidenceSigner],
                not_before_unix: NOW - 100,
                not_after_unix: NOW + 100,
                revoked_at_unix: None,
            }],
            revision_floors: Vec::new(),
        };

        assert_eq!(
            authorize_signing_key(&key, &trust, NOW, KeyRole::EvidenceSigner),
            Err(SigningError::SigningKeyDoesNotMatchTrustedPublic(
                "evidence-key".to_owned()
            ))
        );
        Ok(())
    }

    #[test]
    fn valid_signature_and_revision_are_accepted() -> Result<(), SigningError> {
        let key = fixed_key("target-key", 7);
        let signed = signed_target(&key, 3)?;
        let trust = trust_for(
            &key,
            KeyRole::TargetSigner,
            DocumentKind::Target,
            "fixture-local",
            2,
        )?;

        verify_envelope(&signed, &trust, NOW, KeyRole::TargetSigner)
    }

    #[test]
    fn payload_tampering_is_rejected() -> Result<(), SigningError> {
        let key = fixed_key("target-key", 7);
        let mut signed = signed_target(&key, 3)?;
        signed.payload.count = 8;
        let trust = trust_for(
            &key,
            KeyRole::TargetSigner,
            DocumentKind::Target,
            "fixture-local",
            2,
        )?;

        assert_eq!(
            verify_envelope(&signed, &trust, NOW, KeyRole::TargetSigner),
            Err(SigningError::SignatureVerificationFailed)
        );
        Ok(())
    }

    #[test]
    fn wrong_signer_is_rejected() -> Result<(), SigningError> {
        let signing_key = fixed_key("target-key", 7);
        let wrong_key = fixed_key("other-key", 9);
        let signed = signed_target(&signing_key, 3)?;
        let trust = trust_for(
            &wrong_key,
            KeyRole::TargetSigner,
            DocumentKind::Target,
            "fixture-local",
            2,
        )?;

        assert_eq!(
            verify_envelope(&signed, &trust, NOW, KeyRole::TargetSigner),
            Err(SigningError::UntrustedKey("target-key".to_owned()))
        );
        Ok(())
    }

    #[test]
    fn stale_envelope_is_rejected() -> Result<(), SigningError> {
        let key = fixed_key("target-key", 7);
        let signed = sign_envelope(
            fixture(),
            DocumentKind::Target,
            "fixture-local",
            3,
            NOW - 1_000,
            NOW - 1_000,
            NOW - 1,
            &key,
        )?;
        let trust = trust_for(
            &key,
            KeyRole::TargetSigner,
            DocumentKind::Target,
            "fixture-local",
            2,
        )?;

        assert!(matches!(
            verify_envelope(&signed, &trust, NOW, KeyRole::TargetSigner),
            Err(SigningError::EnvelopeExpired { .. })
        ));
        Ok(())
    }

    #[test]
    fn revoked_key_is_rejected() -> Result<(), SigningError> {
        let key = fixed_key("target-key", 7);
        let signed = signed_target(&key, 3)?;
        let mut trust = trust_for(
            &key,
            KeyRole::TargetSigner,
            DocumentKind::Target,
            "fixture-local",
            2,
        )?;
        trust.keys[0].revoked_at_unix = Some(NOW);

        assert_eq!(
            verify_envelope(&signed, &trust, NOW, KeyRole::TargetSigner),
            Err(SigningError::TrustedKeyRevoked("target-key".to_owned()))
        );
        Ok(())
    }

    #[test]
    fn role_mismatch_is_rejected() -> Result<(), SigningError> {
        let key = fixed_key("target-key", 7);
        let signed = signed_target(&key, 3)?;
        let trust = trust_for(
            &key,
            KeyRole::CampaignSigner,
            DocumentKind::Target,
            "fixture-local",
            2,
        )?;

        assert_eq!(
            verify_envelope(&signed, &trust, NOW, KeyRole::TargetSigner),
            Err(SigningError::RoleNotAuthorized {
                key_id: "target-key".to_owned(),
                role: KeyRole::TargetSigner,
            })
        );
        Ok(())
    }

    #[test]
    fn rollback_revision_is_rejected() -> Result<(), SigningError> {
        let key = fixed_key("target-key", 7);
        let signed = signed_target(&key, 2)?;
        let trust = trust_for(
            &key,
            KeyRole::TargetSigner,
            DocumentKind::Target,
            "fixture-local",
            3,
        )?;

        assert_eq!(
            verify_envelope(&signed, &trust, NOW, KeyRole::TargetSigner),
            Err(SigningError::RevisionRollback {
                document_kind: DocumentKind::Target,
                document_id: "fixture-local".to_owned(),
                revision: 2,
                minimum_revision: 3,
            })
        );
        Ok(())
    }

    #[test]
    fn evidence_signature_survives_later_key_expiry() -> Result<(), SigningError> {
        let key = fixed_key("evidence-key", 11);
        let signed = sign_envelope(
            fixture(),
            DocumentKind::EvidenceManifest,
            "run-001",
            1,
            NOW - 100,
            NOW - 100,
            u64::MAX,
            &key,
        )?;
        let public = public_for(&key)?;
        let trust = TrustPolicy {
            schema_version: TRUST_POLICY_SCHEMA_VERSION,
            keys: vec![TrustedKey {
                key_id: public.key_id,
                algorithm: public.algorithm,
                public_key_hex: public.public_key_hex,
                roles: vec![KeyRole::EvidenceSigner],
                not_before_unix: NOW - 1_000,
                not_after_unix: NOW - 1,
                revoked_at_unix: None,
            }],
            revision_floors: Vec::new(),
        };

        verify_envelope(&signed, &trust, NOW + 50_000, KeyRole::EvidenceSigner)
    }

    #[test]
    fn evidence_manifest_does_not_require_revision_floor() -> Result<(), SigningError> {
        let key = fixed_key("evidence-key", 11);
        let signed = sign_envelope(
            fixture(),
            DocumentKind::EvidenceManifest,
            "run-001",
            1,
            NOW - 10,
            NOW - 10,
            NOW + 1_000,
            &key,
        )?;
        let public = public_for(&key)?;
        let trust = TrustPolicy {
            schema_version: TRUST_POLICY_SCHEMA_VERSION,
            keys: vec![TrustedKey {
                key_id: public.key_id,
                algorithm: public.algorithm,
                public_key_hex: public.public_key_hex,
                roles: vec![KeyRole::EvidenceSigner],
                not_before_unix: NOW - 100,
                not_after_unix: NOW + 10_000,
                revoked_at_unix: None,
            }],
            revision_floors: Vec::new(),
        };

        verify_envelope(&signed, &trust, NOW, KeyRole::EvidenceSigner)
    }
}
