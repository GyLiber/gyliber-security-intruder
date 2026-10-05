use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
};

use intruder_evidence::{
    BundleFileDigest, BundleManifest, SignedBundleManifest, content_sha256_hex,
    verify_bundle_file, verify_signed_bundle_manifest,
};
use intruder_report::RunReport;
use intruder_signing::{
    DocumentKind, KeyRole, SigningKeyFile, TrustPolicy, authorize_signing_key, sign_envelope,
};
use serde::Serialize;

use crate::CliError;

const RUN_BUNDLE_SCHEMA_VERSION: u16 = 2;
const SIGNED_MANIFEST_FILE: &str = "manifest.signed.json";
const CHECKSUM_FILE: &str = "SHA256SUMS";

#[derive(Debug, Serialize)]
pub struct RunBundleMetadata {
    schema_version: u16,
    run_id: String,
    campaign_id: String,
    campaign_version: u32,
    target_id: String,
    target_signer_key_id: String,
    campaign_signer_key_id: String,
    evidence_signer_key_id: String,
    tool_version: String,
    source_commit: String,
    evidence_records: usize,
}

impl RunBundleMetadata {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        run_id: &str,
        target_id: &str,
        campaign_id: &str,
        campaign_version: u32,
        target_signer_key_id: &str,
        campaign_signer_key_id: &str,
        evidence_signer_key_id: &str,
        report: &RunReport,
    ) -> Self {
        Self {
            schema_version: RUN_BUNDLE_SCHEMA_VERSION,
            run_id: run_id.to_owned(),
            campaign_id: campaign_id.to_owned(),
            campaign_version,
            target_id: target_id.to_owned(),
            target_signer_key_id: target_signer_key_id.to_owned(),
            campaign_signer_key_id: campaign_signer_key_id.to_owned(),
            evidence_signer_key_id: evidence_signer_key_id.to_owned(),
            tool_version: env!("CARGO_PKG_VERSION").to_owned(),
            source_commit: source_commit().to_owned(),
            evidence_records: report.evidence().len(),
        }
    }
}

#[derive(Debug)]
struct RunBundle {
    report_json: Vec<u8>,
    report_text: Vec<u8>,
    run_json: Vec<u8>,
    signed_manifest_json: Vec<u8>,
    checksums: Vec<u8>,
}

pub fn write_signed_run_bundle(
    path: &Path,
    report: &RunReport,
    metadata: &RunBundleMetadata,
    evidence_key: &SigningKeyFile,
    trust_policy: &TrustPolicy,
    now_unix: u64,
) -> Result<(), CliError> {
    let bundle = build_signed_run_bundle(
        report,
        metadata,
        evidence_key,
        trust_policy,
        now_unix,
    )?;

    fs::create_dir(path)?;
    let write_result = (|| -> Result<(), CliError> {
        write_new_file(&path.join("report.json"), &bundle.report_json)?;
        write_new_file(&path.join("report.txt"), &bundle.report_text)?;
        write_new_file(&path.join("run.json"), &bundle.run_json)?;
        write_new_file(
            &path.join(SIGNED_MANIFEST_FILE),
            &bundle.signed_manifest_json,
        )?;
        write_new_file(&path.join(CHECKSUM_FILE), &bundle.checksums)?;
        Ok(())
    })();

    if write_result.is_err() {
        drop(fs::remove_dir_all(path));
    }
    write_result
}

pub fn verify_run_bundle(
    path: &Path,
    trust_policy: &TrustPolicy,
    now_unix: u64,
) -> Result<String, CliError> {
    trust_policy.validate()?;

    let manifest_path = path.join(SIGNED_MANIFEST_FILE);
    ensure_regular_file(&manifest_path)?;
    let signed_manifest_bytes = fs::read(&manifest_path)?;
    let signed: SignedBundleManifest = serde_json::from_slice(&signed_manifest_bytes)?;
    let manifest = verify_signed_bundle_manifest(&signed, trust_policy, now_unix)?;

    let mut expected_names = manifest
        .files()
        .iter()
        .map(|file| file.path().to_owned())
        .collect::<Vec<_>>();
    expected_names.push(SIGNED_MANIFEST_FILE.to_owned());
    expected_names.push(CHECKSUM_FILE.to_owned());
    expected_names.sort();

    let mut actual_names = Vec::new();
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let metadata = entry.file_type()?;
        if !metadata.is_file() {
            return Err(CliError::UnexpectedBundleContents);
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| CliError::UnexpectedBundleContents)?;
        actual_names.push(name);
    }
    actual_names.sort();

    if actual_names != expected_names {
        return Err(CliError::UnexpectedBundleContents);
    }

    let mut expected_checksums = String::new();
    for file in manifest.files() {
        let file_path = path.join(file.path());
        ensure_regular_file(&file_path)?;
        let bytes = fs::read(&file_path)?;
        verify_bundle_file(manifest, file.path(), &bytes)?;
        append_checksum_line(&mut expected_checksums, file.sha256(), file.path());
    }

    let signed_manifest_digest = content_sha256_hex(&signed_manifest_bytes);
    append_checksum_line(
        &mut expected_checksums,
        &signed_manifest_digest,
        SIGNED_MANIFEST_FILE,
    );

    let checksum_path = path.join(CHECKSUM_FILE);
    ensure_regular_file(&checksum_path)?;
    let actual_checksums = fs::read(&checksum_path)?;
    if actual_checksums != expected_checksums.as_bytes() {
        return Err(CliError::ChecksumManifestMismatch);
    }

    Ok(format!(
        "bundle verified: run_id={} evidence_signer={} files={}",
        manifest.run_id(),
        signed.key_id(),
        manifest.files().len()
    ))
}

fn build_signed_run_bundle(
    report: &RunReport,
    metadata: &RunBundleMetadata,
    evidence_key: &SigningKeyFile,
    trust_policy: &TrustPolicy,
    now_unix: u64,
) -> Result<RunBundle, CliError> {
    report.verify()?;
    authorize_signing_key(
        evidence_key,
        trust_policy,
        now_unix,
        KeyRole::EvidenceSigner,
    )?;

    let mut report_json = serde_json::to_vec_pretty(report)?;
    report_json.push(b'\n');

    let mut report_text = report.render_human()?.into_bytes();
    if !report_text.ends_with(b"\n") {
        report_text.push(b'\n');
    }

    let mut run_json = serde_json::to_vec_pretty(metadata)?;
    run_json.push(b'\n');

    let manifest = BundleManifest::new(
        metadata.run_id.clone(),
        metadata.target_id.clone(),
        metadata.campaign_id.clone(),
        metadata.campaign_version,
        metadata.tool_version.clone(),
        metadata.source_commit.clone(),
        vec![
            BundleFileDigest::from_bytes("report.json", &report_json),
            BundleFileDigest::from_bytes("report.txt", &report_text),
            BundleFileDigest::from_bytes("run.json", &run_json),
        ],
    );
    manifest.validate()?;

    let signed_manifest = sign_envelope(
        manifest,
        DocumentKind::EvidenceManifest,
        metadata.run_id.clone(),
        1,
        now_unix,
        now_unix,
        u64::MAX,
        evidence_key,
    )?;
    verify_signed_bundle_manifest(&signed_manifest, trust_policy, now_unix)?;

    let mut signed_manifest_json = serde_json::to_vec_pretty(&signed_manifest)?;
    signed_manifest_json.push(b'\n');

    let mut checksums = String::new();
    for file in signed_manifest.payload().files() {
        append_checksum_line(&mut checksums, file.sha256(), file.path());
    }
    append_checksum_line(
        &mut checksums,
        &content_sha256_hex(&signed_manifest_json),
        SIGNED_MANIFEST_FILE,
    );

    Ok(RunBundle {
        report_json,
        report_text,
        run_json,
        signed_manifest_json,
        checksums: checksums.into_bytes(),
    })
}

fn append_checksum_line(output: &mut String, digest: &str, path: &str) {
    output.push_str(digest);
    output.push_str("  ");
    output.push_str(path);
    output.push('\n');
}

fn source_commit() -> &'static str {
    match option_env!("GYLIBER_SOURCE_COMMIT") {
        Some(commit) => commit,
        None => "UNSPECIFIED",
    }
}

fn write_new_file(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn ensure_regular_file(path: &Path) -> Result<(), CliError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() {
        return Err(CliError::UnexpectedBundleContents);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    use intruder_core::Verdict;
    use intruder_evidence::{EvidenceRecord, SealedEvidence};
    use intruder_signing::{
        KeyRole, RevisionFloor, SignatureAlgorithm, TRUST_POLICY_SCHEMA_VERSION, TrustedKey,
        generate_keypair,
    };

    use super::*;

    fn unique_test_dir(name: &str) -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
        let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        Ok(std::env::temp_dir().join(format!(
            "gyliber-intruder-{name}-{}-{stamp}",
            std::process::id()
        )))
    }

    fn report() -> Result<RunReport, intruder_evidence::EvidenceError> {
        let evidence = EvidenceRecord::http_metadata(
            "fixture-local",
            "baseline-health-status",
            Verdict::Pass,
            204,
            204,
            Some(0),
            ["content-length".to_owned()],
        );
        Ok(RunReport::new(
            "run-bundle-test",
            vec![SealedEvidence::seal(evidence)?],
        ))
    }

    fn trust(
        public: intruder_signing::PublicKeyFile,
        now: u64,
    ) -> TrustPolicy {
        TrustPolicy {
            schema_version: TRUST_POLICY_SCHEMA_VERSION,
            keys: vec![TrustedKey {
                key_id: public.key_id,
                algorithm: SignatureAlgorithm::Ed25519,
                public_key_hex: public.public_key_hex,
                roles: vec![KeyRole::EvidenceSigner],
                not_before_unix: now - 10,
                not_after_unix: now + 1_000,
                revoked_at_unix: None,
            }],
            revision_floors: vec![RevisionFloor {
                document_kind: DocumentKind::Target,
                document_id: "unused".to_owned(),
                minimum_revision: 1,
            }],
        }
    }

    #[test]
    fn signed_bundle_round_trip_detects_tampering() -> Result<(), Box<dyn std::error::Error>> {
        let now = 1_800_000_000;
        let (private, public) = generate_keypair("evidence-authority")?;
        let trust = trust(public, now);
        let report = report()?;
        let metadata = RunBundleMetadata::new(
            "run-bundle-test",
            "fixture-local",
            "baseline-health",
            1,
            "target-authority",
            "campaign-authority",
            private.key_id(),
            &report,
        );
        let dir = unique_test_dir("signed-bundle")?;

        write_signed_run_bundle(&dir, &report, &metadata, &private, &trust, now)?;
        assert!(verify_run_bundle(&dir, &trust, now + 10)?.contains("bundle verified"));

        fs::write(dir.join("report.txt"), b"TAMPERED\n")?;
        assert!(matches!(
            verify_run_bundle(&dir, &trust, now + 10),
            Err(CliError::Evidence(
                intruder_evidence::EvidenceError::BundleDigestMismatch { .. }
            ))
        ));

        fs::remove_dir_all(dir)?;
        Ok(())
    }
}
