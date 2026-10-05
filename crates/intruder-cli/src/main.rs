mod auth;
mod bundle;

use std::path::PathBuf;

use auth::{
    DEFAULT_DOCUMENT_VALIDITY_SECONDS, DEFAULT_TRUST_VALIDITY_SECONDS, bootstrap_lab_trust,
    load_json, sign_campaign, sign_target, unix_now, write_json_new, write_private_key_new,
};
use bundle::{RunBundleMetadata, verify_run_bundle, write_signed_run_bundle};
use clap::{Parser, Subcommand};
use intruder_core::{BudgetTracker, KillSwitchState, Verdict};
use intruder_evidence::{EvidenceError, EvidenceRecord, SealedEvidence};
use intruder_net::{ExecutionGate, HttpExecutor, HttpProbeError};
use intruder_policy::{
    CampaignDocument, PolicyError, ProbeKind, SignedCampaignDocument, SignedTargetDocument,
    TargetDocument, VerifiedCampaign, VerifiedTarget, verify_signed_campaign, verify_signed_target,
};
use intruder_report::RunReport;
use intruder_signing::{
    KeyRole, PublicKeyFile, SigningError, SigningKeyFile, TrustPolicy, authorize_signing_key,
    generate_keypair,
};
use thiserror::Error;

#[derive(Debug, Parser)]
#[command(
    name = "intruder",
    version,
    about = "GyLiber controlled adversarial assurance"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Generate local signing identities for controlled assurance.
    Key {
        #[command(subcommand)]
        command: KeyCommand,
    },
    /// Author LAB trust policy for signed assurance documents.
    Trust {
        #[command(subcommand)]
        command: TrustCommand,
    },
    /// Validate, sign, or verify target documents.
    Target {
        #[command(subcommand)]
        command: TargetCommand,
    },
    /// Validate, sign, verify, or plan campaign documents.
    Campaign {
        #[command(subcommand)]
        command: CampaignCommand,
    },
    /// Execute one cryptographically authorized campaign.
    Run {
        /// Signed target envelope.
        #[arg(long)]
        target: PathBuf,
        /// Signed campaign envelope.
        #[arg(long)]
        campaign: PathBuf,
        /// Trust policy used for target, campaign, and evidence signers.
        #[arg(long)]
        trust_policy: PathBuf,
        /// Private evidence-signing key.
        #[arg(long)]
        evidence_signing_key: PathBuf,
        /// Explicit resolved kill-switch snapshot.
        #[arg(long)]
        kill_switch: PathBuf,
        /// Caller-supplied run identifier.
        #[arg(long)]
        run_id: String,
        /// New run-bundle directory. Existing paths are never overwritten.
        #[arg(long)]
        out_dir: PathBuf,
    },
    /// Verify a previously emitted signed run bundle without network access.
    Bundle {
        #[command(subcommand)]
        command: BundleCommand,
    },
    /// Show the default unresolved global kill-switch posture.
    KillSwitchStatus,
}

#[derive(Debug, Subcommand)]
enum KeyCommand {
    /// Generate an Ed25519 keypair. The private file is mode 0600 on Unix.
    Generate {
        #[arg(long)]
        key_id: String,
        #[arg(long)]
        private_out: PathBuf,
        #[arg(long)]
        public_out: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum TrustCommand {
    /// Bootstrap one synthetic/LAB trust policy around one public key.
    BootstrapLab {
        #[arg(long)]
        public_key: PathBuf,
        #[arg(long)]
        target_id: String,
        #[arg(long)]
        campaign_id: String,
        #[arg(long, default_value_t = 1)]
        target_minimum_revision: u64,
        #[arg(long, default_value_t = 1)]
        campaign_minimum_revision: u64,
        #[arg(long, default_value_t = DEFAULT_TRUST_VALIDITY_SECONDS)]
        valid_for_seconds: u64,
        #[arg(long)]
        out: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum TargetCommand {
    /// Validate one unsigned target document while authoring it.
    Validate {
        target: PathBuf,
    },
    /// Sign one validated target document.
    Sign {
        target: PathBuf,
        #[arg(long)]
        key: PathBuf,
        #[arg(long, default_value_t = 1)]
        revision: u64,
        #[arg(long, default_value_t = DEFAULT_DOCUMENT_VALIDITY_SECONDS)]
        valid_for_seconds: u64,
        #[arg(long)]
        out: PathBuf,
    },
    /// Verify target signature, signer role, validity, revocation, and revision.
    Verify {
        signed_target: PathBuf,
        #[arg(long)]
        trust_policy: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum CampaignCommand {
    /// Validate one unsigned campaign against an unsigned target while authoring.
    Validate {
        #[arg(long)]
        target: PathBuf,
        campaign: PathBuf,
    },
    /// Sign one validated campaign. Signed revision equals campaign_version.
    Sign {
        #[arg(long)]
        target: PathBuf,
        campaign: PathBuf,
        #[arg(long)]
        key: PathBuf,
        #[arg(long, default_value_t = DEFAULT_DOCUMENT_VALIDITY_SECONDS)]
        valid_for_seconds: u64,
        #[arg(long)]
        out: PathBuf,
    },
    /// Verify signed target and campaign authorization.
    Verify {
        #[arg(long)]
        target: PathBuf,
        campaign: PathBuf,
        #[arg(long)]
        trust_policy: PathBuf,
    },
    /// Render a non-executing plan only after signature verification.
    Plan {
        #[arg(long)]
        target: PathBuf,
        campaign: PathBuf,
        #[arg(long)]
        trust_policy: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum BundleCommand {
    /// Verify manifest signature, every signed file digest, and SHA256SUMS.
    Verify {
        #[arg(long)]
        dir: PathBuf,
        #[arg(long)]
        trust_policy: PathBuf,
    },
}

#[derive(Debug, Error)]
enum CliError {
    #[error("I/O operation failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON processing failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("run id is required")]
    MissingRunId,
    #[error("system clock is before the Unix epoch")]
    ClockBeforeUnixEpoch,
    #[error(
        "{purpose} validity must be 1..={maximum} seconds; received {seconds}"
    )]
    InvalidValidityWindow {
        purpose: &'static str,
        seconds: u64,
        maximum: u64,
    },
    #[error("validity window overflows Unix timestamp")]
    ValidityWindowOverflow,
    #[error("output path already exists: {0:?}")]
    OutputPathExists(PathBuf),
    #[error("run bundle contains unexpected paths or non-regular files")]
    UnexpectedBundleContents,
    #[error("SHA256SUMS does not match the authenticated bundle contents")]
    ChecksumManifestMismatch,
    #[error(transparent)]
    Core(#[from] intruder_core::CoreError),
    #[error(transparent)]
    Policy(#[from] PolicyError),
    #[error(transparent)]
    Probe(#[from] HttpProbeError),
    #[error(transparent)]
    Evidence(#[from] EvidenceError),
    #[error(transparent)]
    Signing(#[from] SigningError),
}

#[tokio::main]
async fn main() -> Result<(), CliError> {
    let cli = Cli::parse();

    match cli.command {
        Command::Key { command } => execute_key_command(command)?,
        Command::Trust { command } => execute_trust_command(command)?,
        Command::Target { command } => execute_target_command(command)?,
        Command::Campaign { command } => execute_campaign_command(command)?,
        Command::Run {
            target,
            campaign,
            trust_policy,
            evidence_signing_key,
            kill_switch,
            run_id,
            out_dir,
        } => {
            execute_run(
                &target,
                &campaign,
                &trust_policy,
                &evidence_signing_key,
                &kill_switch,
                &run_id,
                &out_dir,
            )
            .await?;
        }
        Command::Bundle { command } => match command {
            BundleCommand::Verify { dir, trust_policy } => {
                let trust = load_json::<TrustPolicy>(&trust_policy)?;
                let now = unix_now()?;
                println!("{}", verify_run_bundle(&dir, &trust, now)?);
            }
        },
        Command::KillSwitchStatus => {
            println!("global kill switch: SAFE_DEFAULT_STOP");
        }
    }

    Ok(())
}

fn execute_key_command(command: KeyCommand) -> Result<(), CliError> {
    match command {
        KeyCommand::Generate {
            key_id,
            private_out,
            public_out,
        } => {
            ensure_outputs_absent([private_out.as_path(), public_out.as_path()])?;
            let (private, public) = generate_keypair(key_id)?;
            write_json_new(&public_out, &public)?;
            write_private_key_new(&private_out, &private)?;
            println!(
                "key generated: id={} public={} private={}",
                public.key_id,
                public_out.display(),
                private_out.display()
            );
        }
    }
    Ok(())
}

fn execute_trust_command(command: TrustCommand) -> Result<(), CliError> {
    match command {
        TrustCommand::BootstrapLab {
            public_key,
            target_id,
            campaign_id,
            target_minimum_revision,
            campaign_minimum_revision,
            valid_for_seconds,
            out,
        } => {
            ensure_outputs_absent([out.as_path()])?;
            let public = load_json::<PublicKeyFile>(&public_key)?;
            let now = unix_now()?;
            let trust = bootstrap_lab_trust(
                &public,
                &target_id,
                &campaign_id,
                target_minimum_revision,
                campaign_minimum_revision,
                now,
                valid_for_seconds,
            )?;
            write_json_new(&out, &trust)?;
            println!(
                "LAB trust policy created: key_id={} target={} campaign={} out={}",
                public.key_id,
                target_id,
                campaign_id,
                out.display()
            );
        }
    }
    Ok(())
}

fn execute_target_command(command: TargetCommand) -> Result<(), CliError> {
    match command {
        TargetCommand::Validate { target } => {
            let target = load_unsigned_target(&target)?;
            println!(
                "target valid: id={} schema_version={}",
                target.target.target_id, target.schema_version
            );
        }
        TargetCommand::Sign {
            target,
            key,
            revision,
            valid_for_seconds,
            out,
        } => {
            ensure_outputs_absent([out.as_path()])?;
            let target = load_unsigned_target(&target)?;
            let key = load_json::<SigningKeyFile>(&key)?;
            let now = unix_now()?;
            let signed = sign_target(&target, &key, revision, now, valid_for_seconds)?;
            write_json_new(&out, &signed)?;
            println!(
                "target signed: id={} revision={} signer={} out={}",
                signed.document_id(),
                signed.revision(),
                signed.key_id(),
                out.display()
            );
        }
        TargetCommand::Verify {
            signed_target,
            trust_policy,
        } => {
            let trust = load_json::<TrustPolicy>(&trust_policy)?;
            let signed = load_json::<SignedTargetDocument>(&signed_target)?;
            let now = unix_now()?;
            let verified = verify_signed_target(&signed, &trust, now)?;
            println!(
                "target signature verified: id={} revision={} signer={} environment={:?}",
                signed.document_id(),
                signed.revision(),
                signed.key_id(),
                verified.document().target.environment
            );
        }
    }
    Ok(())
}

fn execute_campaign_command(command: CampaignCommand) -> Result<(), CliError> {
    match command {
        CampaignCommand::Validate { target, campaign } => {
            let target = load_unsigned_target(&target)?;
            let campaign = load_unsigned_campaign(&campaign, &target)?;
            println!(
                "campaign valid: id={} version={} target={}",
                campaign.campaign_id, campaign.campaign_version, campaign.target_id
            );
        }
        CampaignCommand::Sign {
            target,
            campaign,
            key,
            valid_for_seconds,
            out,
        } => {
            ensure_outputs_absent([out.as_path()])?;
            let target = load_unsigned_target(&target)?;
            let campaign = load_unsigned_campaign(&campaign, &target)?;
            let key = load_json::<SigningKeyFile>(&key)?;
            let now = unix_now()?;
            let signed = sign_campaign(&target, &campaign, &key, now, valid_for_seconds)?;
            write_json_new(&out, &signed)?;
            println!(
                "campaign signed: id={} revision={} signer={} out={}",
                signed.document_id(),
                signed.revision(),
                signed.key_id(),
                out.display()
            );
        }
        CampaignCommand::Verify {
            target,
            campaign,
            trust_policy,
        } => {
            let (signed_target, signed_campaign, trust, now) =
                load_signed_authorization(&target, &campaign, &trust_policy)?;
            let verified_target = verify_signed_target(&signed_target, &trust, now)?;
            let verified_campaign =
                verify_signed_campaign(&signed_campaign, verified_target, &trust, now)?;
            println!(
                "campaign signature verified: id={} revision={} signer={} target={}",
                signed_campaign.document_id(),
                signed_campaign.revision(),
                signed_campaign.key_id(),
                verified_campaign.document().target_id
            );
        }
        CampaignCommand::Plan {
            target,
            campaign,
            trust_policy,
        } => {
            let (signed_target, signed_campaign, trust, now) =
                load_signed_authorization(&target, &campaign, &trust_policy)?;
            let verified_target = verify_signed_target(&signed_target, &trust, now)?;
            let verified_campaign =
                verify_signed_campaign(&signed_campaign, verified_target, &trust, now)?;
            println!(
                "{}",
                render_verified_plan(
                    &signed_target,
                    &signed_campaign,
                    verified_target,
                    verified_campaign
                )
            );
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn execute_run(
    target_path: &std::path::Path,
    campaign_path: &std::path::Path,
    trust_policy_path: &std::path::Path,
    evidence_key_path: &std::path::Path,
    kill_switch_path: &std::path::Path,
    run_id: &str,
    out_dir: &std::path::Path,
) -> Result<(), CliError> {
    if run_id.trim().is_empty() {
        return Err(CliError::MissingRunId);
    }
    if out_dir.try_exists()? {
        return Err(CliError::OutputPathExists(out_dir.to_path_buf()));
    }

    let (signed_target, signed_campaign, trust, now) =
        load_signed_authorization(target_path, campaign_path, trust_policy_path)?;
    let verified_target = verify_signed_target(&signed_target, &trust, now)?;
    let verified_campaign =
        verify_signed_campaign(&signed_campaign, verified_target, &trust, now)?;

    let evidence_key = load_json::<SigningKeyFile>(evidence_key_path)?;
    authorize_signing_key(&evidence_key, &trust, now, KeyRole::EvidenceSigner)?;
    let kill_switches = load_json::<KillSwitchState>(kill_switch_path)?;

    let target = verified_target.document();
    let campaign = verified_campaign.document();
    let report = execute_authorized_campaign(target, campaign, &kill_switches, run_id).await?;
    let metadata = RunBundleMetadata::new(
        run_id,
        &target.target.target_id,
        &campaign.campaign_id,
        campaign.campaign_version,
        signed_target.key_id(),
        signed_campaign.key_id(),
        evidence_key.key_id(),
        &report,
    );
    write_signed_run_bundle(out_dir, &report, &metadata, &evidence_key, &trust, now)?;

    print!("{}", report.render_human()?);
    println!("signed bundle: {}", out_dir.display());
    Ok(())
}

fn load_unsigned_target(path: &std::path::Path) -> Result<TargetDocument, CliError> {
    let target = load_json::<TargetDocument>(path)?;
    target.validate()?;
    Ok(target)
}

fn load_unsigned_campaign(
    path: &std::path::Path,
    target: &TargetDocument,
) -> Result<CampaignDocument, CliError> {
    let campaign = load_json::<CampaignDocument>(path)?;
    campaign.validate_against(target)?;
    Ok(campaign)
}

fn load_signed_authorization(
    target: &std::path::Path,
    campaign: &std::path::Path,
    trust_policy: &std::path::Path,
) -> Result<
    (
        SignedTargetDocument,
        SignedCampaignDocument,
        TrustPolicy,
        u64,
    ),
    CliError,
> {
    let trust = load_json::<TrustPolicy>(trust_policy)?;
    trust.validate()?;
    let signed_target = load_json::<SignedTargetDocument>(target)?;
    let signed_campaign = load_json::<SignedCampaignDocument>(campaign)?;
    let now = unix_now()?;
    Ok((signed_target, signed_campaign, trust, now))
}

fn render_verified_plan(
    signed_target: &SignedTargetDocument,
    signed_campaign: &SignedCampaignDocument,
    target: VerifiedTarget<'_>,
    campaign: VerifiedCampaign<'_>,
) -> String {
    let target = target.document();
    let campaign = campaign.document();
    format!(
        "campaign_plan\nauthorization=SIGNED_VERIFIED\ntarget_signer={}\ntarget_revision={}\ncampaign_signer={}\ncampaign_revision={}\ncampaign_id={}\ntarget_id={}\nenvironment={:?}\nprobe={:?}\ncandidate_url={}\nexpected_status={}\nexecution=NOT_STARTED",
        signed_target.key_id(),
        signed_target.revision(),
        signed_campaign.key_id(),
        signed_campaign.revision(),
        campaign.campaign_id,
        campaign.target_id,
        target.target.environment,
        campaign.probe.kind(),
        campaign.probe.candidate_url(),
        campaign.probe.expected_status()
    )
}

async fn execute_authorized_campaign(
    target: &TargetDocument,
    campaign: &CampaignDocument,
    kill_switches: &KillSwitchState,
    run_id: &str,
) -> Result<RunReport, CliError> {
    campaign.validate_against(target)?;

    let mut budget = BudgetTracker::new(target.target.budget.clone())?;
    let mut gate = ExecutionGate::new(
        &target.target,
        &campaign.campaign_id,
        kill_switches,
        &mut budget,
    );

    let metadata = match campaign.probe.kind() {
        ProbeKind::HttpHeadStatus => {
            HttpExecutor::new()
                .probe_head(&mut gate, campaign.probe.candidate_url())
                .await?
        }
    };

    let verdict = if metadata.status_code == campaign.probe.expected_status() {
        Verdict::Pass
    } else {
        Verdict::Fail
    };

    let evidence = EvidenceRecord::http_metadata(
        target.target.target_id.as_str(),
        campaign.test_case_id.as_str(),
        verdict,
        campaign.probe.expected_status(),
        metadata.status_code,
        metadata.content_length,
        metadata.header_names,
    );
    let sealed = SealedEvidence::seal(evidence)?;
    sealed.verify()?;

    let report = RunReport::new(run_id, vec![sealed]);
    report.verify()?;
    Ok(report)
}

fn ensure_outputs_absent<'a>(
    paths: impl IntoIterator<Item = &'a std::path::Path>,
) -> Result<(), CliError> {
    for path in paths {
        if path.try_exists()? {
            return Err(CliError::OutputPathExists(path.to_path_buf()));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        error::Error,
        io::{self, Read, Write},
        net::TcpListener,
        thread::{self, JoinHandle},
    };

    use intruder_core::{Environment, SafetyBudget};
    use intruder_policy::{CAMPAIGN_SCHEMA_VERSION, CampaignProbe, TARGET_SCHEMA_VERSION};
    use serde::Deserialize;
    use url::Url;

    use super::*;

    fn test_target_document() -> TargetDocument {
        TargetDocument {
            schema_version: TARGET_SCHEMA_VERSION,
            target: intruder_policy::Target {
                target_id: "fixture-local".to_owned(),
                environment: Environment::Lab,
                allowed_hosts: vec!["127.0.0.1".to_owned()],
                allowed_schemes: vec!["http".to_owned()],
                allowed_path_prefixes: vec!["/health".to_owned()],
                allow_private_networks: true,
                budget: SafetyBudget::production_baseline(),
            },
        }
    }

    fn test_campaign(candidate_url: Url, expected_status: u16) -> CampaignDocument {
        CampaignDocument {
            schema_version: CAMPAIGN_SCHEMA_VERSION,
            campaign_id: "baseline-health".to_owned(),
            campaign_version: 1,
            target_id: "fixture-local".to_owned(),
            test_case_id: "baseline-health-status".to_owned(),
            probe: CampaignProbe {
                kind: ProbeKind::HttpHeadStatus,
                candidate_url,
                expected_status,
            },
        }
    }

    struct FixtureServer {
        url: Url,
        handle: JoinHandle<io::Result<()>>,
    }

    fn spawn_fixture(status_code: u16) -> Result<FixtureServer, Box<dyn Error>> {
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        let address = listener.local_addr()?;
        let response = format!(
            "HTTP/1.1 {status_code} Test\r\nContent-Length: 0\r\nX-GyLiber-Fixture: local\r\nConnection: close\r\n\r\n"
        );

        let handle = thread::spawn(move || -> io::Result<()> {
            let (mut stream, _) = listener.accept()?;
            let mut request = [0_u8; 2048];
            let bytes_read = stream.read(&mut request)?;
            if bytes_read == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "fixture received an empty request",
                ));
            }
            stream.write_all(response.as_bytes())?;
            stream.flush()
        });

        let url = Url::parse(&format!("http://{address}/health"))?;
        Ok(FixtureServer { url, handle })
    }

    fn join_fixture(handle: JoinHandle<io::Result<()>>) -> Result<(), Box<dyn Error>> {
        match handle.join() {
            Ok(result) => {
                result?;
                Ok(())
            }
            Err(_) => Err(Box::new(io::Error::other(
                "fixture server thread terminated unexpectedly",
            ))),
        }
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct FixtureDefinition {
        fixture_id: String,
        status_code: u16,
        expected_status: u16,
        expected_verdict: Verdict,
    }

    #[tokio::test]
    async fn fixture_triplet_still_proves_secure_vulnerable_and_fixed_states()
    -> Result<(), Box<dyn Error>> {
        for source in [
            include_str!("../../../fixtures/baseline/secure.json"),
            include_str!("../../../fixtures/baseline/vulnerable.json"),
            include_str!("../../../fixtures/baseline/fixed.json"),
        ] {
            let fixture: FixtureDefinition = serde_json::from_str(source)?;
            let FixtureServer { url, handle } = spawn_fixture(fixture.status_code)?;
            let target = test_target_document();
            let campaign = test_campaign(url, fixture.expected_status);
            let kill_switches = KillSwitchState::default();
            let run_id = format!("run-{}", fixture.fixture_id);
            let report =
                execute_authorized_campaign(&target, &campaign, &kill_switches, &run_id).await?;

            assert_eq!(report.evidence().len(), 1, "fixture={}", fixture.fixture_id);
            assert_eq!(
                report.evidence()[0].record().verdict(),
                fixture.expected_verdict,
                "fixture={}",
                fixture.fixture_id
            );
            report.verify()?;
            join_fixture(handle)?;
        }

        Ok(())
    }

    #[test]
    fn strict_target_and_campaign_documents_reject_unknown_fields() {
        let target_json = r#"{
            "schema_version": 1,
            "target": {
                "target_id": "fixture-local",
                "environment": "LAB",
                "allowed_hosts": ["127.0.0.1"],
                "allowed_schemes": ["http"],
                "allowed_path_prefixes": ["/health"],
                "allow_private_networks": true,
                "budget": {
                    "max_total_requests": 50,
                    "max_requests_per_second": 2,
                    "max_concurrent_requests": 2,
                    "max_request_body_bytes": 16384,
                    "max_response_body_bytes": 262144,
                    "max_execution_seconds": 60,
                    "max_redirects": 3,
                    "max_auth_attempts": 3,
                    "unexpected": true
                }
            }
        }"#;
        assert!(serde_json::from_str::<TargetDocument>(target_json).is_err());

        let campaign_json = r#"{
            "schema_version": 1,
            "campaign_id": "baseline-health",
            "campaign_version": 1,
            "target_id": "fixture-local",
            "test_case_id": "baseline-health-status",
            "probe": {
                "kind": "HTTP_HEAD_STATUS",
                "candidate_url": "http://127.0.0.1/health",
                "expected_status": 204,
                "unexpected": true
            }
        }"#;
        assert!(serde_json::from_str::<CampaignDocument>(campaign_json).is_err());
    }

    #[test]
    fn signed_authorization_plan_is_verified_and_non_executing()
    -> Result<(), Box<dyn Error>> {
        const NOW: u64 = 1_800_000_000;
        let (private, public) = generate_keypair("fixture-authority")?;
        let trust = bootstrap_lab_trust(
            &public,
            "fixture-local",
            "baseline-health",
            1,
            1,
            NOW,
            10_000,
        )?;

        let target = test_target_document();
        let signed_target = sign_target(&target, &private, 1, NOW, 1_000)?;
        let campaign = test_campaign(Url::parse("http://127.0.0.1/health")?, 204);
        let signed_campaign = sign_campaign(&target, &campaign, &private, NOW, 1_000)?;
        let verified_target = verify_signed_target(&signed_target, &trust, NOW)?;
        let verified_campaign =
            verify_signed_campaign(&signed_campaign, verified_target, &trust, NOW)?;
        let plan = render_verified_plan(
            &signed_target,
            &signed_campaign,
            verified_target,
            verified_campaign,
        );

        assert!(plan.contains("authorization=SIGNED_VERIFIED"));
        assert!(plan.contains("execution=NOT_STARTED"));
        assert!(plan.contains("probe=HttpHeadStatus"));
        assert!(plan.contains("expected_status=204"));
        Ok(())
    }
}
