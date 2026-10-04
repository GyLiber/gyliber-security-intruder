use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use clap::{Parser, Subcommand};
use intruder_core::{BudgetTracker, KillSwitchState, Verdict};
use intruder_evidence::{EvidenceError, EvidenceRecord, SealedEvidence, content_sha256_hex};
use intruder_net::{ExecutionGate, HttpExecutor, HttpProbeError};
use intruder_policy::{CampaignDocument, PolicyError, ProbeKind, TargetDocument};
use intruder_report::RunReport;
use serde::{Serialize, de::DeserializeOwned};
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
    /// Validate versioned target documents.
    Target {
        #[command(subcommand)]
        command: TargetCommand,
    },
    /// Validate or inspect versioned campaign documents.
    Campaign {
        #[command(subcommand)]
        command: CampaignCommand,
    },
    /// Execute one armed v0.1.0 campaign.
    Run {
        /// Versioned target document.
        #[arg(long)]
        target: PathBuf,
        /// Versioned campaign document.
        #[arg(long)]
        campaign: PathBuf,
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
    /// Show the default unresolved global kill-switch posture.
    KillSwitchStatus,
}

#[derive(Debug, Subcommand)]
enum TargetCommand {
    /// Validate one target document and its safety budget.
    Validate {
        /// Versioned target document.
        target: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum CampaignCommand {
    /// Validate a campaign against one enrolled target.
    Validate {
        /// Versioned target document.
        #[arg(long)]
        target: PathBuf,
        /// Versioned campaign document.
        campaign: PathBuf,
    },
    /// Render a non-executing campaign plan after validation.
    Plan {
        /// Versioned target document.
        #[arg(long)]
        target: PathBuf,
        /// Versioned campaign document.
        campaign: PathBuf,
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
    #[error(transparent)]
    Core(#[from] intruder_core::CoreError),
    #[error(transparent)]
    Policy(#[from] PolicyError),
    #[error(transparent)]
    Probe(#[from] HttpProbeError),
    #[error(transparent)]
    Evidence(#[from] EvidenceError),
}

#[tokio::main]
async fn main() -> Result<(), CliError> {
    let cli = Cli::parse();

    match cli.command {
        Command::Target { command } => match command {
            TargetCommand::Validate { target } => {
                let target = load_target(&target)?;
                println!(
                    "target valid: id={} schema_version={}",
                    target.target.target_id, target.schema_version
                );
            }
        },
        Command::Campaign { command } => match command {
            CampaignCommand::Validate { target, campaign } => {
                let target = load_target(&target)?;
                let campaign = load_campaign(&campaign, &target)?;
                println!(
                    "campaign valid: id={} version={} target={}",
                    campaign.campaign_id, campaign.campaign_version, campaign.target_id
                );
            }
            CampaignCommand::Plan { target, campaign } => {
                let target = load_target(&target)?;
                let campaign = load_campaign(&campaign, &target)?;
                println!("{}", render_plan(&target, &campaign));
            }
        },
        Command::Run {
            target,
            campaign,
            kill_switch,
            run_id,
            out_dir,
        } => {
            let target = load_target(&target)?;
            let campaign = load_campaign(&campaign, &target)?;
            let kill_switches = load_json::<KillSwitchState>(&kill_switch)?;
            let report = execute_campaign(&target, &campaign, &kill_switches, &run_id).await?;
            let metadata = RunBundleMetadata::new(&run_id, &target, &campaign, &report);
            write_run_bundle(&out_dir, &report, &metadata)?;
            print!("{}", report.render_human()?);
        }
        Command::KillSwitchStatus => {
            println!("global kill switch: SAFE_DEFAULT_STOP");
        }
    }

    Ok(())
}

fn load_json<T: DeserializeOwned>(path: &Path) -> Result<T, CliError> {
    let bytes = fs::read(path)?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn load_target(path: &Path) -> Result<TargetDocument, CliError> {
    let target = load_json::<TargetDocument>(path)?;
    target.validate()?;
    Ok(target)
}

fn load_campaign(path: &Path, target: &TargetDocument) -> Result<CampaignDocument, CliError> {
    let campaign = load_json::<CampaignDocument>(path)?;
    campaign.validate_against(target)?;
    Ok(campaign)
}

fn render_plan(target: &TargetDocument, campaign: &CampaignDocument) -> String {
    format!(
        "campaign_plan\ncampaign_id={}\ncampaign_version={}\ntarget_id={}\nenvironment={:?}\nprobe={:?}\ncandidate_url={}\nexpected_status={}\nexecution=NOT_STARTED",
        campaign.campaign_id,
        campaign.campaign_version,
        campaign.target_id,
        target.target.environment,
        campaign.probe.kind(),
        campaign.probe.candidate_url(),
        campaign.probe.expected_status()
    )
}

async fn execute_campaign(
    target: &TargetDocument,
    campaign: &CampaignDocument,
    kill_switches: &KillSwitchState,
    run_id: &str,
) -> Result<RunReport, CliError> {
    if run_id.trim().is_empty() {
        return Err(CliError::MissingRunId);
    }

    campaign.validate_against(&target)?;

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

const RUN_BUNDLE_SCHEMA_VERSION: u16 = 1;

#[derive(Debug, Serialize)]
struct RunBundleMetadata {
    schema_version: u16,
    run_id: String,
    campaign_id: String,
    campaign_version: u32,
    target_id: String,
    tool_version: String,
    source_commit: String,
    evidence_records: usize,
}

impl RunBundleMetadata {
    fn new(
        run_id: &str,
        target: &TargetDocument,
        campaign: &CampaignDocument,
        report: &RunReport,
    ) -> Self {
        Self {
            schema_version: RUN_BUNDLE_SCHEMA_VERSION,
            run_id: run_id.to_owned(),
            campaign_id: campaign.campaign_id.clone(),
            campaign_version: campaign.campaign_version,
            target_id: target.target.target_id.clone(),
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
    checksums: Vec<u8>,
}

fn source_commit() -> &'static str {
    match option_env!("GYLIBER_SOURCE_COMMIT") {
        Some(commit) => commit,
        None => "UNSPECIFIED",
    }
}

fn build_run_bundle(
    report: &RunReport,
    metadata: &RunBundleMetadata,
) -> Result<RunBundle, CliError> {
    report.verify()?;

    let mut report_json = serde_json::to_vec_pretty(report)?;
    report_json.push(b'\n');

    let mut report_text = report.render_human()?.into_bytes();
    if !report_text.ends_with(b"\n") {
        report_text.push(b'\n');
    }

    let mut run_json = serde_json::to_vec_pretty(metadata)?;
    run_json.push(b'\n');

    let checksums = format!(
        "{}  report.json\n{}  report.txt\n{}  run.json\n",
        content_sha256_hex(&report_json),
        content_sha256_hex(&report_text),
        content_sha256_hex(&run_json)
    )
    .into_bytes();

    Ok(RunBundle {
        report_json,
        report_text,
        run_json,
        checksums,
    })
}

fn write_run_bundle(
    path: &Path,
    report: &RunReport,
    metadata: &RunBundleMetadata,
) -> Result<(), CliError> {
    let bundle = build_run_bundle(report, metadata)?;
    fs::create_dir(path)?;

    write_new_file(&path.join("report.json"), &bundle.report_json)?;
    write_new_file(&path.join("report.txt"), &bundle.report_text)?;
    write_new_file(&path.join("run.json"), &bundle.run_json)?;
    write_new_file(&path.join("SHA256SUMS"), &bundle.checksums)?;
    Ok(())
}

fn write_new_file(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
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
    async fn fixture_triplet_proves_secure_vulnerable_and_fixed_states()
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
                execute_campaign(&target, &campaign, &kill_switches, &run_id).await?;

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
    fn run_bundle_manifest_covers_all_emitted_files() -> Result<(), Box<dyn Error>> {
        let evidence = EvidenceRecord::http_metadata(
            "fixture-local",
            "baseline-health-status",
            Verdict::Pass,
            204,
            204,
            Some(0),
            ["content-length".to_owned()],
        );
        let report = RunReport::new("run-bundle-test", vec![SealedEvidence::seal(evidence)?]);
        let target = test_target_document();
        let campaign = test_campaign(Url::parse("http://127.0.0.1/health")?, 204);
        let metadata = RunBundleMetadata::new("run-bundle-test", &target, &campaign, &report);
        let bundle = build_run_bundle(&report, &metadata)?;
        let manifest = String::from_utf8(bundle.checksums.clone())?;

        assert!(manifest.contains(&content_sha256_hex(&bundle.report_json)));
        assert!(manifest.contains(&content_sha256_hex(&bundle.report_text)));
        assert!(manifest.contains(&content_sha256_hex(&bundle.run_json)));
        assert!(manifest.contains("report.json"));
        assert!(manifest.contains("report.txt"));
        assert!(manifest.contains("run.json"));
        Ok(())
    }

    #[test]
    fn campaign_plan_is_non_executing_and_explicit() -> Result<(), Box<dyn Error>> {
        let campaign = test_campaign(Url::parse("http://127.0.0.1/health")?, 204);
        let plan = render_plan(&test_target_document(), &campaign);

        assert!(plan.contains("execution=NOT_STARTED"));
        assert!(plan.contains("probe=HttpHeadStatus"));
        assert!(plan.contains("expected_status=204"));
        Ok(())
    }
}
