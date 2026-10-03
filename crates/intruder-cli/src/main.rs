use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use clap::{Parser, Subcommand};
use intruder_core::{BudgetTracker, KillSwitchState, Verdict};
use intruder_evidence::{EvidenceError, EvidenceRecord, SealedEvidence};
use intruder_net::{ExecutionGate, HttpExecutor, HttpProbeError};
use intruder_policy::{PolicyError, Target};
use intruder_report::RunReport;
use serde::Deserialize;
use thiserror::Error;
use url::Url;

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
    /// Execute one bounded v0.1.0 baseline probe from a strict JSON specification.
    BaselineRun {
        /// Path to the strict baseline execution specification.
        #[arg(long)]
        spec: PathBuf,
        /// New JSON report path. Existing files are never overwritten.
        #[arg(long)]
        json_out: PathBuf,
    },
    /// Show the default unresolved global kill-switch posture.
    KillSwitchStatus,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BaselineRunSpec {
    run_id: String,
    campaign_id: String,
    test_case_id: String,
    expected_status: u16,
    candidate_url: Url,
    target: Target,
    kill_switches: KillSwitchState,
}

#[derive(Debug, Error)]
enum CliError {
    #[error("I/O operation failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON processing failed: {0}")]
    Json(#[from] serde_json::Error),
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
        Command::BaselineRun { spec, json_out } => {
            let spec = load_spec(&spec)?;
            let report = execute_baseline(spec).await?;
            write_json_report(&json_out, &report)?;
            print!("{}", report.render_human()?);
        }
        Command::KillSwitchStatus => {
            println!("global kill switch: SAFE_DEFAULT_STOP");
        }
    }

    Ok(())
}

fn load_spec(path: &Path) -> Result<BaselineRunSpec, CliError> {
    let bytes = fs::read(path)?;
    Ok(serde_json::from_slice(&bytes)?)
}

async fn execute_baseline(spec: BaselineRunSpec) -> Result<RunReport, CliError> {
    spec.target.validate()?;

    let mut budget = BudgetTracker::new(spec.target.budget.clone())?;
    let mut gate = ExecutionGate::new(
        &spec.target,
        &spec.campaign_id,
        &spec.kill_switches,
        &mut budget,
    );

    let metadata = HttpExecutor::new()
        .probe_head(&mut gate, &spec.candidate_url)
        .await?;

    let verdict = if metadata.status_code == spec.expected_status {
        Verdict::Pass
    } else {
        Verdict::Fail
    };

    let evidence = EvidenceRecord::http_metadata(
        spec.target.target_id,
        spec.test_case_id,
        verdict,
        spec.expected_status,
        metadata.status_code,
        metadata.content_length,
        metadata.header_names,
    );
    let sealed = SealedEvidence::seal(evidence)?;
    sealed.verify()?;

    let report = RunReport::new(spec.run_id, vec![sealed]);
    report.verify()?;
    Ok(report)
}

fn write_json_report(path: &Path, report: &RunReport) -> Result<(), CliError> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    serde_json::to_writer_pretty(&mut file, report)?;
    file.write_all(b"\n")?;
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

    use super::*;

    fn test_spec(candidate_url: Url, expected_status: u16) -> BaselineRunSpec {
        BaselineRunSpec {
            run_id: "run-cli-baseline".to_owned(),
            campaign_id: "baseline".to_owned(),
            test_case_id: "baseline-health".to_owned(),
            expected_status,
            candidate_url,
            target: Target {
                target_id: "fixture-local".to_owned(),
                environment: Environment::Lab,
                allowed_hosts: vec!["127.0.0.1".to_owned()],
                allowed_schemes: vec!["http".to_owned()],
                allowed_path_prefixes: vec!["/health".to_owned()],
                allow_private_networks: true,
                budget: SafetyBudget::production_baseline(),
            },
            kill_switches: KillSwitchState::default(),
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

    #[tokio::test]
    async fn baseline_loop_emits_verified_pass_evidence() -> Result<(), Box<dyn Error>> {
        let FixtureServer { url, handle } = spawn_fixture(204)?;
        let report = execute_baseline(test_spec(url, 204)).await?;

        assert_eq!(report.evidence().len(), 1);
        assert_eq!(report.evidence()[0].record().verdict(), Verdict::Pass);
        report.verify()?;
        join_fixture(handle)
    }

    #[tokio::test]
    async fn baseline_loop_preserves_fail_verdict() -> Result<(), Box<dyn Error>> {
        let FixtureServer { url, handle } = spawn_fixture(500)?;
        let report = execute_baseline(test_spec(url, 204)).await?;

        assert_eq!(report.evidence().len(), 1);
        assert_eq!(report.evidence()[0].record().verdict(), Verdict::Fail);
        report.verify()?;
        join_fixture(handle)
    }
}
