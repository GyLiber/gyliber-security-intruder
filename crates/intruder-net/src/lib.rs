//! Non-bypassable production networking boundary.
//!
//! All future production outbound HTTP execution must pass through the execution
//! gate before opening a socket. The gate combines target authorization,
//! kill-switch evaluation, and central budget reservation.

use std::{
    net::IpAddr,
    time::Duration,
};

use intruder_core::{BudgetTracker, CoreError, KillSwitchState};
use intruder_policy::{PolicyError, Target};
use reqwest::{redirect::Policy as RedirectPolicy, retry, tls::Version as TlsVersion};
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
    /// Returns `TargetGateError` when the candidate is outside the enrolled
    /// target boundary or the target definition itself is invalid.
    pub fn authorize(&self, candidate: &Url) -> Result<(), TargetGateError> {
        self.target.authorize_url(candidate)?;
        Ok(())
    }

    /// Apply the target network policy to one resolved destination address.
    ///
    /// # Errors
    ///
    /// Returns `TargetGateError` when the address is outside the enrolled
    /// target's permitted network class.
    pub fn authorize_resolved_ip(&self, address: IpAddr) -> Result<(), TargetGateError> {
        self.target.authorize_resolved_ip(address)?;
        Ok(())
    }
}

/// Composite execution boundary used before any outbound request.
///
/// A request permit is issued only after the target, kill-switch snapshot, and
/// budget all authorize the operation.
#[derive(Debug)]
pub struct ExecutionGate<'a> {
    target: &'a Target,
    campaign_id: &'a str,
    kill_switches: &'a KillSwitchState,
    budget: &'a mut BudgetTracker,
}

impl<'a> ExecutionGate<'a> {
    #[must_use]
    pub fn new(
        target: &'a Target,
        campaign_id: &'a str,
        kill_switches: &'a KillSwitchState,
        budget: &'a mut BudgetTracker,
    ) -> Self {
        Self {
            target,
            campaign_id,
            kill_switches,
            budget,
        }
    }

    /// Authorize and reserve capacity for one outbound request.
    ///
    /// # Errors
    ///
    /// Returns `ExecutionGateError` when execution is stopped, the URL is outside
    /// target policy, or request capacity is exhausted.
    pub fn begin_request(
        &mut self,
        candidate: &Url,
    ) -> Result<RequestPermit<'_>, ExecutionGateError> {
        if self.budget.budget() != &self.target.budget {
            return Err(ExecutionGateError::BudgetPolicyMismatch);
        }

        self.kill_switches
            .authorize(&self.target.target_id, self.campaign_id)?;
        TargetGate::new(self.target).authorize(candidate)?;
        self.budget.try_start_request()?;

        Ok(RequestPermit {
            target: self.target,
            budget: self.budget,
            finished: false,
        })
    }
}

/// In-flight request reservation.
///
/// Dropping a permit automatically releases the concurrent-request slot. Total
/// request consumption remains counted, because capacity was reserved for the
/// attempted request.
#[derive(Debug)]
pub struct RequestPermit<'a> {
    target: &'a Target,
    budget: &'a mut BudgetTracker,
    finished: bool,
}

impl RequestPermit<'_> {
    /// Re-authorize each resolved address before a connection is opened.
    ///
    /// # Errors
    ///
    /// Returns `TargetGateError` when DNS resolution yields a destination outside
    /// the target's permitted network class.
    pub fn authorize_resolved_ip(&self, address: IpAddr) -> Result<(), TargetGateError> {
        TargetGate::new(self.target).authorize_resolved_ip(address)
    }

    /// Release the concurrent-request slot explicitly.
    pub fn finish(mut self) {
        self.release();
    }

    fn release(&mut self) {
        if !self.finished {
            self.budget.finish_request();
            self.finished = true;
        }
    }
}

impl Drop for RequestPermit<'_> {
    fn drop(&mut self) {
        self.release();
    }
}

/// Metadata-only result from the bounded v0.1.0 HTTP probe.
///
/// Header values and response bodies are intentionally excluded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpMetadata {
    pub status_code: u16,
    pub content_length: Option<u64>,
    pub header_names: Vec<String>,
}

/// First real network executor.
///
/// v0.1.0 deliberately restricts execution to enrolled IP-literal destinations.
/// Hostname execution is added only after DNS resolution can be bound to the
/// same resolved-address authorization gate.
#[derive(Debug, Default)]
pub struct HttpExecutor;

impl HttpExecutor {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Execute one bounded metadata-only HEAD probe.
    ///
    /// Automatic redirects, retries, proxy inheritance, response-body reads,
    /// and hostname resolution are disabled for this initial transport.
    ///
    /// # Errors
    ///
    /// Returns HttpProbeError when the candidate is not IP-literal, execution
    /// policy denies the request, the resolved address is forbidden, or the
    /// HTTP client cannot complete the request.
    pub async fn probe_head(
        &self,
        gate: &mut ExecutionGate<'_>,
        candidate: &Url,
    ) -> Result<HttpMetadata, HttpProbeError> {
        let address = match candidate.host() {
            Some(url::Host::Ipv4(address)) => IpAddr::V4(address),
            Some(url::Host::Ipv6(address)) => IpAddr::V6(address),
            Some(url::Host::Domain(host)) => {
                return Err(HttpProbeError::HostnameNotArmed(host.to_owned()));
            }
            None => return Err(HttpProbeError::MissingHost),
        };

        let permit = gate.begin_request(candidate)?;
        permit.authorize_resolved_ip(address)?;

        let timeout = Duration::from_secs(permit.target.budget.max_execution_seconds);
        let connect_timeout = timeout.min(Duration::from_secs(10));
        let client = reqwest::Client::builder()
            .redirect(RedirectPolicy::none())
            .retry(retry::never())
            .referer(false)
            .no_proxy()
            .tls_version_min(TlsVersion::TLS_1_2)
            .timeout(timeout)
            .connect_timeout(connect_timeout)
            .user_agent(concat!(
                "GyLiber-Security-Intruder/",
                env!("CARGO_PKG_VERSION")
            ))
            .build()?;

        let response = client.head(candidate.clone()).send().await?;
        let mut header_names = response
            .headers()
            .keys()
            .map(|name| name.as_str().to_owned())
            .collect::<Vec<_>>();
        header_names.sort_unstable();

        let metadata = HttpMetadata {
            status_code: response.status().as_u16(),
            content_length: response.content_length(),
            header_names,
        };

        drop(response);
        permit.finish();
        Ok(metadata)
    }
}

#[derive(Debug, Error)]
pub enum HttpProbeError {
    #[error("HTTP target has no host")]
    MissingHost,
    #[error("hostname execution is not armed in v0.1.0: {0}")]
    HostnameNotArmed(String),
    #[error(transparent)]
    Execution(#[from] ExecutionGateError),
    #[error(transparent)]
    Target(#[from] TargetGateError),
    #[error("HTTP transport failed: {0}")]
    Transport(#[from] reqwest::Error),
}

#[derive(Debug, Error)]
pub enum TargetGateError {
    #[error(transparent)]
    Policy(#[from] PolicyError),
}

#[derive(Debug, Error)]
pub enum ExecutionGateError {
    #[error("execution budget does not match the enrolled target policy")]
    BudgetPolicyMismatch,
    #[error(transparent)]
    Core(#[from] CoreError),
    #[error(transparent)]
    Target(#[from] TargetGateError),
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Read, Write},
        net::TcpListener,
        thread,
    };

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


    #[tokio::test]
    async fn metadata_probe_reaches_authorized_ip_fixture() -> Result<(), Box<dyn std::error::Error>>
    {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        let fixture = thread::spawn(move || -> std::io::Result<()> {
            let (mut stream, _) = listener.accept()?;
            stream.set_read_timeout(Some(Duration::from_secs(5)))?;

            let mut request = [0_u8; 1024];
            let read = stream.read(&mut request)?;
            if !request[..read].starts_with(b"HEAD /health HTTP/1.1") {
                return Err(std::io::Error::other("fixture received a non-HEAD request"));
            }

            stream.write_all(
                b"HTTP/1.1 204 No Content\r\nX-GyLiber-Fixture: secure\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            )?;
            stream.flush()
        });

        let target = Target {
            target_id: "fixture-http".to_owned(),
            environment: Environment::Lab,
            allowed_hosts: vec!["127.0.0.1".to_owned()],
            allowed_schemes: vec!["http".to_owned()],
            allowed_path_prefixes: vec!["/health".to_owned()],
            allow_private_networks: true,
            budget: SafetyBudget::production_baseline(),
        };
        let mut budget = BudgetTracker::new(target.budget.clone())?;
        let switches = KillSwitchState::default();
        let candidate = Url::parse(&format!("http://{address}/health"))?;
        let mut gate = ExecutionGate::new(&target, "baseline", &switches, &mut budget);

        let metadata = HttpExecutor::new()
            .probe_head(&mut gate, &candidate)
            .await?;

        fixture
            .join()
            .map_err(|_| std::io::Error::other("fixture thread panicked"))??;

        assert_eq!(metadata.status_code, 204);
        assert!(metadata
            .header_names
            .iter()
            .any(|name| name == "x-gyliber-fixture"));
        assert_eq!(budget.total_requests(), 1);
        assert_eq!(budget.concurrent_requests(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn metadata_probe_does_not_follow_redirects() -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        let fixture = thread::spawn(move || -> std::io::Result<()> {
            let (mut stream, _) = listener.accept()?;
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request)?;
            stream.write_all(
                b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:9/denied\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            )?;
            stream.flush()
        });

        let target = Target {
            target_id: "fixture-redirect".to_owned(),
            environment: Environment::Lab,
            allowed_hosts: vec!["127.0.0.1".to_owned()],
            allowed_schemes: vec!["http".to_owned()],
            allowed_path_prefixes: vec!["/redirect".to_owned()],
            allow_private_networks: true,
            budget: SafetyBudget::production_baseline(),
        };
        let mut budget = BudgetTracker::new(target.budget.clone())?;
        let switches = KillSwitchState::default();
        let candidate = Url::parse(&format!("http://{address}/redirect"))?;
        let mut gate = ExecutionGate::new(&target, "baseline", &switches, &mut budget);

        let metadata = HttpExecutor::new()
            .probe_head(&mut gate, &candidate)
            .await?;

        fixture
            .join()
            .map_err(|_| std::io::Error::other("fixture thread panicked"))??;

        assert_eq!(metadata.status_code, 302);
        assert_eq!(budget.total_requests(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn metadata_probe_refuses_hostname_execution_before_network()
    -> Result<(), Box<dyn std::error::Error>> {
        let target = target(Environment::Lab, true);
        let mut budget = BudgetTracker::new(target.budget.clone())?;
        let switches = KillSwitchState::default();
        let candidate = Url::parse("http://localhost/")?;
        let mut gate = ExecutionGate::new(&target, "baseline", &switches, &mut budget);

        assert!(matches!(
            HttpExecutor::new().probe_head(&mut gate, &candidate).await,
            Err(HttpProbeError::HostnameNotArmed(host)) if host == "localhost"
        ));
        assert_eq!(budget.total_requests(), 0);
        Ok(())
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

    #[test]
    fn execution_gate_rejects_mismatched_budget() -> Result<(), Box<dyn std::error::Error>> {
        let target = target(Environment::Lab, true);
        let looser_budget = SafetyBudget {
            max_total_requests: target.budget.max_total_requests + 1,
            ..target.budget.clone()
        };
        let mut budget = BudgetTracker::new(looser_budget)?;
        let switches = KillSwitchState::default();
        let candidate = Url::parse("http://localhost/")?;

        let mut gate = ExecutionGate::new(&target, "baseline", &switches, &mut budget);
        assert!(matches!(
            gate.begin_request(&candidate),
            Err(ExecutionGateError::BudgetPolicyMismatch)
        ));
        assert_eq!(budget.total_requests(), 0);
        Ok(())
    }

    #[test]
    fn execution_gate_stops_before_budget_on_global_kill() -> Result<(), Box<dyn std::error::Error>>
    {
        let target = target(Environment::Lab, true);
        let mut budget = BudgetTracker::new(target.budget.clone())?;
        let switches = KillSwitchState {
            global_active: true,
            ..KillSwitchState::default()
        };
        let candidate = Url::parse("http://localhost/")?;

        let mut gate = ExecutionGate::new(&target, "baseline", &switches, &mut budget);
        assert!(matches!(
            gate.begin_request(&candidate),
            Err(ExecutionGateError::Core(CoreError::GlobalKillSwitchActive))
        ));
        assert_eq!(budget.total_requests(), 0);
        Ok(())
    }

    #[test]
    fn execution_gate_rejects_url_before_budget_reservation()
    -> Result<(), Box<dyn std::error::Error>> {
        let target = target(Environment::Lab, true);
        let mut budget = BudgetTracker::new(target.budget.clone())?;
        let switches = KillSwitchState::default();
        let candidate = Url::parse("http://example.com/")?;

        let mut gate = ExecutionGate::new(&target, "baseline", &switches, &mut budget);
        assert!(matches!(
            gate.begin_request(&candidate),
            Err(ExecutionGateError::Target(_))
        ));
        assert_eq!(budget.total_requests(), 0);
        Ok(())
    }

    #[test]
    fn permit_releases_concurrency_on_drop() -> Result<(), Box<dyn std::error::Error>> {
        let mut target = target(Environment::Lab, true);
        target.budget.max_concurrent_requests = 1;
        let mut budget = BudgetTracker::new(target.budget.clone())?;
        let switches = KillSwitchState::default();
        let candidate = Url::parse("http://localhost/")?;

        {
            let mut gate = ExecutionGate::new(&target, "baseline", &switches, &mut budget);
            let permit = gate.begin_request(&candidate)?;
            permit.authorize_resolved_ip("127.0.0.1".parse()?)?;
        }

        assert_eq!(budget.total_requests(), 1);
        assert_eq!(budget.concurrent_requests(), 0);
        Ok(())
    }

    #[test]
    fn permit_blocks_forbidden_resolution() -> Result<(), Box<dyn std::error::Error>> {
        let target = target(Environment::Production, false);
        let mut budget = BudgetTracker::new(target.budget.clone())?;
        let switches = KillSwitchState::default();
        let candidate = Url::parse("http://localhost/")?;

        let mut gate = ExecutionGate::new(&target, "baseline", &switches, &mut budget);
        let permit = gate.begin_request(&candidate)?;
        assert!(permit.authorize_resolved_ip("127.0.0.1".parse()?).is_err());
        Ok(())
    }
}
