use std::path::Path;
use std::process::Command;
use std::time::Instant;

use crate::{
    ChildProcessCoverage, DegradeReasonCode, EnforcementReport, EnforcementStrength,
    PathInterceptionStats, SandboxCommandRequest, SandboxError, SandboxExecOutput, SandboxPolicy,
};

use super::command_runner::{configure_piped_stdio, run_command_with_timeout};

pub(super) fn execute(
    request: &SandboxCommandRequest,
    policy: &SandboxPolicy,
    _workspace_root: &Path,
) -> Result<SandboxExecOutput, SandboxError> {
    if !policy.is_danger_full_access() {
        return Err(SandboxError::Unavailable(format!(
            "OS-level sandboxing is unavailable on target '{}'. Supported adapters currently cover windows/linux/macos. On this platform, use danger-full-access explicitly or implement a platform adapter.",
            std::env::consts::OS
        )));
    }

    let start = Instant::now();
    let mut command = Command::new(&request.command[0]);
    if request.command.len() > 1 {
        command.args(&request.command[1..]);
    }
    command
        .current_dir(&request.cwd)
        .env_clear()
        .envs(request.env.clone());
    configure_piped_stdio(&mut command);

    let enforcement = EnforcementReport {
        backend: format!("fallback-{}", std::env::consts::OS),
        requested_read_allowlist: policy.requested_read_enforcement(),
        requested_write_allowlist: policy.requested_write_enforcement(),
        effective_read_enforcement: EnforcementStrength::None,
        effective_write_enforcement: EnforcementStrength::None,
        read_allowlist_enforced: false,
        write_allowlist_enforced: false,
        network_restricted: !policy.has_full_network_access(),
        child_process_coverage: ChildProcessCoverage::None,
        path_interception: PathInterceptionStats::default(),
        degraded_reason_codes: vec![DegradeReasonCode::OsSandboxUnavailable],
        degraded_reasons: vec!["os-sandbox-unavailable-best-effort-only".to_string()],
    };

    run_command_with_timeout(&mut command, request.timeout_ms, start, enforcement)
}
