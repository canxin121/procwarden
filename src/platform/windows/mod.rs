mod acl;
mod appcontainer;
mod audit;
mod env;
mod process;
mod token;
mod util;

use std::path::Path;
use std::process::Command;
use std::time::Instant;

use crate::{
    ChildProcessCoverage, EnforcementReport, EnforcementStrength, PathInterceptionStats,
    SandboxCommandRequest, SandboxError, SandboxExecOutput, SandboxPolicy,
};

use super::command_runner::{configure_piped_stdio, run_command_with_timeout};

pub(super) fn execute(
    request: &SandboxCommandRequest,
    policy: &SandboxPolicy,
    workspace_root: &Path,
) -> Result<SandboxExecOutput, SandboxError> {
    if policy.is_danger_full_access() {
        return execute_without_sandbox(request);
    }

    let mut env_map = request.env.clone();
    util::normalize_null_device_env(&mut env_map);
    util::ensure_non_interactive_pager(&mut env_map);

    if !policy.has_full_network_access() {
        env::apply_no_network_hardening(&mut env_map)?;
    }

    appcontainer::execute(request, policy, workspace_root, &env_map)
}

fn execute_without_sandbox(
    request: &SandboxCommandRequest,
) -> Result<SandboxExecOutput, SandboxError> {
    execute_without_sandbox_with_env(request, &request.env)
}

fn execute_without_sandbox_with_env(
    request: &SandboxCommandRequest,
    env_map: &std::collections::HashMap<String, String>,
) -> Result<SandboxExecOutput, SandboxError> {
    let start = Instant::now();

    let mut command = Command::new(&request.command[0]);
    if request.command.len() > 1 {
        command.args(&request.command[1..]);
    }

    command
        .current_dir(&request.cwd)
        .env_clear()
        .envs(env_map.clone());
    configure_piped_stdio(&mut command);

    let enforcement = EnforcementReport {
        backend: "windows-unsandboxed".to_string(),
        requested_read_allowlist: false,
        requested_write_allowlist: false,
        effective_read_enforcement: EnforcementStrength::None,
        effective_write_enforcement: EnforcementStrength::None,
        read_allowlist_enforced: false,
        write_allowlist_enforced: false,
        network_restricted: false,
        child_process_coverage: ChildProcessCoverage::None,
        path_interception: PathInterceptionStats::default(),
        degraded_reason_codes: Vec::new(),
        degraded_reasons: Vec::new(),
    };

    run_command_with_timeout(&mut command, request.timeout_ms, start, enforcement)
}
