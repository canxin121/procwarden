use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnforcementStrength {
    None,
    BestEffort,
    Strong,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DegradeReasonCode {
    OsSandboxUnavailable,
    WindowsLoopbackExemptionDetected,
    WindowsLoopbackExemptionCheckFailed,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PathInterceptionStats {
    pub allow_paths_checked: u32,
    pub deny_paths_checked: u32,
    pub dangerous_namespace_blocks: u32,
    pub unc_blocks: u32,
    pub reparse_blocks: u32,
    pub symlink_blocks: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnforcementReport {
    pub backend: String,
    pub requested_read_allowlist: bool,
    pub requested_write_allowlist: bool,
    pub effective_read_enforcement: EnforcementStrength,
    pub effective_write_enforcement: EnforcementStrength,
    pub read_allowlist_enforced: bool,
    pub write_allowlist_enforced: bool,
    pub network_restricted: bool,
    pub effective_network_enforcement: EnforcementStrength,
    pub path_interception: PathInterceptionStats,
    pub degraded_reason_codes: Vec<DegradeReasonCode>,
    pub degraded_reasons: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxExecOutput {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub aggregated_output: String,
    pub duration: Duration,
    pub timed_out: bool,
    pub enforcement: EnforcementReport,
}
