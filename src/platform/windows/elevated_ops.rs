#![allow(unsafe_op_in_unsafe_fn)]

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::thread::sleep;
use std::time::{Duration, Instant};

use rand::random;

use crate::SandboxError;

use super::elevation::{self, ElevatedProcess};

const ELEVATED_HELPER_READY_TIMEOUT: Duration = Duration::from_secs(20);
const ELEVATED_HELPER_STOP_TIMEOUT_MS: u32 = 5_000;
const ELEVATED_HELPER_POLL_INTERVAL: Duration = Duration::from_millis(100);

const ELEVATED_OPS_HELPER_SCRIPT: &str = r#"
param(
    [Parameter(Mandatory=$true)][string]$Sid,
    [Parameter(Mandatory=$true)][string]$SpecFile,
    [Parameter(Mandatory=$true)][string]$StopFile,
    [Parameter(Mandatory=$true)][string]$ReadyFile,
    [Parameter(Mandatory=$true)][string]$Executable,
    [Parameter(Mandatory=$true)][string]$OutRule,
    [Parameter(Mandatory=$true)][string]$InRule,
    [Parameter(Mandatory=$true)][int]$BlockNetwork
)

$ErrorActionPreference = "Stop"

function Invoke-Icacls([string[]]$Arguments) {
    & icacls @Arguments | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "icacls failed with exit code ${LASTEXITCODE}: $($Arguments -join ' ')"
    }
}

function Invoke-Netsh([string[]]$Arguments) {
    & netsh @Arguments | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "netsh failed with exit code ${LASTEXITCODE}: $($Arguments -join ' ')"
    }
}

function Rule-Permission([string]$Kind, [bool]$IsDirectory) {
    switch ($Kind) {
        "ro" { return $(if ($IsDirectory) { "(OI)(CI)(RX)" } else { "(RX)" }) }
        "rw" { return $(if ($IsDirectory) { "(OI)(CI)(M)" } else { "(M)" }) }
        "dw" { return $(if ($IsDirectory) { "(OI)(CI)(W)" } else { "(W)" }) }
        "dn" { return $(if ($IsDirectory) { "(OI)(CI)(RX,W)" } else { "(RX,W)" }) }
        default { throw "unknown ACL rule kind: $Kind" }
    }
}

function Rule-AccessMode([string]$Kind) {
    switch ($Kind) {
        "ro" { return "/grant" }
        "rw" { return "/grant" }
        "dw" { return "/deny" }
        "dn" { return "/deny" }
        default { throw "unknown ACL rule kind: $Kind" }
    }
}

function Apply-Rule([string]$Kind, [string]$Path, [string]$SidValue) {
    if (-not (Test-Path -LiteralPath $Path)) {
        return
    }

    $isDir = Test-Path -LiteralPath $Path -PathType Container
    $mode = Rule-AccessMode -Kind $Kind
    $perm = Rule-Permission -Kind $Kind -IsDirectory $isDir
    Invoke-Icacls @($Path, $mode, "*${SidValue}:$perm", "/C")
}

function Remove-Rule([string]$Path, [string]$SidValue) {
    if (-not (Test-Path -LiteralPath $Path)) {
        return
    }

    & icacls $Path /remove:g "*${SidValue}" /C | Out-Null
    & icacls $Path /remove:d "*${SidValue}" /C | Out-Null
}

$entries = @()
if (Test-Path -LiteralPath $SpecFile) {
    $entries = Get-Content -LiteralPath $SpecFile -Encoding UTF8
}

$appliedPaths = New-Object System.Collections.Generic.List[string]
$firewallEnabled = $false

try {
    foreach ($line in $entries) {
        if ([string]::IsNullOrWhiteSpace($line)) {
            continue
        }

        $parts = $line.Split("`t", 2)
        if ($parts.Count -ne 2) {
            throw "invalid ACL spec line: $line"
        }

        $kind = $parts[0].Trim()
        $path = $parts[1]
        Apply-Rule -Kind $kind -Path $path -SidValue $Sid
        $appliedPaths.Add($path)
    }

    if ($BlockNetwork -ne 0) {
        Invoke-Netsh @("advfirewall", "firewall", "add", "rule", "name=$OutRule", "dir=out", "action=block", "program=$Executable", "enable=yes", "profile=any")
        Invoke-Netsh @("advfirewall", "firewall", "add", "rule", "name=$InRule", "dir=in", "action=block", "program=$Executable", "enable=yes", "profile=any")
        $firewallEnabled = $true
    }

    Set-Content -LiteralPath $ReadyFile -Value "ok" -NoNewline -Encoding ascii

    while (-not (Test-Path -LiteralPath $StopFile)) {
        Start-Sleep -Milliseconds 200
    }
}
catch {
    Set-Content -LiteralPath $ReadyFile -Value ("error:" + $_.Exception.Message) -NoNewline -Encoding utf8
    exit 1
}
finally {
    for ($i = $appliedPaths.Count - 1; $i -ge 0; $i--) {
        Remove-Rule -Path $appliedPaths[$i] -SidValue $Sid
    }

    if ($firewallEnabled) {
        & netsh advfirewall firewall delete rule name="$OutRule" program="$Executable" | Out-Null
        & netsh advfirewall firewall delete rule name="$InRule" program="$Executable" | Out-Null
    }
}
"#;

#[derive(Debug, Clone)]
pub(super) struct ElevatedOpsSpec {
    pub(super) sid_string: String,
    pub(super) executable: PathBuf,
    pub(super) block_network: bool,
    pub(super) allow_readonly_paths: Vec<PathBuf>,
    pub(super) allow_readwrite_paths: Vec<PathBuf>,
    pub(super) deny_write_paths: Vec<PathBuf>,
    pub(super) deny_readwrite_paths: Vec<PathBuf>,
}

pub(super) struct ElevatedOpsGuard {
    process: ElevatedProcess,
    workspace_dir: PathBuf,
    stop_file: PathBuf,
    ready_file: PathBuf,
}

impl ElevatedOpsGuard {
    pub(super) fn spawn(spec: &ElevatedOpsSpec) -> Result<Self, SandboxError> {
        let workspace_dir = create_elevated_workspace_dir()?;
        let script_path = workspace_dir.join("elevated-ops-helper.ps1");
        let spec_path = workspace_dir.join("acl-spec.tsv");
        let stop_file = workspace_dir.join("stop.signal");
        let ready_file = workspace_dir.join("ready.signal");
        let rule_prefix = format!(
            "procwarden-elevated-all-{}-{}",
            std::process::id(),
            random::<u32>()
        );
        let out_rule_name = format!("{rule_prefix}-out");
        let in_rule_name = format!("{rule_prefix}-in");

        if let Err(error) = fs::write(&script_path, ELEVATED_OPS_HELPER_SCRIPT) {
            let _ = fs::remove_dir_all(&workspace_dir);
            return Err(SandboxError::Io(error));
        }

        if let Err(error) = fs::write(&spec_path, serialize_acl_spec(spec)) {
            let _ = fs::remove_dir_all(&workspace_dir);
            return Err(SandboxError::Io(error));
        }

        let _ = fs::remove_file(&ready_file);

        let powershell_exe = powershell_executable_path();
        let parameters = elevated_powershell_parameters(
            &script_path,
            &spec_path,
            &stop_file,
            &ready_file,
            &spec.executable,
            &out_rule_name,
            &in_rule_name,
            &spec.sid_string,
            spec.block_network,
        );

        let process = match ElevatedProcess::shell_execute_runas(&powershell_exe, &parameters) {
            Ok(value) => value,
            Err(error) => {
                let _ = fs::remove_dir_all(&workspace_dir);
                return Err(error);
            }
        };

        let guard = Self {
            process,
            workspace_dir,
            stop_file,
            ready_file,
        };
        guard.wait_until_initialized()?;
        Ok(guard)
    }

    fn wait_until_initialized(&self) -> Result<(), SandboxError> {
        let started = Instant::now();
        loop {
            match read_ready_signal(&self.ready_file)? {
                ReadySignal::Pending => {}
                ReadySignal::Ok => return Ok(()),
                ReadySignal::Error(message) => {
                    return Err(SandboxError::Denied(format!(
                        "automatic administrator elevated-ops initialization failed: {message}"
                    )));
                }
            }

            if let Some(exit_code) = self.process.try_wait_exit_code(0)? {
                return Err(SandboxError::Denied(format!(
                    "automatic administrator elevated-ops helper exited before initialization (exit code {exit_code}, workspace: {})",
                    self.workspace_dir.display()
                )));
            }

            if started.elapsed() >= ELEVATED_HELPER_READY_TIMEOUT {
                return Err(SandboxError::Denied(format!(
                    "automatic administrator elevated-ops helper timed out before readiness (workspace: {})",
                    self.workspace_dir.display()
                )));
            }

            sleep(ELEVATED_HELPER_POLL_INTERVAL);
        }
    }
}

impl Drop for ElevatedOpsGuard {
    fn drop(&mut self) {
        let _ = fs::write(&self.stop_file, b"stop");

        match self
            .process
            .try_wait_exit_code(ELEVATED_HELPER_STOP_TIMEOUT_MS)
        {
            Ok(Some(_)) => {}
            Ok(None) => {
                self.process.terminate(1);
                let _ = self
                    .process
                    .try_wait_exit_code(ELEVATED_HELPER_STOP_TIMEOUT_MS);
            }
            Err(_) => {
                self.process.terminate(1);
            }
        }

        let _ = fs::remove_dir_all(&self.workspace_dir);
    }
}

#[allow(clippy::too_many_arguments)]
fn elevated_powershell_parameters(
    script_path: &Path,
    spec_path: &Path,
    stop_file: &Path,
    ready_file: &Path,
    executable: &Path,
    out_rule_name: &str,
    in_rule_name: &str,
    sid_string: &str,
    block_network: bool,
) -> String {
    format!(
        "-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File {} -Sid {} -SpecFile {} -StopFile {} -ReadyFile {} -Executable {} -OutRule {} -InRule {} -BlockNetwork {}",
        elevation::quote_windows_arg(&script_path.to_string_lossy()),
        elevation::quote_windows_arg(sid_string),
        elevation::quote_windows_arg(&spec_path.to_string_lossy()),
        elevation::quote_windows_arg(&stop_file.to_string_lossy()),
        elevation::quote_windows_arg(&ready_file.to_string_lossy()),
        elevation::quote_windows_arg(&executable.to_string_lossy()),
        elevation::quote_windows_arg(out_rule_name),
        elevation::quote_windows_arg(in_rule_name),
        if block_network { "1" } else { "0" },
    )
}

fn serialize_acl_spec(spec: &ElevatedOpsSpec) -> String {
    let mut lines = Vec::new();

    for path in &spec.deny_readwrite_paths {
        lines.push(format!("dn\t{}", path.to_string_lossy()));
    }
    for path in &spec.deny_write_paths {
        lines.push(format!("dw\t{}", path.to_string_lossy()));
    }
    for path in &spec.allow_readonly_paths {
        lines.push(format!("ro\t{}", path.to_string_lossy()));
    }
    for path in &spec.allow_readwrite_paths {
        lines.push(format!("rw\t{}", path.to_string_lossy()));
    }

    if lines.is_empty() {
        String::new()
    } else {
        format!("{}\n", lines.join("\n"))
    }
}

fn create_elevated_workspace_dir() -> Result<PathBuf, SandboxError> {
    let path = std::env::temp_dir().join(format!(
        "procwarden-elevated-ops-{}-{}",
        std::process::id(),
        random::<u32>()
    ));
    fs::create_dir_all(&path).map_err(SandboxError::Io)?;
    Ok(path)
}

fn powershell_executable_path() -> String {
    let windir = std::env::var("WINDIR").unwrap_or_else(|_| "C:\\Windows".to_string());
    Path::new(&windir)
        .join("System32")
        .join("WindowsPowerShell")
        .join("v1.0")
        .join("powershell.exe")
        .to_string_lossy()
        .to_string()
}

enum ReadySignal {
    Pending,
    Ok,
    Error(String),
}

fn read_ready_signal(path: &Path) -> Result<ReadySignal, SandboxError> {
    match fs::read_to_string(path) {
        Ok(contents) => {
            let normalized = contents.trim();
            if normalized.is_empty() {
                return Ok(ReadySignal::Pending);
            }
            if normalized.eq_ignore_ascii_case("ok") {
                return Ok(ReadySignal::Ok);
            }
            if let Some(error) = normalized.strip_prefix("error:") {
                return Ok(ReadySignal::Error(error.trim().to_string()));
            }
            Ok(ReadySignal::Error(normalized.to_string()))
        }
        Err(error)
            if matches!(
                error.kind(),
                ErrorKind::NotFound | ErrorKind::PermissionDenied
            ) || error.raw_os_error() == Some(32) =>
        {
            Ok(ReadySignal::Pending)
        }
        Err(error) => Err(SandboxError::Io(error)),
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{ELEVATED_OPS_HELPER_SCRIPT, ElevatedOpsSpec, serialize_acl_spec};

    #[test]
    fn serialize_acl_spec_preserves_priority_order() {
        let spec = ElevatedOpsSpec {
            sid_string: "S-1-15-2-1234".to_string(),
            executable: PathBuf::from(r"C:\tool.exe"),
            block_network: true,
            allow_readonly_paths: vec![PathBuf::from(r"C:\ro")],
            allow_readwrite_paths: vec![PathBuf::from(r"C:\rw")],
            deny_write_paths: vec![PathBuf::from(r"C:\dw")],
            deny_readwrite_paths: vec![PathBuf::from(r"C:\dn")],
        };

        let rendered = serialize_acl_spec(&spec);
        let lines = rendered.lines().collect::<Vec<_>>();
        assert_eq!(
            lines,
            vec![r"dn	C:\dn", r"dw	C:\dw", r"ro	C:\ro", r"rw	C:\rw"]
        );
    }

    #[test]
    fn serialize_acl_spec_empty_plan_is_empty_string() {
        let spec = ElevatedOpsSpec {
            sid_string: "S-1-15-2-1234".to_string(),
            executable: PathBuf::from(r"C:\tool.exe"),
            block_network: false,
            allow_readonly_paths: Vec::new(),
            allow_readwrite_paths: Vec::new(),
            deny_write_paths: Vec::new(),
            deny_readwrite_paths: Vec::new(),
        };

        assert!(serialize_acl_spec(&spec).is_empty());
    }

    #[test]
    fn helper_script_uses_deny_mode_for_deny_kinds() {
        assert!(ELEVATED_OPS_HELPER_SCRIPT.contains(r#""dw" { return "/deny" }"#));
        assert!(ELEVATED_OPS_HELPER_SCRIPT.contains(r#""dn" { return "/deny" }"#));
        assert!(ELEVATED_OPS_HELPER_SCRIPT.contains("Invoke-Icacls @($Path, $mode,"));
    }
}
