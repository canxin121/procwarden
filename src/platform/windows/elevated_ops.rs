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
const LOOPBACK_SERVER_READY_TIMEOUT: Duration = Duration::from_secs(5);
const FIREWALL_RULE_PREFIX: &str = "procwarden-elevated-all";

const ELEVATED_OPS_HELPER_SCRIPT: &str = r#"
param(
    [Parameter(Mandatory=$true)][string]$Sid,
    [Parameter(Mandatory=$true)][string]$AppContainerName,
    [Parameter(Mandatory=$true)][string]$SpecFile,
    [Parameter(Mandatory=$true)][string]$StopFile,
    [Parameter(Mandatory=$true)][string]$ReadyFile,
    [Parameter(Mandatory=$true)][string]$ProgressFile,
    [Parameter(Mandatory=$true)][string]$LoopbackServerStartFile,
    [Parameter(Mandatory=$true)][string]$LoopbackServerReadyFile,
    [Parameter(Mandatory=$true)][int]$ParentPid,
    [Parameter(Mandatory=$true)][string]$Executable,
    [Parameter(Mandatory=$true)][string]$OutRule,
    [Parameter(Mandatory=$true)][string]$InRule,
    [Parameter(Mandatory=$true)][int]$NetworkRuleMode
)

$ErrorActionPreference = "Stop"

function Invoke-Icacls([string[]]$Arguments) {
    & icacls @Arguments 2>$null | Out-Null
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

function Apply-FirewallRule([string]$Direction, [string]$Action) {
    Invoke-Netsh @("advfirewall", "firewall", "add", "rule", "name=$(if ($Direction -eq 'out') { $OutRule } else { $InRule })", "dir=$Direction", "action=$Action", "program=$Executable", "enable=yes", "profile=any")
}

function Set-LoopbackExemption([string]$Operation, [string]$SidValue) {
    & CheckNetIsolation.exe LoopbackExempt $Operation "-p=$SidValue" | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "CheckNetIsolation LoopbackExempt $Operation failed with exit code ${LASTEXITCODE}"
    }
}

function Start-LoopbackServerExemption([string]$SidValue) {
    $process = Start-Process -FilePath "CheckNetIsolation.exe" -ArgumentList @("LoopbackExempt", "-is", "-p=$SidValue") -WindowStyle Hidden -PassThru
    if ($null -eq $process) {
        throw "CheckNetIsolation LoopbackExempt -is did not return a process handle"
    }

    Start-Sleep -Milliseconds 200
    if ($process.HasExited) {
        throw "CheckNetIsolation LoopbackExempt -is exited early with code $($process.ExitCode)"
    }

    return $process
}

function Remove-Stale-LoopbackServerProcesses {
    try {
        $staleProcesses = Get-CimInstance Win32_Process -Filter "Name = 'CheckNetIsolation.exe'" -ErrorAction Stop |
            Where-Object {
                $_.CommandLine -match 'LoopbackExempt\s+-is'
            }

        foreach ($stale in $staleProcesses) {
            try {
                Stop-Process -Id $stale.ProcessId -Force -ErrorAction Stop
                Log-Progress ("removed_stale_loopback_server|" + $stale.ProcessId)
            }
            catch {
                Log-Progress ("skip_stale_loopback_server_cleanup|" + $stale.ProcessId + "|" + $_.Exception.Message)
            }
        }
    }
    catch {
        Log-Progress ("skip_stale_loopback_server_enumeration|" + $_.Exception.Message)
    }
}

function Stop-LoopbackServerProcess($Process) {
    if ($null -eq $Process) {
        return
    }

    try {
        Stop-Process -Id $Process.Id -Force -ErrorAction Stop
        Wait-Process -Id $Process.Id -Timeout 2 -ErrorAction SilentlyContinue
        Log-Progress ("stopped_loopback_server|" + $Process.Id)
        return
    }
    catch {
        Log-Progress ("stop_loopback_server_fallback|" + $Process.Id + "|" + $_.Exception.Message)
    }

    try {
        & taskkill.exe /PID $Process.Id /T /F | Out-Null
        Log-Progress ("taskkill_loopback_server|" + $Process.Id)
    }
    catch {
        Log-Progress ("taskkill_loopback_server_failed|" + $Process.Id + "|" + $_.Exception.Message)
    }
}

function Test-ParentProcessAlive([int]$ProcessId) {
    try {
        $null = Get-Process -Id $ProcessId -ErrorAction Stop
        return $true
    }
    catch {
        return $false
    }
}

function Remove-Stale-ProcwardenFirewallRules {
    try {
        foreach ($line in (& netsh advfirewall firewall show rule name=all 2>$null)) {
            if ($line -notlike 'Rule Name:*procwarden-elevated-all-*') {
                continue
            }

            $ruleName = $line.Substring($line.IndexOf(':') + 1).Trim()
            if ($ruleName -notmatch '^procwarden-elevated-all-(\d+)-\d+-(in|out)$') {
                continue
            }

            & netsh advfirewall firewall delete rule name="$ruleName" | Out-Null
            Log-Progress ("removed_stale_firewall_rule|" + $ruleName)
        }
    }
    catch {
        Log-Progress ("skip_stale_firewall_cleanup|" + $_.Exception.Message)
    }
}

function Rule-Permission([string]$Kind, [bool]$IsDirectory) {
    switch ($Kind) {
        "dn" { return $(if ($IsDirectory) { "(OI)(CI)(F)" } else { "(F)" }) }
        "ro" { return $(if ($IsDirectory) { "(OI)(CI)(RX)" } else { "(RX)" }) }
        "rw" { return $(if ($IsDirectory) { "(OI)(CI)(M)" } else { "(M)" }) }
        "dw" { return $(if ($IsDirectory) { "(OI)(CI)(W)" } else { "(W)" }) }
        default { throw "unknown ACL rule kind: $Kind" }
    }
}

function Rule-AccessMode([string]$Kind) {
    switch ($Kind) {
        "dn" { return "/deny" }
        "ro" { return "/grant" }
        "rw" { return "/grant" }
        "dw" { return "/deny" }
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

    & icacls $Path /remove:g "*${SidValue}" /C 2>$null | Out-Null
    & icacls $Path /remove:d "*${SidValue}" /C 2>$null | Out-Null
}

function Log-Progress([string]$Message) {
    Add-Content -LiteralPath $ProgressFile -Value ((Get-Date -Format o) + "|" + $Message)
}

$entries = @()
if (Test-Path -LiteralPath $SpecFile) {
    $entries = Get-Content -LiteralPath $SpecFile -Encoding UTF8
}

$appliedPaths = New-Object System.Collections.Generic.List[string]
$firewallEnabled = $false
$loopbackClientEnabled = $false
$loopbackServerProcess = $null
$loopbackServerRequested = $NetworkRuleMode -eq 3
$loopbackServerStarted = $false

try {
    Set-Content -LiteralPath $ProgressFile -Value "" -NoNewline -Encoding utf8
    $null = Remove-Item -LiteralPath $LoopbackServerReadyFile -Force -ErrorAction SilentlyContinue
    Log-Progress ("sid=" + $Sid)
    Log-Progress ("appcontainer_name=" + $AppContainerName)
    Log-Progress ("parent_pid=" + $ParentPid)
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    Log-Progress ("is_admin=" + $isAdmin)
    Log-Progress ("entries=" + $entries.Count)

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
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        Log-Progress ("begin|" + $kind + "|" + $path)
        try {
            Apply-Rule -Kind $kind -Path $path -SidValue $Sid
            $sw.Stop()
            Log-Progress ("end|" + $kind + "|" + $path + "|ms=" + $sw.ElapsedMilliseconds)
            $appliedPaths.Add($path)
        }
        catch {
            $sw.Stop()
            if ($kind -eq "ro" -or $kind -eq "rw") {
                Log-Progress ("skip_allow_error|" + $kind + "|" + $path + "|ms=" + $sw.ElapsedMilliseconds + "|error=" + $_.Exception.Message)
                continue
            }
            throw
        }
    }

    if ($NetworkRuleMode -ne 0) {
        switch ($NetworkRuleMode) {
            1 {
                $outboundAction = "block"
                $inboundAction = "block"
            }
            2 {
                $outboundAction = "allow"
                $inboundAction = "block"
            }
            3 {
                $outboundAction = "allow"
                $inboundAction = "allow"
            }
            default {
                throw "unknown network rule mode: $NetworkRuleMode"
            }
        }
        Remove-Stale-ProcwardenFirewallRules
        Log-Progress "begin|network"
        Apply-FirewallRule -Direction "out" -Action $outboundAction
        Apply-FirewallRule -Direction "in" -Action $inboundAction
        $firewallEnabled = $true
        Log-Progress "end|network"
    }

    if ($NetworkRuleMode -eq 2 -or $NetworkRuleMode -eq 3) {
        Log-Progress "begin|loopback_client"
        Set-LoopbackExemption -Operation "-a" -SidValue $Sid
        $loopbackClientEnabled = $true
        Log-Progress "end|loopback_client"
    }

    Set-Content -LiteralPath $ReadyFile -Value "ok" -NoNewline -Encoding ascii
    Log-Progress "ready"

    while (-not (Test-Path -LiteralPath $StopFile)) {
        if ($loopbackServerRequested -and -not $loopbackServerStarted -and (Test-Path -LiteralPath $LoopbackServerStartFile)) {
            Log-Progress "begin|loopback_server"
            try {
                Remove-Stale-LoopbackServerProcesses
                $loopbackServerProcess = Start-LoopbackServerExemption -SidValue $Sid
                Set-Content -LiteralPath $LoopbackServerReadyFile -Value "ok" -NoNewline -Encoding ascii
                Log-Progress ("end|loopback_server|pid=" + $loopbackServerProcess.Id)
            }
            catch {
                Set-Content -LiteralPath $LoopbackServerReadyFile -Value ("error:" + $_.Exception.Message) -NoNewline -Encoding utf8
                Log-Progress ("skip_loopback_server|" + $_.Exception.Message)
            }
            $loopbackServerStarted = $true
        }

        if (-not (Test-ParentProcessAlive -ProcessId $ParentPid)) {
            Log-Progress "parent_exited"
            break
        }
        Start-Sleep -Milliseconds 200
    }
}
catch {
    Log-Progress ("error|" + $_.Exception.Message)
    Set-Content -LiteralPath $ReadyFile -Value ("error:" + $_.Exception.Message) -NoNewline -Encoding utf8
    exit 1
}
finally {
    Log-Progress "cleanup_begin"
    for ($i = $appliedPaths.Count - 1; $i -ge 0; $i--) {
        Remove-Rule -Path $appliedPaths[$i] -SidValue $Sid
    }

    if ($firewallEnabled) {
        & netsh advfirewall firewall delete rule name="$OutRule" | Out-Null
        & netsh advfirewall firewall delete rule name="$InRule" | Out-Null
    }
    Stop-LoopbackServerProcess $loopbackServerProcess
    if ($loopbackClientEnabled) {
        & CheckNetIsolation.exe LoopbackExempt -d "-p=$Sid" | Out-Null
    }
    Log-Progress "cleanup_end"
}
"#;

#[derive(Debug, Clone)]
pub(super) struct ElevatedOpsSpec {
    pub(super) sid_string: String,
    pub(super) appcontainer_name: String,
    pub(super) executable: PathBuf,
    pub(super) network_rule_mode: NetworkRuleMode,
    pub(super) deny_access_paths: Vec<PathBuf>,
    pub(super) allow_readonly_paths: Vec<PathBuf>,
    pub(super) allow_readwrite_paths: Vec<PathBuf>,
    pub(super) deny_write_paths: Vec<PathBuf>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum NetworkRuleMode {
    None,
    BlockAll,
    OutboundOnly,
    Bidirectional,
}

impl NetworkRuleMode {
    fn as_int(self) -> i32 {
        match self {
            Self::None => 0,
            Self::BlockAll => 1,
            Self::OutboundOnly => 2,
            Self::Bidirectional => 3,
        }
    }
}

pub(super) struct ElevatedOpsGuard {
    process: ElevatedProcess,
    workspace_dir: PathBuf,
    stop_file: PathBuf,
    ready_file: PathBuf,
    progress_file: PathBuf,
    loopback_server_start_file: PathBuf,
    loopback_server_ready_file: PathBuf,
    network_rule_mode: NetworkRuleMode,
}

impl ElevatedOpsGuard {
    pub(super) fn spawn(spec: &ElevatedOpsSpec) -> Result<Self, SandboxError> {
        let workspace_dir = create_elevated_workspace_dir()?;
        let script_path = workspace_dir.join("elevated-ops-helper.ps1");
        let spec_path = workspace_dir.join("acl-spec.tsv");
        let stop_file = workspace_dir.join("stop.signal");
        let ready_file = workspace_dir.join("ready.signal");
        let progress_file = workspace_dir.join("progress.log");
        let loopback_server_start_file = workspace_dir.join("loopback-server.start.signal");
        let loopback_server_ready_file = workspace_dir.join("loopback-server.ready.signal");
        let rule_prefix = format!(
            "{FIREWALL_RULE_PREFIX}-{}-{}",
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
            &progress_file,
            &loopback_server_start_file,
            &loopback_server_ready_file,
            std::process::id(),
            &spec.appcontainer_name,
            &spec.executable,
            &out_rule_name,
            &in_rule_name,
            &spec.sid_string,
            spec.network_rule_mode,
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
            progress_file,
            loopback_server_start_file,
            loopback_server_ready_file,
            network_rule_mode: spec.network_rule_mode,
        };
        guard.wait_until_initialized()?;
        Ok(guard)
    }

    pub(super) fn enable_loopback_server(&self) -> Result<(), SandboxError> {
        if !matches!(self.network_rule_mode, NetworkRuleMode::Bidirectional) {
            return Ok(());
        }

        let _ = fs::remove_file(&self.loopback_server_ready_file);
        fs::write(&self.loopback_server_start_file, b"start").map_err(SandboxError::Io)?;

        let started = Instant::now();
        loop {
            match read_ready_signal(&self.loopback_server_ready_file)? {
                ReadySignal::Pending => {}
                ReadySignal::Ok => return Ok(()),
                ReadySignal::Error(message) => {
                    let progress_tail = read_progress_tail(&self.progress_file, 20);
                    return Err(SandboxError::Denied(format!(
                        "automatic administrator loopback-server initialization failed: {message}; last progress: {progress_tail}"
                    )));
                }
            }

            if let Some(exit_code) = self.process.try_wait_exit_code(0)? {
                let progress_tail = read_progress_tail(&self.progress_file, 20);
                return Err(SandboxError::Denied(format!(
                    "automatic administrator elevated-ops helper exited before loopback-server readiness (exit code {exit_code}, workspace: {}, last progress: {progress_tail})",
                    self.workspace_dir.display(),
                )));
            }

            if started.elapsed() >= LOOPBACK_SERVER_READY_TIMEOUT {
                let progress_tail = read_progress_tail(&self.progress_file, 20);
                return Err(SandboxError::Denied(format!(
                    "automatic administrator loopback-server helper timed out before readiness (workspace: {}, last progress: {progress_tail})",
                    self.workspace_dir.display(),
                )));
            }

            sleep(ELEVATED_HELPER_POLL_INTERVAL);
        }
    }

    fn wait_until_initialized(&self) -> Result<(), SandboxError> {
        let started = Instant::now();
        loop {
            match read_ready_signal(&self.ready_file)? {
                ReadySignal::Pending => {}
                ReadySignal::Ok => return Ok(()),
                ReadySignal::Error(message) => {
                    let progress_tail = read_progress_tail(&self.progress_file, 20);
                    return Err(SandboxError::Denied(format!(
                        "automatic administrator elevated-ops initialization failed: {message}; last progress: {progress_tail}"
                    )));
                }
            }

            if let Some(exit_code) = self.process.try_wait_exit_code(0)? {
                let progress_tail = read_progress_tail(&self.progress_file, 20);
                return Err(SandboxError::Denied(format!(
                    "automatic administrator elevated-ops helper exited before initialization (exit code {exit_code}, workspace: {}, last progress: {progress_tail})",
                    self.workspace_dir.display(),
                )));
            }

            if started.elapsed() >= ELEVATED_HELPER_READY_TIMEOUT {
                let progress_tail = read_progress_tail(&self.progress_file, 20);
                return Err(SandboxError::Denied(format!(
                    "automatic administrator elevated-ops helper timed out before readiness (workspace: {}, last progress: {progress_tail})",
                    self.workspace_dir.display(),
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
    progress_file: &Path,
    loopback_server_start_file: &Path,
    loopback_server_ready_file: &Path,
    parent_pid: u32,
    appcontainer_name: &str,
    executable: &Path,
    out_rule_name: &str,
    in_rule_name: &str,
    sid_string: &str,
    network_rule_mode: NetworkRuleMode,
) -> String {
    format!(
        "-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File {} -Sid {} -AppContainerName {} -SpecFile {} -StopFile {} -ReadyFile {} -ProgressFile {} -LoopbackServerStartFile {} -LoopbackServerReadyFile {} -ParentPid {} -Executable {} -OutRule {} -InRule {} -NetworkRuleMode {}",
        elevation::quote_windows_arg(&script_path.to_string_lossy()),
        elevation::quote_windows_arg(sid_string),
        elevation::quote_windows_arg(appcontainer_name),
        elevation::quote_windows_arg(&spec_path.to_string_lossy()),
        elevation::quote_windows_arg(&stop_file.to_string_lossy()),
        elevation::quote_windows_arg(&ready_file.to_string_lossy()),
        elevation::quote_windows_arg(&progress_file.to_string_lossy()),
        elevation::quote_windows_arg(&loopback_server_start_file.to_string_lossy()),
        elevation::quote_windows_arg(&loopback_server_ready_file.to_string_lossy()),
        parent_pid,
        elevation::quote_windows_arg(&executable.to_string_lossy()),
        elevation::quote_windows_arg(out_rule_name),
        elevation::quote_windows_arg(in_rule_name),
        network_rule_mode.as_int(),
    )
}

fn serialize_acl_spec(spec: &ElevatedOpsSpec) -> String {
    let mut lines = Vec::new();

    for path in &spec.deny_access_paths {
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

fn read_progress_tail(path: &Path, max_lines: usize) -> String {
    match fs::read_to_string(path) {
        Ok(content) => {
            let lines = content
                .lines()
                .filter(|line| !line.trim().is_empty())
                .collect::<Vec<_>>();
            if lines.is_empty() {
                return "(no progress lines)".to_string();
            }

            let start = lines.len().saturating_sub(max_lines);
            lines[start..].join(" || ")
        }
        Err(error) if error.kind() == ErrorKind::NotFound => "(progress file missing)".to_string(),
        Err(error) => format!("(failed to read progress file: {error})"),
    }
}
