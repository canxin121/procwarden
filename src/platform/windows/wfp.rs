#![allow(unsafe_op_in_unsafe_fn)]

use std::ffi::c_void;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::thread::sleep;
use std::time::{Duration, Instant};

use rand::random;
use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_NOT_SUPPORTED, HANDLE};
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWP_ACTION_BLOCK, FWP_BYTE_BLOB, FWP_BYTE_BLOB_TYPE, FWP_CONDITION_VALUE0,
    FWP_CONDITION_VALUE0_0, FWP_EMPTY, FWP_MATCH_EQUAL, FWP_SID, FWP_VALUE0, FWPM_ACTION0,
    FWPM_CONDITION_ALE_APP_ID, FWPM_CONDITION_ALE_PACKAGE_ID, FWPM_FILTER_CONDITION0, FWPM_FILTER0,
    FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6,
    FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
    FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4, FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V6,
    FWPM_SESSION_FLAG_DYNAMIC, FWPM_SESSION0, FWPM_SUBLAYER_UNIVERSAL, FwpmEngineClose0,
    FwpmEngineOpen0, FwpmFilterAdd0, FwpmFreeMemory0, FwpmGetAppIdFromFileName0,
    FwpmTransactionAbort0, FwpmTransactionBegin0, FwpmTransactionCommit0,
};
use windows_sys::Win32::Security::SID;

use crate::SandboxError;

use super::elevation::{self, ElevatedProcess};
use super::util::{format_last_error, to_wide};

const BLOCK_LAYERS: [windows_sys::core::GUID; 6] = [
    FWPM_LAYER_ALE_AUTH_CONNECT_V4,
    FWPM_LAYER_ALE_AUTH_CONNECT_V6,
    FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
    FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
    FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4,
    FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V6,
];

const ELEVATED_HELPER_READY_TIMEOUT: Duration = Duration::from_secs(20);
const ELEVATED_HELPER_STOP_TIMEOUT_MS: u32 = 5_000;
const ELEVATED_HELPER_POLL_INTERVAL: Duration = Duration::from_millis(100);
const ELEVATED_FIREWALL_HELPER_SCRIPT: &str = r#"
param(
    [Parameter(Mandatory=$true)][string]$Executable,
    [Parameter(Mandatory=$true)][string]$RulePrefix,
    [Parameter(Mandatory=$true)][string]$StopFile,
    [Parameter(Mandatory=$true)][string]$ReadyFile
)

$ErrorActionPreference = "Stop"
$outRule = "$RulePrefix-out"
$inRule = "$RulePrefix-in"

function Invoke-Netsh([string[]]$Arguments) {
    & netsh @Arguments | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "netsh failed with exit code ${LASTEXITCODE}: $($Arguments -join ' ')"
    }
}

function Remove-Rules {
    & netsh advfirewall firewall delete rule name="$outRule" program="$Executable" | Out-Null
    & netsh advfirewall firewall delete rule name="$inRule" program="$Executable" | Out-Null
}

try {
    Invoke-Netsh @("advfirewall", "firewall", "add", "rule", "name=$outRule", "dir=out", "action=block", "program=$Executable", "enable=yes", "profile=any")
    Invoke-Netsh @("advfirewall", "firewall", "add", "rule", "name=$inRule", "dir=in", "action=block", "program=$Executable", "enable=yes", "profile=any")

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
    Remove-Rules
}
"#;

#[derive(Debug, Clone, Copy)]
struct WfpStatusError {
    context: &'static str,
    status: u32,
}

impl WfpStatusError {
    fn new(context: &'static str, status: u32) -> Self {
        Self { context, status }
    }

    fn into_sandbox_error(self) -> SandboxError {
        wfp_error(self.context, self.status)
    }

    fn should_try_auto_elevation(self) -> bool {
        matches!(self.status, ERROR_ACCESS_DENIED | ERROR_NOT_SUPPORTED)
    }
}

pub(super) struct NetworkFilterGuard {
    _wfp_session: Option<WfpSessionGuard>,
    _elevated_firewall: Option<ElevatedFirewallGuard>,
}

impl NetworkFilterGuard {
    fn wfp_session(session: WfpSessionGuard) -> Self {
        Self {
            _wfp_session: Some(session),
            _elevated_firewall: None,
        }
    }

    fn elevated_firewall(guard: ElevatedFirewallGuard) -> Self {
        Self {
            _wfp_session: None,
            _elevated_firewall: Some(guard),
        }
    }
}

struct WfpSessionGuard {
    engine: HANDLE,
    _app_id: AppIdBlob,
}

impl Drop for WfpSessionGuard {
    fn drop(&mut self) {
        if !self.engine.is_null() {
            unsafe {
                let _ = FwpmEngineClose0(self.engine);
            }
            self.engine = std::ptr::null_mut();
        }
    }
}

struct ElevatedFirewallGuard {
    process: ElevatedProcess,
    workspace_dir: PathBuf,
    stop_file: PathBuf,
    ready_file: PathBuf,
    _out_rule_name: String,
    _in_rule_name: String,
}

impl ElevatedFirewallGuard {
    fn spawn(executable: &Path) -> Result<Self, SandboxError> {
        let workspace_dir = create_elevated_workspace_dir()?;
        let script_path = workspace_dir.join("elevated-firewall-helper.ps1");
        let stop_file = workspace_dir.join("stop.signal");
        let ready_file = workspace_dir.join("ready.signal");
        let rule_prefix = format!(
            "procwarden-elevated-{}-{}",
            std::process::id(),
            random::<u32>()
        );
        let out_rule_name = format!("{rule_prefix}-out");
        let in_rule_name = format!("{rule_prefix}-in");

        if let Err(error) = fs::write(&script_path, ELEVATED_FIREWALL_HELPER_SCRIPT) {
            let _ = fs::remove_dir_all(&workspace_dir);
            return Err(SandboxError::Io(error));
        }

        let _ = fs::remove_file(&ready_file);

        let parameters = elevated_powershell_parameters(
            &script_path,
            executable,
            &rule_prefix,
            &stop_file,
            &ready_file,
        );
        let powershell_exe = powershell_executable_path();
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
            _out_rule_name: out_rule_name,
            _in_rule_name: in_rule_name,
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
                        "automatic administrator elevation helper initialization failed: {message}"
                    )));
                }
            }

            if let Some(exit_code) = self.process.try_wait_exit_code(0)? {
                return Err(SandboxError::Denied(format!(
                    "automatic administrator elevation helper exited before initialization (exit code {exit_code}, workspace: {})",
                    self.workspace_dir.display()
                )));
            }

            if started.elapsed() >= ELEVATED_HELPER_READY_TIMEOUT {
                return Err(SandboxError::Denied(format!(
                    "automatic administrator elevation helper timed out before readiness (workspace: {})",
                    self.workspace_dir.display()
                )));
            }

            sleep(ELEVATED_HELPER_POLL_INTERVAL);
        }
    }
}

impl Drop for ElevatedFirewallGuard {
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
            ) =>
        {
            Ok(ReadySignal::Pending)
        }
        Err(error) => Err(SandboxError::Io(error)),
    }
}

pub(super) fn install_block_all_network_filters(
    executable: &Path,
    appcontainer_sid: *mut c_void,
) -> Result<NetworkFilterGuard, SandboxError> {
    let engine = match open_dynamic_engine() {
        Ok(engine) => engine,
        Err(error) => return try_elevated_network_guard(executable, error),
    };

    let app_id = match AppIdBlob::from_executable(executable) {
        Ok(value) => value,
        Err(error) => {
            unsafe {
                let _ = FwpmEngineClose0(engine);
            }
            return Err(error);
        }
    };

    if let Err(error) = unsafe { install_filters(engine, app_id.ptr(), appcontainer_sid) } {
        unsafe {
            let _ = FwpmEngineClose0(engine);
        }
        return try_elevated_network_guard(executable, error);
    }

    Ok(NetworkFilterGuard::wfp_session(WfpSessionGuard {
        engine,
        _app_id: app_id,
    }))
}

unsafe fn install_filters(
    engine: HANDLE,
    app_id: *mut FWP_BYTE_BLOB,
    appcontainer_sid: *mut c_void,
) -> Result<(), WfpStatusError> {
    let begin_status = FwpmTransactionBegin0(engine, 0);
    if begin_status != 0 {
        return Err(WfpStatusError::new("FwpmTransactionBegin0", begin_status));
    }

    for (index, layer) in BLOCK_LAYERS.into_iter().enumerate() {
        if let Err(error) = add_block_filter(engine, layer, app_id, appcontainer_sid, index) {
            let _ = FwpmTransactionAbort0(engine);
            return Err(error);
        }
    }

    let commit_status = FwpmTransactionCommit0(engine);
    if commit_status != 0 {
        let _ = FwpmTransactionAbort0(engine);
        return Err(WfpStatusError::new("FwpmTransactionCommit0", commit_status));
    }

    Ok(())
}

unsafe fn add_block_filter(
    engine: HANDLE,
    layer_key: windows_sys::core::GUID,
    app_id: *mut FWP_BYTE_BLOB,
    appcontainer_sid: *mut c_void,
    index: usize,
) -> Result<(), WfpStatusError> {
    let mut conditions = [
        FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_ALE_APP_ID,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_BYTE_BLOB_TYPE,
                Anonymous: FWP_CONDITION_VALUE0_0 { byteBlob: app_id },
            },
        },
        FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_ALE_PACKAGE_ID,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_SID,
                Anonymous: FWP_CONDITION_VALUE0_0 {
                    sid: appcontainer_sid as *mut SID,
                },
            },
        },
    ];

    let mut filter = FWPM_FILTER0 {
        layerKey: layer_key,
        subLayerKey: FWPM_SUBLAYER_UNIVERSAL,
        action: FWPM_ACTION0 {
            r#type: FWP_ACTION_BLOCK,
            ..FWPM_ACTION0::default()
        },
        weight: FWP_VALUE0 {
            r#type: FWP_EMPTY,
            ..FWP_VALUE0::default()
        },
        numFilterConditions: conditions.len() as u32,
        filterCondition: conditions.as_mut_ptr(),
        ..FWPM_FILTER0::default()
    };

    let filter_name = format!("procwarden-network-block-{index}");
    let mut filter_name_wide = to_wide(filter_name);
    filter.displayData.name = filter_name_wide.as_mut_ptr();

    let status = FwpmFilterAdd0(engine, &filter, std::ptr::null_mut(), std::ptr::null_mut());
    if status != 0 {
        return Err(WfpStatusError::new("FwpmFilterAdd0", status));
    }

    Ok(())
}

fn open_dynamic_engine() -> Result<HANDLE, WfpStatusError> {
    let session = FWPM_SESSION0 {
        flags: FWPM_SESSION_FLAG_DYNAMIC,
        ..FWPM_SESSION0::default()
    };

    let mut engine: HANDLE = std::ptr::null_mut();
    let status =
        unsafe { FwpmEngineOpen0(std::ptr::null(), 0, std::ptr::null(), &session, &mut engine) };
    if status != 0 {
        return Err(WfpStatusError::new("FwpmEngineOpen0", status));
    }
    if engine.is_null() {
        return Err(WfpStatusError::new("FwpmEngineOpen0", ERROR_NOT_SUPPORTED));
    }

    Ok(engine)
}

fn try_elevated_network_guard(
    executable: &Path,
    original_error: WfpStatusError,
) -> Result<NetworkFilterGuard, SandboxError> {
    if !original_error.should_try_auto_elevation() {
        return Err(original_error.into_sandbox_error());
    }

    if elevation::current_process_is_elevated()? {
        return Err(original_error.into_sandbox_error());
    }

    match ElevatedFirewallGuard::spawn(executable) {
        Ok(guard) => Ok(NetworkFilterGuard::elevated_firewall(guard)),
        Err(elevation_error) => {
            let base = original_error.into_sandbox_error();
            Err(SandboxError::Denied(format!(
                "{base}; automatic administrator elevation failed: {elevation_error}"
            )))
        }
    }
}

fn elevated_powershell_parameters(
    script_path: &Path,
    executable: &Path,
    rule_prefix: &str,
    stop_file: &Path,
    ready_file: &Path,
) -> String {
    format!(
        "-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File {} -Executable {} -RulePrefix {} -StopFile {} -ReadyFile {}",
        elevation::quote_windows_arg(&script_path.to_string_lossy()),
        elevation::quote_windows_arg(&executable.to_string_lossy()),
        elevation::quote_windows_arg(rule_prefix),
        elevation::quote_windows_arg(&stop_file.to_string_lossy()),
        elevation::quote_windows_arg(&ready_file.to_string_lossy()),
    )
}

fn create_elevated_workspace_dir() -> Result<PathBuf, SandboxError> {
    let path = std::env::temp_dir().join(format!(
        "procwarden-elevated-wfp-{}-{}",
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

fn wfp_error(context: &str, status: u32) -> SandboxError {
    let detail = format_last_error(status as i32);
    if status == ERROR_ACCESS_DENIED {
        SandboxError::Denied(format!(
            "{context} failed with access denied ({}): requires privileges to install temporary WFP filters",
            detail
        ))
    } else {
        SandboxError::Windows(format!("{context} failed: {status} ({detail})"))
    }
}

struct AppIdBlob {
    ptr: *mut FWP_BYTE_BLOB,
}

impl AppIdBlob {
    fn from_executable(executable: &Path) -> Result<Self, SandboxError> {
        let wide_executable = to_wide(executable);
        let mut ptr: *mut FWP_BYTE_BLOB = std::ptr::null_mut();
        let status = unsafe { FwpmGetAppIdFromFileName0(wide_executable.as_ptr(), &mut ptr) };
        if status != 0 {
            return Err(wfp_error("FwpmGetAppIdFromFileName0", status));
        }
        if ptr.is_null() {
            return Err(SandboxError::Windows(
                "FwpmGetAppIdFromFileName0 returned null app id blob".to_string(),
            ));
        }

        Ok(Self { ptr })
    }

    fn ptr(&self) -> *mut FWP_BYTE_BLOB {
        self.ptr
    }
}

impl Drop for AppIdBlob {
    fn drop(&mut self) {
        if self.ptr.is_null() {
            return;
        }

        unsafe {
            let mut pointer = self.ptr as *mut c_void;
            FwpmFreeMemory0(&mut pointer);
        }
        self.ptr = std::ptr::null_mut();
    }
}
