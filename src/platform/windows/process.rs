#![allow(unsafe_op_in_unsafe_fn)]

use std::collections::HashMap;
use std::ffi::c_void;
use std::path::{Path, PathBuf};

use which::which_in;
use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::Foundation::ERROR_ACCESS_DENIED;
use windows_sys::Win32::Foundation::ERROR_BAD_LENGTH;
use windows_sys::Win32::Foundation::ERROR_INVALID_PARAMETER;
use windows_sys::Win32::Foundation::ERROR_NOT_SUPPORTED;
use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Foundation::HANDLE_FLAG_INHERIT;
use windows_sys::Win32::Foundation::HLOCAL;
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Foundation::SetHandleInformation;
use windows_sys::Win32::Security::Authorization::ConvertStringSidToSidW;
use windows_sys::Win32::Security::SECURITY_CAPABILITIES;
use windows_sys::Win32::Security::SID_AND_ATTRIBUTES;
use windows_sys::Win32::Storage::FileSystem::ReadFile;
use windows_sys::Win32::System::JobObjects::CreateJobObjectW;
use windows_sys::Win32::System::JobObjects::JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
use windows_sys::Win32::System::JobObjects::JOBOBJECT_EXTENDED_LIMIT_INFORMATION;
use windows_sys::Win32::System::JobObjects::JobObjectExtendedLimitInformation;
use windows_sys::Win32::System::JobObjects::SetInformationJobObject;
use windows_sys::Win32::System::Pipes::CreatePipe;
use windows_sys::Win32::System::Threading::CREATE_UNICODE_ENVIRONMENT;
use windows_sys::Win32::System::Threading::CreateProcessW;
use windows_sys::Win32::System::Threading::DeleteProcThreadAttributeList;
use windows_sys::Win32::System::Threading::EXTENDED_STARTUPINFO_PRESENT;
use windows_sys::Win32::System::Threading::GetExitCodeProcess;
use windows_sys::Win32::System::Threading::INFINITE;
use windows_sys::Win32::System::Threading::InitializeProcThreadAttributeList;
use windows_sys::Win32::System::Threading::LPPROC_THREAD_ATTRIBUTE_LIST;
use windows_sys::Win32::System::Threading::PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY;
use windows_sys::Win32::System::Threading::PROC_THREAD_ATTRIBUTE_JOB_LIST;
use windows_sys::Win32::System::Threading::PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES;
use windows_sys::Win32::System::Threading::PROCESS_INFORMATION;
use windows_sys::Win32::System::Threading::STARTF_USESHOWWINDOW;
use windows_sys::Win32::System::Threading::STARTF_USESTDHANDLES;
use windows_sys::Win32::System::Threading::STARTUPINFOEXW;
use windows_sys::Win32::System::Threading::TerminateProcess;
use windows_sys::Win32::System::Threading::UpdateProcThreadAttribute;
use windows_sys::Win32::System::Threading::WaitForSingleObject;

use crate::{SandboxError, cap_fs};

use super::util::{format_last_error, to_wide};

const GROUP_ATTRIBUTE_ENABLED: u32 = 0x0000_0004;

pub(super) struct CaptureResult {
    pub(super) exit_code: i32,
    pub(super) stdout: Vec<u8>,
    pub(super) stderr: Vec<u8>,
    pub(super) timed_out: bool,
    pub(super) degraded_mode_reason: Option<String>,
}

type PipeHandles = ((HANDLE, HANDLE), (HANDLE, HANDLE), (HANDLE, HANDLE));

struct ProcThreadAttributes {
    _buffer: Vec<u8>,
    list: LPPROC_THREAD_ATTRIBUTE_LIST,
}

struct PreparedAttributes {
    attrs: ProcThreadAttributes,
    security_capabilities: Box<SECURITY_CAPABILITIES>,
    _capability_sids: Vec<OwnedCapabilitySid>,
    _capability_entries: Vec<SID_AND_ATTRIBUTES>,
    child_policy: Option<Box<u32>>,
    job_list: Box<[HANDLE; 1]>,
    degraded_mode_reason: Option<String>,
}

struct OwnedCapabilitySid {
    ptr: *mut c_void,
}

impl Drop for OwnedCapabilitySid {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            unsafe {
                LocalFree(self.ptr as HLOCAL);
            }
        }
    }
}

impl ProcThreadAttributes {
    unsafe fn new(count: u32) -> Result<Self, SandboxError> {
        let mut attr_size: usize = 0;
        let _ = InitializeProcThreadAttributeList(std::ptr::null_mut(), count, 0, &mut attr_size);
        let mut buffer = vec![0_u8; attr_size];
        let list = buffer.as_mut_ptr() as LPPROC_THREAD_ATTRIBUTE_LIST;
        if InitializeProcThreadAttributeList(list, count, 0, &mut attr_size) == 0 {
            return Err(last_error("InitializeProcThreadAttributeList"));
        }
        Ok(Self {
            _buffer: buffer,
            list,
        })
    }

    fn as_mut_ptr(&mut self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        self.list
    }
}

impl Drop for ProcThreadAttributes {
    fn drop(&mut self) {
        unsafe {
            DeleteProcThreadAttributeList(self.list);
        }
    }
}

pub(super) fn resolve_executable(
    program: &str,
    cwd: &Path,
    env_map: &HashMap<String, String>,
) -> Option<PathBuf> {
    let program_path = PathBuf::from(program);
    if program_path.components().count() > 1 || program.contains(':') {
        let absolute = if program_path.is_absolute() {
            program_path
        } else {
            cwd.join(program_path)
        };
        if cap_fs::is_file(&absolute) {
            return Some(absolute);
        }

        return None;
    }

    let path_var = env_map
        .get("PATH")
        .cloned()
        .or_else(|| std::env::var("PATH").ok())
        .unwrap_or_default();

    let has_extension = Path::new(program)
        .extension()
        .is_some_and(|ext| !ext.is_empty());

    let mut candidates = Vec::new();
    if has_extension {
        candidates.push(program.to_string());
    } else {
        candidates.push(program.to_string());
        candidates.extend(
            path_extensions(env_map)
                .into_iter()
                .map(|extension| format!("{program}{extension}")),
        );
    }

    for candidate in candidates {
        if let Ok(resolved) = which_in(&candidate, Some(path_var.as_str()), cwd) {
            return Some(resolved);
        }
    }

    None
}

fn path_extensions(env_map: &HashMap<String, String>) -> Vec<String> {
    env_map
        .get("PATHEXT")
        .cloned()
        .or_else(|| std::env::var("PATHEXT").ok())
        .unwrap_or_else(|| ".COM;.EXE;.BAT;.CMD".to_string())
        .split(';')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(str::to_string)
        .collect()
}

pub(super) fn run_process_in_appcontainer(
    appcontainer_sid: *mut c_void,
    application_name: &Path,
    command: &[String],
    cwd: &Path,
    env_map: &HashMap<String, String>,
    timeout_ms: Option<u64>,
    network_access: bool,
) -> Result<CaptureResult, SandboxError> {
    unsafe {
        let (stdin_pair, stdout_pair, stderr_pair) = setup_stdio_pipes()?;
        let ((in_r, in_w), (out_r, out_w), (err_r, err_w)) = (stdin_pair, stdout_pair, stderr_pair);

        let job_handle = create_job_kill_on_close()?;
        let mut prepared = match prepare_appcontainer_child_job_attributes(
            appcontainer_sid,
            job_handle,
            network_access,
        ) {
            Ok(value) => value,
            Err(error) => {
                close_many(&[in_r, in_w, out_r, out_w, err_r, err_w, job_handle]);
                return Err(error);
            }
        };

        let mut startup_info_ex: STARTUPINFOEXW = std::mem::zeroed();
        startup_info_ex.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
        startup_info_ex.StartupInfo.dwFlags |= STARTF_USESTDHANDLES;
        startup_info_ex.StartupInfo.dwFlags |= STARTF_USESHOWWINDOW;
        startup_info_ex.StartupInfo.hStdInput = in_r;
        startup_info_ex.StartupInfo.hStdOutput = out_w;
        startup_info_ex.StartupInfo.hStdError = err_w;
        startup_info_ex.StartupInfo.wShowWindow = 0;
        startup_info_ex.lpAttributeList = prepared.attrs.as_mut_ptr();

        let mut process_info: PROCESS_INFORMATION = std::mem::zeroed();
        let command_line_string = command
            .iter()
            .map(|arg| quote_windows_arg(arg))
            .collect::<Vec<_>>()
            .join(" ");
        let mut command_line = to_wide(&command_line_string);
        let env_block = environment_block_for_create_process(env_map);
        let app_name = to_wide(application_name.as_os_str());
        let cwd_wide = to_wide(cwd);

        let flags = CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT;
        let spawn_ok = CreateProcessW(
            app_name.as_ptr(),
            command_line.as_mut_ptr(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            1,
            flags,
            env_block
                .as_ref()
                .map_or(std::ptr::null_mut(), |block| block.as_ptr() as *mut c_void),
            cwd_wide.as_ptr(),
            &startup_info_ex.StartupInfo,
            &mut process_info,
        );
        if spawn_ok == 0 {
            let code = GetLastError() as i32;
            close_many(&[in_r, in_w, out_r, out_w, err_r, err_w, job_handle]);
            return Err(SandboxError::Windows(format!(
                "CreateProcessW(AppContainer) failed: {} ({})",
                code,
                format_last_error(code)
            )));
        }

        close_many(&[in_r, in_w, out_w, err_w]);

        let stdout_thread = spawn_pipe_reader_thread(out_r);
        let stderr_thread = spawn_pipe_reader_thread(err_r);

        let timeout = timeout_ms.map(|ms| ms as u32).unwrap_or(INFINITE);
        let wait_result = WaitForSingleObject(process_info.hProcess, timeout);
        let timed_out = wait_result == 0x0000_0102;
        if timed_out {
            let _ = TerminateProcess(process_info.hProcess, 1);
        }

        let mut exit_code_raw: u32 = 1;
        if !timed_out {
            let _ = GetExitCodeProcess(process_info.hProcess, &mut exit_code_raw);
        }

        close_many(&[process_info.hThread, process_info.hProcess, job_handle]);

        let stdout = stdout_thread.join().unwrap_or_default();
        let stderr = stderr_thread.join().unwrap_or_default();

        Ok(CaptureResult {
            exit_code: if timed_out { 124 } else { exit_code_raw as i32 },
            stdout,
            stderr,
            timed_out,
            degraded_mode_reason: prepared.degraded_mode_reason.take(),
        })
    }
}

fn spawn_pipe_reader_thread(handle: HANDLE) -> std::thread::JoinHandle<Vec<u8>> {
    let raw = handle as usize;
    std::thread::spawn(move || unsafe { read_pipe_to_end(raw as HANDLE) })
}

unsafe fn read_pipe_to_end(handle: HANDLE) -> Vec<u8> {
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 8192];
    loop {
        let mut read_bytes: u32 = 0;
        let ok = ReadFile(
            handle,
            chunk.as_mut_ptr(),
            chunk.len() as u32,
            &mut read_bytes,
            std::ptr::null_mut(),
        );
        if ok == 0 || read_bytes == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..read_bytes as usize]);
    }
    CloseHandle(handle);
    buffer
}

unsafe fn prepare_appcontainer_child_job_attributes(
    appcontainer_sid: *mut c_void,
    job_handle: HANDLE,
    network_access: bool,
) -> Result<PreparedAttributes, SandboxError> {
    let mut prepared = new_prepared_attributes(
        3,
        appcontainer_sid,
        job_handle,
        Some(Box::new(0x0000_0001_u32)),
        None,
        network_access,
    )?;
    set_security_capabilities_attr(&mut prepared)?;

    match set_child_process_policy_attr(&mut prepared) {
        Ok(()) => {
            set_job_list_attr(&mut prepared)?;
            Ok(prepared)
        }
        Err(code) if child_policy_degrade_allowed(code) => {
            let mut fallback = new_prepared_attributes(
                2,
                appcontainer_sid,
                job_handle,
                None,
                Some(child_policy_degraded_reason(code)),
                network_access,
            )?;
            set_security_capabilities_attr(&mut fallback)?;
            set_job_list_attr(&mut fallback)?;
            Ok(fallback)
        }
        Err(code) => Err(windows_error(
            "UpdateProcThreadAttribute(CHILD_PROCESS_POLICY)",
            code,
        )),
    }
}

unsafe fn new_prepared_attributes(
    attr_count: u32,
    appcontainer_sid: *mut c_void,
    job_handle: HANDLE,
    child_policy: Option<Box<u32>>,
    degraded_mode_reason: Option<String>,
    network_access: bool,
) -> Result<PreparedAttributes, SandboxError> {
    let (capability_sids, mut capability_entries) = network_capability_entries(network_access)?;

    Ok(PreparedAttributes {
        attrs: ProcThreadAttributes::new(attr_count)?,
        security_capabilities: security_capabilities_for_sid(
            appcontainer_sid,
            capability_entries.as_mut_ptr(),
            capability_entries.len() as u32,
        ),
        _capability_sids: capability_sids,
        _capability_entries: capability_entries,
        child_policy,
        job_list: Box::new([job_handle]),
        degraded_mode_reason,
    })
}

fn network_capability_entries(
    network_access: bool,
) -> Result<(Vec<OwnedCapabilitySid>, Vec<SID_AND_ATTRIBUTES>), SandboxError> {
    if !network_access {
        return Ok((Vec::new(), Vec::new()));
    }

    const NETWORK_CAPABILITY_SIDS: [&str; 3] = ["S-1-15-3-1", "S-1-15-3-2", "S-1-15-3-3"];

    let mut capability_sids = Vec::with_capacity(NETWORK_CAPABILITY_SIDS.len());
    for sid_string in NETWORK_CAPABILITY_SIDS {
        let mut sid_ptr = std::ptr::null_mut();
        let sid_wide = to_wide(sid_string);
        let ok = unsafe { ConvertStringSidToSidW(sid_wide.as_ptr(), &mut sid_ptr) };
        if ok == 0 || sid_ptr.is_null() {
            let code = unsafe { GetLastError() as i32 };
            return Err(SandboxError::Windows(format!(
                "ConvertStringSidToSidW failed for network capability SID {sid_string}: {} ({})",
                code,
                format_last_error(code)
            )));
        }
        capability_sids.push(OwnedCapabilitySid { ptr: sid_ptr });
    }

    let capability_entries = capability_sids
        .iter()
        .map(|sid| SID_AND_ATTRIBUTES {
            Sid: sid.ptr,
            Attributes: GROUP_ATTRIBUTE_ENABLED,
        })
        .collect::<Vec<_>>();

    Ok((capability_sids, capability_entries))
}

fn security_capabilities_for_sid(
    appcontainer_sid: *mut c_void,
    capability_entries: *mut SID_AND_ATTRIBUTES,
    capability_count: u32,
) -> Box<SECURITY_CAPABILITIES> {
    Box::new(SECURITY_CAPABILITIES {
        AppContainerSid: appcontainer_sid,
        Capabilities: if capability_count == 0 {
            std::ptr::null_mut()
        } else {
            capability_entries
        },
        CapabilityCount: capability_count,
        Reserved: 0,
    })
}

unsafe fn set_security_capabilities_attr(
    prepared: &mut PreparedAttributes,
) -> Result<(), SandboxError> {
    if UpdateProcThreadAttribute(
        prepared.attrs.as_mut_ptr(),
        0,
        PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize,
        prepared.security_capabilities.as_mut() as *mut _ as *mut c_void,
        std::mem::size_of::<SECURITY_CAPABILITIES>(),
        std::ptr::null_mut(),
        std::ptr::null(),
    ) == 0
    {
        return Err(last_error(
            "UpdateProcThreadAttribute(SECURITY_CAPABILITIES)",
        ));
    }
    Ok(())
}

unsafe fn set_child_process_policy_attr(prepared: &mut PreparedAttributes) -> Result<(), i32> {
    let child_policy = prepared
        .child_policy
        .as_mut()
        .expect("child policy backing store should exist in primary path");
    if UpdateProcThreadAttribute(
        prepared.attrs.as_mut_ptr(),
        0,
        PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY as usize,
        child_policy.as_mut() as *mut _ as *mut c_void,
        std::mem::size_of::<u32>(),
        std::ptr::null_mut(),
        std::ptr::null(),
    ) == 0
    {
        return Err(GetLastError() as i32);
    }
    Ok(())
}

unsafe fn set_job_list_attr(prepared: &mut PreparedAttributes) -> Result<(), SandboxError> {
    if UpdateProcThreadAttribute(
        prepared.attrs.as_mut_ptr(),
        0,
        PROC_THREAD_ATTRIBUTE_JOB_LIST as usize,
        prepared.job_list.as_mut_ptr() as *mut c_void,
        std::mem::size_of::<HANDLE>(),
        std::ptr::null_mut(),
        std::ptr::null(),
    ) == 0
    {
        return Err(last_error("UpdateProcThreadAttribute(JOB_LIST)"));
    }
    Ok(())
}

unsafe fn setup_stdio_pipes() -> Result<PipeHandles, SandboxError> {
    let mut in_r: HANDLE = std::ptr::null_mut();
    let mut in_w: HANDLE = std::ptr::null_mut();
    let mut out_r: HANDLE = std::ptr::null_mut();
    let mut out_w: HANDLE = std::ptr::null_mut();
    let mut err_r: HANDLE = std::ptr::null_mut();
    let mut err_w: HANDLE = std::ptr::null_mut();

    if CreatePipe(&mut in_r, &mut in_w, std::ptr::null_mut(), 0) == 0 {
        return Err(last_error("CreatePipe(stdin)"));
    }
    if CreatePipe(&mut out_r, &mut out_w, std::ptr::null_mut(), 0) == 0 {
        close_many(&[in_r, in_w]);
        return Err(last_error("CreatePipe(stdout)"));
    }
    if CreatePipe(&mut err_r, &mut err_w, std::ptr::null_mut(), 0) == 0 {
        close_many(&[in_r, in_w, out_r, out_w]);
        return Err(last_error("CreatePipe(stderr)"));
    }

    if SetHandleInformation(in_r, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) == 0 {
        close_many(&[in_r, in_w, out_r, out_w, err_r, err_w]);
        return Err(last_error("SetHandleInformation(stdin)"));
    }
    if SetHandleInformation(out_w, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) == 0 {
        close_many(&[in_r, in_w, out_r, out_w, err_r, err_w]);
        return Err(last_error("SetHandleInformation(stdout)"));
    }
    if SetHandleInformation(err_w, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) == 0 {
        close_many(&[in_r, in_w, out_r, out_w, err_r, err_w]);
        return Err(last_error("SetHandleInformation(stderr)"));
    }

    Ok(((in_r, in_w), (out_r, out_w), (err_r, err_w)))
}

unsafe fn create_job_kill_on_close() -> Result<HANDLE, SandboxError> {
    let job = CreateJobObjectW(std::ptr::null_mut(), std::ptr::null());
    if job.is_null() {
        return Err(last_error("CreateJobObjectW"));
    }

    let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    let ok = SetInformationJobObject(
        job,
        JobObjectExtendedLimitInformation,
        &mut limits as *mut _ as *mut c_void,
        std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
    );
    if ok == 0 {
        let err = last_error("SetInformationJobObject");
        CloseHandle(job);
        return Err(err);
    }
    Ok(job)
}

unsafe fn close_many(handles: &[HANDLE]) {
    for handle in handles {
        if !handle.is_null() {
            CloseHandle(*handle);
        }
    }
}

fn make_env_block(env: &HashMap<String, String>) -> Vec<u16> {
    let mut pairs = env
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect::<Vec<_>>();
    pairs.sort_by(|left, right| {
        left.0
            .to_ascii_uppercase()
            .cmp(&right.0.to_ascii_uppercase())
            .then(left.0.cmp(&right.0))
    });

    let mut out = Vec::new();
    for (key, value) in pairs {
        let mut entry = to_wide(format!("{key}={value}"));
        entry.pop();
        out.extend_from_slice(&entry);
        out.push(0);
    }
    out.push(0);
    if out.len() == 1 {
        out.push(0);
    }
    out
}

fn environment_block_for_create_process(env: &HashMap<String, String>) -> Option<Vec<u16>> {
    let mut merged = env.clone();
    for required in [
        "SystemRoot",
        "WINDIR",
        "PATH",
        "PATHEXT",
        "TEMP",
        "TMP",
        "COMSPEC",
        "USERPROFILE",
        "APPDATA",
        "LOCALAPPDATA",
    ] {
        if has_env_key_case_insensitive(&merged, required) {
            continue;
        }
        if let Ok(value) = std::env::var(required) {
            merged.insert(required.to_string(), value);
        }
    }

    if merged.is_empty() {
        return None;
    }

    Some(make_env_block(&merged))
}

fn has_env_key_case_insensitive(env: &HashMap<String, String>, key: &str) -> bool {
    env.keys()
        .any(|candidate| candidate.eq_ignore_ascii_case(key))
}

fn quote_windows_arg(arg: &str) -> String {
    let needs_quotes = arg.is_empty()
        || arg
            .chars()
            .any(|ch| matches!(ch, ' ' | '\t' | '\n' | '\r' | '"'));
    if !needs_quotes {
        return arg.to_string();
    }

    let mut out = String::with_capacity(arg.len() + 2);
    out.push('"');
    let mut backslashes = 0;
    for ch in arg.chars() {
        match ch {
            '\\' => {
                backslashes += 1;
            }
            '"' => {
                out.push_str(&"\\".repeat(backslashes * 2 + 1));
                out.push('"');
                backslashes = 0;
            }
            _ => {
                if backslashes > 0 {
                    out.push_str(&"\\".repeat(backslashes));
                    backslashes = 0;
                }
                out.push(ch);
            }
        }
    }

    if backslashes > 0 {
        out.push_str(&"\\".repeat(backslashes * 2));
    }
    out.push('"');
    out
}

fn last_error(context: &str) -> SandboxError {
    let code = unsafe { GetLastError() } as i32;
    windows_error(context, code)
}

fn windows_error(context: &str, code: i32) -> SandboxError {
    SandboxError::Windows(format!(
        "{context} failed: {} ({})",
        code,
        format_last_error(code)
    ))
}
fn child_policy_degrade_allowed(code: i32) -> bool {
    matches!(
        code as u32,
        ERROR_ACCESS_DENIED | ERROR_BAD_LENGTH | ERROR_INVALID_PARAMETER | ERROR_NOT_SUPPORTED
    )
}

fn child_policy_degraded_reason(code: i32) -> String {
    format!(
        "windows sandbox degraded mode: child-process restriction policy unavailable ({}: {}); job containment remains active",
        code,
        format_last_error(code)
    )
}
