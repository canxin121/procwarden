#![allow(unsafe_op_in_unsafe_fn)]

use std::collections::HashMap;
use std::ffi::c_void;
use std::path::{Path, PathBuf};

use which::which_in;
use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Foundation::HANDLE_FLAG_INHERIT;
use windows_sys::Win32::Foundation::SetHandleInformation;
use windows_sys::Win32::Security::SECURITY_CAPABILITIES;
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
use windows_sys::Win32::System::Threading::STARTF_USESTDHANDLES;
use windows_sys::Win32::System::Threading::STARTUPINFOEXW;
use windows_sys::Win32::System::Threading::TerminateProcess;
use windows_sys::Win32::System::Threading::UpdateProcThreadAttribute;
use windows_sys::Win32::System::Threading::WaitForSingleObject;
use windows_sys::Win32::System::WindowsProgramming::PROCESS_CREATION_CHILD_PROCESS_RESTRICTED;

use crate::{SandboxError, cap_fs};

use super::util::{format_last_error, to_wide};

pub(super) struct CaptureResult {
    pub(super) exit_code: i32,
    pub(super) stdout: Vec<u8>,
    pub(super) stderr: Vec<u8>,
    pub(super) timed_out: bool,
}

type PipeHandles = ((HANDLE, HANDLE), (HANDLE, HANDLE), (HANDLE, HANDLE));

struct ProcThreadAttributes {
    _buffer: Vec<u8>,
    list: LPPROC_THREAD_ATTRIBUTE_LIST,
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
) -> Result<CaptureResult, SandboxError> {
    unsafe {
        let (stdin_pair, stdout_pair, stderr_pair) = setup_stdio_pipes()?;
        let ((in_r, in_w), (out_r, out_w), (err_r, err_w)) = (stdin_pair, stdout_pair, stderr_pair);

        let job_handle = create_job_kill_on_close()?;
        let mut attrs =
            match prepare_appcontainer_child_job_attributes(appcontainer_sid, job_handle) {
                Ok(value) => value,
                Err(error) => {
                    close_many(&[in_r, in_w, out_r, out_w, err_r, err_w, job_handle]);
                    return Err(error);
                }
            };

        let mut startup_info_ex: STARTUPINFOEXW = std::mem::zeroed();
        startup_info_ex.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
        startup_info_ex.StartupInfo.dwFlags |= STARTF_USESTDHANDLES;
        startup_info_ex.StartupInfo.hStdInput = in_r;
        startup_info_ex.StartupInfo.hStdOutput = out_w;
        startup_info_ex.StartupInfo.hStdError = err_w;
        let desktop = to_wide("Winsta0\\Default");
        startup_info_ex.StartupInfo.lpDesktop = desktop.as_ptr() as *mut u16;
        startup_info_ex.lpAttributeList = attrs.as_mut_ptr();

        let mut process_info: PROCESS_INFORMATION = std::mem::zeroed();
        let command_line_string = command
            .iter()
            .map(|arg| quote_windows_arg(arg))
            .collect::<Vec<_>>()
            .join(" ");
        let mut command_line = to_wide(&command_line_string);
        let env_block = make_env_block(env_map);
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
            env_block.as_ptr() as *mut c_void,
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
) -> Result<ProcThreadAttributes, SandboxError> {
    let mut attrs = ProcThreadAttributes::new(3)?;

    let mut security_capabilities = SECURITY_CAPABILITIES {
        AppContainerSid: appcontainer_sid,
        Capabilities: std::ptr::null_mut(),
        CapabilityCount: 0,
        Reserved: 0,
    };
    if UpdateProcThreadAttribute(
        attrs.as_mut_ptr(),
        0,
        PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize,
        &mut security_capabilities as *mut _ as *mut c_void,
        std::mem::size_of::<SECURITY_CAPABILITIES>(),
        std::ptr::null_mut(),
        std::ptr::null(),
    ) == 0
    {
        return Err(last_error(
            "UpdateProcThreadAttribute(SECURITY_CAPABILITIES)",
        ));
    }

    let mut child_policy: u64 = PROCESS_CREATION_CHILD_PROCESS_RESTRICTED as u64;
    if UpdateProcThreadAttribute(
        attrs.as_mut_ptr(),
        0,
        PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY as usize,
        &mut child_policy as *mut _ as *mut c_void,
        std::mem::size_of::<u64>(),
        std::ptr::null_mut(),
        std::ptr::null(),
    ) == 0
    {
        return Err(last_error(
            "UpdateProcThreadAttribute(CHILD_PROCESS_POLICY)",
        ));
    }

    let mut job = job_handle;
    if UpdateProcThreadAttribute(
        attrs.as_mut_ptr(),
        0,
        PROC_THREAD_ATTRIBUTE_JOB_LIST as usize,
        &mut job as *mut _ as *mut c_void,
        std::mem::size_of::<HANDLE>(),
        std::ptr::null_mut(),
        std::ptr::null(),
    ) == 0
    {
        return Err(last_error("UpdateProcThreadAttribute(JOB_LIST)"));
    }

    Ok(attrs)
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
    out
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
    SandboxError::Windows(format!(
        "{context} failed: {} ({})",
        code,
        format_last_error(code)
    ))
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{quote_windows_arg, resolve_executable};

    #[test]
    fn resolve_executable_honors_custom_path_and_pathext() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be monotonic")
            .as_nanos();
        let temp_dir = std::env::temp_dir().join(format!("agena-resolve-exec-test-{nonce}"));
        fs::create_dir_all(&temp_dir).expect("temp directory should be created");

        let tool_path = temp_dir.join("demo.cmd");
        fs::write(&tool_path, "@echo off\r\nexit /b 0\r\n")
            .expect("stub command should be written");

        let mut env = HashMap::new();
        env.insert("PATH".to_string(), temp_dir.to_string_lossy().to_string());
        env.insert("PATHEXT".to_string(), ".CMD;.EXE".to_string());

        let resolved = resolve_executable("demo", &temp_dir, &env)
            .expect("executable should resolve via PATH/PATHEXT");

        assert_eq!(
            resolved
                .canonicalize()
                .expect("resolved path should canonicalize"),
            tool_path
                .canonicalize()
                .expect("tool path should canonicalize"),
        );

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn resolve_executable_does_not_fallback_to_path_for_relative_binary() {
        let cwd = std::env::temp_dir();
        let env = HashMap::new();

        let resolved = resolve_executable(r".\missing-command", &cwd, &env);
        assert!(resolved.is_none());
    }

    #[test]
    fn quote_windows_arg_handles_spaces_quotes_and_trailing_backslashes() {
        assert_eq!(quote_windows_arg("plain"), "plain");
        assert_eq!(quote_windows_arg("two words"), r#""two words""#);
        assert_eq!(
            quote_windows_arg(r#"a\"b"#),
            r#""a\\\"b""#,
            "embedded quote should be escaped with preceding backslashes"
        );
        assert_eq!(
            quote_windows_arg(r"path with tail\\"),
            r#""path with tail\\\\""#,
            "trailing backslashes must be doubled inside quoted arg"
        );
    }
}
