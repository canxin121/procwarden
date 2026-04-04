#![allow(unsafe_op_in_unsafe_fn)]

use std::ffi::c_void;

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_CANCELLED, GetLastError, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetExitCodeProcess, OpenProcessToken, TerminateProcess, WaitForSingleObject,
};
use windows_sys::Win32::UI::Shell::{
    SEE_MASK_NO_CONSOLE, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW,
};

use crate::SandboxError;

use super::util::{format_last_error, to_wide};

pub(super) struct ElevatedProcess {
    handle: HANDLE,
}

unsafe impl Send for ElevatedProcess {}

impl ElevatedProcess {
    pub(super) fn shell_execute_runas(file: &str, parameters: &str) -> Result<Self, SandboxError> {
        let verb = to_wide("runas");
        let file_wide = to_wide(file);
        let parameters_wide = to_wide(parameters);

        let mut exec_info: SHELLEXECUTEINFOW = unsafe { std::mem::zeroed() };
        exec_info.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
        exec_info.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NO_CONSOLE;
        exec_info.lpVerb = verb.as_ptr();
        exec_info.lpFile = file_wide.as_ptr();
        exec_info.lpParameters = parameters_wide.as_ptr();
        exec_info.nShow = 0;

        if unsafe { ShellExecuteExW(&mut exec_info) } == 0 {
            let code = unsafe { GetLastError() } as i32;
            if code as u32 == ERROR_CANCELLED {
                return Err(SandboxError::Denied(
                    "administrator elevation was cancelled by user".to_string(),
                ));
            }
            return Err(windows_error("ShellExecuteExW(runas)", code));
        }

        if exec_info.hProcess.is_null() {
            return Err(SandboxError::Windows(
                "ShellExecuteExW(runas) returned null process handle".to_string(),
            ));
        }

        Ok(Self {
            handle: exec_info.hProcess,
        })
    }

    pub(super) fn try_wait_exit_code(&self, timeout_ms: u32) -> Result<Option<u32>, SandboxError> {
        let wait_result = unsafe { WaitForSingleObject(self.handle, timeout_ms) };
        match wait_result {
            WAIT_OBJECT_0 => {
                let mut exit_code = 1_u32;
                if unsafe { GetExitCodeProcess(self.handle, &mut exit_code) } == 0 {
                    return Err(last_error("GetExitCodeProcess"));
                }
                Ok(Some(exit_code))
            }
            WAIT_TIMEOUT => Ok(None),
            _ => Err(last_error("WaitForSingleObject")),
        }
    }

    pub(super) fn terminate(&self, exit_code: u32) {
        unsafe {
            let _ = TerminateProcess(self.handle, exit_code);
        }
    }
}

impl Drop for ElevatedProcess {
    fn drop(&mut self) {
        if self.handle.is_null() {
            return;
        }

        unsafe {
            CloseHandle(self.handle);
        }
        self.handle = std::ptr::null_mut();
    }
}

pub(super) fn current_process_is_elevated() -> Result<bool, SandboxError> {
    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return Err(last_error("OpenProcessToken"));
        }

        let mut elevation: TOKEN_ELEVATION = std::mem::zeroed();
        let mut returned: u32 = 0;
        let info_ok = GetTokenInformation(
            token,
            TokenElevation,
            &mut elevation as *mut _ as *mut c_void,
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        );

        CloseHandle(token);

        if info_ok == 0 {
            return Err(last_error("GetTokenInformation(TokenElevation)"));
        }
        Ok(elevation.TokenIsElevated != 0)
    }
}

pub(super) fn quote_windows_arg(arg: &str) -> String {
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
