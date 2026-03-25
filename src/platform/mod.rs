#[cfg(any(target_os = "linux", target_os = "macos"))]
mod command_runner;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;

use crate::{SandboxCommandRequest, SandboxError, SandboxExecOutput, SandboxPolicy};

#[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
compile_error!(
    "procwarden only supports windows, linux, and macos targets. Unsupported OS builds are intentionally disallowed."
);

pub(crate) fn execute(
    request: &SandboxCommandRequest,
    policy: &SandboxPolicy,
) -> Result<SandboxExecOutput, SandboxError> {
    #[cfg(target_os = "windows")]
    {
        windows::execute(request, policy)
    }

    #[cfg(target_os = "linux")]
    {
        linux::execute(request, policy)
    }

    #[cfg(target_os = "macos")]
    {
        macos::execute(request, policy)
    }
}
