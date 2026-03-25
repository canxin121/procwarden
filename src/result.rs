use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxExecOutput {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub aggregated_output: String,
    pub duration: Duration,
    pub timed_out: bool,
}

impl SandboxExecOutput {
    pub(crate) const TIMEOUT_EXIT_CODE: i32 = 124;

    pub(crate) fn from_text_output(
        exit_code: i32,
        stdout: String,
        stderr: String,
        duration: Duration,
        timed_out: bool,
    ) -> Self {
        let effective_exit_code = if timed_out {
            Self::TIMEOUT_EXIT_CODE
        } else {
            exit_code
        };
        let aggregated_output = format!("{stdout}{stderr}");

        Self {
            exit_code: effective_exit_code,
            stdout,
            stderr,
            aggregated_output,
            duration,
            timed_out,
        }
    }

    pub(crate) fn from_utf8_lossy(
        exit_code: i32,
        stdout: &[u8],
        stderr: &[u8],
        duration: Duration,
        timed_out: bool,
    ) -> Self {
        Self::from_text_output(
            exit_code,
            String::from_utf8_lossy(stdout).to_string(),
            String::from_utf8_lossy(stderr).to_string(),
            duration,
            timed_out,
        )
    }
}
