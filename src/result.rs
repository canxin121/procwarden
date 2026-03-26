use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxExecOutput {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub aggregated_output: String,
    pub duration: Duration,
    pub timed_out: bool,
    pub degraded_mode_reason: Option<String>,
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
            degraded_mode_reason: None,
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

    pub(crate) fn with_degraded_mode_reason(mut self, reason: Option<String>) -> Self {
        self.degraded_mode_reason = reason;
        self
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::SandboxExecOutput;

    #[test]
    fn output_defaults_to_non_degraded_mode() {
        let output = SandboxExecOutput::from_text_output(
            0,
            "stdout".to_string(),
            "stderr".to_string(),
            Duration::from_millis(5),
            false,
        );

        assert!(output.degraded_mode_reason.is_none());
    }

    #[test]
    fn output_can_carry_degraded_mode_reason() {
        let reason = "child policy unavailable".to_string();
        let output = SandboxExecOutput::from_text_output(
            0,
            String::new(),
            String::new(),
            Duration::from_millis(1),
            false,
        )
        .with_degraded_mode_reason(Some(reason.clone()));

        assert_eq!(
            output.degraded_mode_reason.as_deref(),
            Some(reason.as_str())
        );
    }
}
