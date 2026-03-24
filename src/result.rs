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

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::SandboxExecOutput;

    #[test]
    fn builds_aggregated_output_and_preserves_exit_code_when_not_timed_out() {
        let output = SandboxExecOutput::from_text_output(
            7,
            "out".to_string(),
            "err".to_string(),
            Duration::from_millis(10),
            false,
        );

        assert_eq!(output.exit_code, 7);
        assert_eq!(output.aggregated_output, "outerr");
        assert!(!output.timed_out);
    }

    #[test]
    fn timeout_forces_standard_exit_code() {
        let output = SandboxExecOutput::from_text_output(
            1,
            "".to_string(),
            "timeout".to_string(),
            Duration::from_millis(50),
            true,
        );

        assert_eq!(output.exit_code, SandboxExecOutput::TIMEOUT_EXIT_CODE);
        assert_eq!(output.stderr, "timeout");
        assert!(output.timed_out);
    }

    #[test]
    fn converts_lossy_utf8_for_binary_streams() {
        let stdout = b"ok\xF0\x28\x8C\x28";
        let output =
            SandboxExecOutput::from_utf8_lossy(0, stdout, b"", Duration::from_millis(1), false);

        assert!(output.stdout.contains('�'));
    }
}
