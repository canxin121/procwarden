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
