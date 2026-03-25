use std::process::Command;
use std::time::Instant;

use super::{configure_piped_stdio, run_command_with_timeout};

#[test]
fn captures_stdout_stderr_and_exit_code() {
    let mut command = platform_script_command(if cfg!(windows) {
        "echo out && echo err 1>&2 && exit /b 7"
    } else {
        "printf out && printf err 1>&2 && exit 7"
    });
    configure_piped_stdio(&mut command);

    let output = run_command_with_timeout(&mut command, Some(5_000), Instant::now())
        .expect("command should run");

    assert_eq!(output.exit_code, 7);
    assert!(output.stdout.contains("out"));
    assert!(output.stderr.contains("err"));
    assert!(output.aggregated_output.contains("out"));
    assert!(output.aggregated_output.contains("err"));
    assert!(!output.timed_out);
}

#[test]
fn timeout_sets_expected_exit_code_and_flag() {
    let mut command = platform_script_command(if cfg!(windows) {
        "ping 127.0.0.1 -n 6 >NUL"
    } else {
        "sleep 1"
    });
    configure_piped_stdio(&mut command);

    let output = run_command_with_timeout(&mut command, Some(50), Instant::now())
        .expect("timeout execution should still return output");

    assert_eq!(output.exit_code, 124);
    assert!(output.timed_out);
}

fn platform_script_command(script: &str) -> Command {
    if cfg!(windows) {
        let mut command = Command::new("cmd");
        command.args(["/C", script]);
        command
    } else {
        let mut command = Command::new("sh");
        command.args(["-c", script]);
        command
    }
}
