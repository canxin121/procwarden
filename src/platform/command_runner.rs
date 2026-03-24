use std::io::{self, Read};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use command_group::CommandGroup;

use crate::{SandboxError, SandboxExecOutput};

pub(super) fn configure_piped_stdio(command: &mut Command) {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
}

pub(super) fn run_command_with_timeout(
    command: &mut Command,
    timeout_ms: Option<u64>,
    start: Instant,
) -> Result<SandboxExecOutput, SandboxError> {
    let mut child = command.group_spawn()?;

    let stdout = child
        .inner()
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("child stdout pipe unavailable"))?;
    let stderr = child
        .inner()
        .stderr
        .take()
        .ok_or_else(|| io::Error::other("child stderr pipe unavailable"))?;

    let stdout_thread = spawn_pipe_reader(stdout);
    let stderr_thread = spawn_pipe_reader(stderr);

    let mut timed_out = false;
    if let Some(timeout_ms) = timeout_ms {
        let timeout = Duration::from_millis(timeout_ms);
        loop {
            if child.try_wait()?.is_some() {
                break;
            }

            if start.elapsed() >= timeout {
                timed_out = true;
                let _ = child.kill();
                break;
            }

            thread::sleep(Duration::from_millis(10));
        }
    }

    let status = child.wait()?;
    let stdout = stdout_thread.join().unwrap_or_default();
    let stderr = stderr_thread.join().unwrap_or_default();

    Ok(SandboxExecOutput::from_utf8_lossy(
        status.code().unwrap_or(-1),
        &stdout,
        &stderr,
        start.elapsed(),
        timed_out,
    ))
}

fn spawn_pipe_reader(pipe: impl Read + Send + 'static) -> thread::JoinHandle<Vec<u8>> {
    thread::spawn(move || read_pipe(pipe))
}

fn read_pipe(mut pipe: impl Read) -> Vec<u8> {
    let mut output = Vec::new();
    let _ = pipe.read_to_end(&mut output);
    output
}

#[cfg(test)]
mod tests {
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
}
