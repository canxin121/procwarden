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
