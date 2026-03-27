#![cfg(target_os = "macos")]

use std::collections::HashMap;
use std::fs;
use std::io::{self, Read};
use std::net::{TcpListener, TcpStream};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use procwarden::{
    SandboxAccess, SandboxCommandRequest, SandboxError, SandboxManager, SandboxPolicy,
};

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(prefix: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be monotonic")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("procwarden-macos-{prefix}-{nonce}"));
        fs::create_dir_all(&path).expect("temp directory should be created");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn dup_inheritable_fd(fd: i32) -> i32 {
    let duplicated = unsafe { libc::fcntl(fd, libc::F_DUPFD, 200) };
    assert!(duplicated >= 0, "duplicating fd should succeed");

    let flags = unsafe { libc::fcntl(duplicated, libc::F_GETFD) };
    assert!(flags >= 0, "querying fd flags should succeed");

    let set_rc = unsafe { libc::fcntl(duplicated, libc::F_SETFD, flags & !libc::FD_CLOEXEC) };
    assert_eq!(set_rc, 0, "clearing close-on-exec should succeed");

    duplicated
}

#[test]
fn macos_network_disabled_rejects_inherited_connected_socket_fd_writes() {
    let manager = SandboxManager::new();
    let workspace = TempDir::new("network-inherited-fd");

    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("listener should bind");
    let port = listener
        .local_addr()
        .expect("listener addr should resolve")
        .port();
    let (tx, rx) = mpsc::channel();

    thread::spawn(move || {
        let result = (|| {
            let (mut accepted, _) = listener.accept()?;
            accepted.set_read_timeout(Some(Duration::from_secs(2)))?;
            let mut buf = [0_u8; 4];
            accepted.read_exact(&mut buf)?;
            Ok::<String, io::Error>(String::from_utf8_lossy(&buf).to_string())
        })();
        let _ = tx.send(result);
    });

    let stream = TcpStream::connect(("127.0.0.1", port)).expect("stream should connect");
    let inherited_fd = dup_inheritable_fd(stream.as_raw_fd());

    let request = SandboxCommandRequest {
        command: vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            format!("printf 'PING' >&{inherited_fd}"),
        ],
        cwd: workspace.path().to_path_buf(),
        env: HashMap::new(),
        timeout_ms: Some(4_000),
    };
    let policy = SandboxPolicy {
        path_permissions: Vec::new(),
        default_access: SandboxAccess::ReadWrite,
        network_access: false,
    };

    let output = match manager.execute(&request, &policy) {
        Ok(output) => output,
        Err(SandboxError::Unavailable(_)) => {
            unsafe {
                libc::close(inherited_fd);
            }
            drop(stream);
            return;
        }
        Err(error) => panic!("unexpected network inherited-fd manager error: {error:?}"),
    };

    unsafe {
        libc::close(inherited_fd);
    }
    drop(stream);

    assert_ne!(
        output.exit_code, 0,
        "inherited connected socket fd should be closed before exec"
    );

    let observation = rx
        .recv_timeout(Duration::from_secs(3))
        .expect("listener thread should report read outcome");
    if let Ok(payload) = observation {
        panic!("inherited socket fd should not deliver payload, got {payload}");
    }
}

#[test]
fn macos_readonly_blocks_writes_via_inherited_writable_file_fd() {
    let manager = SandboxManager::new();
    let workspace = TempDir::new("readonly-inherited-file-fd");

    let target = workspace.path().join("target.txt");
    fs::write(&target, "seed").expect("seed file should exist");

    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&target)
        .expect("seed file should open for inherited fd setup");

    assert!(
        unsafe { libc::lseek(file.as_raw_fd(), 0, libc::SEEK_SET) } >= 0,
        "lseek should succeed before inherited write probe"
    );
    let inherited_fd = dup_inheritable_fd(file.as_raw_fd());

    let request = SandboxCommandRequest {
        command: vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            format!("printf 'PWN!' >&{inherited_fd}"),
        ],
        cwd: workspace.path().to_path_buf(),
        env: HashMap::new(),
        timeout_ms: Some(4_000),
    };
    let policy = SandboxPolicy {
        path_permissions: Vec::new(),
        default_access: SandboxAccess::ReadOnly,
        network_access: true,
    };

    let output = match manager.execute(&request, &policy) {
        Ok(output) => output,
        Err(SandboxError::Unavailable(_)) => {
            unsafe {
                libc::close(inherited_fd);
            }
            drop(file);
            return;
        }
        Err(error) => panic!("unexpected readonly inherited-fd manager error: {error:?}"),
    };

    unsafe {
        libc::close(inherited_fd);
    }
    drop(file);

    assert_ne!(
        output.exit_code, 0,
        "inherited writable file fd should be closed before exec"
    );
    assert_eq!(
        fs::read_to_string(&target).expect("target should remain readable"),
        "seed",
        "readonly policy should not be bypassable via inherited file fd"
    );
}
