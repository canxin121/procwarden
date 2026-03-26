use std::collections::BTreeMap;
use std::io;
use std::os::unix::process::CommandExt;
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::time::Instant;

use landlock::ABI;
use landlock::Access;
use landlock::AccessFs;
use landlock::CompatLevel;
use landlock::Compatible;
use landlock::Ruleset;
use landlock::RulesetAttr;
use landlock::RulesetCreatedAttr;
use seccompiler::BpfProgram;
use seccompiler::SeccompAction;
use seccompiler::SeccompCmpArgLen;
use seccompiler::SeccompCmpOp;
use seccompiler::SeccompCondition;
use seccompiler::SeccompFilter;
use seccompiler::SeccompRule;
use seccompiler::TargetArch;
use seccompiler::apply_filter;

use crate::{SandboxCommandRequest, SandboxError, SandboxExecOutput, SandboxPolicy};

use super::command_runner::{configure_piped_stdio, run_command_with_timeout};

pub(super) fn execute(
    request: &SandboxCommandRequest,
    policy: &SandboxPolicy,
) -> Result<SandboxExecOutput, SandboxError> {
    let start = Instant::now();

    let mut command = Command::new(&request.command[0]);
    if request.command.len() > 1 {
        command.args(&request.command[1..]);
    }

    command
        .current_dir(&request.cwd)
        .env_clear()
        .envs(request.env.clone());
    configure_piped_stdio(&mut command);

    let default_read_access = policy.default_read_access();
    let default_write_access = policy.default_write_access();
    let read_only_paths = policy.read_only_paths();
    let denied_paths = policy.denied_paths();
    let readable_roots = policy.readable_paths();
    let writable_roots = policy.writable_paths();
    let network_access = policy.network_access;

    validate_linux_policy_shape(
        default_read_access,
        default_write_access,
        &read_only_paths,
        &denied_paths,
        &readable_roots,
        &writable_roots,
    )?;

    unsafe {
        command.pre_exec(move || {
            close_non_stdio_fds_on_current_process()?;
            if !network_access {
                install_network_seccomp_filter_on_current_thread()?;
            }
            if !default_write_access {
                install_filesystem_landlock_rules_on_current_thread(
                    default_read_access,
                    &readable_roots,
                    &writable_roots,
                )?;
            }
            Ok(())
        });
    }

    run_command_with_timeout(&mut command, request.timeout_ms, start)
}

fn validate_linux_policy_shape(
    default_read_access: bool,
    default_write_access: bool,
    read_only_paths: &[PathBuf],
    denied_paths: &[PathBuf],
    readable_roots: &[PathBuf],
    writable_roots: &[PathBuf],
) -> Result<(), SandboxError> {
    if default_write_access && (!read_only_paths.is_empty() || !denied_paths.is_empty()) {
        return Err(SandboxError::InvalidRequest(
            "linux backend does not support default_access=ReadWrite with ReadOnly/NoAccess path overrides; use default_access=ReadOnly or NoAccess with explicit read_write carve-outs"
                .to_string(),
        ));
    }

    if denied_paths.is_empty() {
        return Ok(());
    }

    if default_read_access {
        return Err(SandboxError::InvalidRequest(
            "linux backend does not support NoAccess path overrides when default_access grants read access; use default_access=NoAccess with explicit allow paths"
                .to_string(),
        ));
    }

    let mut allow_roots = Vec::with_capacity(readable_roots.len() + writable_roots.len());
    allow_roots.extend(readable_roots.iter().cloned());
    allow_roots.extend(writable_roots.iter().cloned());

    if denied_overlaps_any_allowed_root(denied_paths, &allow_roots)? {
        return Err(SandboxError::InvalidRequest(
            "linux backend does not support overlapping allow and NoAccess path overrides under default_access=NoAccess; Landlock cannot express subtractive deny rules"
                .to_string(),
        ));
    }

    Ok(())
}

fn denied_overlaps_any_allowed_root(
    denied_paths: &[PathBuf],
    allow_roots: &[PathBuf],
) -> Result<bool, SandboxError> {
    if denied_paths.is_empty() || allow_roots.is_empty() {
        return Ok(false);
    }

    let normalized_denied = denied_paths
        .iter()
        .map(|path| normalize_scope_path(path))
        .collect::<Result<Vec<_>, _>>()?;
    let normalized_allowed = allow_roots
        .iter()
        .map(|path| normalize_scope_path(path))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(normalized_denied.iter().any(|denied| {
        normalized_allowed
            .iter()
            .any(|allowed| paths_overlap(denied, allowed))
    }))
}

fn normalize_scope_path(path: &Path) -> Result<PathBuf, SandboxError> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };

    match absolute.canonicalize() {
        Ok(canonical) => Ok(canonical),
        Err(_) => Ok(lexically_normalize_path(&absolute)),
    }
}

fn lexically_normalize_path(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                let _ = normalized.pop();
            }
            Component::Prefix(_) | Component::RootDir | Component::Normal(_) => {
                normalized.push(component.as_os_str());
            }
        }
    }
    normalized
}

fn paths_overlap(left: &Path, right: &Path) -> bool {
    left.starts_with(right) || right.starts_with(left)
}

fn close_non_stdio_fds_on_current_process() -> io::Result<()> {
    let open_fds = match collect_open_fds_from_proc() {
        Ok(fds) => fds,
        Err(_) => collect_fd_range_from_rlimit()?,
    };

    for fd in open_fds {
        if fd <= 2 {
            continue;
        }

        close_fd_ignore_ebadf(fd)?;
    }

    Ok(())
}

fn collect_open_fds_from_proc() -> io::Result<Vec<i32>> {
    let mut fds = Vec::new();
    for entry in std::fs::read_dir("/proc/self/fd")? {
        let entry = entry?;
        let Some(value) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse().ok())
        else {
            continue;
        };
        fds.push(value);
    }
    Ok(fds)
}

fn collect_fd_range_from_rlimit() -> io::Result<Vec<i32>> {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 {
        return Err(io::Error::last_os_error());
    }

    let cap = if limit.rlim_cur == libc::RLIM_INFINITY {
        1_048_576_u64
    } else {
        limit.rlim_cur.min(1_048_576)
    };

    Ok((3..cap as i32).collect())
}

fn close_fd_ignore_ebadf(fd: i32) -> io::Result<()> {
    if unsafe { libc::close(fd) } == 0 {
        return Ok(());
    }

    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::EBADF) {
        Ok(())
    } else {
        Err(error)
    }
}

fn install_filesystem_landlock_rules_on_current_thread(
    default_read_access: bool,
    readable_roots: &[PathBuf],
    writable_roots: &[PathBuf],
) -> io::Result<()> {
    let abi = ABI::V5;
    let access_rw = AccessFs::from_all(abi);
    let access_ro = AccessFs::from_read(abi);

    let mut ruleset = Ruleset::default()
        .set_compatibility(CompatLevel::BestEffort)
        .handle_access(access_rw)
        .map_err(to_io_error)?
        .create()
        .map_err(to_io_error)?;

    if default_read_access {
        ruleset = ruleset
            .add_rules(landlock::path_beneath_rules(&["/"], access_ro))
            .map_err(to_io_error)?;
    } else if !readable_roots.is_empty() {
        let refs = readable_roots
            .iter()
            .map(PathBuf::as_path)
            .collect::<Vec<_>>();
        ruleset = ruleset
            .add_rules(landlock::path_beneath_rules(&refs, access_ro))
            .map_err(to_io_error)?;
    }

    ruleset = ruleset
        .add_rules(landlock::path_beneath_rules(&["/dev/null"], access_rw))
        .map_err(to_io_error)?
        .set_no_new_privs(true);

    if !writable_roots.is_empty() {
        let refs = writable_roots
            .iter()
            .map(PathBuf::as_path)
            .collect::<Vec<_>>();
        ruleset = ruleset
            .add_rules(landlock::path_beneath_rules(&refs, access_rw))
            .map_err(to_io_error)?;
    }

    let status = ruleset.restrict_self().map_err(to_io_error)?;
    if status.ruleset == landlock::RulesetStatus::NotEnforced {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "landlock could not enforce all filesystem rules",
        ));
    }
    Ok(())
}

fn install_network_seccomp_filter_on_current_thread() -> io::Result<()> {
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();

    let mut deny_syscall = |number: i64| {
        rules.insert(number, vec![]);
    };

    deny_syscall(libc::SYS_connect);
    deny_syscall(libc::SYS_accept);
    deny_syscall(libc::SYS_accept4);
    deny_syscall(libc::SYS_bind);
    deny_syscall(libc::SYS_listen);
    deny_syscall(libc::SYS_getpeername);
    deny_syscall(libc::SYS_getsockname);
    deny_syscall(libc::SYS_shutdown);
    deny_syscall(libc::SYS_sendto);
    deny_syscall(libc::SYS_sendmsg);
    deny_syscall(libc::SYS_sendmmsg);
    deny_syscall(libc::SYS_recvmsg);
    deny_syscall(libc::SYS_recvmmsg);
    deny_syscall(libc::SYS_getsockopt);
    deny_syscall(libc::SYS_setsockopt);
    deny_syscall(libc::SYS_ptrace);

    let unix_only = SeccompRule::new(vec![
        SeccompCondition::new(
            0,
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::Ne,
            libc::AF_UNIX as u64,
        )
        .map_err(to_io_error)?,
    ])
    .map_err(to_io_error)?;
    rules.insert(libc::SYS_socket, vec![unix_only.clone()]);
    rules.insert(libc::SYS_socketpair, vec![unix_only]);

    let arch = if cfg!(target_arch = "x86_64") {
        TargetArch::x86_64
    } else if cfg!(target_arch = "aarch64") {
        TargetArch::aarch64
    } else {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "unsupported architecture for seccomp sandbox",
        ));
    };

    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::Errno(libc::EPERM as u32),
        arch,
    )
    .map_err(to_io_error)?;

    let program: BpfProgram = filter.try_into().map_err(to_io_error)?;
    apply_filter(&program).map_err(to_io_error)?;
    Ok(())
}

fn to_io_error(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, error.to_string())
}
