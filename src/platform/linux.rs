use std::collections::BTreeMap;
use std::ffi::CString;
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
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

use crate::{
    SandboxCommandRequest, SandboxDefaultAccess, SandboxError, SandboxExecOutput, SandboxPolicy,
};

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

    let default_write_access = policy.default_write_access();
    let read_only_paths = policy.read_only_paths();
    let denied_paths = policy.denied_paths();
    let writable_roots = policy.writable_paths();
    let network_access = policy.network_access;
    let host_uid = unsafe { libc::geteuid() };
    let host_gid = unsafe { libc::getegid() };

    let mount_overlay_entries = if default_write_access {
        let normalized_read_only_overlays = normalize_existing_overlay_paths(
            &read_only_paths,
            "read_only",
            overlay_context_label(SandboxDefaultAccess::ReadWrite),
        )?;
        let normalized_deny_overlays = normalize_existing_overlay_paths(
            &denied_paths,
            "deny",
            overlay_context_label(SandboxDefaultAccess::ReadWrite),
        )?;
        collect_readwrite_overlay_entries(&normalized_read_only_overlays, &normalized_deny_overlays)
    } else {
        let normalized_deny_overlays = normalize_existing_overlay_paths(
            &denied_paths,
            "deny",
            overlay_context_label(SandboxDefaultAccess::ReadOnly),
        )?;
        collect_deny_overlay_entries(&normalized_deny_overlays)
    };
    let should_install_mount_overlays = !mount_overlay_entries.is_empty();

    unsafe {
        command.pre_exec(move || {
            if should_install_mount_overlays {
                install_readwrite_mount_overlays_on_current_process(
                    &mount_overlay_entries,
                    host_uid,
                    host_gid,
                )?;
            }
            if !default_write_access {
                install_filesystem_landlock_rules_on_current_thread(&writable_roots)?;
            }
            if !network_access {
                install_network_seccomp_filter_on_current_thread()?;
            }
            close_non_stdio_fds_on_current_process()?;
            Ok(())
        });
    }

    let execution = run_command_with_timeout(&mut command, request.timeout_ms, start);
    if should_install_mount_overlays {
        match execution {
            Err(SandboxError::Io(error)) if is_overlay_namespace_unavailable_error(&error) => {
                Err(SandboxError::Unavailable(format!(
                    "linux path overlays require mount-namespace support (CLONE_NEWUSER/CLONE_NEWNS or CAP_SYS_ADMIN): {error}"
                )))
            }
            other => other,
        }
    } else {
        execution
    }
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReadWriteOverlayKind {
    ReadOnly,
    Deny,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReadWriteOverlayEntry {
    path: PathBuf,
    kind: ReadWriteOverlayKind,
}

fn normalize_existing_overlay_paths(
    paths: &[PathBuf],
    label: &str,
    context: &str,
) -> Result<Vec<PathBuf>, SandboxError> {
    let mut normalized = Vec::with_capacity(paths.len());
    for path in paths {
        let resolved = normalize_scope_path(path)?;
        if !resolved.exists() {
            return Err(SandboxError::InvalidRequest(format!(
                "linux backend requires existing {label} overlay targets for {context}: {}",
                path.display()
            )));
        }
        normalized.push(resolved);
    }
    Ok(normalized)
}

fn overlay_context_label(default_access: SandboxDefaultAccess) -> &'static str {
    match default_access {
        SandboxDefaultAccess::ReadWrite => "default_access=ReadWrite",
        SandboxDefaultAccess::ReadOnly => "default_access=ReadOnly with deny overlays",
    }
}

fn collect_readwrite_overlay_entries(
    read_only_paths: &[PathBuf],
    denied_paths: &[PathBuf],
) -> Vec<ReadWriteOverlayEntry> {
    let mut merged = BTreeMap::new();
    for path in read_only_paths {
        merged.insert(path.clone(), ReadWriteOverlayKind::ReadOnly);
    }
    for path in denied_paths {
        merged.insert(path.clone(), ReadWriteOverlayKind::Deny);
    }

    let mut entries = merged
        .into_iter()
        .map(|(path, kind)| ReadWriteOverlayEntry { path, kind })
        .collect::<Vec<_>>();

    entries.sort_by(|left, right| {
        path_depth(&right.path)
            .cmp(&path_depth(&left.path))
            .then_with(|| left.path.cmp(&right.path))
    });
    entries
}

fn collect_deny_overlay_entries(denied_paths: &[PathBuf]) -> Vec<ReadWriteOverlayEntry> {
    let mut entries = denied_paths
        .iter()
        .cloned()
        .map(|path| ReadWriteOverlayEntry {
            path,
            kind: ReadWriteOverlayKind::Deny,
        })
        .collect::<Vec<_>>();

    entries.sort_by(|left, right| {
        path_depth(&right.path)
            .cmp(&path_depth(&left.path))
            .then_with(|| left.path.cmp(&right.path))
    });
    entries
}

fn path_depth(path: &Path) -> usize {
    path.components().count()
}

fn install_readwrite_mount_overlays_on_current_process(
    overlays: &[ReadWriteOverlayEntry],
    host_uid: libc::uid_t,
    host_gid: libc::gid_t,
) -> io::Result<()> {
    if overlays.is_empty() {
        return Ok(());
    }

    enter_overlay_mount_namespace(host_uid, host_gid)?;

    let scratch_root = create_overlay_scratch_root()?;
    for (index, overlay) in overlays.iter().enumerate() {
        match overlay.kind {
            ReadWriteOverlayKind::ReadOnly => {
                apply_readonly_bind_mount(&overlay.path)?;
            }
            ReadWriteOverlayKind::Deny => {
                apply_deny_bind_mount(&overlay.path, &scratch_root, index)?;
            }
        }
    }

    let _ = fs::remove_dir(&scratch_root);
    Ok(())
}

fn is_overlay_namespace_unavailable_error(error: &io::Error) -> bool {
    if matches!(
        error.kind(),
        io::ErrorKind::PermissionDenied | io::ErrorKind::Unsupported
    ) {
        return true;
    }

    matches!(
        error.raw_os_error(),
        Some(code)
            if code == libc::EPERM
                || code == libc::EOPNOTSUPP
                || code == libc::EINVAL
                || code == libc::ENOSYS
    )
}

fn enter_overlay_mount_namespace(host_uid: libc::uid_t, host_gid: libc::gid_t) -> io::Result<()> {
    let combined_flags = libc::CLONE_NEWUSER | libc::CLONE_NEWNS;
    if unsafe { libc::unshare(combined_flags) } == 0 {
        configure_current_process_user_namespace_mapping(host_uid, host_gid)?;
        return mark_mount_tree_private();
    }

    let combined_error = io::Error::last_os_error();
    let combined_code = combined_error.raw_os_error();
    if combined_code != Some(libc::EPERM) && combined_code != Some(libc::EINVAL) {
        return Err(io::Error::new(
            combined_error.kind(),
            format!("unshare(CLONE_NEWUSER|CLONE_NEWNS) failed: {combined_error}"),
        ));
    }

    let userns_result = unsafe { libc::unshare(libc::CLONE_NEWUSER) };
    if userns_result == 0 {
        configure_current_process_user_namespace_mapping(host_uid, host_gid)?;
    } else {
        let error = io::Error::last_os_error();
        let code = error.raw_os_error();
        if code != Some(libc::EPERM) && code != Some(libc::EINVAL) {
            return Err(io::Error::new(
                error.kind(),
                format!("unshare(CLONE_NEWUSER) failed: {error}"),
            ));
        }
    }

    if unsafe { libc::unshare(libc::CLONE_NEWNS) } != 0 {
        let error = io::Error::last_os_error();
        return Err(io::Error::new(
            error.kind(),
            format!("unshare(CLONE_NEWNS) failed: {error}"),
        ));
    }

    mark_mount_tree_private()
}

fn configure_current_process_user_namespace_mapping(
    host_uid: libc::uid_t,
    host_gid: libc::gid_t,
) -> io::Result<()> {
    match fs::write("/proc/self/setgroups", "deny\n") {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(io::Error::new(
                error.kind(),
                format!("writing /proc/self/setgroups failed: {error}"),
            ));
        }
    }

    fs::write("/proc/self/uid_map", format!("0 {host_uid} 1\n")).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("writing /proc/self/uid_map failed: {error}"),
        )
    })?;
    fs::write("/proc/self/gid_map", format!("0 {host_gid} 1\n")).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("writing /proc/self/gid_map failed: {error}"),
        )
    })?;

    if unsafe { libc::setresgid(0, 0, 0) } != 0 {
        let error = io::Error::last_os_error();
        return Err(io::Error::new(
            error.kind(),
            format!("setresgid(0,0,0) failed: {error}"),
        ));
    }
    if unsafe { libc::setresuid(0, 0, 0) } != 0 {
        let error = io::Error::last_os_error();
        return Err(io::Error::new(
            error.kind(),
            format!("setresuid(0,0,0) failed: {error}"),
        ));
    }

    Ok(())
}

fn mark_mount_tree_private() -> io::Result<()> {
    let root = c_path(Path::new("/"))?;
    if unsafe {
        libc::mount(
            std::ptr::null(),
            root.as_ptr(),
            std::ptr::null(),
            (libc::MS_REC | libc::MS_PRIVATE) as libc::c_ulong,
            std::ptr::null(),
        )
    } != 0
    {
        let error = io::Error::last_os_error();
        return Err(io::Error::new(
            error.kind(),
            format!("mount(MS_PRIVATE) failed: {error}"),
        ));
    }
    Ok(())
}

fn create_overlay_scratch_root() -> io::Result<PathBuf> {
    let mut scratch = std::env::temp_dir();
    let pid = unsafe { libc::getpid() };
    scratch.push(format!("procwarden-linux-overlay-{pid}"));
    if scratch.exists() {
        let _ = fs::remove_dir_all(&scratch);
    }
    fs::create_dir_all(&scratch)?;
    Ok(scratch)
}

fn apply_readonly_bind_mount(target: &Path) -> io::Result<()> {
    let metadata = fs::metadata(target)?;
    let recursive = metadata.is_dir();
    bind_mount(target, target, recursive)?;
    remount_bind_readonly(target, recursive)
}

fn apply_deny_bind_mount(target: &Path, scratch_root: &Path, index: usize) -> io::Result<()> {
    let metadata = fs::metadata(target)?;
    let recursive = metadata.is_dir();

    let placeholder = if recursive {
        let dir = scratch_root.join(format!("deny-dir-{index}"));
        fs::create_dir_all(&dir)?;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o000))?;
        dir
    } else {
        let file = scratch_root.join(format!("deny-file-{index}"));
        fs::File::create(&file)?;
        fs::set_permissions(&file, fs::Permissions::from_mode(0o000))?;
        file
    };

    bind_mount(&placeholder, target, recursive)?;
    remount_bind_readonly(target, recursive)?;

    if recursive {
        let _ = fs::remove_dir(&placeholder);
    } else {
        let _ = fs::remove_file(&placeholder);
    }

    Ok(())
}

fn bind_mount(source: &Path, target: &Path, recursive: bool) -> io::Result<()> {
    let source_c = c_path(source)?;
    let target_c = c_path(target)?;
    let mut flags = libc::MS_BIND as libc::c_ulong;
    if recursive {
        flags |= libc::MS_REC as libc::c_ulong;
    }

    if unsafe {
        libc::mount(
            source_c.as_ptr(),
            target_c.as_ptr(),
            std::ptr::null(),
            flags,
            std::ptr::null(),
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

fn remount_bind_readonly(target: &Path, recursive: bool) -> io::Result<()> {
    let target_c = c_path(target)?;
    let mut flags = (libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY) as libc::c_ulong;
    if recursive {
        flags |= libc::MS_REC as libc::c_ulong;
    }

    if unsafe {
        libc::mount(
            std::ptr::null(),
            target_c.as_ptr(),
            std::ptr::null(),
            flags,
            std::ptr::null(),
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

fn c_path(path: &Path) -> io::Result<CString> {
    CString::new(path.as_os_str().as_bytes()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("path contains interior NUL bytes: {}", path.display()),
        )
    })
}

fn install_filesystem_landlock_rules_on_current_thread(
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

    ruleset = ruleset
        .add_rules(landlock::path_beneath_rules(&["/"], access_ro))
        .map_err(to_io_error)?;

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
