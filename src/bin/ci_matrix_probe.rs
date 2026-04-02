use std::collections::HashMap;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
#[cfg(target_os = "windows")]
use std::time::Instant;
use std::time::{SystemTime, UNIX_EPOCH};

use procwarden::{
    SandboxCommandRequest, SandboxDefaultAccess, SandboxError, SandboxManager,
    SandboxPathPermission, SandboxPolicy,
};

fn main() -> Result<(), Box<dyn Error>> {
    println!("platform={}", std::env::consts::OS);

    probe_frontloaded_missing_path_validation()?;

    #[cfg(target_os = "linux")]
    probe_linux_overlay_capability()?;

    #[cfg(target_os = "macos")]
    probe_macos_matrix_contract()?;

    #[cfg(target_os = "windows")]
    probe_windows_matrix_and_timings()?;

    Ok(())
}

fn probe_frontloaded_missing_path_validation() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new("frontloaded-missing-path");
    let manager = SandboxManager::new();
    let missing_path = fixture.runtime_cwd.join("missing-readonly-target");

    let policy = SandboxPolicy {
        default_access: SandboxDefaultAccess::ReadWrite,
        network_access: false,
        path_permissions: vec![SandboxPathPermission::read_only(missing_path.clone())],
    };

    let result = manager.execute(
        &sandbox_request(exit_zero_command(), &fixture.runtime_cwd),
        &policy,
    );
    match result {
        Err(SandboxError::InvalidRequest(message))
            if message.contains("read_only path does not exist") =>
        {
            println!("manager.missing_path_validation=frontloaded_invalid_request");
            Ok(())
        }
        other => Err(format!(
            "expected frontloaded InvalidRequest for missing policy path, got {other:?}"
        )
        .into()),
    }
}

#[cfg(target_os = "linux")]
fn probe_linux_overlay_capability() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new("linux-overlay-capability");
    let manager = SandboxManager::new();
    let policy = readwrite_with_readonly_policy(&fixture);

    let bootstrap = manager.execute(
        &sandbox_request(exit_zero_command(), &fixture.runtime_cwd),
        &policy,
    );
    match bootstrap {
        Ok(output) => {
            assert_success(&output, "linux bootstrap command")?;

            let write_target = fixture.rw_dir.join("linux-overlay-write.txt");
            let write_output = manager.execute(
                &sandbox_request(
                    write_command(&write_target, "overlay-ok"),
                    &fixture.runtime_cwd,
                ),
                &policy,
            )?;
            assert_success(&write_output, "linux writable carve-out")?;

            let readonly_target = fixture.ro_dir.join("linux-overlay-readonly.txt");
            let readonly_output = manager.execute(
                &sandbox_request(
                    write_command(&readonly_target, "blocked"),
                    &fixture.runtime_cwd,
                ),
                &policy,
            )?;
            assert_failure(&readonly_output, "linux readonly overlay enforcement")?;

            println!("linux.overlay_subtractive=available");
            println!("linux.readwrite_plus_readonly_enforcement=ok");
            Ok(())
        }
        Err(SandboxError::Unavailable(message)) if message.contains("mount-namespace support") => {
            println!("linux.overlay_subtractive=unavailable");
            println!("linux.unavailable_reason={message}");
            Ok(())
        }
        Err(error) => Err(format!("unexpected linux overlay capability result: {error:?}").into()),
    }
}

#[cfg(target_os = "macos")]
fn probe_macos_matrix_contract() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new("macos-matrix-contract");
    let manager = SandboxManager::new();
    let policy = SandboxPolicy {
        default_access: SandboxDefaultAccess::ReadOnly,
        network_access: false,
        path_permissions: vec![
            SandboxPathPermission::read_write(fixture.runtime_cwd.clone()),
            SandboxPathPermission::read_write(fixture.alias_rw_dir.clone()),
            SandboxPathPermission::read_only(fixture.ro_dir.clone()),
        ],
    };

    let write_target = fixture.rw_dir.join("macos-overlay-write.txt");
    let write_output = manager.execute(
        &sandbox_request(
            write_command(&write_target, "seatbelt-ok"),
            &fixture.runtime_cwd,
        ),
        &policy,
    )?;
    assert_success(&write_output, "macos writable carve-out")?;

    let readonly_target = fixture.ro_dir.join("macos-readonly-blocked.txt");
    let readonly_output = manager.execute(
        &sandbox_request(
            write_command(&readonly_target, "blocked"),
            &fixture.runtime_cwd,
        ),
        &policy,
    )?;
    assert_failure(&readonly_output, "macos readonly enforcement")?;

    println!("macos.readonly_plus_readwrite=usable");
    println!("macos.alias_path_canonicalization=ok");
    Ok(())
}

#[cfg(target_os = "windows")]
fn probe_windows_matrix_and_timings() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new("windows-matrix-contract");
    let manager = SandboxManager::new();

    println!(
        "windows.host_process_elevated={}",
        windows_host_process_is_elevated()?
    );

    probe_windows_network_access_shape(&manager, &fixture)?;
    probe_windows_policy_shape_matrix(&manager, &fixture)?;
    probe_windows_enforcement_cases(&manager, &fixture)?;
    probe_windows_timing_samples(&manager, &fixture)?;

    Ok(())
}

#[cfg(target_os = "windows")]
fn probe_windows_network_access_shape(
    manager: &SandboxManager,
    fixture: &Fixture,
) -> Result<(), Box<dyn Error>> {
    let policy = SandboxPolicy {
        default_access: SandboxDefaultAccess::ReadOnly,
        network_access: true,
        path_permissions: vec![SandboxPathPermission::read_write(
            fixture.runtime_cwd.clone(),
        )],
    };

    let result = manager.execute(
        &sandbox_request(exit_zero_command(), &fixture.runtime_cwd),
        &policy,
    );
    match result {
        Err(SandboxError::InvalidRequest(message)) if message.contains("network_access=true") => {
            println!("windows.network_access_true=invalid_request");
            Ok(())
        }
        other => Err(format!(
            "expected InvalidRequest for windows network_access=true, got {other:?}"
        )
        .into()),
    }
}

#[cfg(target_os = "windows")]
fn probe_windows_policy_shape_matrix(
    manager: &SandboxManager,
    fixture: &Fixture,
) -> Result<(), Box<dyn Error>> {
    let cases = vec![
        WindowsMatrixCase::new(
            "readwrite_none",
            SandboxDefaultAccess::ReadWrite,
            false,
            false,
        ),
        WindowsMatrixCase::new(
            "readwrite_readwrite",
            SandboxDefaultAccess::ReadWrite,
            false,
            true,
        ),
        WindowsMatrixCase::new(
            "readwrite_readonly",
            SandboxDefaultAccess::ReadWrite,
            true,
            false,
        ),
        WindowsMatrixCase::new(
            "readwrite_readonly_readwrite",
            SandboxDefaultAccess::ReadWrite,
            true,
            true,
        ),
        WindowsMatrixCase::new(
            "readonly_none",
            SandboxDefaultAccess::ReadOnly,
            false,
            false,
        ),
        WindowsMatrixCase::new(
            "readonly_readonly",
            SandboxDefaultAccess::ReadOnly,
            true,
            false,
        ),
        WindowsMatrixCase::new(
            "readonly_readwrite",
            SandboxDefaultAccess::ReadOnly,
            false,
            true,
        ),
        WindowsMatrixCase::new(
            "readonly_readonly_readwrite",
            SandboxDefaultAccess::ReadOnly,
            true,
            true,
        ),
    ];

    for case in cases {
        let result = manager.execute(
            &sandbox_request(exit_zero_command(), &fixture.runtime_cwd),
            &case.policy(fixture),
        );
        println!(
            "windows.matrix.{}={}",
            case.name,
            render_windows_matrix_result(&result)
        );
    }

    Ok(())
}

#[cfg(target_os = "windows")]
fn probe_windows_enforcement_cases(
    manager: &SandboxManager,
    fixture: &Fixture,
) -> Result<(), Box<dyn Error>> {
    let read_only_policy = SandboxPolicy {
        default_access: SandboxDefaultAccess::ReadOnly,
        network_access: false,
        path_permissions: vec![
            SandboxPathPermission::read_write(fixture.runtime_cwd.clone()),
            SandboxPathPermission::read_write(fixture.rw_dir.clone()),
        ],
    };

    let write_rw_target = fixture.rw_dir.join("probe-readonly-rw.txt");
    let write_rw = manager.execute(
        &sandbox_request(write_command(&write_rw_target, "ok"), &fixture.runtime_cwd),
        &read_only_policy,
    );
    if is_windows_wfp_unavailable(&write_rw) {
        println!("windows.enforcement.readonly_readwrite=wfp_unavailable");
        println!("windows.enforcement.readwrite_readonly=wfp_unavailable");
        println!("windows.timing.skipped_reason=wfp_unavailable");
        return Ok(());
    }
    assert_success(
        &write_rw
            .map_err(|error| format!("windows readonly+readwrite manager error: {error:?}"))?,
        "windows readonly+readwrite write carve-out",
    )?;

    let write_outside_target = fixture.outside_dir.join("probe-readonly-outside.txt");
    let write_outside = manager.execute(
        &sandbox_request(
            write_command(&write_outside_target, "blocked"),
            &fixture.runtime_cwd,
        ),
        &read_only_policy,
    );
    assert_failed_result(&write_outside, "windows readonly+readwrite outside write")?;
    println!("windows.enforcement.readonly_readwrite=ok");

    let read_write_policy = SandboxPolicy {
        default_access: SandboxDefaultAccess::ReadWrite,
        network_access: false,
        path_permissions: vec![
            SandboxPathPermission::read_write(fixture.runtime_cwd.clone()),
            SandboxPathPermission::read_only(fixture.ro_dir.clone()),
        ],
    };

    let write_outside_target = fixture.outside_dir.join("probe-readwrite-outside.txt");
    let write_outside = manager.execute(
        &sandbox_request(
            write_command(&write_outside_target, "outside-ok"),
            &fixture.runtime_cwd,
        ),
        &read_write_policy,
    );
    assert_success(
        &write_outside
            .map_err(|error| format!("windows readwrite+readonly manager error: {error:?}"))?,
        "windows readwrite+readonly outside write",
    )?;

    let write_ro_target = fixture.ro_dir.join("probe-readwrite-ro.txt");
    let write_ro = manager.execute(
        &sandbox_request(
            write_command(&write_ro_target, "blocked"),
            &fixture.runtime_cwd,
        ),
        &read_write_policy,
    );
    assert_failed_result(&write_ro, "windows readwrite+readonly readonly override")?;
    println!("windows.enforcement.readwrite_readonly=ok");

    Ok(())
}

#[cfg(target_os = "windows")]
fn probe_windows_timing_samples(
    manager: &SandboxManager,
    fixture: &Fixture,
) -> Result<(), Box<dyn Error>> {
    println!("windows.timing.note=wall_clock_ms_for_manager_execute");
    println!(
        "windows.timing.redundant_shapes_note=default_equivalent_entries_are_normalized_before_backend_dispatch"
    );

    let cases = vec![
        WindowsTimingCase::new("readonly_none", SandboxDefaultAccess::ReadOnly, vec![]),
        WindowsTimingCase::new(
            "readonly_readwrite",
            SandboxDefaultAccess::ReadOnly,
            vec![SandboxPathPermission::read_write(fixture.rw_dir.clone())],
        ),
        WindowsTimingCase::new(
            "readonly_readonly",
            SandboxDefaultAccess::ReadOnly,
            vec![SandboxPathPermission::read_only(fixture.ro_dir.clone())],
        ),
        WindowsTimingCase::new("readwrite_none", SandboxDefaultAccess::ReadWrite, vec![]),
        WindowsTimingCase::new(
            "readwrite_readonly",
            SandboxDefaultAccess::ReadWrite,
            vec![SandboxPathPermission::read_only(fixture.ro_dir.clone())],
        ),
        WindowsTimingCase::new(
            "readwrite_readwrite",
            SandboxDefaultAccess::ReadWrite,
            vec![SandboxPathPermission::read_write(fixture.rw_dir.clone())],
        ),
    ];

    for case in cases {
        let Some(samples) = benchmark_windows_policy_case(manager, fixture, &case)? else {
            println!("windows.timing.skipped_reason=wfp_unavailable");
            return Ok(());
        };
        println!(
            "windows.timing.{}.samples_ms={}",
            case.name,
            join_samples(&samples)
        );
        println!(
            "windows.timing.{}.avg_ms={}",
            case.name,
            average_ms(&samples)
        );
        println!(
            "windows.timing.{}.min_ms={}",
            case.name,
            samples.iter().min().copied().unwrap_or_default()
        );
        println!(
            "windows.timing.{}.max_ms={}",
            case.name,
            samples.iter().max().copied().unwrap_or_default()
        );
    }

    Ok(())
}

#[cfg(target_os = "windows")]
fn benchmark_windows_policy_case(
    manager: &SandboxManager,
    fixture: &Fixture,
    case: &WindowsTimingCase,
) -> Result<Option<Vec<u128>>, Box<dyn Error>> {
    const ITERATIONS: usize = 3;

    let mut samples = Vec::with_capacity(ITERATIONS);
    let policy = SandboxPolicy {
        default_access: case.default_access,
        network_access: false,
        path_permissions: case.path_permissions.clone(),
    };

    for _ in 0..ITERATIONS {
        let start = Instant::now();
        let result = manager.execute(
            &sandbox_request(exit_zero_command(), &fixture.runtime_cwd),
            &policy,
        );
        if is_windows_wfp_unavailable(&result) {
            return Ok(None);
        }
        let output = result.map_err(|error| {
            format!(
                "windows timing case {} failed to execute: {error:?}",
                case.name
            )
        })?;
        assert_success(&output, case.name)?;
        samples.push(start.elapsed().as_millis());
    }

    Ok(Some(samples))
}

#[cfg(target_os = "windows")]
fn render_windows_matrix_result(
    result: &Result<procwarden::SandboxExecOutput, SandboxError>,
) -> String {
    match result {
        Ok(output) if output.exit_code == 0 => "runnable".to_string(),
        Ok(output) => format!("command_failed(exit={})", output.exit_code),
        Err(SandboxError::InvalidRequest(message)) => {
            format!("invalid_request({})", sanitize_probe_message(message))
        }
        Err(SandboxError::Denied(message)) => {
            format!("denied({})", sanitize_probe_message(message))
        }
        Err(SandboxError::Unavailable(message)) => {
            format!("unavailable({})", sanitize_probe_message(message))
        }
        Err(SandboxError::Windows(message)) => {
            format!("windows_error({})", sanitize_probe_message(message))
        }
        Err(SandboxError::Io(error)) => {
            format!("io_error({})", sanitize_probe_message(&error.to_string()))
        }
    }
}

#[cfg(target_os = "windows")]
fn sanitize_probe_message(message: &str) -> String {
    message.replace(['\n', '\r'], " ")
}

#[cfg(target_os = "windows")]
fn is_windows_wfp_unavailable(
    result: &Result<procwarden::SandboxExecOutput, SandboxError>,
) -> bool {
    matches!(
        result,
        Err(SandboxError::Windows(message)) if message.contains("FwpmEngineOpen0 failed: 50")
    )
}

#[cfg(target_os = "windows")]
fn assert_failed_result(
    result: &Result<procwarden::SandboxExecOutput, SandboxError>,
    context: &str,
) -> Result<(), Box<dyn Error>> {
    match result {
        Ok(output) if output.exit_code != 0 => Ok(()),
        Ok(output) => Err(format!(
            "{context} succeeded unexpectedly: stdout={}, stderr={}",
            output.stdout, output.stderr
        )
        .into()),
        Err(error) => Err(format!("{context} returned unexpected manager error: {error:?}").into()),
    }
}

#[cfg(target_os = "windows")]
#[cfg(target_os = "windows")]
fn average_ms(samples: &[u128]) -> u128 {
    let total = samples.iter().sum::<u128>();
    total / samples.len() as u128
}

#[cfg(target_os = "windows")]
fn join_samples(samples: &[u128]) -> String {
    samples
        .iter()
        .map(|value| value.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

#[cfg(target_os = "windows")]
fn windows_host_process_is_elevated() -> Result<bool, Box<dyn Error>> {
    let output = std::process::Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)",
        ])
        .output()?;

    if !output.status.success() {
        return Err(format!(
            "powershell elevation probe failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }

    match String::from_utf8_lossy(&output.stdout).trim() {
        "True" => Ok(true),
        "False" => Ok(false),
        other => Err(format!("unexpected powershell elevation probe output: {other}").into()),
    }
}

#[cfg(target_os = "windows")]
struct WindowsMatrixCase {
    name: &'static str,
    default_access: SandboxDefaultAccess,
    include_read_only: bool,
    include_read_write: bool,
}

#[cfg(target_os = "windows")]
impl WindowsMatrixCase {
    const fn new(
        name: &'static str,
        default_access: SandboxDefaultAccess,
        include_read_only: bool,
        include_read_write: bool,
    ) -> Self {
        Self {
            name,
            default_access,
            include_read_only,
            include_read_write,
        }
    }

    fn policy(&self, fixture: &Fixture) -> SandboxPolicy {
        let mut path_permissions = Vec::new();
        if self.include_read_only {
            path_permissions.push(SandboxPathPermission::read_only(fixture.ro_dir.clone()));
        }
        if self.include_read_write {
            path_permissions.push(SandboxPathPermission::read_write(fixture.rw_dir.clone()));
        }

        SandboxPolicy {
            default_access: self.default_access,
            network_access: false,
            path_permissions,
        }
    }
}

#[cfg(target_os = "windows")]
struct WindowsTimingCase {
    name: &'static str,
    default_access: SandboxDefaultAccess,
    path_permissions: Vec<SandboxPathPermission>,
}

#[cfg(target_os = "windows")]
impl WindowsTimingCase {
    fn new(
        name: &'static str,
        default_access: SandboxDefaultAccess,
        path_permissions: Vec<SandboxPathPermission>,
    ) -> Self {
        Self {
            name,
            default_access,
            path_permissions,
        }
    }
}

#[cfg(target_os = "linux")]
fn readwrite_with_readonly_policy(fixture: &Fixture) -> SandboxPolicy {
    SandboxPolicy {
        default_access: SandboxDefaultAccess::ReadWrite,
        network_access: false,
        path_permissions: vec![SandboxPathPermission::read_only(fixture.ro_dir.clone())],
    }
}

fn assert_success(
    output: &procwarden::SandboxExecOutput,
    context: &str,
) -> Result<(), Box<dyn Error>> {
    if output.exit_code == 0 {
        return Ok(());
    }

    Err(format!(
        "{context} failed unexpectedly: exit_code={}, stdout={}, stderr={}",
        output.exit_code, output.stdout, output.stderr
    )
    .into())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn assert_failure(
    output: &procwarden::SandboxExecOutput,
    context: &str,
) -> Result<(), Box<dyn Error>> {
    if output.exit_code != 0 {
        return Ok(());
    }

    Err(format!(
        "{context} succeeded unexpectedly: stdout={}, stderr={}",
        output.stdout, output.stderr
    )
    .into())
}

fn sandbox_request(command: Vec<String>, cwd: &Path) -> SandboxCommandRequest {
    SandboxCommandRequest {
        command,
        cwd: cwd.to_path_buf(),
        env: sandbox_env(),
        timeout_ms: Some(2_500),
    }
}

fn sandbox_env() -> HashMap<String, String> {
    let mut env = HashMap::new();
    for key in [
        "PATH",
        "PATHEXT",
        "SystemRoot",
        "WINDIR",
        "HOME",
        "USERPROFILE",
        "TMP",
        "TEMP",
        "TMPDIR",
    ] {
        if let Ok(value) = std::env::var(key) {
            env.insert(key.to_string(), value);
        }
    }
    env
}

#[cfg(windows)]
fn exit_zero_command() -> Vec<String> {
    vec![
        "cmd.exe".to_string(),
        "/C".to_string(),
        "exit 0".to_string(),
    ]
}

#[cfg(not(windows))]
fn exit_zero_command() -> Vec<String> {
    vec![
        "/bin/sh".to_string(),
        "-c".to_string(),
        "exit 0".to_string(),
    ]
}

fn write_command(target: &Path, payload: &str) -> Vec<String> {
    #[cfg(windows)]
    {
        let escaped_target = escape_powershell_single_quoted(target);
        let escaped_payload = payload.replace('\'', "''");
        vec![
            "powershell.exe".to_string(),
            "-NoProfile".to_string(),
            "-NonInteractive".to_string(),
            "-Command".to_string(),
            format!(
                "try {{ [System.IO.File]::WriteAllText('{escaped_target}', '{escaped_payload}'); exit 0 }} catch {{ [Console]::Error.WriteLine($_.Exception.Message); exit 1 }}"
            ),
        ]
    }

    #[cfg(not(windows))]
    {
        vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            "printf '%s' \"$2\" > \"$1\"".to_string(),
            "sh".to_string(),
            path_arg(target),
            payload.to_string(),
        ]
    }
}

fn path_arg(path: &Path) -> String {
    path.to_string_lossy().to_string()
}

#[cfg(windows)]
fn escape_powershell_single_quoted(path: &Path) -> String {
    path_arg(path).replace('\'', "''")
}

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(prefix: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be monotonic")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "procwarden-ci-probe-{prefix}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("probe temp dir should be created");
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

struct Fixture {
    _workspace: TempDir,
    runtime_cwd: PathBuf,
    ro_dir: PathBuf,
    rw_dir: PathBuf,
    #[cfg(target_os = "macos")]
    alias_rw_dir: PathBuf,
    #[cfg(target_os = "windows")]
    outside_dir: PathBuf,
}

impl Fixture {
    fn new(prefix: &str) -> Self {
        let workspace = TempDir::new(prefix);
        let runtime_cwd = workspace.path().join("runtime-cwd");
        let ro_dir = workspace.path().join("readonly");
        let rw_dir = workspace.path().join("readwrite");
        let outside_dir = workspace.path().join("outside");

        for dir in [&runtime_cwd, &ro_dir, &rw_dir, &outside_dir] {
            fs::create_dir_all(dir).expect("probe directory should be created");
        }
        let ro_seed = ro_dir.join("seed-ro.txt");
        fs::write(&ro_seed, "readonly-seed").expect("readonly seed should be created");

        #[cfg(target_os = "macos")]
        let alias_rw_dir = workspace
            .path()
            .join("readwrite")
            .join("..")
            .join("readwrite");

        Self {
            _workspace: workspace,
            runtime_cwd,
            ro_dir,
            rw_dir,
            #[cfg(target_os = "macos")]
            alias_rw_dir,
            #[cfg(target_os = "windows")]
            outside_dir,
        }
    }
}
