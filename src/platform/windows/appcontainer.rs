use std::collections::HashMap;
use std::collections::HashSet;
use std::path::PathBuf;
use std::time::Instant;

use crate::{SandboxCommandRequest, SandboxError, SandboxExecOutput, SandboxPolicy, cap_fs};

use super::{acl, elevated_ops, elevation, process, token, util, wfp};

pub(super) fn execute(
    request: &SandboxCommandRequest,
    policy: &SandboxPolicy,
    env_map: &HashMap<String, String>,
) -> Result<SandboxExecOutput, SandboxError> {
    let start = Instant::now();

    let executable = process::resolve_executable(&request.command[0], &request.cwd, env_map)
        .ok_or_else(|| {
            SandboxError::InvalidRequest(format!(
                "unable to resolve executable '{}' from cwd {}",
                request.command[0],
                request.cwd.display()
            ))
        })?;

    let acl_plan = collect_acl_plan(policy);
    let allow_readonly_paths = sanitize_policy_paths(acl_plan.allow_readonly_paths)?;
    let allow_readwrite_paths = sanitize_policy_paths(acl_plan.allow_readwrite_paths)?;
    let deny_write_paths = sanitize_policy_paths(acl_plan.deny_write_paths)?;
    let deny_readwrite_paths = sanitize_policy_paths(acl_plan.deny_readwrite_paths)?;
    let acl_plan = resolve_acl_conflicts(AclPlan {
        allow_readonly_paths,
        allow_readwrite_paths,
        deny_write_paths,
        deny_readwrite_paths,
    });

    let appcontainer = token::create_appcontainer_context()?;
    let sid = appcontainer.sid();

    let optional_bootstrap_paths =
        sanitize_optional_existing_paths(runtime_bootstrap_readonly_paths(request, &executable))?;
    let use_elevated_ops = !elevation::current_process_is_elevated()?;

    let mut elevated_ops_guard = None;
    let mut network_guard = None;
    let mut optional_bootstrap_rollback = None;
    let mut acl_rollback = None;

    if use_elevated_ops {
        let mut elevated_plan = acl_plan.clone();
        elevated_plan
            .allow_readonly_paths
            .extend(optional_bootstrap_paths.clone());
        let elevated_plan = resolve_acl_conflicts(elevated_plan);

        elevated_ops_guard = Some(elevated_ops::ElevatedOpsGuard::spawn(
            &elevated_ops::ElevatedOpsSpec {
                sid_string: util::sid_to_string(sid)?,
                executable: executable.clone(),
                block_network: !policy.network_access,
                allow_readonly_paths: elevated_plan.allow_readonly_paths,
                allow_readwrite_paths: elevated_plan.allow_readwrite_paths,
                deny_write_paths: elevated_plan.deny_write_paths,
                deny_readwrite_paths: elevated_plan.deny_readwrite_paths,
            },
        )?);
    } else {
        network_guard = if policy.network_access {
            None
        } else {
            Some(wfp::install_block_all_network_filters(&executable, sid)?)
        };

        optional_bootstrap_rollback =
            Some(unsafe { acl::apply_optional_readonly_paths(&optional_bootstrap_paths, sid) });

        acl_rollback = Some(unsafe {
            acl::apply_access_plan(
                &acl::AclAccessPlan {
                    allow_readonly_paths: acl_plan.allow_readonly_paths,
                    allow_readwrite_paths: acl_plan.allow_readwrite_paths,
                    deny_write_paths: acl_plan.deny_write_paths,
                    deny_readwrite_paths: acl_plan.deny_readwrite_paths,
                },
                sid,
            )?
        });
    }

    let capture = process::run_process_in_appcontainer(
        sid,
        &executable,
        &request.command,
        &request.cwd,
        env_map,
        request.timeout_ms,
    )?;

    drop(elevated_ops_guard);
    drop(network_guard);
    drop(optional_bootstrap_rollback);
    drop(acl_rollback);
    drop(appcontainer);

    Ok(SandboxExecOutput::from_utf8_lossy(
        capture.exit_code,
        &capture.stdout,
        &capture.stderr,
        start.elapsed(),
        capture.timed_out,
    )
    .with_degraded_mode_reason(capture.degraded_mode_reason))
}

#[derive(Clone)]
struct AclPlan {
    allow_readonly_paths: Vec<PathBuf>,
    allow_readwrite_paths: Vec<PathBuf>,
    deny_write_paths: Vec<PathBuf>,
    deny_readwrite_paths: Vec<PathBuf>,
}

fn collect_acl_plan(policy: &SandboxPolicy) -> AclPlan {
    let allow_readonly_paths = policy.read_only_paths();
    let allow_readwrite_paths = policy.read_write_paths();
    let deny_readwrite_paths = policy.denied_paths();

    match policy.default_access {
        crate::SandboxAccess::ReadWrite => AclPlan {
            deny_write_paths: allow_readonly_paths.clone(),
            allow_readonly_paths,
            allow_readwrite_paths,
            deny_readwrite_paths,
        },
        crate::SandboxAccess::ReadOnly | crate::SandboxAccess::NoAccess => AclPlan {
            allow_readonly_paths,
            allow_readwrite_paths,
            deny_write_paths: Vec::new(),
            deny_readwrite_paths,
        },
    }
}

fn sanitize_policy_paths(paths: Vec<PathBuf>) -> Result<Vec<PathBuf>, SandboxError> {
    cap_fs::PathPolicy::ascii_case_insensitive()
        .validate_and_dedupe(paths, util::ensure_safe_allow_path)
}

fn sanitize_optional_existing_paths(paths: Vec<PathBuf>) -> Result<Vec<PathBuf>, SandboxError> {
    sanitize_policy_paths(
        paths
            .into_iter()
            .filter(|path| cap_fs::path_exists(path))
            .collect(),
    )
}

fn runtime_bootstrap_readonly_paths(
    request: &SandboxCommandRequest,
    executable: &std::path::Path,
) -> Vec<PathBuf> {
    let mut paths = Vec::new();

    paths.push(request.cwd.clone());
    paths.push(executable.to_path_buf());
    if let Some(parent) = executable.parent() {
        paths.push(parent.to_path_buf());
    }

    if let Some(script_or_path_arg) = request.command.get(1) {
        let candidate = PathBuf::from(script_or_path_arg);
        if candidate.components().count() > 1 || candidate.is_absolute() {
            let absolute = if candidate.is_absolute() {
                candidate
            } else {
                request.cwd.join(candidate)
            };
            if cap_fs::path_exists(&absolute) {
                paths.push(absolute.clone());
                if let Some(parent) = absolute.parent() {
                    paths.push(parent.to_path_buf());
                }
            }
        }
    }

    paths
}

fn resolve_acl_conflicts(mut plan: AclPlan) -> AclPlan {
    let deny_readwrite_keys = build_casefolded_path_set(&plan.deny_readwrite_paths);
    plan.allow_readonly_paths
        .retain(|path| !deny_readwrite_keys.contains(&casefolded_path(path)));
    plan.allow_readwrite_paths
        .retain(|path| !deny_readwrite_keys.contains(&casefolded_path(path)));
    plan.deny_write_paths
        .retain(|path| !deny_readwrite_keys.contains(&casefolded_path(path)));

    let readwrite_keys = build_casefolded_path_set(&plan.allow_readwrite_paths);
    plan.allow_readonly_paths
        .retain(|path| !readwrite_keys.contains(&casefolded_path(path)));
    plan.deny_write_paths.retain(|path| {
        let key = casefolded_path(path);
        !deny_readwrite_keys.contains(&key) && !readwrite_keys.contains(&key)
    });

    plan
}

fn build_casefolded_path_set(paths: &[PathBuf]) -> HashSet<String> {
    paths
        .iter()
        .map(|path| casefolded_path(path.as_path()))
        .collect()
}

fn casefolded_path(path: &std::path::Path) -> String {
    path.to_string_lossy().to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::{SandboxAccess, SandboxCommandRequest, SandboxPathPermission, SandboxPolicy};

    use super::{
        AclPlan, collect_acl_plan, resolve_acl_conflicts, runtime_bootstrap_readonly_paths,
    };

    #[test]
    fn collect_acl_plan_preserves_read_only_and_read_write_layers() {
        let policy = SandboxPolicy {
            path_permissions: vec![
                SandboxPathPermission::read_only(r"C:\\safe\\ro"),
                SandboxPathPermission::read_write(r"C:\\safe\\rw"),
                SandboxPathPermission::deny(r"C:\\safe\\deny"),
            ],
            default_access: SandboxAccess::NoAccess,
            network_access: false,
        };

        let plan = collect_acl_plan(&policy);
        assert_eq!(
            plan.allow_readonly_paths,
            vec![PathBuf::from(r"C:\\safe\\ro")]
        );
        assert_eq!(
            plan.allow_readwrite_paths,
            vec![PathBuf::from(r"C:\\safe\\rw")]
        );
        assert!(plan.deny_write_paths.is_empty());
        assert_eq!(
            plan.deny_readwrite_paths,
            vec![PathBuf::from(r"C:\\safe\\deny")]
        );
    }

    #[test]
    fn acl_conflict_resolution_prefers_deny_then_read_write_then_read_only() {
        let resolved = resolve_acl_conflicts(AclPlan {
            allow_readonly_paths: vec![
                PathBuf::from(r"C:\\safe\\readonly"),
                PathBuf::from(r"C:\\safe\\overlap"),
                PathBuf::from(r"C:\\safe\\denyall"),
            ],
            allow_readwrite_paths: vec![
                PathBuf::from(r"C:\\safe\\overlap"),
                PathBuf::from(r"C:\\safe\\RWCase"),
            ],
            deny_write_paths: vec![
                PathBuf::from(r"C:\\safe\\readonly"),
                PathBuf::from(r"C:\\safe\\rwcase"),
            ],
            deny_readwrite_paths: vec![PathBuf::from(r"C:\\safe\\denyAll")],
        });

        assert_eq!(
            resolved.allow_readonly_paths,
            vec![PathBuf::from(r"C:\\safe\\readonly")]
        );
        assert_eq!(
            resolved.allow_readwrite_paths,
            vec![
                PathBuf::from(r"C:\\safe\\overlap"),
                PathBuf::from(r"C:\\safe\\RWCase")
            ]
        );
        assert_eq!(
            resolved.deny_write_paths,
            vec![PathBuf::from(r"C:\\safe\\readonly")]
        );
        assert_eq!(
            resolved.deny_readwrite_paths,
            vec![PathBuf::from(r"C:\\safe\\denyAll")]
        );
    }

    #[test]
    fn runtime_bootstrap_paths_include_cwd_executable_and_absolute_script_parent() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be monotonic")
            .as_nanos();
        let workspace = std::env::temp_dir().join(format!("procwarden-bootstrap-{nonce}"));
        std::fs::create_dir_all(&workspace).expect("workspace should be created");
        let script = workspace.join("script.py");
        std::fs::write(&script, "print('ok')\n").expect("script should be written");

        let request = SandboxCommandRequest {
            command: vec![
                "python".to_string(),
                script.to_string_lossy().to_string(),
                "arg".to_string(),
            ],
            cwd: workspace.clone(),
            env: HashMap::new(),
            timeout_ms: Some(1_000),
        };
        let executable = PathBuf::from(r"C:\\Python310\\python.exe");

        let paths = runtime_bootstrap_readonly_paths(&request, &executable);

        assert!(paths.iter().any(|path| path == &workspace));
        assert!(paths.iter().any(|path| path == &script));
        assert!(
            paths
                .iter()
                .any(|path| path == &PathBuf::from(r"C:\\Python310"))
        );
        assert!(paths.iter().any(|path| path == &executable));

        let _ = std::fs::remove_file(&script);
        let _ = std::fs::remove_dir_all(&workspace);
    }
}
