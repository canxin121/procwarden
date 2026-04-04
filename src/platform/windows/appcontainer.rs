use std::collections::HashMap;
use std::collections::HashSet;
use std::path::Component;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

use crate::{
    SandboxCommandRequest, SandboxError, SandboxExecOutput, SandboxNetworkMode, SandboxPolicy,
    cap_fs,
};

use super::{acl, elevated_ops, elevation, process, token, util, wfp};

static ELEVATED_OPS_EXECUTION_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

pub(super) fn execute(
    request: &SandboxCommandRequest,
    policy: &SandboxPolicy,
    env_map: &HashMap<String, String>,
) -> Result<SandboxExecOutput, SandboxError> {
    let start = Instant::now();

    validate_policy_shape(policy)?;

    let executable = process::resolve_executable(&request.command[0], &request.cwd, env_map)
        .ok_or_else(|| {
            SandboxError::InvalidRequest(format!(
                "unable to resolve executable '{}' from cwd {}",
                request.command[0],
                request.cwd.display()
            ))
        })?;

    let default_access_scope_paths = sanitize_optional_existing_paths(default_access_scope_paths(
        request,
        policy,
        &executable,
    )?)?;
    let acl_plan = collect_acl_plan(policy, default_access_scope_paths);
    let deny_access_paths = sanitize_policy_paths(acl_plan.deny_access_paths)?;
    let allow_readonly_paths = sanitize_policy_paths(acl_plan.allow_readonly_paths)?;
    let allow_readwrite_paths = sanitize_policy_paths(acl_plan.allow_readwrite_paths)?;
    let deny_write_paths = sanitize_policy_paths(acl_plan.deny_write_paths)?;
    let acl_plan = resolve_acl_conflicts(AclPlan {
        deny_access_paths,
        allow_readonly_paths,
        allow_readwrite_paths,
        deny_write_paths,
    });

    let appcontainer = token::create_appcontainer_context_with_network(policy.network_mode)?;
    let sid = appcontainer.sid();
    if policy.network_mode.allows_ip_network() {
        appcontainer.register_network_binary(&executable)?;
    }

    let optional_bootstrap_paths =
        sanitize_optional_existing_paths(runtime_bootstrap_readonly_paths(request, &executable))?;
    let use_elevated_ops = !elevation::current_process_is_elevated()?
        || !matches!(policy.network_mode, SandboxNetworkMode::Disabled);
    let _elevated_ops_lock = if use_elevated_ops {
        Some(lock_elevated_ops_execution())
    } else {
        None
    };

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
                appcontainer_name: appcontainer.profile_name().to_string(),
                executable: executable.clone(),
                network_rule_mode: match policy.network_mode {
                    SandboxNetworkMode::Disabled => elevated_ops::NetworkRuleMode::BlockAll,
                    SandboxNetworkMode::OutboundOnly => elevated_ops::NetworkRuleMode::OutboundOnly,
                    SandboxNetworkMode::Bidirectional => {
                        elevated_ops::NetworkRuleMode::Bidirectional
                    }
                },
                deny_access_paths: elevated_plan.deny_access_paths,
                allow_readonly_paths: elevated_plan.allow_readonly_paths,
                allow_readwrite_paths: elevated_plan.allow_readwrite_paths,
                deny_write_paths: elevated_plan.deny_write_paths,
            },
        )?);
    } else {
        network_guard = if policy.network_mode.allows_ip_network() {
            None
        } else {
            Some(wfp::install_block_all_network_filters(&executable, sid)?)
        };

        optional_bootstrap_rollback =
            Some(unsafe { acl::apply_optional_readonly_paths(&optional_bootstrap_paths, sid) });

        acl_rollback = Some(unsafe {
            acl::apply_access_plan(
                &acl::AclAccessPlan {
                    deny_access_paths: acl_plan.deny_access_paths,
                    allow_readonly_paths: acl_plan.allow_readonly_paths,
                    allow_readwrite_paths: acl_plan.allow_readwrite_paths,
                    deny_write_paths: acl_plan.deny_write_paths,
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
        policy.network_mode,
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

fn validate_policy_shape(policy: &SandboxPolicy) -> Result<(), SandboxError> {
    let _ = policy;
    Ok(())
}

fn lock_elevated_ops_execution() -> std::sync::MutexGuard<'static, ()> {
    ELEVATED_OPS_EXECUTION_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
}

#[derive(Clone)]
struct AclPlan {
    deny_access_paths: Vec<PathBuf>,
    allow_readonly_paths: Vec<PathBuf>,
    allow_readwrite_paths: Vec<PathBuf>,
    deny_write_paths: Vec<PathBuf>,
}

fn collect_acl_plan(policy: &SandboxPolicy, default_access_scope_paths: Vec<PathBuf>) -> AclPlan {
    let deny_access_paths = policy.denied_paths();
    let allow_readonly_paths =
        filter_paths_not_under_roots(policy.read_only_paths(), &deny_access_paths);
    let mut restricted_roots = allow_readonly_paths.clone();
    restricted_roots.extend(deny_access_paths.clone());
    let allow_readwrite_paths =
        filter_paths_not_under_roots(policy.read_write_paths(), &deny_access_paths);

    match policy.default_access {
        crate::SandboxDefaultAccess::ReadOnly => AclPlan {
            deny_access_paths,
            allow_readonly_paths: filter_paths_not_under_roots(
                default_access_scope_paths,
                &restricted_roots,
            ),
            allow_readwrite_paths,
            deny_write_paths: Vec::new(),
        },
        crate::SandboxDefaultAccess::ReadWrite => {
            let mut default_readwrite_paths =
                filter_paths_not_under_roots(default_access_scope_paths, &restricted_roots);
            default_readwrite_paths.extend(allow_readwrite_paths);
            AclPlan {
                deny_access_paths,
                deny_write_paths: allow_readonly_paths.clone(),
                allow_readonly_paths,
                allow_readwrite_paths: default_readwrite_paths,
            }
        }
    }
}

fn default_access_scope_paths(
    request: &SandboxCommandRequest,
    policy: &SandboxPolicy,
    executable: &std::path::Path,
) -> Result<Vec<PathBuf>, SandboxError> {
    let mut paths = Vec::new();

    paths.push(request.cwd.clone());
    paths.push(executable.to_path_buf());
    if let Some(parent) = executable.parent() {
        paths.push(parent.to_path_buf());
    }

    for permission in &policy.path_permissions {
        paths.push(permission.path.clone());
    }

    for argument in request.command.iter().skip(1) {
        for path in command_argument_path_candidates(argument, &request.cwd) {
            paths.push(path);
        }
    }

    Ok(paths)
}

fn command_argument_path_candidates(argument: &str, cwd: &std::path::Path) -> Vec<PathBuf> {
    let mut candidates = Vec::new();

    if let Some(path) = materialize_path_candidate(argument, cwd) {
        candidates.push(path);
    }

    for quoted in single_quoted_segments(argument) {
        if let Some(path) = materialize_path_candidate(&quoted, cwd) {
            candidates.push(path);
        }
    }

    candidates
}

fn materialize_path_candidate(argument: &str, cwd: &std::path::Path) -> Option<PathBuf> {
    if argument.trim().is_empty() || !looks_like_filesystem_path(argument) {
        return None;
    }

    let candidate = PathBuf::from(argument);
    let absolute = if candidate.is_absolute() {
        candidate
    } else {
        cwd.join(candidate)
    };

    if cap_fs::path_exists(&absolute) {
        return Some(absolute);
    }

    absolute
        .parent()
        .filter(|parent| cap_fs::path_exists(parent))
        .map(|parent| parent.to_path_buf())
}

fn single_quoted_segments(input: &str) -> Vec<String> {
    let chars = input.chars().collect::<Vec<_>>();
    let mut segments = Vec::new();
    let mut index = 0;

    while index < chars.len() {
        if chars[index] != '\'' {
            index += 1;
            continue;
        }

        index += 1;
        let mut buffer = String::new();
        while index < chars.len() {
            if chars[index] == '\'' {
                if index + 1 < chars.len() && chars[index + 1] == '\'' {
                    buffer.push('\'');
                    index += 2;
                    continue;
                }
                index += 1;
                break;
            }
            buffer.push(chars[index]);
            index += 1;
        }

        if !buffer.is_empty() {
            segments.push(buffer);
        }
    }

    segments
}

fn looks_like_filesystem_path(argument: &str) -> bool {
    argument.starts_with('/')
        || argument.starts_with("./")
        || argument.starts_with("../")
        || argument.starts_with(r".\")
        || argument.starts_with(r"..\")
        || argument.contains('\\')
        || argument
            .as_bytes()
            .get(1)
            .is_some_and(|separator| *separator == b':')
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
    let readwrite_keys = build_casefolded_path_set(&plan.allow_readwrite_paths);
    plan.allow_readonly_paths
        .retain(|path| !readwrite_keys.contains(&casefolded_path(path)));
    plan.deny_write_paths
        .retain(|path| !readwrite_keys.contains(&casefolded_path(path)));

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

fn filter_paths_not_under_roots(paths: Vec<PathBuf>, roots: &[PathBuf]) -> Vec<PathBuf> {
    paths
        .into_iter()
        .filter(|path| !roots.iter().any(|root| is_same_or_descendant(path, root)))
        .collect()
}

fn is_same_or_descendant(path: &std::path::Path, ancestor: &std::path::Path) -> bool {
    let path_components = path.components().collect::<Vec<_>>();
    let ancestor_components = ancestor.components().collect::<Vec<_>>();
    if ancestor_components.len() > path_components.len() {
        return false;
    }

    ancestor_components
        .iter()
        .zip(path_components.iter())
        .all(|(left, right)| component_eq_case_insensitive(left, right))
}

fn component_eq_case_insensitive(left: &Component<'_>, right: &Component<'_>) -> bool {
    left.as_os_str()
        .to_string_lossy()
        .eq_ignore_ascii_case(&right.as_os_str().to_string_lossy())
}

#[cfg(test)]
mod tests {
    use super::{collect_acl_plan, filter_paths_not_under_roots};
    use crate::{SandboxDefaultAccess, SandboxNetworkMode, SandboxPathPermission, SandboxPolicy};
    use std::path::PathBuf;

    #[test]
    fn readwrite_default_readonly_roots_are_excluded_from_readwrite_scope() {
        let readonly_root = PathBuf::from(r"C:\Temp\Readonly");
        let readonly_child = readonly_root.join("child.txt");
        let outside = PathBuf::from(r"C:\Temp\Outside");

        let plan = collect_acl_plan(
            &SandboxPolicy {
                path_permissions: vec![SandboxPathPermission::read_only(readonly_root.clone())],
                default_access: SandboxDefaultAccess::ReadWrite,
                network_mode: SandboxNetworkMode::Disabled,
            },
            vec![outside.clone(), readonly_root.clone(), readonly_child],
        );

        assert!(plan.deny_access_paths.is_empty());
        assert_eq!(plan.allow_readonly_paths, vec![readonly_root.clone()]);
        assert_eq!(plan.deny_write_paths, vec![readonly_root]);
        assert_eq!(plan.allow_readwrite_paths, vec![outside]);
    }

    #[test]
    fn deny_roots_are_excluded_from_all_allow_scopes() {
        let denied_root = PathBuf::from(r"C:\Temp\Denied");
        let denied_child = denied_root.join("child.txt");
        let writable_root = PathBuf::from(r"C:\Temp\Writable");
        let outside = PathBuf::from(r"C:\Temp\Outside");

        let plan = collect_acl_plan(
            &SandboxPolicy {
                path_permissions: vec![
                    SandboxPathPermission::deny(denied_root.clone()),
                    SandboxPathPermission::read_write(writable_root.clone()),
                ],
                default_access: SandboxDefaultAccess::ReadOnly,
                network_mode: SandboxNetworkMode::Disabled,
            },
            vec![outside.clone(), denied_root.clone(), denied_child],
        );

        assert_eq!(plan.deny_access_paths, vec![denied_root]);
        assert_eq!(plan.allow_readonly_paths, vec![outside]);
        assert_eq!(plan.allow_readwrite_paths, vec![writable_root]);
        assert!(plan.deny_write_paths.is_empty());
    }

    #[test]
    fn readonly_root_filter_is_case_insensitive_and_descendant_aware() {
        let filtered = filter_paths_not_under_roots(
            vec![
                PathBuf::from(r"c:\temp\readonly\child.txt"),
                PathBuf::from(r"C:\Temp\Other\child.txt"),
            ],
            &[PathBuf::from(r"C:\Temp\Readonly")],
        );

        assert_eq!(filtered, vec![PathBuf::from(r"C:\Temp\Other\child.txt")]);
    }
}
