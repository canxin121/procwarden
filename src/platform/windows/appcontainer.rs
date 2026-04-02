use std::collections::HashMap;
use std::collections::HashSet;
use std::path::Component;
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
    let allow_readonly_paths = sanitize_policy_paths(acl_plan.allow_readonly_paths)?;
    let allow_readwrite_paths = sanitize_policy_paths(acl_plan.allow_readwrite_paths)?;
    let deny_write_paths = sanitize_policy_paths(acl_plan.deny_write_paths)?;
    let deny_readwrite_paths = sanitize_policy_paths(acl_plan.deny_readwrite_paths)?;

    if command_references_denied_path(request, &deny_readwrite_paths) {
        return Err(SandboxError::Denied(
            "command arguments reference a path denied by sandbox policy".to_string(),
        ));
    }

    let allow_readonly_paths =
        filter_paths_not_under_denied_roots(allow_readonly_paths, &deny_readwrite_paths);
    let allow_readwrite_paths =
        filter_paths_not_under_denied_roots(allow_readwrite_paths, &deny_readwrite_paths);
    let acl_plan = resolve_acl_conflicts(AclPlan {
        allow_readonly_paths,
        allow_readwrite_paths,
        deny_write_paths,
        deny_readwrite_paths,
    });

    let appcontainer = token::create_appcontainer_context_with_network(policy.network_access)?;
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
        policy.network_access,
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
    if policy.network_access {
        return Err(SandboxError::InvalidRequest(
            "windows backend cannot safely enforce network_access=true with current AppContainer profile configuration; use network_access=false".to_string(),
        ));
    }

    Ok(())
}

#[derive(Clone)]
struct AclPlan {
    allow_readonly_paths: Vec<PathBuf>,
    allow_readwrite_paths: Vec<PathBuf>,
    deny_write_paths: Vec<PathBuf>,
    deny_readwrite_paths: Vec<PathBuf>,
}

fn collect_acl_plan(policy: &SandboxPolicy, default_access_scope_paths: Vec<PathBuf>) -> AclPlan {
    let allow_readonly_paths = policy.read_only_paths();
    let allow_readwrite_paths = policy.read_write_paths();
    let deny_readwrite_paths = policy.denied_paths();

    match policy.default_access {
        crate::SandboxDefaultAccess::ReadOnly => {
            let mut default_readonly_paths = default_access_scope_paths;
            default_readonly_paths.extend(allow_readonly_paths);
            AclPlan {
                allow_readonly_paths: default_readonly_paths,
                allow_readwrite_paths,
                deny_write_paths: Vec::new(),
                deny_readwrite_paths,
            }
        }
        crate::SandboxDefaultAccess::ReadWrite => {
            let mut default_readwrite_paths = filter_paths_not_under_denied_roots(
                default_access_scope_paths,
                &allow_readonly_paths,
            );
            default_readwrite_paths.extend(allow_readwrite_paths);
            AclPlan {
                deny_write_paths: allow_readonly_paths.clone(),
                allow_readonly_paths,
                allow_readwrite_paths: default_readwrite_paths,
                deny_readwrite_paths,
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

fn filter_paths_not_under_denied_roots(
    paths: Vec<PathBuf>,
    denied_roots: &[PathBuf],
) -> Vec<PathBuf> {
    paths
        .into_iter()
        .filter(|path| {
            !denied_roots
                .iter()
                .any(|denied| is_same_or_descendant(path, denied))
        })
        .collect()
}

fn is_same_or_descendant(path: &std::path::Path, denied_root: &std::path::Path) -> bool {
    let path_components = path.components().collect::<Vec<_>>();
    let denied_components = denied_root.components().collect::<Vec<_>>();
    if denied_components.len() > path_components.len() {
        return false;
    }

    denied_components
        .iter()
        .zip(path_components.iter())
        .all(|(left, right)| component_eq_case_insensitive(left, right))
}

fn component_eq_case_insensitive(left: &Component<'_>, right: &Component<'_>) -> bool {
    left.as_os_str()
        .to_string_lossy()
        .eq_ignore_ascii_case(&right.as_os_str().to_string_lossy())
}

fn command_references_denied_path(
    request: &SandboxCommandRequest,
    denied_roots: &[PathBuf],
) -> bool {
    request
        .command
        .iter()
        .skip(1)
        .flat_map(|argument| command_argument_path_candidates(argument, &request.cwd))
        .any(|candidate| {
            denied_roots
                .iter()
                .any(|denied| is_same_or_descendant(&candidate, denied))
        })
}
