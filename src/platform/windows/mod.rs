mod acl;
mod appcontainer;
mod env;
mod process;
mod token;
mod util;

use crate::{SandboxCommandRequest, SandboxError, SandboxExecOutput, SandboxPolicy};

pub(super) fn execute(
    request: &SandboxCommandRequest,
    policy: &SandboxPolicy,
) -> Result<SandboxExecOutput, SandboxError> {
    let mut env_map = request.env.clone();
    util::normalize_null_device_env(&mut env_map);
    util::ensure_non_interactive_pager(&mut env_map);

    if !policy.network_access {
        env::apply_no_network_hardening(&mut env_map, None)?;
    }

    appcontainer::execute(request, policy, &env_map)
}
