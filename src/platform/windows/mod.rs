mod acl;
mod appcontainer;
mod process;
mod token;
mod util;
mod wfp;

use crate::{SandboxCommandRequest, SandboxError, SandboxExecOutput, SandboxPolicy};

pub(super) fn execute(
    request: &SandboxCommandRequest,
    policy: &SandboxPolicy,
) -> Result<SandboxExecOutput, SandboxError> {
    let mut env_map = request.env.clone();
    util::normalize_null_device_env(&mut env_map);
    util::ensure_non_interactive_pager(&mut env_map);

    appcontainer::execute(request, policy, &env_map)
}
