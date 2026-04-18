use ssh_core::ssh::auth::{self, LaunchAuthConsumer, LaunchAuthPreparation};

use super::super::LaunchContext;

pub(super) const RUSTDESK_DIRECT_IP_PORT: u16 = 21118;

pub(super) async fn prepare_ssh_launch_auth(
    context: &LaunchContext,
    consumer: LaunchAuthConsumer,
) -> Result<LaunchAuthPreparation, String> {
    let preparation = auth::prepare_launch_auth_for_consumer(
        &context.device_ip,
        &context.username,
        context.password.as_deref(),
        consumer,
        auth::LAUNCH_AUTH_TIMEOUT,
    )
    .await;

    match preparation {
        LaunchAuthPreparation::HardFailure { reason } => Err(reason),
        other => Ok(other),
    }
}
