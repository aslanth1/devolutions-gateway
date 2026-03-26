use anyhow::Context as _;
use honeypot_control_plane::{config::ControlPlaneConfig, run_control_plane};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();

    let config = ControlPlaneConfig::load_from_env().context("load control-plane config")?;
    run_control_plane(config).await
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .try_init();
}
