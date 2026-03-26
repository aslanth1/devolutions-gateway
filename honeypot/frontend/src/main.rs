use std::path::PathBuf;

use anyhow::Context as _;
use honeypot_frontend::config::{DEFAULT_FRONTEND_CONFIG_PATH, FrontendConfig};
use honeypot_frontend::run_frontend;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_target(false)
        .compact()
        .init();

    let config_path = std::env::var("HONEYPOT_FRONTEND_CONFIG_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_FRONTEND_CONFIG_PATH));
    let config = FrontendConfig::load_from_path(&config_path)
        .with_context(|| format!("load frontend config from {}", config_path.display()))?;

    run_frontend(config).await
}
