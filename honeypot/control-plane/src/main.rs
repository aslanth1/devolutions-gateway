use std::ffi::OsString;
use std::io::Write as _;
use std::path::PathBuf;

use anyhow::Context as _;
use honeypot_control_plane::config::{CONTROL_PLANE_CONFIG_ENV, ControlPlaneConfig, DEFAULT_CONTROL_PLANE_CONFIG_PATH};
use honeypot_control_plane::{consume_trusted_image, run_control_plane};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();

    match parse_command(std::env::args_os())? {
        ControlPlaneCommand::Serve => {
            let config = ControlPlaneConfig::load_from_env().context("load control-plane config")?;
            run_control_plane(config).await
        }
        ControlPlaneCommand::ConsumeImage {
            config_path,
            source_manifest_path,
        } => {
            let config_path = config_path.unwrap_or_else(resolve_config_path_from_env);
            let config =
                ControlPlaneConfig::load_from_path(&config_path).context("load control-plane config for import")?;
            let imported =
                consume_trusted_image(&config.paths, &source_manifest_path).context("consume trusted image bundle")?;
            let payload = serde_json::to_string_pretty(&imported).context("serialize imported trusted image")?;
            let mut stdout = std::io::stdout();
            stdout
                .write_all(payload.as_bytes())
                .context("write imported trusted image json")?;
            stdout
                .write_all(b"\n")
                .context("write imported trusted image newline")?;
            Ok(())
        }
    }
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .try_init();
}

#[derive(Debug, PartialEq, Eq)]
enum ControlPlaneCommand {
    Serve,
    ConsumeImage {
        config_path: Option<PathBuf>,
        source_manifest_path: PathBuf,
    },
}

fn parse_command(args: impl IntoIterator<Item = OsString>) -> anyhow::Result<ControlPlaneCommand> {
    let mut args = args.into_iter();
    let _binary = args.next();

    let Some(command) = args.next() else {
        return Ok(ControlPlaneCommand::Serve);
    };

    if command == "consume-image" {
        return parse_consume_image_command(args);
    }

    anyhow::bail!("unsupported control-plane command {}", command.to_string_lossy());
}

fn parse_consume_image_command(args: impl IntoIterator<Item = OsString>) -> anyhow::Result<ControlPlaneCommand> {
    let mut config_path = None;
    let mut source_manifest_path = None;
    let mut args = args.into_iter();

    while let Some(argument) = args.next() {
        match argument.to_string_lossy().as_ref() {
            "--config" => {
                let value = args.next().context("missing value for --config")?;
                config_path = Some(PathBuf::from(value));
            }
            "--source-manifest" => {
                let value = args.next().context("missing value for --source-manifest")?;
                source_manifest_path = Some(PathBuf::from(value));
            }
            unknown => anyhow::bail!("unsupported consume-image argument {unknown}"),
        }
    }

    Ok(ControlPlaneCommand::ConsumeImage {
        config_path,
        source_manifest_path: source_manifest_path.context("missing required --source-manifest")?,
    })
}

fn resolve_config_path_from_env() -> PathBuf {
    std::env::var_os(CONTROL_PLANE_CONFIG_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_CONTROL_PLANE_CONFIG_PATH))
}
