#![allow(
    clippy::print_stderr,
    reason = "test utility cli reports operational errors on stderr"
)]
#![allow(
    clippy::print_stdout,
    reason = "test utility cli reports operational status on stdout"
)]

#[cfg(not(unix))]
fn main() {
    eprintln!("honeypot-manual-lab is only supported on unix hosts");
    std::process::exit(1);
}

#[cfg(unix)]
fn main() {
    match real_main() {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("{error:#}");
            std::process::exit(1);
        }
    }
}

#[cfg(unix)]
use anyhow::{Context as _, bail, ensure};
#[cfg(unix)]
use testsuite::honeypot_manual_lab::{
    self, ManualLabBootstrapOptions, ManualLabBootstrapReport, ManualLabPreflightReport,
    ManualLabRememberSourceManifestReport, ManualLabTeardownReport, ManualLabUpOptions,
};

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ManualLabOutputFormat {
    Text,
    Json,
}

#[cfg(unix)]
fn real_main() -> anyhow::Result<i32> {
    let mut args = std::env::args().skip(1);
    let command = args.next().unwrap_or_else(|| "help".to_owned());

    match command.as_str() {
        "up" => {
            let mut open_browser = true;
            for arg in args {
                match arg.as_str() {
                    "--no-browser" => open_browser = false,
                    other => bail!("unknown argument for up: {other}\n\n{}", usage()),
                }
            }

            let state = honeypot_manual_lab::up(ManualLabUpOptions { open_browser })?;
            println!("manual lab is live");
            println!("run_id={}", state.run_id);
            println!("dashboard_url={}", state.dashboard_url);
            println!("run_root={}", state.run_root.display());
            println!(
                "ports control_plane={} proxy_http={} proxy_tcp={} frontend={}",
                state.ports.control_plane_http,
                state.ports.proxy_http,
                state.ports.proxy_tcp,
                state.ports.frontend_http
            );
            for session in &state.sessions {
                println!(
                    "slot={} session_id={} guest_rdp_port={} vm_lease_id={} stream_id={}",
                    session.slot,
                    session.session_id,
                    session.expected_guest_rdp_port,
                    session.vm_lease_id.as_deref().unwrap_or("<pending>"),
                    session.stream_id.as_deref().unwrap_or("<pending>")
                );
            }
            if let Some(pid) = state.chrome_pid {
                println!("chrome_pid={pid}");
            }
            if let Some(pid) = state.xvfb_pid {
                println!("xvfb_pid={pid}");
            }
            Ok(0)
        }
        "preflight" => {
            let mut open_browser = true;
            let mut format = ManualLabOutputFormat::Text;
            for arg in args {
                match arg.as_str() {
                    "--no-browser" => open_browser = false,
                    "--format=json" => format = ManualLabOutputFormat::Json,
                    "--format=text" => format = ManualLabOutputFormat::Text,
                    other => bail!("unknown argument for preflight: {other}\n\n{}", usage()),
                }
            }

            let report = honeypot_manual_lab::preflight(ManualLabUpOptions { open_browser })?;
            print_preflight_report(&report, format)?;
            Ok(if report.is_ready() { 0 } else { 2 })
        }
        "bootstrap-store" => {
            let mut options = ManualLabBootstrapOptions::default();
            let mut format = ManualLabOutputFormat::Text;
            while let Some(arg) = args.next() {
                match arg.as_str() {
                    "--execute" => options.execute = true,
                    "--format=json" => format = ManualLabOutputFormat::Json,
                    "--format=text" => format = ManualLabOutputFormat::Text,
                    "--source-manifest" => {
                        let value = args.next().context("missing value for --source-manifest")?;
                        options.source_manifest_path = Some(value.into());
                    }
                    "--config" => {
                        let value = args.next().context("missing value for --config")?;
                        options.config_path = Some(value.into());
                    }
                    other => bail!("unknown argument for bootstrap-store: {other}\n\n{}", usage()),
                }
            }

            let report = honeypot_manual_lab::bootstrap_store(options)?;
            print_bootstrap_report(&report, format)?;
            Ok(if report.is_success() { 0 } else { 2 })
        }
        "remember-source-manifest" => {
            let mut format = ManualLabOutputFormat::Text;
            let mut source_manifest_path = None;
            while let Some(arg) = args.next() {
                match arg.as_str() {
                    "--format=json" => format = ManualLabOutputFormat::Json,
                    "--format=text" => format = ManualLabOutputFormat::Text,
                    "--source-manifest" => {
                        let value = args.next().context("missing value for --source-manifest")?;
                        source_manifest_path = Some(value);
                    }
                    other => bail!("unknown argument for remember-source-manifest: {other}\n\n{}", usage()),
                }
            }
            let source_manifest_path =
                source_manifest_path.context("remember-source-manifest requires --source-manifest <path>")?;
            let report = honeypot_manual_lab::remember_source_manifest(source_manifest_path.as_ref())?;
            print_remember_source_manifest_report(&report, format)?;
            Ok(if report.is_success() { 0 } else { 2 })
        }
        "status" => {
            ensure!(args.next().is_none(), "status does not accept arguments\n\n{}", usage());
            match honeypot_manual_lab::status()? {
                Some(report) => {
                    let state = report.state;
                    println!("manual lab is active");
                    println!("run_id={}", state.run_id);
                    println!("dashboard_url={}", state.dashboard_url);
                    println!("run_root={}", state.run_root.display());
                    println!(
                        "pids control_plane={} proxy={} frontend={} chrome={} xvfb={}",
                        state.control_plane.pid,
                        state.proxy.pid,
                        state.frontend.pid,
                        state
                            .chrome_pid
                            .map_or_else(|| "<none>".to_owned(), |pid| pid.to_string()),
                        state
                            .xvfb_pid
                            .map_or_else(|| "<none>".to_owned(), |pid| pid.to_string())
                    );
                    if let Some(health) = report.control_plane_health {
                        println!("control_plane_health={health}");
                    }
                    if let Some(health) = report.proxy_health {
                        println!("proxy_health={health}");
                    }
                    if let Some(health) = report.frontend_health {
                        println!("frontend_health={health}");
                    }
                    if let Some(bootstrap) = report.bootstrap {
                        println!("bootstrap_session_count={}", bootstrap.sessions.len());
                    }
                    for session in &state.sessions {
                        println!(
                            "slot={} session_id={} vm_lease_id={} stream_id={} xfreerdp_pid={}",
                            session.slot,
                            session.session_id,
                            session.vm_lease_id.as_deref().unwrap_or("<pending>"),
                            session.stream_id.as_deref().unwrap_or("<pending>"),
                            session
                                .xfreerdp_pid
                                .map_or_else(|| "<none>".to_owned(), |pid| pid.to_string())
                        );
                    }
                    Ok(0)
                }
                None => {
                    println!("manual lab is not active");
                    Ok(0)
                }
            }
        }
        "down" => {
            ensure!(args.next().is_none(), "down does not accept arguments\n\n{}", usage());
            let report = honeypot_manual_lab::down()?;
            print_teardown_report(&report);
            Ok(0)
        }
        "help" | "-h" | "--help" => {
            println!("{}", usage());
            Ok(0)
        }
        other => bail!("unknown subcommand {other}\n\n{}", usage()),
    }
}

#[cfg(unix)]
fn print_preflight_report(report: &ManualLabPreflightReport, format: ManualLabOutputFormat) -> anyhow::Result<()> {
    match format {
        ManualLabOutputFormat::Text => println!("{}", report.render_text()),
        ManualLabOutputFormat::Json => println!("{}", report.render_json()?),
    }
    Ok(())
}

#[cfg(unix)]
fn print_bootstrap_report(report: &ManualLabBootstrapReport, format: ManualLabOutputFormat) -> anyhow::Result<()> {
    match format {
        ManualLabOutputFormat::Text => println!("{}", report.render_text()),
        ManualLabOutputFormat::Json => println!("{}", report.render_json()?),
    }
    Ok(())
}

#[cfg(unix)]
fn print_remember_source_manifest_report(
    report: &ManualLabRememberSourceManifestReport,
    format: ManualLabOutputFormat,
) -> anyhow::Result<()> {
    match format {
        ManualLabOutputFormat::Text => println!("{}", report.render_text()),
        ManualLabOutputFormat::Json => println!("{}", report.render_json()?),
    }
    Ok(())
}

#[cfg(unix)]
fn print_teardown_report(report: &ManualLabTeardownReport) {
    match &report.state {
        Some(state) => {
            println!("manual lab teardown attempted for run {}", state.run_id);
            println!("run_root={}", state.run_root.display());
            println!("removed_active_state={}", report.removed_active_state);
        }
        None => {
            println!("manual lab is not active");
            println!("removed_active_state={}", report.removed_active_state);
        }
    }

    if report.notes.is_empty() {
        println!("notes=<none>");
    } else {
        for note in &report.notes {
            println!("note={note}");
        }
    }
}

#[cfg(unix)]
fn usage() -> &'static str {
    "Usage:
  cargo run -p testsuite --bin honeypot-manual-lab -- up [--no-browser]
  cargo run -p testsuite --bin honeypot-manual-lab -- preflight [--no-browser] [--format=json|text]
  cargo run -p testsuite --bin honeypot-manual-lab -- bootstrap-store [--source-manifest <path>] [--config <path>] [--execute] [--format=json|text]
  cargo run -p testsuite --bin honeypot-manual-lab -- remember-source-manifest --source-manifest <path> [--format=json|text]
  cargo run -p testsuite --bin honeypot-manual-lab -- status
  cargo run -p testsuite --bin honeypot-manual-lab -- down

Commands:
  up         Launch control-plane, proxy, frontend, and three Tiny11-backed live sessions.
  preflight  Check manual-lab prerequisites without starting services.
  bootstrap-store  Resolve and optionally import a sanctioned Tiny11 source bundle into the canonical interop store.
  remember-source-manifest  Remember one admissible source manifest for repeated manual bootstrap runs.
  status     Print the active manual-lab run state and current health snapshots.
  down       Tear down the active manual-lab run and recycle known leases.

Notes:
  up opens Chrome by default after the frontend reports three ready tiles.
  preflight checks the same gate path that up uses and exits non-zero when blocked.
  bootstrap-store is dry-run by default; add --execute to run consume-image and then rerun preflight.
  remember-source-manifest stores a local git-ignored hint under target/manual-lab/ and never weakens explicit --source-manifest precedence.
  Use --no-browser to leave the deck running without opening Chrome."
}
