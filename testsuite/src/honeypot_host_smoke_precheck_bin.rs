use std::io::{self, Write as _};
use std::process::ExitCode;

use testsuite::honeypot_release::{
    HONEYPOT_COMPOSE_PATH, HONEYPOT_IMAGES_LOCK_PATH, HONEYPOT_PROMOTION_MANIFEST_PATH, HostSmokeImageCacheState,
    ensure_host_smoke_service_cache_images, repo_relative_path, validate_host_smoke_release_preflight,
};

fn main() -> ExitCode {
    match std::env::args().nth(1).as_deref() {
        Some("ensure-images") => ensure_images(),
        None | Some("check") => check_release_inputs(),
        Some(other) => {
            let _ = writeln!(
                io::stderr(),
                "unsupported host-smoke mode {other}; expected `check` or `ensure-images`"
            );
            ExitCode::from(64)
        }
    }
}

fn check_release_inputs() -> ExitCode {
    match validate_host_smoke_release_preflight(
        &repo_relative_path(HONEYPOT_IMAGES_LOCK_PATH),
        &repo_relative_path(HONEYPOT_PROMOTION_MANIFEST_PATH),
        &repo_relative_path(HONEYPOT_COMPOSE_PATH),
    ) {
        Ok(()) => {
            let _ = writeln!(
                io::stdout(),
                "host-smoke release-input preflight ready: checked-in release inputs are internally consistent and both current and previous slots are promoted"
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            let _ = writeln!(io::stderr(), "host-smoke release-input preflight blocked: {error:#}");
            ExitCode::from(2)
        }
    }
}

fn ensure_images() -> ExitCode {
    match ensure_host_smoke_service_cache_images() {
        Ok(outcomes) => {
            for outcome in outcomes {
                let state = match outcome.state {
                    HostSmokeImageCacheState::Hit => "cache_hit",
                    HostSmokeImageCacheState::Built => "built",
                };
                let _ = writeln!(
                    io::stdout(),
                    "host-smoke image cache {state}: service={} tag={} fingerprint={}",
                    outcome.service,
                    outcome.cache_tag,
                    outcome.fingerprint
                );
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            let _ = writeln!(io::stderr(), "host-smoke image ensure blocked: {error:#}");
            ExitCode::from(2)
        }
    }
}
