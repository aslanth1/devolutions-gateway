use std::io::{self, Write as _};
use std::process::ExitCode;

use testsuite::honeypot_release::{
    HONEYPOT_COMPOSE_PATH, HONEYPOT_IMAGES_LOCK_PATH, HONEYPOT_PROMOTION_MANIFEST_PATH, repo_relative_path,
    validate_host_smoke_release_preflight,
};

fn main() -> ExitCode {
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
