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
    eprintln!("honeypot-manual-headed-writer is only supported on unix hosts");
    std::process::exit(1);
}

#[cfg(unix)]
fn main() {
    if let Err(error) = real_main() {
        eprintln!("{error:#}");
        std::process::exit(1);
    }
}

#[cfg(unix)]
use std::env;
#[cfg(unix)]
use std::fs;
#[cfg(unix)]
use std::path::{Component, Path, PathBuf};
#[cfg(unix)]
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use anyhow::Context as _;
#[cfg(unix)]
use anyhow::{bail, ensure};
#[cfg(unix)]
use serde_json::Value;
#[cfg(unix)]
use sha2::{Digest, Sha256};
#[cfg(unix)]
use testsuite::honeypot_control_plane::{
    MANUAL_HEADED_ANCHOR_VIDEO_EVIDENCE, MANUAL_HEADED_EVIDENCE_SCHEMA_VERSION, ManualHeadedAnchorResult,
    ManualHeadedAnchorStatus, manual_headed_anchor_runtime_required, manual_headed_begin_run,
    manual_headed_complete_run, manual_headed_profile_dir, resolve_manual_headed_anchor_artifact_path,
    row706_default_evidence_dir, verify_manual_headed_evidence_envelope, verify_row706_evidence_envelope,
    write_manual_headed_anchor_result,
};

#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CommandMode {
    Preflight,
    Runtime,
}

#[cfg(unix)]
#[derive(Debug)]
struct RecordCommand {
    evidence_root: PathBuf,
    run_id: String,
    anchor_id: String,
    status: ManualHeadedAnchorStatus,
    producer: String,
    artifact_path: PathBuf,
    artifact_relpath: PathBuf,
    captured_at_unix_secs: u64,
    session_id: Option<String>,
    vm_lease_id: Option<String>,
    detail: Option<String>,
}

#[cfg(unix)]
#[derive(Debug)]
struct FinalizeCommand {
    evidence_root: PathBuf,
    run_id: String,
}

#[cfg(unix)]
fn real_main() -> anyhow::Result<()> {
    let mut args = env::args().skip(1);
    let command = args
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing subcommand\n\n{}", usage()))?;

    match command.as_str() {
        "preflight" => run_record_command(CommandMode::Preflight, parse_record_command(args.collect())?),
        "runtime" => run_record_command(CommandMode::Runtime, parse_record_command(args.collect())?),
        "finalize" => run_finalize_command(parse_finalize_command(args.collect())?),
        "-h" | "--help" | "help" => {
            println!("{}", usage());
            Ok(())
        }
        other => bail!("unknown subcommand {other}\n\n{}", usage()),
    }
}

#[cfg(unix)]
fn run_record_command(mode: CommandMode, command: RecordCommand) -> anyhow::Result<()> {
    let runtime_required = manual_headed_anchor_runtime_required(&command.anchor_id)?;
    match mode {
        CommandMode::Preflight => ensure!(
            !runtime_required,
            "anchor {} is runtime-required and must be recorded with the runtime subcommand",
            command.anchor_id
        ),
        CommandMode::Runtime => ensure!(
            runtime_required,
            "anchor {} is preflight-only and must be recorded with the preflight subcommand",
            command.anchor_id
        ),
    }

    if mode == CommandMode::Runtime {
        verify_row706_evidence_envelope(&command.evidence_root, &command.run_id).with_context(|| {
            format!(
                "runtime manual-headed evidence requires a verified row706 run {}",
                command.run_id
            )
        })?;
    }

    ensure_manual_headed_run_started(&command.evidence_root, &command.run_id)?;
    let copied_artifact_path = ingest_artifact(
        &command.evidence_root,
        &command.run_id,
        &command.artifact_path,
        &command.artifact_relpath,
    )?;
    validate_anchor_artifact(
        &command.anchor_id,
        &copied_artifact_path,
        command.session_id.as_deref(),
        command.vm_lease_id.as_deref(),
    )?;

    let result = ManualHeadedAnchorResult {
        schema_version: MANUAL_HEADED_EVIDENCE_SCHEMA_VERSION,
        run_id: command.run_id.clone(),
        row706_run_id: command.run_id.clone(),
        anchor_id: command.anchor_id.clone(),
        executed: command.status != ManualHeadedAnchorStatus::BlockedPrereq,
        status: command.status,
        producer: command.producer,
        captured_at_unix_secs: command.captured_at_unix_secs,
        source_artifact_relpath: command.artifact_relpath,
        source_artifact_sha256: sha256_file_hex(&copied_artifact_path)?,
        session_id: command.session_id,
        vm_lease_id: command.vm_lease_id,
        detail: command.detail,
    };
    write_manual_headed_anchor_result(&command.evidence_root, &command.run_id, &result)
        .with_context(|| format!("write manual-headed anchor {}", result.anchor_id))?;

    println!(
        "recorded {} anchor {} under run {}",
        match mode {
            CommandMode::Preflight => "preflight",
            CommandMode::Runtime => "runtime",
        },
        result.anchor_id,
        result.run_id
    );

    Ok(())
}

#[cfg(unix)]
fn run_finalize_command(command: FinalizeCommand) -> anyhow::Result<()> {
    let completed = manual_headed_complete_run(&command.evidence_root, &command.run_id)
        .with_context(|| format!("complete manual-headed run {}", command.run_id))?;
    ensure!(
        completed,
        "manual-headed run {} is incomplete and cannot be finalized yet",
        command.run_id
    );

    let envelope = verify_manual_headed_evidence_envelope(&command.evidence_root, &command.run_id)
        .with_context(|| format!("verify manual-headed run {}", command.run_id))?;
    println!(
        "verified manual-headed run {} with {} anchors",
        envelope.row706_run_id,
        envelope.anchor_results.len()
    );

    Ok(())
}

#[cfg(unix)]
fn ensure_manual_headed_run_started(root: &Path, run_id: &str) -> anyhow::Result<PathBuf> {
    let profile_dir = manual_headed_profile_dir(root, run_id)?;
    let manifest_path = profile_dir.join("manifest.json");
    if manifest_path.exists() {
        return Ok(profile_dir);
    }

    manual_headed_begin_run(root, run_id)
}

#[cfg(unix)]
fn ingest_artifact(root: &Path, run_id: &str, source_path: &Path, artifact_relpath: &Path) -> anyhow::Result<PathBuf> {
    let source_metadata = fs::symlink_metadata(source_path)
        .with_context(|| format!("read source artifact metadata {}", source_path.display()))?;
    ensure!(
        source_metadata.file_type().is_file() && !source_metadata.file_type().is_symlink(),
        "source artifact must be a real file: {}",
        source_path.display()
    );

    let destination_path = resolve_manual_headed_anchor_artifact_path(root, run_id, artifact_relpath)?;
    if destination_path.exists() {
        let canonical_destination = destination_path
            .canonicalize()
            .with_context(|| format!("canonicalize destination artifact {}", destination_path.display()))?;
        let canonical_source = source_path
            .canonicalize()
            .with_context(|| format!("canonicalize source artifact {}", source_path.display()))?;
        ensure!(
            canonical_source == canonical_destination,
            "destination artifact already exists: {}",
            destination_path.display()
        );
        return Ok(destination_path);
    }

    fs::copy(source_path, &destination_path).with_context(|| {
        format!(
            "copy source artifact {} into {}",
            source_path.display(),
            destination_path.display()
        )
    })?;

    Ok(destination_path)
}

#[cfg(unix)]
fn validate_anchor_artifact(
    anchor_id: &str,
    artifact_path: &Path,
    session_id: Option<&str>,
    vm_lease_id: Option<&str>,
) -> anyhow::Result<()> {
    match anchor_id {
        MANUAL_HEADED_ANCHOR_VIDEO_EVIDENCE => validate_video_metadata_artifact(artifact_path, session_id, vm_lease_id),
        _ => Ok(()),
    }
}

#[cfg(unix)]
fn validate_video_metadata_artifact(
    artifact_path: &Path,
    session_id: Option<&str>,
    vm_lease_id: Option<&str>,
) -> anyhow::Result<()> {
    let document = read_json_document(artifact_path)?;
    let Some(object) = document.as_object() else {
        bail!(
            "video evidence artifact {} must be a json object",
            artifact_path.display()
        );
    };

    validate_nonempty_string_field(object.get("video_sha256"), "video_sha256", artifact_path)?;
    ensure!(
        object
            .get("video_sha256")
            .and_then(Value::as_str)
            .is_some_and(is_sha256_hex),
        "video evidence artifact {} must provide a 64-character hex video_sha256",
        artifact_path.display()
    );
    ensure!(
        object
            .get("duration_floor_secs")
            .and_then(Value::as_u64)
            .is_some_and(|value| value > 0),
        "video evidence artifact {} must provide duration_floor_secs > 0",
        artifact_path.display()
    );
    validate_timestamp_window(object.get("timestamp_window"), artifact_path)?;
    validate_nonempty_string_field(object.get("storage_uri"), "storage_uri", artifact_path)?;
    validate_retention_window(object.get("retention_window"), artifact_path)?;
    validate_optional_matching_string_field(object.get("session_id"), "session_id", session_id, artifact_path)?;
    validate_optional_matching_string_field(object.get("vm_lease_id"), "vm_lease_id", vm_lease_id, artifact_path)?;

    Ok(())
}

#[cfg(unix)]
fn read_json_document(path: &Path) -> anyhow::Result<Value> {
    let bytes = fs::read(path).with_context(|| format!("read json artifact {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("parse json artifact {}", path.display()))
}

#[cfg(unix)]
fn validate_timestamp_window(value: Option<&Value>, artifact_path: &Path) -> anyhow::Result<()> {
    let Some(window) = value.and_then(Value::as_object) else {
        bail!(
            "video evidence artifact {} must provide timestamp_window.start_unix_secs and timestamp_window.end_unix_secs",
            artifact_path.display()
        );
    };
    let start = window.get("start_unix_secs").and_then(Value::as_u64).ok_or_else(|| {
        anyhow::anyhow!(
            "video evidence artifact {} must provide timestamp_window.start_unix_secs",
            artifact_path.display()
        )
    })?;
    let end = window.get("end_unix_secs").and_then(Value::as_u64).ok_or_else(|| {
        anyhow::anyhow!(
            "video evidence artifact {} must provide timestamp_window.end_unix_secs",
            artifact_path.display()
        )
    })?;
    ensure!(
        start > 0 && end >= start,
        "video evidence artifact {} must provide a valid timestamp window",
        artifact_path.display()
    );
    Ok(())
}

#[cfg(unix)]
fn validate_retention_window(value: Option<&Value>, artifact_path: &Path) -> anyhow::Result<()> {
    let Some(retention_window) = value.and_then(Value::as_object) else {
        bail!(
            "video evidence artifact {} must provide retention_window.policy and retention_window.expires_at_unix_secs",
            artifact_path.display()
        );
    };
    validate_nonempty_string_field(retention_window.get("policy"), "retention_window.policy", artifact_path)?;
    ensure!(
        retention_window
            .get("expires_at_unix_secs")
            .and_then(Value::as_u64)
            .is_some_and(|value| value > 0),
        "video evidence artifact {} must provide retention_window.expires_at_unix_secs > 0",
        artifact_path.display()
    );
    Ok(())
}

#[cfg(unix)]
fn validate_nonempty_string_field(value: Option<&Value>, field: &str, artifact_path: &Path) -> anyhow::Result<()> {
    ensure!(
        value
            .and_then(Value::as_str)
            .is_some_and(|value| !value.trim().is_empty()),
        "artifact {} must provide a non-empty {}",
        artifact_path.display(),
        field
    );
    Ok(())
}

#[cfg(unix)]
fn validate_optional_matching_string_field(
    value: Option<&Value>,
    field: &str,
    expected: Option<&str>,
    artifact_path: &Path,
) -> anyhow::Result<()> {
    if let Some(expected) = expected {
        let actual = value
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("artifact {} must provide {}", artifact_path.display(), field))?;
        ensure!(
            actual == expected,
            "artifact {} {} {} does not match requested {}",
            artifact_path.display(),
            field,
            actual,
            expected
        );
    }
    Ok(())
}

#[cfg(unix)]
fn parse_record_command(arguments: Vec<String>) -> anyhow::Result<RecordCommand> {
    let mut evidence_root = row706_default_evidence_dir();
    let mut run_id = None;
    let mut anchor_id = None;
    let mut status = None;
    let mut producer = None;
    let mut artifact_path = None;
    let mut artifact_relpath = None;
    let mut captured_at_unix_secs = None;
    let mut session_id = None;
    let mut vm_lease_id = None;
    let mut detail = None;

    let mut parser = FlagParser::new(arguments);
    while let Some(flag) = parser.next_flag()? {
        match flag.as_str() {
            "--evidence-root" => evidence_root = PathBuf::from(parser.take_value(&flag)?),
            "--run-id" => run_id = Some(parser.take_value(&flag)?),
            "--anchor-id" => anchor_id = Some(parser.take_value(&flag)?),
            "--status" => status = Some(parse_status(&parser.take_value(&flag)?)?),
            "--producer" => producer = Some(parser.take_value(&flag)?),
            "--artifact" => artifact_path = Some(PathBuf::from(parser.take_value(&flag)?)),
            "--artifact-relpath" => artifact_relpath = Some(PathBuf::from(parser.take_value(&flag)?)),
            "--captured-at-unix-secs" => {
                captured_at_unix_secs = Some(
                    parser
                        .take_value(&flag)?
                        .parse::<u64>()
                        .with_context(|| format!("parse {flag} as u64"))?,
                );
            }
            "--session-id" => session_id = Some(parser.take_value(&flag)?),
            "--vm-lease-id" => vm_lease_id = Some(parser.take_value(&flag)?),
            "--detail" => detail = Some(parser.take_value(&flag)?),
            other => bail!("unknown flag {other}\n\n{}", usage()),
        }
    }

    let artifact_relpath = artifact_relpath.ok_or_else(|| anyhow::anyhow!("missing --artifact-relpath"))?;
    validate_relative_normal_path(&artifact_relpath)?;

    Ok(RecordCommand {
        evidence_root,
        run_id: run_id.ok_or_else(|| anyhow::anyhow!("missing --run-id"))?,
        anchor_id: anchor_id.ok_or_else(|| anyhow::anyhow!("missing --anchor-id"))?,
        status: status.ok_or_else(|| anyhow::anyhow!("missing --status"))?,
        producer: producer.ok_or_else(|| anyhow::anyhow!("missing --producer"))?,
        artifact_path: artifact_path.ok_or_else(|| anyhow::anyhow!("missing --artifact"))?,
        artifact_relpath,
        captured_at_unix_secs: captured_at_unix_secs.unwrap_or(now_unix_secs()?),
        session_id,
        vm_lease_id,
        detail,
    })
}

#[cfg(unix)]
fn parse_finalize_command(arguments: Vec<String>) -> anyhow::Result<FinalizeCommand> {
    let mut evidence_root = row706_default_evidence_dir();
    let mut run_id = None;

    let mut parser = FlagParser::new(arguments);
    while let Some(flag) = parser.next_flag()? {
        match flag.as_str() {
            "--evidence-root" => evidence_root = PathBuf::from(parser.take_value(&flag)?),
            "--run-id" => run_id = Some(parser.take_value(&flag)?),
            other => bail!("unknown flag {other}\n\n{}", usage()),
        }
    }

    Ok(FinalizeCommand {
        evidence_root,
        run_id: run_id.ok_or_else(|| anyhow::anyhow!("missing --run-id"))?,
    })
}

#[cfg(unix)]
fn parse_status(value: &str) -> anyhow::Result<ManualHeadedAnchorStatus> {
    match value {
        "passed" => Ok(ManualHeadedAnchorStatus::Passed),
        "blocked_prereq" => Ok(ManualHeadedAnchorStatus::BlockedPrereq),
        "failed" => Ok(ManualHeadedAnchorStatus::Failed),
        _ => bail!("unsupported status {value}; expected passed, blocked_prereq, or failed"),
    }
}

#[cfg(unix)]
fn validate_relative_normal_path(path: &Path) -> anyhow::Result<()> {
    ensure!(!path.as_os_str().is_empty(), "artifact relpath must not be empty");
    ensure!(
        path.is_relative(),
        "artifact relpath must stay relative: {}",
        path.display()
    );
    ensure!(
        path.components()
            .all(|component| matches!(component, Component::Normal(_))),
        "artifact relpath must not escape or use special components: {}",
        path.display()
    );
    Ok(())
}

#[cfg(unix)]
fn sha256_file_hex(path: &Path) -> anyhow::Result<String> {
    let bytes = fs::read(path).with_context(|| format!("read file for sha256 {}", path.display()))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

#[cfg(unix)]
fn now_unix_secs() -> anyhow::Result<u64> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock must be after unix epoch")?;
    Ok(duration.as_secs())
}

#[cfg(unix)]
fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.as_bytes().iter().all(u8::is_ascii_hexdigit)
}

#[cfg(unix)]
fn usage() -> &'static str {
    "usage:
  honeypot-manual-headed-writer preflight --run-id <uuid> --anchor-id <anchor> --status <passed|blocked_prereq|failed> --producer <producer> --artifact <path> --artifact-relpath <relative-path> [--detail <text>] [--captured-at-unix-secs <secs>] [--evidence-root <path>]
  honeypot-manual-headed-writer runtime --run-id <uuid> --anchor-id <anchor> --status <passed|blocked_prereq|failed> --producer <producer> --artifact <path> --artifact-relpath <relative-path> [--session-id <id>] [--vm-lease-id <id>] [--detail <text>] [--captured-at-unix-secs <secs>] [--evidence-root <path>]
  honeypot-manual-headed-writer finalize --run-id <uuid> [--evidence-root <path>]"
}

#[cfg(unix)]
struct FlagParser {
    arguments: Vec<String>,
    index: usize,
}

#[cfg(unix)]
impl FlagParser {
    fn new(arguments: Vec<String>) -> Self {
        Self { arguments, index: 0 }
    }

    fn next_flag(&mut self) -> anyhow::Result<Option<String>> {
        if self.index >= self.arguments.len() {
            return Ok(None);
        }
        let flag = self.arguments[self.index].clone();
        self.index += 1;
        ensure!(flag.starts_with("--"), "unexpected positional argument {flag}");
        Ok(Some(flag))
    }

    fn take_value(&mut self, flag: &str) -> anyhow::Result<String> {
        let value = self
            .arguments
            .get(self.index)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("missing value for {flag}"))?;
        ensure!(!value.starts_with("--"), "missing value for {flag}");
        self.index += 1;
        Ok(value)
    }
}
