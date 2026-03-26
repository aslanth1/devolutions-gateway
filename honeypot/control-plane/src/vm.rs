use std::fs;
use std::os::unix::net::UnixListener;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::Context as _;

use crate::config::{ControlPlaneConfig, VmLifecycleDriver};
use crate::lease::LeaseLaunchPlanSnapshot;

const PROCESS_START_TIMEOUT_SECS: u64 = 5;

pub(crate) fn create_vm(plan: &LeaseLaunchPlanSnapshot) -> anyhow::Result<()> {
    cleanup_artifacts(plan)?;
    fs::create_dir_all(&plan.runtime_dir)
        .with_context(|| format!("create runtime dir {}", plan.runtime_dir.display()))?;
    fs::copy(&plan.base_image_path, &plan.overlay_path).with_context(|| {
        format!(
            "copy base image {} to lease overlay {}",
            plan.base_image_path.display(),
            plan.overlay_path.display()
        )
    })?;
    Ok(())
}

pub(crate) fn start_vm(config: &ControlPlaneConfig, plan: &LeaseLaunchPlanSnapshot) -> anyhow::Result<()> {
    match config.runtime.lifecycle_driver {
        VmLifecycleDriver::Process => start_process_vm(plan),
        VmLifecycleDriver::Simulated => start_simulated_vm(plan),
    }
}

pub(crate) fn stop_vm(config: &ControlPlaneConfig, plan: &LeaseLaunchPlanSnapshot) -> anyhow::Result<()> {
    match config.runtime.lifecycle_driver {
        VmLifecycleDriver::Process => stop_process_vm(config, plan),
        VmLifecycleDriver::Simulated => stop_simulated_vm(plan),
    }
}

pub(crate) fn reset_vm(config: &ControlPlaneConfig, plan: &LeaseLaunchPlanSnapshot) -> anyhow::Result<()> {
    stop_vm(config, plan)?;
    create_vm(plan)?;
    start_vm(config, plan)
}

pub(crate) fn destroy_vm(plan: &LeaseLaunchPlanSnapshot) -> anyhow::Result<()> {
    cleanup_artifacts(plan)
}

pub(crate) fn runtime_looks_active(plan: &LeaseLaunchPlanSnapshot) -> anyhow::Result<bool> {
    if !plan.runtime_dir.is_dir() || !plan.overlay_path.is_file() || !plan.pid_file_path.is_file() {
        return Ok(false);
    }

    if !plan.qmp_socket_path.exists() {
        return Ok(false);
    }

    if let Some(qga_socket_path) = &plan.qga_socket_path
        && !qga_socket_path.exists()
    {
        return Ok(false);
    }

    let pid = read_pid(&plan.pid_file_path)?;
    process_exists(pid)
}

pub(crate) fn cleanup_orphaned_vm(config: &ControlPlaneConfig, plan: &LeaseLaunchPlanSnapshot) -> anyhow::Result<()> {
    match config.runtime.lifecycle_driver {
        VmLifecycleDriver::Process => terminate_orphaned_process_vm(config, plan)?,
        VmLifecycleDriver::Simulated => cleanup_runtime_markers(plan)?,
    }

    Ok(())
}

fn start_process_vm(plan: &LeaseLaunchPlanSnapshot) -> anyhow::Result<()> {
    let mut command = Command::new(&plan.qemu_binary_path);
    command
        .args(&plan.argv)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    let mut child = command.spawn().with_context(|| {
        format!(
            "spawn qemu process {} for {}",
            plan.qemu_binary_path.display(),
            plan.vm_name
        )
    })?;

    fs::write(&plan.pid_file_path, child.id().to_string())
        .with_context(|| format!("write pid file {}", plan.pid_file_path.display()))?;
    wait_for_process_runtime_ready(&mut child, plan)?;

    Ok(())
}

fn start_simulated_vm(plan: &LeaseLaunchPlanSnapshot) -> anyhow::Result<()> {
    fs::write(&plan.pid_file_path, std::process::id().to_string())
        .with_context(|| format!("write simulated pid file {}", plan.pid_file_path.display()))?;
    create_socket_marker(&plan.qmp_socket_path)?;

    if let Some(qga_socket_path) = &plan.qga_socket_path {
        create_socket_marker(qga_socket_path)?;
    }

    Ok(())
}

fn stop_process_vm(config: &ControlPlaneConfig, plan: &LeaseLaunchPlanSnapshot) -> anyhow::Result<()> {
    let pid = read_pid(&plan.pid_file_path)?;
    // SAFETY: `kill` is called with a PID read from our own pidfile and a fixed signal number.
    let result = unsafe { libc::kill(pid, libc::SIGTERM) };
    if result != 0 {
        let error = std::io::Error::last_os_error();
        anyhow::ensure!(
            error.raw_os_error() == Some(libc::ESRCH),
            "send SIGTERM to qemu pid {pid}: {error}",
        );
    }

    let deadline = Instant::now() + Duration::from_secs(config.runtime.stop_timeout_secs);
    while !wait_for_process_exit(pid)? {
        if Instant::now() >= deadline {
            anyhow::bail!(
                "qemu pid {pid} did not exit within {} seconds",
                config.runtime.stop_timeout_secs
            );
        }

        thread::sleep(Duration::from_millis(50));
    }

    cleanup_runtime_markers(plan)
}

fn stop_simulated_vm(plan: &LeaseLaunchPlanSnapshot) -> anyhow::Result<()> {
    cleanup_runtime_markers(plan)
}

fn terminate_orphaned_process_vm(config: &ControlPlaneConfig, plan: &LeaseLaunchPlanSnapshot) -> anyhow::Result<()> {
    if !plan.pid_file_path.exists() {
        return cleanup_runtime_markers(plan);
    }

    let pid = read_pid(&plan.pid_file_path)?;
    if process_exists(pid)? {
        signal_process(pid, libc::SIGTERM)?;
        if !wait_for_external_process_exit(pid, Duration::from_secs(config.runtime.stop_timeout_secs))? {
            signal_process(pid, libc::SIGKILL)?;
            anyhow::ensure!(
                wait_for_external_process_exit(pid, Duration::from_secs(1))?,
                "qemu pid {pid} did not exit during orphan cleanup",
            );
        }
    }

    cleanup_runtime_markers(plan)
}

fn cleanup_artifacts(plan: &LeaseLaunchPlanSnapshot) -> anyhow::Result<()> {
    cleanup_runtime_markers(plan)?;

    if plan.overlay_path.exists() {
        fs::remove_file(&plan.overlay_path)
            .with_context(|| format!("remove overlay {}", plan.overlay_path.display()))?;
    }

    if plan.runtime_dir.exists() {
        fs::remove_dir_all(&plan.runtime_dir)
            .with_context(|| format!("remove runtime dir {}", plan.runtime_dir.display()))?;
    }

    Ok(())
}

fn cleanup_runtime_markers(plan: &LeaseLaunchPlanSnapshot) -> anyhow::Result<()> {
    remove_if_exists(&plan.pid_file_path)?;
    remove_if_exists(&plan.qmp_socket_path)?;

    if let Some(qga_socket_path) = &plan.qga_socket_path {
        remove_if_exists(qga_socket_path)?;
    }

    Ok(())
}

fn create_socket_marker(path: &std::path::Path) -> anyhow::Result<()> {
    if path.exists() {
        fs::remove_file(path).with_context(|| format!("remove stale socket {}", path.display()))?;
    }

    let listener = UnixListener::bind(path).with_context(|| format!("bind simulated socket {}", path.display()))?;
    drop(listener);
    Ok(())
}

fn remove_if_exists(path: &std::path::Path) -> anyhow::Result<()> {
    if path.exists() {
        fs::remove_file(path).with_context(|| format!("remove {}", path.display()))?;
    }

    Ok(())
}

fn read_pid(path: &std::path::Path) -> anyhow::Result<i32> {
    let pid = fs::read_to_string(path).with_context(|| format!("read pid file {}", path.display()))?;
    pid.trim()
        .parse::<i32>()
        .with_context(|| format!("parse pid from {}", path.display()))
}

fn signal_process(pid: i32, signal: i32) -> anyhow::Result<()> {
    // SAFETY: `kill` is called with a PID parsed from our own pidfile and a fixed signal number.
    let result = unsafe { libc::kill(pid, signal) };
    if result == 0 {
        return Ok(());
    }

    let error = std::io::Error::last_os_error();
    anyhow::ensure!(
        error.raw_os_error() == Some(libc::ESRCH),
        "send signal {signal} to qemu pid {pid}: {error}",
    );
    Ok(())
}

fn process_exists(pid: i32) -> anyhow::Result<bool> {
    // SAFETY: `kill` with signal 0 does not modify process state and only checks liveness for the parsed PID.
    let result = unsafe { libc::kill(pid, 0) };
    if result == 0 {
        return Ok(true);
    }

    let error = std::io::Error::last_os_error();
    match error.raw_os_error() {
        Some(libc::ESRCH) => Ok(false),
        Some(libc::EPERM) => Ok(true),
        _ => Err(error).with_context(|| format!("probe qemu pid {pid} liveness")),
    }
}

fn wait_for_external_process_exit(pid: i32, timeout: Duration) -> anyhow::Result<bool> {
    let deadline = Instant::now() + timeout;
    loop {
        if !process_exists(pid)? {
            return Ok(true);
        }

        if Instant::now() >= deadline {
            return Ok(false);
        }

        thread::sleep(Duration::from_millis(50));
    }
}

fn wait_for_process_runtime_ready(
    child: &mut std::process::Child,
    plan: &LeaseLaunchPlanSnapshot,
) -> anyhow::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(PROCESS_START_TIMEOUT_SECS);

    loop {
        if runtime_ready(plan) {
            return Ok(());
        }

        if let Some(status) = child.try_wait().context("check qemu early exit status")? {
            anyhow::bail!("qemu exited before the lease reached running state: {status}");
        }

        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            anyhow::bail!(
                "qemu did not create the required runtime sockets within {PROCESS_START_TIMEOUT_SECS} seconds",
            );
        }

        thread::sleep(Duration::from_millis(50));
    }
}

fn runtime_ready(plan: &LeaseLaunchPlanSnapshot) -> bool {
    plan.qmp_socket_path.exists()
        && plan
            .qga_socket_path
            .as_ref()
            .is_none_or(|qga_socket_path| qga_socket_path.exists())
}

fn wait_for_process_exit(pid: i32) -> anyhow::Result<bool> {
    let mut status = 0;
    // SAFETY: `waitpid` is called for a child PID that we started earlier, and `status` points to valid storage.
    let result = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
    if result == pid {
        return Ok(true);
    }
    if result == 0 {
        return Ok(false);
    }

    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ECHILD) {
        return Ok(true);
    }

    Err(error).with_context(|| format!("wait for qemu pid {pid} to exit"))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use super::{create_vm, destroy_vm, reset_vm, start_vm, stop_vm};
    use crate::config::{ControlPlaneConfig, VmLifecycleDriver};
    use crate::lease::LeaseLaunchPlanSnapshot;

    #[test]
    fn simulated_lifecycle_creates_starts_stops_and_resets_runtime_artifacts() {
        let tempdir = tempfile::tempdir().expect("create tempdir");
        let mut config = test_config(tempdir.path());
        config.runtime.lifecycle_driver = VmLifecycleDriver::Simulated;
        let plan = test_plan(tempdir.path());

        create_vm(&plan).expect("create simulated vm");
        assert!(plan.runtime_dir.is_dir());
        assert!(plan.overlay_path.is_file());
        assert!(!plan.pid_file_path.exists());
        assert!(!plan.qmp_socket_path.exists());

        start_vm(&config, &plan).expect("start simulated vm");
        assert!(plan.pid_file_path.is_file());
        assert!(plan.qmp_socket_path.exists());

        stop_vm(&config, &plan).expect("stop simulated vm");
        assert!(!plan.pid_file_path.exists());
        assert!(!plan.qmp_socket_path.exists());
        assert!(plan.overlay_path.is_file());

        reset_vm(&config, &plan).expect("reset simulated vm");
        assert!(plan.runtime_dir.is_dir());
        assert!(plan.overlay_path.is_file());
        assert!(plan.pid_file_path.is_file());
        assert!(plan.qmp_socket_path.exists());

        destroy_vm(&plan).expect("destroy simulated vm");
        assert!(!plan.runtime_dir.exists());
        assert!(!plan.qmp_socket_path.exists());
    }

    fn test_config(root: &Path) -> ControlPlaneConfig {
        let mut config = ControlPlaneConfig::default();
        let qga_dir = root.join("qga");

        fs::create_dir_all(&qga_dir).expect("create qga dir");
        config.paths.qga_dir = Some(qga_dir);
        config
    }

    fn test_plan(root: &Path) -> LeaseLaunchPlanSnapshot {
        let image_store = root.join("images");
        let runtime_dir = root.join("leases").join("lease-00000001");
        let qmp_dir = root.join("qmp");
        let qga_dir = root.join("qga");
        let base_image_path = image_store.join("gold-image.qcow2");

        fs::create_dir_all(&image_store).expect("create image store");
        fs::create_dir_all(&qmp_dir).expect("create qmp dir");
        fs::write(&base_image_path, b"fake-base-image").expect("write fake base image");

        LeaseLaunchPlanSnapshot {
            qemu_binary_path: root.join("bin").join("qemu-system-x86_64"),
            vm_name: "honeypot-gold-image".to_owned(),
            runtime_dir: runtime_dir.clone(),
            base_image_path,
            overlay_path: runtime_dir.join("overlay.qcow2"),
            pid_file_path: runtime_dir.join("qemu.pid"),
            qmp_socket_path: qmp_dir.join("lease-00000001.sock"),
            qga_socket_path: Some(qga_dir.join("lease-00000001.sock")),
            argv: Vec::new(),
        }
    }
}
