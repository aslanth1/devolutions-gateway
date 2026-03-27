use std::path::{Path, PathBuf};

use crate::config::{ControlPlaneConfig, QemuNetworkMode};

const GUEST_RDP_PORT: u16 = 3389;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct QemuLaunchPlan {
    pub qemu_binary_path: PathBuf,
    pub vm_name: String,
    pub runtime_dir: PathBuf,
    pub base_image_path: PathBuf,
    pub overlay_path: PathBuf,
    pub pid_file_path: PathBuf,
    pub qmp_socket_path: PathBuf,
    pub qga_socket_path: Option<PathBuf>,
    pub argv: Vec<String>,
}

impl QemuLaunchPlan {
    pub(crate) fn build(
        config: &ControlPlaneConfig,
        vm_lease_id: &str,
        vm_name: &str,
        base_image_path: &Path,
        guest_rdp_port: u16,
    ) -> anyhow::Result<Self> {
        validate_lease_id(vm_lease_id)?;
        validate_qemu_runtime_contract(config)?;
        ensure_file("base_image_path", base_image_path)?;

        let runtime_dir = config.paths.lease_store.join(vm_lease_id);
        let overlay_path = runtime_dir.join("overlay.qcow2");
        let pid_file_path = runtime_dir.join("qemu.pid");
        let qmp_socket_path = config.paths.qmp_dir.join(format!("{vm_lease_id}.sock"));
        let qga_socket_path = if config.runtime.enable_guest_agent {
            Some(config.paths.qga_dir()?.join(format!("{vm_lease_id}.sock")))
        } else {
            None
        };

        let qemu_config = &config.runtime.qemu;
        let mut argv = vec![
            "-name".to_owned(),
            vm_name.to_owned(),
            "-machine".to_owned(),
            format!(
                "{},accel={}",
                qemu_config.machine_type,
                qemu_config.accelerator.as_qemu_value()
            ),
            "-cpu".to_owned(),
            qemu_config.cpu_model.clone(),
            "-smp".to_owned(),
            qemu_config.vcpu_count.to_string(),
            "-m".to_owned(),
            qemu_config.memory_mib.to_string(),
            "-nodefaults".to_owned(),
            "-display".to_owned(),
            "none".to_owned(),
            "-no-user-config".to_owned(),
            "-enable-kvm".to_owned(),
            "-pidfile".to_owned(),
            pid_file_path.display().to_string(),
            "-qmp".to_owned(),
            format!("unix:{},server=on,wait=off", qmp_socket_path.display()),
            "-drive".to_owned(),
            format!(
                "if=none,id=os-disk,file={},format=qcow2,cache=writeback",
                overlay_path.display()
            ),
            "-device".to_owned(),
            format!("{},drive=os-disk", qemu_config.disk_interface.as_qemu_device()),
        ];

        argv.extend(network_argv(config, guest_rdp_port));

        if let Some(qga_socket_path) = &qga_socket_path {
            argv.extend([
                "-device".to_owned(),
                "virtio-serial".to_owned(),
                "-chardev".to_owned(),
                format!("socket,id=qga0,path={},server=on,wait=off", qga_socket_path.display()),
                "-device".to_owned(),
                "virtserialport,chardev=qga0,name=org.qemu.guest_agent.0".to_owned(),
            ]);
        }

        validate_control_socket_isolation(&argv, &qmp_socket_path, qga_socket_path.as_deref())?;

        Ok(Self {
            qemu_binary_path: qemu_config.binary_path.clone(),
            vm_name: vm_name.to_owned(),
            runtime_dir,
            base_image_path: base_image_path.to_path_buf(),
            overlay_path,
            pid_file_path,
            qmp_socket_path,
            qga_socket_path,
            argv,
        })
    }
}

pub(crate) fn validate_qemu_runtime_contract(config: &ControlPlaneConfig) -> anyhow::Result<()> {
    let qemu_config = &config.runtime.qemu;

    ensure_file("runtime.qemu.binary_path", &qemu_config.binary_path)?;
    anyhow::ensure!(
        !qemu_config.machine_type.trim().is_empty(),
        "runtime.qemu.machine_type must not be empty",
    );
    anyhow::ensure!(
        !qemu_config.cpu_model.trim().is_empty(),
        "runtime.qemu.cpu_model must not be empty",
    );
    anyhow::ensure!(
        qemu_config.vcpu_count > 0,
        "runtime.qemu.vcpu_count must be greater than zero",
    );
    anyhow::ensure!(
        qemu_config.memory_mib > 0,
        "runtime.qemu.memory_mib must be greater than zero",
    );
    anyhow::ensure!(
        !qemu_config.network.netdev_id.trim().is_empty(),
        "runtime.qemu.network.netdev_id must not be empty",
    );
    anyhow::ensure!(
        config.runtime.stop_timeout_secs > 0,
        "runtime.stop_timeout_secs must be greater than zero",
    );

    if matches!(qemu_config.network.mode, QemuNetworkMode::User) {
        anyhow::ensure!(
            qemu_config.network.host_loopback_addr.is_loopback(),
            "runtime.qemu.network.host_loopback_addr must stay on loopback for user-mode networking",
        );
    }

    if config.runtime.enable_guest_agent {
        let qga_dir = config.paths.qga_dir()?;
        anyhow::ensure!(
            qga_dir.is_dir(),
            "runtime.enable_guest_agent requires a valid qga_dir at {}",
            qga_dir.display(),
        );
    }

    Ok(())
}

fn validate_control_socket_isolation(
    argv: &[String],
    qmp_socket_path: &Path,
    qga_socket_path: Option<&Path>,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        argv.windows(2)
            .any(|window| window.first().map(String::as_str) == Some("-display")
                && window.get(1).map(String::as_str) == Some("none")),
        "qemu launch plan must stay headless with -display none",
    );
    anyhow::ensure!(
        !argv.iter().any(|arg| arg == "-vnc"),
        "qemu launch plan must not enable VNC control channels",
    );
    anyhow::ensure!(
        !argv.iter().any(|arg| arg == "-monitor"),
        "qemu launch plan must not expose monitor control channels",
    );

    let expected_qmp = format!("unix:{},server=on,wait=off", qmp_socket_path.display());
    anyhow::ensure!(
        argv.windows(2)
            .any(|window| window.first().map(String::as_str) == Some("-qmp") && window.get(1) == Some(&expected_qmp)),
        "qemu launch plan must keep qmp on unix:{}",
        qmp_socket_path.display(),
    );

    if let Some(qga_socket_path) = qga_socket_path {
        let expected_qga = format!("socket,id=qga0,path={},server=on,wait=off", qga_socket_path.display());
        anyhow::ensure!(
            argv.windows(2)
                .any(|window| window.first().map(String::as_str) == Some("-chardev")
                    && window.get(1) == Some(&expected_qga)),
            "qemu launch plan must keep qga on {}",
            qga_socket_path.display(),
        );
    }

    Ok(())
}

fn network_argv(config: &ControlPlaneConfig, guest_rdp_port: u16) -> Vec<String> {
    let network = &config.runtime.qemu.network;

    vec![
        "-netdev".to_owned(),
        format!(
            "{},id={},hostfwd=tcp:{}:{}-:{}",
            network.mode.as_qemu_value(),
            network.netdev_id,
            network.host_loopback_addr,
            guest_rdp_port,
            GUEST_RDP_PORT
        ),
        "-device".to_owned(),
        format!("{},netdev={}", network.device_model.as_qemu_device(), network.netdev_id),
    ]
}

fn validate_lease_id(vm_lease_id: &str) -> anyhow::Result<()> {
    anyhow::ensure!(!vm_lease_id.is_empty(), "vm_lease_id must not be empty");
    anyhow::ensure!(
        vm_lease_id.chars().all(|ch| ch.is_ascii_alphanumeric() || ch == '-'),
        "vm_lease_id must contain only ASCII letters, digits, and hyphens",
    );
    Ok(())
}

fn ensure_file(label: &str, path: &Path) -> anyhow::Result<()> {
    anyhow::ensure!(path.exists(), "{label} does not exist at {}", path.display());
    anyhow::ensure!(path.is_file(), "{label} is not a file at {}", path.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use super::{QemuLaunchPlan, validate_control_socket_isolation};
    use crate::config::ControlPlaneConfig;

    #[test]
    fn qemu_launch_plan_uses_typed_runtime_contract() {
        let tempdir = tempfile::tempdir().expect("create tempdir");
        let config = test_config(tempdir.path());
        let base_image_path = tempdir.path().join("images").join("gold-image.qcow2");
        fs::write(&base_image_path, b"not-a-real-qcow2").expect("write fake base image");

        let plan = QemuLaunchPlan::build(&config, "lease-00000001", "honeypot-gold-image", &base_image_path, 3390)
            .expect("build qemu launch plan");

        assert_eq!(
            plan.qemu_binary_path,
            tempdir.path().join("bin").join("qemu-system-x86_64")
        );
        assert_eq!(plan.runtime_dir, tempdir.path().join("leases").join("lease-00000001"));
        assert_eq!(plan.overlay_path, plan.runtime_dir.join("overlay.qcow2"));
        assert_eq!(
            plan.qmp_socket_path,
            tempdir.path().join("qmp").join("lease-00000001.sock")
        );
        assert_eq!(
            plan.qga_socket_path,
            Some(tempdir.path().join("qga").join("lease-00000001.sock"))
        );
        assert!(
            plan.argv.iter().any(|arg| arg == "virtio-blk-pci,drive=os-disk"),
            "{:?}",
            plan.argv
        );
        assert!(
            plan.argv
                .iter()
                .any(|arg| arg.contains("hostfwd=tcp:127.0.0.1:3390-:3389")),
            "{:?}",
            plan.argv
        );
        assert!(plan.argv.windows(2).any(|window| {
            window.first().map(String::as_str) == Some("-display") && window.get(1).map(String::as_str) == Some("none")
        }));
        assert!(!plan.argv.iter().any(|arg| arg == "-vnc"));
        assert!(!plan.argv.iter().any(|arg| arg == "-monitor"));
    }

    #[test]
    fn qemu_launch_plan_rejects_missing_base_image() {
        let tempdir = tempfile::tempdir().expect("create tempdir");
        let config = test_config(tempdir.path());
        let base_image_path = tempdir.path().join("images").join("missing.qcow2");

        let error = QemuLaunchPlan::build(&config, "lease-00000001", "honeypot-gold-image", &base_image_path, 3390)
            .expect_err("missing base image should fail");

        assert!(format!("{error:#}").contains("base_image_path"), "{error:#}");
    }

    #[test]
    fn qemu_launch_plan_rejects_non_loopback_user_networking() {
        let tempdir = tempfile::tempdir().expect("create tempdir");
        let mut config = test_config(tempdir.path());
        config.runtime.qemu.network.host_loopback_addr = "10.0.0.5".parse().expect("parse ip");
        let base_image_path = tempdir.path().join("images").join("gold-image.qcow2");
        fs::write(&base_image_path, b"not-a-real-qcow2").expect("write fake base image");

        let error = QemuLaunchPlan::build(&config, "lease-00000001", "honeypot-gold-image", &base_image_path, 3390)
            .expect_err("non-loopback user networking should fail");

        assert!(format!("{error:#}").contains("host_loopback_addr"), "{error:#}");
    }

    #[test]
    fn qemu_launch_plan_rejects_exposed_control_channel_regression() {
        let qmp_socket_path = Path::new("/run/honeypot/qmp/lease.sock");
        let qga_socket_path = Path::new("/run/honeypot/qga/lease.sock");
        let argv = vec![
            "-display".to_owned(),
            "none".to_owned(),
            "-qmp".to_owned(),
            "tcp:0.0.0.0:4444,server=on,wait=off".to_owned(),
            "-chardev".to_owned(),
            format!("socket,id=qga0,path={},server=on,wait=off", qga_socket_path.display()),
        ];

        let error = validate_control_socket_isolation(&argv, qmp_socket_path, Some(qga_socket_path))
            .expect_err("tcp-based qmp channel should be rejected");

        assert!(format!("{error:#}").contains("qmp"), "{error:#}");
    }

    fn test_config(root: &Path) -> ControlPlaneConfig {
        let mut config = ControlPlaneConfig::default();
        let bin_dir = root.join("bin");
        let image_store = root.join("images");
        let lease_store = root.join("leases");
        let quarantine_store = root.join("quarantine");
        let qmp_dir = root.join("qmp");
        let qga_dir = root.join("qga");
        let secret_dir = root.join("secrets");
        let kvm_path = root.join("kvm");

        fs::create_dir_all(&bin_dir).expect("create bin dir");
        fs::create_dir_all(&image_store).expect("create image store");
        fs::create_dir_all(&lease_store).expect("create lease store");
        fs::create_dir_all(&quarantine_store).expect("create quarantine store");
        fs::create_dir_all(&qmp_dir).expect("create qmp dir");
        fs::create_dir_all(&qga_dir).expect("create qga dir");
        fs::create_dir_all(&secret_dir).expect("create secret dir");
        fs::write(bin_dir.join("qemu-system-x86_64"), b"fake-binary").expect("write fake qemu");
        fs::write(&kvm_path, b"fake-kvm").expect("write fake kvm");

        config.runtime.enable_guest_agent = true;
        config.runtime.qemu.binary_path = bin_dir.join("qemu-system-x86_64");
        config.paths.image_store = image_store;
        config.paths.lease_store = lease_store;
        config.paths.quarantine_store = quarantine_store;
        config.paths.qmp_dir = qmp_dir;
        config.paths.qga_dir = Some(qga_dir);
        config.paths.secret_dir = secret_dir;
        config.paths.kvm_path = kvm_path;
        config
    }
}
