use std::path::{Path, PathBuf};

use anyhow::Context as _;

use crate::config::{ControlPlaneConfig, QemuDiskInterface, QemuFirmwareMode, QemuNetworkDeviceModel, QemuNetworkMode};
use crate::image::TrustedBootProfileV1;

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
    pub firmware_code_path: Option<PathBuf>,
    pub vars_seed_path: Option<PathBuf>,
    pub runtime_vars_path: Option<PathBuf>,
    pub argv: Vec<String>,
}

impl QemuLaunchPlan {
    pub(crate) fn build(
        config: &ControlPlaneConfig,
        vm_lease_id: &str,
        vm_name: &str,
        base_image_path: &Path,
        guest_rdp_port: u16,
        boot_profile_v1: Option<&TrustedBootProfileV1>,
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
        let disk_interface = boot_profile_v1
            .map(|profile| profile.disk_interface)
            .unwrap_or(qemu_config.disk_interface);
        let network_device_model = boot_profile_v1
            .map(|profile| profile.network_device_model)
            .unwrap_or(qemu_config.network.device_model);
        let rtc_base = boot_profile_v1
            .map(|profile| profile.rtc_base)
            .unwrap_or(qemu_config.rtc_base);
        let firmware_mode = boot_profile_v1
            .map(|profile| profile.firmware_mode)
            .unwrap_or(qemu_config.firmware_mode);
        let firmware_code_path = boot_profile_v1.and_then(|profile| profile.firmware_code_path.clone());
        let vars_seed_path = boot_profile_v1.and_then(|profile| profile.vars_seed_path.clone());
        let runtime_vars_path = if vars_seed_path.is_some() {
            Some(runtime_dir.join("OVMF_VARS.fd"))
        } else {
            None
        };
        validate_firmware_runtime_contract(firmware_mode, firmware_code_path.as_deref(), vars_seed_path.as_deref())?;

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
            "-rtc".to_owned(),
            format!("base={}", rtc_base.as_qemu_value()),
            "-nodefaults".to_owned(),
            "-display".to_owned(),
            "none".to_owned(),
            "-no-user-config".to_owned(),
            "-enable-kvm".to_owned(),
            "-pidfile".to_owned(),
            pid_file_path.display().to_string(),
            "-qmp".to_owned(),
            format!("unix:{},server=on,wait=off", qmp_socket_path.display()),
        ];

        if firmware_mode.requires_pflash() {
            let firmware_code_path = firmware_code_path
                .as_ref()
                .context("uefi_pflash firmware mode requires firmware_code_path")?;
            let runtime_vars_path = runtime_vars_path
                .as_ref()
                .context("uefi_pflash firmware mode requires runtime_vars_path")?;
            argv.extend([
                "-drive".to_owned(),
                format!("if=pflash,format=raw,readonly=on,file={}", firmware_code_path.display()),
                "-drive".to_owned(),
                format!("if=pflash,format=raw,file={}", runtime_vars_path.display()),
            ]);
        }

        argv.extend(disk_argv(&overlay_path, disk_interface));
        argv.extend(network_argv(config, guest_rdp_port, network_device_model));

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
            firmware_code_path,
            vars_seed_path,
            runtime_vars_path,
            argv,
        })
    }
}

pub(crate) fn validate_qemu_runtime_contract(config: &ControlPlaneConfig) -> anyhow::Result<()> {
    let qemu_config = &config.runtime.qemu;
    let limits = &config.runtime.limits;

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
        limits.max_vcpu_count > 0,
        "runtime.limits.max_vcpu_count must be greater than zero",
    );
    anyhow::ensure!(
        qemu_config.vcpu_count <= limits.max_vcpu_count,
        "runtime.qemu.vcpu_count must be less than or equal to runtime.limits.max_vcpu_count",
    );
    anyhow::ensure!(
        qemu_config.memory_mib > 0,
        "runtime.qemu.memory_mib must be greater than zero",
    );
    anyhow::ensure!(
        limits.max_memory_mib > 0,
        "runtime.limits.max_memory_mib must be greater than zero",
    );
    anyhow::ensure!(
        qemu_config.memory_mib <= limits.max_memory_mib,
        "runtime.qemu.memory_mib must be less than or equal to runtime.limits.max_memory_mib",
    );
    anyhow::ensure!(
        !qemu_config.network.netdev_id.trim().is_empty(),
        "runtime.qemu.network.netdev_id must not be empty",
    );
    anyhow::ensure!(
        qemu_config
            .network
            .netdev_id
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_')),
        "runtime.qemu.network.netdev_id must contain only ASCII letters, digits, hyphens, and underscores",
    );
    anyhow::ensure!(
        config.runtime.stop_timeout_secs > 0,
        "runtime.stop_timeout_secs must be greater than zero",
    );
    anyhow::ensure!(
        limits.max_stop_timeout_secs > 0,
        "runtime.limits.max_stop_timeout_secs must be greater than zero",
    );
    anyhow::ensure!(
        config.runtime.stop_timeout_secs <= limits.max_stop_timeout_secs,
        "runtime.stop_timeout_secs must be less than or equal to runtime.limits.max_stop_timeout_secs",
    );
    anyhow::ensure!(
        limits.max_overlay_size_mib > 0,
        "runtime.limits.max_overlay_size_mib must be greater than zero",
    );
    let _ = limits.max_overlay_size_bytes()?;

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

fn network_argv(config: &ControlPlaneConfig, guest_rdp_port: u16, device_model: QemuNetworkDeviceModel) -> Vec<String> {
    let network = &config.runtime.qemu.network;

    vec![
        "-netdev".to_owned(),
        format!(
            "{},restrict=on,id={},hostfwd=tcp:{}:{}-:{}",
            network.mode.as_qemu_value(),
            network.netdev_id,
            network.host_loopback_addr,
            guest_rdp_port,
            GUEST_RDP_PORT
        ),
        "-device".to_owned(),
        format!("{},netdev={}", device_model.as_qemu_device(), network.netdev_id),
    ]
}

fn disk_argv(overlay_path: &Path, disk_interface: QemuDiskInterface) -> Vec<String> {
    let mut argv = vec![
        "-drive".to_owned(),
        format!(
            "if=none,id=os-disk,file={},format=qcow2,cache=writeback",
            overlay_path.display()
        ),
    ];

    match disk_interface {
        QemuDiskInterface::VirtioBlkPci => {
            argv.extend(["-device".to_owned(), "virtio-blk-pci,drive=os-disk".to_owned()]);
        }
        QemuDiskInterface::AhciIde => {
            argv.extend([
                "-device".to_owned(),
                "ich9-ahci,id=sata".to_owned(),
                "-device".to_owned(),
                "ide-hd,drive=os-disk,bus=sata.0".to_owned(),
            ]);
        }
    }

    argv
}

fn validate_firmware_runtime_contract(
    firmware_mode: QemuFirmwareMode,
    firmware_code_path: Option<&Path>,
    vars_seed_path: Option<&Path>,
) -> anyhow::Result<()> {
    match firmware_mode {
        QemuFirmwareMode::None => {
            anyhow::ensure!(
                firmware_code_path.is_none(),
                "runtime boot profile must not set firmware_code_path when firmware_mode is none",
            );
            anyhow::ensure!(
                vars_seed_path.is_none(),
                "runtime boot profile must not set vars_seed_path when firmware_mode is none",
            );
        }
        QemuFirmwareMode::UefiPflash => {
            let firmware_code_path =
                firmware_code_path.context("uefi_pflash firmware mode requires firmware_code_path")?;
            let vars_seed_path = vars_seed_path.context("uefi_pflash firmware mode requires vars_seed_path")?;
            ensure_file("firmware_code_path", firmware_code_path)?;
            ensure_file("vars_seed_path", vars_seed_path)?;
        }
    }

    Ok(())
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
    use crate::config::{ControlPlaneConfig, QemuDiskInterface, QemuFirmwareMode, QemuNetworkDeviceModel, QemuRtcBase};
    use crate::image::TrustedBootProfileV1;

    #[test]
    fn qemu_launch_plan_uses_typed_runtime_contract() {
        let tempdir = tempfile::tempdir().expect("create tempdir");
        let config = test_config(tempdir.path());
        let base_image_path = tempdir.path().join("images").join("gold-image.qcow2");
        fs::write(&base_image_path, b"not-a-real-qcow2").expect("write fake base image");

        let plan = QemuLaunchPlan::build(
            &config,
            "lease-00000001",
            "honeypot-gold-image",
            &base_image_path,
            3390,
            None,
        )
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
            window.first().map(String::as_str) == Some("-rtc") && window.get(1).map(String::as_str) == Some("base=utc")
        }));
        assert!(
            plan.argv.iter().any(|arg| arg.contains("restrict=on")),
            "{:?}",
            plan.argv
        );
        assert!(plan.argv.windows(2).any(|window| {
            window.first().map(String::as_str) == Some("-display") && window.get(1).map(String::as_str) == Some("none")
        }));
        assert!(!plan.argv.iter().any(|arg| arg == "-vnc"));
        assert!(!plan.argv.iter().any(|arg| arg == "-monitor"));
        assert_eq!(plan.firmware_code_path, None);
        assert_eq!(plan.vars_seed_path, None);
        assert_eq!(plan.runtime_vars_path, None);
    }

    #[test]
    fn qemu_launch_plan_replays_allowlisted_boot_profile_v1() {
        let tempdir = tempfile::tempdir().expect("create tempdir");
        let config = test_config(tempdir.path());
        let base_image_path = tempdir.path().join("images").join("gold-image.qcow2");
        let firmware_code_path = tempdir.path().join("images").join("OVMF_CODE.fd");
        let vars_seed_path = tempdir.path().join("images").join("OVMF_VARS.seed.fd");
        fs::write(&base_image_path, b"not-a-real-qcow2").expect("write fake base image");
        fs::write(&firmware_code_path, b"fake firmware code").expect("write fake firmware code");
        fs::write(&vars_seed_path, b"fake vars seed").expect("write fake vars seed");
        let boot_profile = TrustedBootProfileV1 {
            disk_interface: QemuDiskInterface::AhciIde,
            network_device_model: QemuNetworkDeviceModel::E1000,
            rtc_base: QemuRtcBase::Localtime,
            firmware_mode: QemuFirmwareMode::UefiPflash,
            firmware_code_path: Some(firmware_code_path.clone()),
            vars_seed_path: Some(vars_seed_path.clone()),
        };

        let plan = QemuLaunchPlan::build(
            &config,
            "lease-00000001",
            "honeypot-gold-image",
            &base_image_path,
            3390,
            Some(&boot_profile),
        )
        .expect("build qemu launch plan");

        assert_eq!(plan.firmware_code_path, Some(firmware_code_path));
        assert_eq!(plan.vars_seed_path, Some(vars_seed_path));
        assert_eq!(plan.runtime_vars_path, Some(plan.runtime_dir.join("OVMF_VARS.fd")));
        assert!(plan.argv.windows(2).any(|window| {
            window.first().map(String::as_str) == Some("-rtc")
                && window.get(1).map(String::as_str) == Some("base=localtime")
        }));
        assert!(
            plan.argv.iter().any(|arg| arg == "ich9-ahci,id=sata"),
            "{:?}",
            plan.argv
        );
        assert!(
            plan.argv.iter().any(|arg| arg == "ide-hd,drive=os-disk,bus=sata.0"),
            "{:?}",
            plan.argv
        );
        assert!(
            plan.argv.iter().any(|arg| arg == "e1000,netdev=net0"),
            "{:?}",
            plan.argv
        );
        assert!(
            plan.argv
                .iter()
                .any(|arg| arg.contains("if=pflash,format=raw,readonly=on,file=")),
            "{:?}",
            plan.argv
        );
        assert!(
            plan.argv
                .iter()
                .any(|arg| arg.contains("if=pflash,format=raw,file=") && arg.contains("OVMF_VARS.fd")),
            "{:?}",
            plan.argv
        );
        assert!(!plan.argv.iter().any(|arg| arg == "virtio-blk-pci,drive=os-disk"));
    }

    #[test]
    fn qemu_launch_plan_rejects_missing_base_image() {
        let tempdir = tempfile::tempdir().expect("create tempdir");
        let config = test_config(tempdir.path());
        let base_image_path = tempdir.path().join("images").join("missing.qcow2");

        let error = QemuLaunchPlan::build(
            &config,
            "lease-00000001",
            "honeypot-gold-image",
            &base_image_path,
            3390,
            None,
        )
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

        let error = QemuLaunchPlan::build(
            &config,
            "lease-00000001",
            "honeypot-gold-image",
            &base_image_path,
            3390,
            None,
        )
        .expect_err("non-loopback user networking should fail");

        assert!(format!("{error:#}").contains("host_loopback_addr"), "{error:#}");
    }

    #[test]
    fn qemu_launch_plan_rejects_vcpu_counts_above_runtime_limit() {
        let tempdir = tempfile::tempdir().expect("create tempdir");
        let mut config = test_config(tempdir.path());
        config.runtime.limits.max_vcpu_count = 2;
        let base_image_path = tempdir.path().join("images").join("gold-image.qcow2");
        fs::write(&base_image_path, b"not-a-real-qcow2").expect("write fake base image");

        let error = QemuLaunchPlan::build(
            &config,
            "lease-00000001",
            "honeypot-gold-image",
            &base_image_path,
            3390,
            None,
        )
        .expect_err("vcpu counts above the configured runtime limit should fail");

        assert!(format!("{error:#}").contains("max_vcpu_count"), "{error:#}");
    }

    #[test]
    fn qemu_launch_plan_rejects_memory_above_runtime_limit() {
        let tempdir = tempfile::tempdir().expect("create tempdir");
        let mut config = test_config(tempdir.path());
        config.runtime.limits.max_memory_mib = 1024;
        let base_image_path = tempdir.path().join("images").join("gold-image.qcow2");
        fs::write(&base_image_path, b"not-a-real-qcow2").expect("write fake base image");

        let error = QemuLaunchPlan::build(
            &config,
            "lease-00000001",
            "honeypot-gold-image",
            &base_image_path,
            3390,
            None,
        )
        .expect_err("memory above the configured runtime limit should fail");

        assert!(format!("{error:#}").contains("max_memory_mib"), "{error:#}");
    }

    #[test]
    fn qemu_launch_plan_rejects_stop_timeout_above_runtime_limit() {
        let tempdir = tempfile::tempdir().expect("create tempdir");
        let mut config = test_config(tempdir.path());
        config.runtime.stop_timeout_secs = 30;
        config.runtime.limits.max_stop_timeout_secs = 10;
        let base_image_path = tempdir.path().join("images").join("gold-image.qcow2");
        fs::write(&base_image_path, b"not-a-real-qcow2").expect("write fake base image");

        let error = QemuLaunchPlan::build(
            &config,
            "lease-00000001",
            "honeypot-gold-image",
            &base_image_path,
            3390,
            None,
        )
        .expect_err("stop timeout above the configured runtime limit should fail");

        assert!(format!("{error:#}").contains("max_stop_timeout_secs"), "{error:#}");
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
