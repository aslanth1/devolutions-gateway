#[cfg(not(unix))]
fn main() {
    panic!("fake-qemu is only supported on unix test hosts");
}

#[cfg(unix)]
fn main() -> anyhow::Result<()> {
    use std::net::TcpListener;
    use std::path::PathBuf;
    use std::time::Duration;

    let mode = std::env::args()
        .next()
        .and_then(|argv0| {
            PathBuf::from(argv0)
                .file_stem()
                .and_then(|stem| stem.to_str())
                .map(ToOwned::to_owned)
        })
        .unwrap_or_else(|| "fake-qemu".to_owned());
    // SAFETY: `getppid` has no preconditions.
    let original_parent_pid = unsafe { libc::getppid() };

    if mode.contains("early-exit") {
        std::process::exit(41);
    }

    if mode.contains("ignore-term") {
        // SAFETY: ignoring SIGTERM is a test-only behavior used to simulate a hung QEMU shutdown.
        unsafe {
            libc::signal(libc::SIGTERM, libc::SIG_IGN);
        }
    }

    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let qmp_socket_path = qmp_socket_path(&args).ok_or_else(|| anyhow::anyhow!("missing -qmp socket path"))?;
    let qga_socket_path = qga_socket_path(&args);
    let rdp_listener = if mode.contains("rdp-ready") {
        rdp_forward_listener(&args).transpose()?
    } else {
        None
    };

    let mut listeners = Vec::new();
    listeners.push(bind_socket(&qmp_socket_path)?);
    if let Some(qga_socket_path) = &qga_socket_path {
        listeners.push(bind_socket(qga_socket_path)?);
    }
    let _rdp_listener: Option<TcpListener> = rdp_listener;

    loop {
        // Exit if the control-plane parent changed so the helper never outlives the test harness.
        // SAFETY: `getppid` has no preconditions.
        let parent_pid = unsafe { libc::getppid() };
        if parent_pid != original_parent_pid {
            break;
        }

        std::thread::sleep(Duration::from_millis(100));
    }

    drop(listeners);
    Ok(())
}

#[cfg(unix)]
fn bind_socket(path: &std::path::Path) -> anyhow::Result<std::os::unix::net::UnixListener> {
    use std::os::unix::net::UnixListener;

    if path.exists() {
        std::fs::remove_file(path)?;
    }

    Ok(UnixListener::bind(path)?)
}

#[cfg(unix)]
fn qmp_socket_path(args: &[String]) -> Option<std::path::PathBuf> {
    find_arg_value(args, "-qmp").and_then(|value| {
        value
            .strip_prefix("unix:")
            .and_then(|value| value.split_once(',').map(|(path, _)| path).or(Some(value)))
            .map(std::path::PathBuf::from)
    })
}

#[cfg(unix)]
fn qga_socket_path(args: &[String]) -> Option<std::path::PathBuf> {
    find_arg_value(args, "-chardev").and_then(|value| {
        value
            .split(',')
            .find_map(|field| field.strip_prefix("path=").map(std::path::PathBuf::from))
    })
}

#[cfg(unix)]
fn rdp_forward_listener(args: &[String]) -> Option<anyhow::Result<std::net::TcpListener>> {
    find_arg_value(args, "-netdev")
        .and_then(parse_hostfwd_loopback_addr)
        .map(bind_tcp_listener)
}

#[cfg(unix)]
fn parse_hostfwd_loopback_addr(value: &str) -> Option<std::net::SocketAddrV4> {
    use std::net::{Ipv4Addr, SocketAddrV4};

    value.split(',').find_map(|field| {
        let hostfwd = field.strip_prefix("hostfwd=tcp:")?;
        let (host_bind, _guest_bind) = hostfwd.split_once("-:")?;
        let (host, port) = host_bind.rsplit_once(':')?;
        let host: Ipv4Addr = host.parse().ok()?;
        let port: u16 = port.parse().ok()?;
        Some(SocketAddrV4::new(host, port))
    })
}

#[cfg(unix)]
fn bind_tcp_listener(addr: std::net::SocketAddrV4) -> anyhow::Result<std::net::TcpListener> {
    Ok(std::net::TcpListener::bind(addr)?)
}

#[cfg(unix)]
fn find_arg_value<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    args.windows(2).find_map(|window| {
        if window[0] == flag {
            Some(window[1].as_str())
        } else {
            None
        }
    })
}
