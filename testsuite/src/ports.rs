use std::net::{Ipv4Addr, SocketAddrV4, TcpListener};
use std::sync::LazyLock;
use std::sync::atomic::{AtomicUsize, Ordering};

const DEFAULT_TEST_PORT_START: u16 = 20_000;
const FALLBACK_EPHEMERAL_PORT_START: u16 = 32_768;
const MIN_TEST_PORT_WINDOW: u16 = 1_024;

static TEST_PORT_ALLOCATOR: LazyLock<TestPortAllocator> = LazyLock::new(TestPortAllocator::detect);

pub fn allocate_test_port() -> u16 {
    TEST_PORT_ALLOCATOR.allocate()
}

struct TestPortAllocator {
    start: u16,
    len: usize,
    next_offset: AtomicUsize,
}

impl TestPortAllocator {
    fn detect() -> Self {
        let ephemeral_start = detect_ephemeral_port_start().unwrap_or(FALLBACK_EPHEMERAL_PORT_START);
        let range_end = ephemeral_start.saturating_sub(1);
        let start = preferred_test_port_start(range_end);
        let len = usize::from(range_end - start + 1);
        let seed_port = seed_test_port();
        let seed_offset = usize::from(seed_port.saturating_sub(start)) % len;

        Self {
            start,
            len,
            next_offset: AtomicUsize::new(seed_offset),
        }
    }

    fn allocate(&self) -> u16 {
        for _ in 0..self.len {
            let offset = self.next_offset.fetch_add(1, Ordering::Relaxed) % self.len;
            let offset = u16::try_from(offset).expect("test port offset must fit in u16");
            let candidate = self.start + offset;
            let addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, candidate);

            if TcpListener::bind(addr).is_ok() {
                return candidate;
            }
        }

        panic!("unable to allocate an unused localhost test port");
    }
}

fn preferred_test_port_start(range_end: u16) -> u16 {
    let preferred_width_end = DEFAULT_TEST_PORT_START.saturating_add(MIN_TEST_PORT_WINDOW - 1);

    if range_end >= preferred_width_end {
        return DEFAULT_TEST_PORT_START;
    }

    range_end.saturating_sub(MIN_TEST_PORT_WINDOW - 1).max(1_024)
}

fn seed_test_port() -> u16 {
    let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).expect("bind localhost seed port");
    let seed = listener.local_addr().expect("read localhost seed port").port();
    let ephemeral_start = detect_ephemeral_port_start().unwrap_or(FALLBACK_EPHEMERAL_PORT_START);
    let range_end = ephemeral_start.saturating_sub(1);
    let start = preferred_test_port_start(range_end);
    let len = range_end - start + 1;

    start + (seed % len)
}

#[cfg(target_os = "linux")]
fn detect_ephemeral_port_start() -> Option<u16> {
    let range = std::fs::read_to_string("/proc/sys/net/ipv4/ip_local_port_range").ok()?;
    let mut parts = range.split_whitespace();
    let start = parts.next()?.parse::<u16>().ok()?;
    let _end = parts.next()?.parse::<u16>().ok()?;

    Some(start.max(DEFAULT_TEST_PORT_START + MIN_TEST_PORT_WINDOW))
}

#[cfg(not(target_os = "linux"))]
fn detect_ephemeral_port_start() -> Option<u16> {
    None
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::allocate_test_port;

    #[test]
    fn allocate_test_port_returns_unique_ports_within_one_process() {
        let ports = (0..32).map(|_| allocate_test_port()).collect::<Vec<_>>();
        let unique = ports.iter().copied().collect::<BTreeSet<_>>();

        assert_eq!(ports.len(), unique.len(), "expected unique test ports");
    }
}
