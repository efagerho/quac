//! NIC introspection helpers used to drive the SO_INCOMING_CPU + per-queue
//! thread-pinning alignment described in [`docs/SOCKETS.md`](../../docs/SOCKETS.md).
//!
//! All three helpers walk Linux-specific filesystems (`/sys/class/net`,
//! `/proc/interrupts`, `/proc/irq/<n>/smp_affinity_list`); the module is
//! gated `cfg(target_os = "linux")` by its caller.

use std::ffi::CStr;
use std::fs;
use std::io;
use std::net::IpAddr;

/// Resolve a non-wildcard bind IP to the interface that owns it.
///
/// Implementation: walks `getifaddrs(3)` and returns the name of the first
/// interface whose address exactly matches `ip`. Fails if `ip` is the
/// unspecified address or if no interface owns it.
pub fn interface_for_addr(ip: IpAddr) -> io::Result<String> {
    if ip.is_unspecified() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "interface_for_addr: bind address is unspecified (0.0.0.0 / [::])",
        ));
    }

    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return Err(io::Error::last_os_error());
    }

    // Always free the list, including on the success path.
    struct Freer(*mut libc::ifaddrs);
    impl Drop for Freer {
        fn drop(&mut self) {
            unsafe { libc::freeifaddrs(self.0) };
        }
    }
    let _guard = Freer(head);

    let mut cur = head;
    while !cur.is_null() {
        let ent = unsafe { &*cur };
        if ent.ifa_addr.is_null() {
            cur = ent.ifa_next;
            continue;
        }
        let family = unsafe { (*ent.ifa_addr).sa_family } as i32;
        let matched = match (family, ip) {
            (libc::AF_INET, IpAddr::V4(want)) => {
                let sin = unsafe { &*(ent.ifa_addr as *const libc::sockaddr_in) };
                u32::from_be(sin.sin_addr.s_addr) == u32::from(want)
            }
            (libc::AF_INET6, IpAddr::V6(want)) => {
                let sin6 = unsafe { &*(ent.ifa_addr as *const libc::sockaddr_in6) };
                sin6.sin6_addr.s6_addr == want.octets()
            }
            _ => false,
        };
        if matched {
            let name = unsafe { CStr::from_ptr(ent.ifa_name) }
                .to_string_lossy()
                .into_owned();
            return Ok(name);
        }
        cur = ent.ifa_next;
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!("interface_for_addr: no interface owns {ip}"),
    ))
}

/// Resolve a kernel `if_index` to its textual interface name via
/// `if_indextoname(3)`. Returns `Err` for `if_index == 0` (which means
/// "no interface" in netlink semantics) and for any index the kernel
/// doesn't know.
///
/// Used by AF_XDP, which binds to `(if_index, queue_id)` and only stores
/// the index — `pin_current_thread_to_queue_cpu` needs the textual name
/// to drive `cpu_for_rx_queue`.
pub fn iface_name(if_index: u32) -> io::Result<String> {
    if if_index == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "iface_name: if_index 0 is not a valid interface",
        ));
    }
    let mut buf = [0u8; libc::IF_NAMESIZE];
    // SAFETY: buf has libc::IF_NAMESIZE bytes; if_indextoname writes at
    // most that many including the NUL terminator.
    let r = unsafe { libc::if_indextoname(if_index, buf.as_mut_ptr() as *mut _) };
    if r.is_null() {
        return Err(io::Error::last_os_error());
    }
    let cstr = unsafe { CStr::from_ptr(buf.as_ptr() as *const _) };
    Ok(cstr.to_string_lossy().into_owned())
}

/// Slave names from `/sys/class/net/<iface>/bonding/slaves` if `iface` is
/// a bond, `None` otherwise. Bonds own no IRQs, so the other helpers
/// recurse through the physical slaves.
pub fn bond_slaves(iface: &str) -> io::Result<Option<Vec<String>>> {
    let path = format!("/sys/class/net/{iface}/bonding/slaves");
    match fs::read_to_string(&path) {
        Ok(s) => Ok(Some(s.split_whitespace().map(String::from).collect())),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(io::Error::new(
            e.kind(),
            format!("bond_slaves: read({path}): {e}"),
        )),
    }
}

/// One physical NIC RX queue. `iface` is the slave name, `queue_id` is
/// the queue's index within that slave, `cpu` is the single-CPU IRQ
/// affinity, and `flat_index` is the position in the bond-flattened
/// `enumerate_rx_queues` result (equals `queue_id` for non-bonds). Pass
/// `flat_index` as the `queue_id` argument to OS / io_uring `bind` so
/// the internal `cpu_for_rx_queue` recursion lands on the right slave.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RxQueue {
    pub iface: String,
    pub queue_id: u16,
    pub cpu: u32,
    pub flat_index: u16,
}

/// All RX queues attached to `iface`, with bond slaves expanded in sysfs
/// order. Errors on the first multi-CPU IRQ affinity it encounters.
pub fn enumerate_rx_queues(iface: &str) -> io::Result<Vec<RxQueue>> {
    let mut out = enumerate_rx_queues_inner(iface)?;
    for (i, rq) in out.iter_mut().enumerate() {
        rq.flat_index = i as u16;
    }
    Ok(out)
}

fn enumerate_rx_queues_inner(iface: &str) -> io::Result<Vec<RxQueue>> {
    if let Some(slaves) = bond_slaves(iface)? {
        let mut out = Vec::new();
        for slave in &slaves {
            out.extend(enumerate_rx_queues_inner(slave)?);
        }
        return Ok(out);
    }

    let n = nic_queue_count_local(iface)?;
    let mut out = Vec::with_capacity(n as usize);
    for q in 0..n as u16 {
        let cpu = cpu_for_rx_queue_local(iface, q)?;
        // flat_index gets overwritten by the top-level enumerate_rx_queues.
        out.push(RxQueue {
            iface: iface.to_string(),
            queue_id: q,
            cpu,
            flat_index: 0,
        });
    }
    Ok(out)
}

/// Group queues by CPU into per-tile assignments. Groups are ordered by
/// ascending CPU for deterministic tile indexing.
pub fn coalesce_by_cpu(queues: Vec<RxQueue>) -> Vec<(u32, Vec<RxQueue>)> {
    use std::collections::BTreeMap;
    let mut by_cpu: BTreeMap<u32, Vec<RxQueue>> = BTreeMap::new();
    for q in queues {
        by_cpu.entry(q.cpu).or_default().push(q);
    }
    by_cpu.into_iter().collect()
}

/// Number of RX queues on `iface`. Counts `/sys/class/net/<iface>/queues/rx-*`
/// entries; for bonds, sums across slaves (the bond itself owns no real
/// RX queues — its sysfs dirs are virtual, sized by the `tx_queues`
/// mod-param).
pub fn nic_queue_count(iface: &str) -> io::Result<u32> {
    if let Some(slaves) = bond_slaves(iface)? {
        let mut total = 0u32;
        for slave in &slaves {
            total += nic_queue_count(slave)?;
        }
        return Ok(total);
    }
    nic_queue_count_local(iface)
}

/// Sysfs-only queue count, ignoring bonding.
fn nic_queue_count_local(iface: &str) -> io::Result<u32> {
    let dir = format!("/sys/class/net/{iface}/queues");
    let entries = fs::read_dir(&dir)
        .map_err(|e| io::Error::new(e.kind(), format!("nic_queue_count: read_dir({dir}): {e}")))?;
    let mut n = 0u32;
    for ent in entries {
        let ent = ent?;
        let name = ent.file_name();
        let name = name.to_string_lossy();
        if let Some(rest) = name.strip_prefix("rx-") {
            if rest.parse::<u32>().is_ok() {
                n += 1;
            }
        }
    }
    if n == 0 {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("nic_queue_count: {iface} has no rx-* queues"),
        ));
    }
    Ok(n)
}

/// CPU running the IRQ for `<iface>` rx queue `queue_id`.
///
/// Walks `/proc/interrupts` looking for a line whose interrupt name ends in
/// `-<queue_id>` (or `-rx-<queue_id>`, `-Rx-<queue_id>`, `-TxRx-<queue_id>`,
/// `<n>@<iface>`-style mlx5 names) AND mentions `<iface>`. Returns the IRQ
/// number from the first column, then reads
/// `/proc/irq/<irq>/smp_affinity_list` and returns the CPU.
///
/// Returns `Ok(cpu)` only when the affinity mask names **exactly one CPU**.
/// Multi-CPU affinity is rejected with an `io::Error` whose message points
/// at the IRQ-pinning prerequisite — the caller (in practice, the bench
/// harness) catches this and prints the standard
/// "[quac-socket] SO_INCOMING_CPU skipped: …" warning.
///
/// For bonds the flat `queue_id` rolls across slaves in sysfs order; the
/// lookup recurses on the resolved slave.
pub fn cpu_for_rx_queue(iface: &str, queue_id: u16) -> io::Result<u32> {
    if let Some(slaves) = bond_slaves(iface)? {
        let mut offset: u32 = 0;
        for slave in &slaves {
            let slave_n = nic_queue_count(slave)?;
            if (queue_id as u32) < offset + slave_n {
                let slave_q = (queue_id as u32 - offset) as u16;
                return cpu_for_rx_queue(slave, slave_q);
            }
            offset += slave_n;
        }
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "cpu_for_rx_queue: bond {iface} flat queue {queue_id} is past the \
                 sum of slave queue counts ({offset})"
            ),
        ));
    }
    cpu_for_rx_queue_local(iface, queue_id)
}

/// Non-bond IRQ → CPU lookup.
fn cpu_for_rx_queue_local(iface: &str, queue_id: u16) -> io::Result<u32> {
    let irq = irq_for_rx_queue(iface, queue_id)?;
    let path = format!("/proc/irq/{irq}/smp_affinity_list");
    let raw = fs::read_to_string(&path)
        .map_err(|e| io::Error::new(e.kind(), format!("cpu_for_rx_queue: read({path}): {e}")))?;
    parse_single_cpu_affinity_list(raw.trim()).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "cpu_for_rx_queue: irq {irq} ({iface} rx-{queue_id}) has affinity \
                 list {raw:?} ({e}); pin each NIC IRQ to exactly one CPU \
                 (see docs/SOCKETS.md \"Multi-queue setup\") -- e.g. \
                 `echo <cpu> > {path}` and stop irqbalance",
                raw = raw.trim()
            ),
        )
    })
}

/// Find the IRQ number serving `<iface>` rx queue `queue_id` by scanning
/// `/proc/interrupts`. Driver-specific naming conventions:
///
/// - intel ice / i40e / ixgbe:  `<iface>-TxRx-<N>`, `<iface>-Tx-<N>`, `<iface>-Rx-<N>`
/// - mellanox mlx5:             `mlx5_comp<N>@<iface>`
/// - virtio-net:                `<iface>-input.<N>`
/// - generic fallback:          `<iface>-rx-<N>` or `<iface>-<N>`
///
/// We accept any IRQ-name token that contains `<iface>` and ends in
/// `-<queue_id>`, `.<queue_id>`, or `<queue_id>@<iface>`. The first match
/// wins; on the boards we care about there is at most one.
fn irq_for_rx_queue(iface: &str, queue_id: u16) -> io::Result<u32> {
    let raw = fs::read_to_string("/proc/interrupts").map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("irq_for_rx_queue: read(/proc/interrupts): {e}"),
        )
    })?;

    let qid_str = queue_id.to_string();
    for line in raw.lines() {
        // Format: " 145:   0  0 ...   IO-APIC  <name1> <name2> ..."
        // Split off the leading "IRQ:" token.
        let line = line.trim_start();
        let Some((head, rest)) = line.split_once(':') else {
            continue;
        };
        let Ok(irq) = head.trim().parse::<u32>() else {
            continue;
        };

        // The interrupt name(s) are the trailing whitespace-separated tokens.
        // Tokens before them are per-CPU counters and the controller name.
        // Rather than parse position-wise, just scan all tokens for a match.
        for tok in rest.split_whitespace() {
            if !tok.contains(iface) {
                continue;
            }
            let matches = tok.ends_with(&format!("-{qid_str}"))
                || tok.ends_with(&format!(".{qid_str}"))
                || tok.starts_with(&format!("mlx5_comp{qid_str}@"));
            if matches {
                return Ok(irq);
            }
        }
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!(
            "irq_for_rx_queue: no IRQ in /proc/interrupts matches {iface} rx-{queue_id}; \
             check ethtool -l/-x setup or that the driver names IRQs predictably"
        ),
    ))
}

/// Parse a comma-separated CPU list (e.g. `"3"`, `"0-7"`, `"1,3,5"`) and
/// return the single CPU id, or an error if the list resolves to zero or
/// more than one CPU.
fn parse_single_cpu_affinity_list(s: &str) -> Result<u32, String> {
    let mut cpus: Vec<u32> = Vec::new();
    for part in s.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        match part.split_once('-') {
            Some((lo, hi)) => {
                let lo: u32 = lo
                    .parse()
                    .map_err(|e| format!("bad range lo {part:?}: {e}"))?;
                let hi: u32 = hi
                    .parse()
                    .map_err(|e| format!("bad range hi {part:?}: {e}"))?;
                if hi < lo {
                    return Err(format!("inverted range {part:?}"));
                }
                for c in lo..=hi {
                    cpus.push(c);
                    if cpus.len() > 1 {
                        return Err(format!("affinity covers more than one CPU ({s:?})"));
                    }
                }
            }
            None => {
                let c: u32 = part
                    .parse()
                    .map_err(|e| format!("bad cpu id {part:?}: {e}"))?;
                cpus.push(c);
                if cpus.len() > 1 {
                    return Err(format!("affinity covers more than one CPU ({s:?})"));
                }
            }
        }
    }
    cpus.into_iter()
        .next()
        .ok_or_else(|| format!("empty affinity list {s:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn loopback_resolves_to_lo() {
        let name = interface_for_addr(IpAddr::V4(Ipv4Addr::LOCALHOST))
            .expect("interface_for_addr(127.0.0.1)");
        assert_eq!(name, "lo");
    }

    #[test]
    fn unspecified_addr_errors() {
        let r = interface_for_addr(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        assert!(r.is_err(), "0.0.0.0 must be rejected");
    }

    #[test]
    fn iface_name_round_trips_loopback() {
        // /sys/class/net/lo/ifindex is the canonical lo index (almost
        // always 1, but read it instead of hard-coding so this passes in
        // exotic netns setups).
        let raw = std::fs::read_to_string("/sys/class/net/lo/ifindex")
            .expect("read /sys/class/net/lo/ifindex");
        let lo_idx: u32 = raw.trim().parse().expect("parse lo ifindex");
        assert_eq!(iface_name(lo_idx).unwrap(), "lo");
    }

    #[test]
    fn iface_name_zero_errors() {
        assert!(iface_name(0).is_err());
    }

    #[test]
    fn iface_name_unknown_errors() {
        // u32::MAX is virtually guaranteed not to be a real if_index.
        assert!(iface_name(u32::MAX).is_err());
    }

    #[test]
    fn loopback_has_at_least_one_rx_queue() {
        let n = nic_queue_count("lo").expect("nic_queue_count(lo)");
        assert!(n >= 1, "lo must report at least rx-0, got {n}");
    }

    #[test]
    fn nonexistent_iface_errors() {
        let r = nic_queue_count("definitely-not-a-real-iface-quac42");
        assert!(r.is_err());
    }

    #[test]
    fn lo_has_no_irq_named_rx_queue() {
        // Loopback rx-0 has no entry in /proc/interrupts, so the lookup
        // must fail with a clear NotFound. This locks in the soft-fail
        // path the bench depends on.
        let r = irq_for_rx_queue("lo", 0);
        assert!(r.is_err(), "lo rx-0 must not resolve to an IRQ");
    }

    #[test]
    fn parse_affinity_list_single_cpu() {
        assert_eq!(parse_single_cpu_affinity_list("0"), Ok(0));
        assert_eq!(parse_single_cpu_affinity_list("17"), Ok(17));
        assert_eq!(parse_single_cpu_affinity_list("3-3"), Ok(3));
    }

    #[test]
    fn parse_affinity_list_rejects_multi_cpu() {
        assert!(parse_single_cpu_affinity_list("0,1").is_err());
        assert!(parse_single_cpu_affinity_list("0-7").is_err());
        assert!(parse_single_cpu_affinity_list("3,5").is_err());
    }

    #[test]
    fn parse_affinity_list_rejects_empty() {
        assert!(parse_single_cpu_affinity_list("").is_err());
    }

    #[test]
    fn bond_slaves_returns_none_for_non_bond() {
        assert_eq!(bond_slaves("lo").unwrap(), None);
    }

    #[test]
    fn bond_slaves_errors_for_unknown_iface() {
        // A name that won't exist as a sysfs entry: read_to_string will
        // return NotFound, which we map back to Ok(None) (the iface
        // "isn't a bond" — but it also isn't anything else). That mirrors
        // the contract: bond_slaves only reports bonds, all other shapes
        // (including missing) report None.
        assert_eq!(
            bond_slaves("definitely-not-a-real-iface-quac42").unwrap(),
            None
        );
    }

    #[test]
    fn coalesce_by_cpu_groups_by_cpu() {
        let queues = vec![
            RxQueue {
                iface: "eth0".into(),
                queue_id: 0,
                cpu: 5,
                flat_index: 0,
            },
            RxQueue {
                iface: "eth0".into(),
                queue_id: 1,
                cpu: 7,
                flat_index: 1,
            },
            RxQueue {
                iface: "eth1".into(),
                queue_id: 0,
                cpu: 5,
                flat_index: 2,
            },
        ];
        let groups = coalesce_by_cpu(queues);
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].0, 5);
        assert_eq!(groups[0].1.len(), 2);
        assert_eq!(groups[1].0, 7);
        assert_eq!(groups[1].1.len(), 1);
    }

    #[test]
    fn coalesce_by_cpu_orders_by_cpu_ascending() {
        let queues = vec![
            RxQueue {
                iface: "eth0".into(),
                queue_id: 0,
                cpu: 9,
                flat_index: 0,
            },
            RxQueue {
                iface: "eth0".into(),
                queue_id: 1,
                cpu: 1,
                flat_index: 1,
            },
            RxQueue {
                iface: "eth0".into(),
                queue_id: 2,
                cpu: 4,
                flat_index: 2,
            },
        ];
        let groups = coalesce_by_cpu(queues);
        let cpus: Vec<u32> = groups.iter().map(|(c, _)| *c).collect();
        assert_eq!(cpus, vec![1, 4, 9]);
    }

    #[test]
    fn coalesce_by_cpu_empty_input() {
        let groups = coalesce_by_cpu(Vec::new());
        assert!(groups.is_empty());
    }

    #[test]
    fn nic_queue_count_non_bond_unchanged() {
        // Loopback isn't a bond; the function path is the same as
        // before this change.
        let n = nic_queue_count("lo").unwrap();
        assert!(n >= 1);
    }
}
