//! aya-based loader for the AF_XDP redirect program. Defaults to the
//! embedded [`quac-socket-xdp-ebpf`] program; custom BPF objects can be
//! supplied via [`crate::XdpConfig::program_bytes`].
//!
//! ## Custom-program contract
//!
//! Required symbols (looked up by string name):
//! - `quac_xdp` -- `BPF_PROG_TYPE_XDP` entry point.
//! - `BOUND_PORTS` -- `BPF_MAP_TYPE_HASH<u16, u8>`. Userspace inserts/removes
//!   on bind/drop; the program checks membership before redirecting.
//! - `XSKMAP` -- `BPF_MAP_TYPE_XSKMAP`. Userspace inserts the AF_XDP fd at
//!   the socket's `rx_queue_id` after `bind(2)` succeeds.
//!
//! Optional: `DROP_COUNTERS` -- `BPF_MAP_TYPE_PERCPU_ARRAY<u64>`.
//!
//! ## Lifecycle
//!
//! One program per NIC; multiple `XdpSocket`s share it and add their own
//! entries to its maps. The first `get_or_load` per `if_index` decides
//! which bytes are loaded; subsequent calls must supply matching bytes or
//! `None` (mismatches error rather than silently reuse). The program is
//! never unloaded -- manual cleanup via `ip link set dev <if> xdp{generic,drv}
//! off` is the only way to detach.

use std::collections::{BTreeSet, HashMap};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, RawFd};
use std::sync::{Arc, Mutex, OnceLock};

use aya::Ebpf;
use aya::maps::{HashMap as AyaHashMap, XskMap};
use aya::programs::{Xdp, XdpFlags};

use quac_socket_xdp_ebpf::QUAC_SOCKET_XDP_EBPF_PROGRAM;

/// XDP attach mode. `Default` lets the kernel pick. `Skb` forces generic
/// XDP (works everywhere, slowest). `Drv` forces native (required for
/// zero-copy). `Hw` offloads to NIC hardware.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachMode {
    Default,
    Skb,
    Drv,
    Hw,
}

impl AttachMode {
    fn flags(self) -> XdpFlags {
        match self {
            AttachMode::Default => XdpFlags::default(),
            AttachMode::Skb => XdpFlags::SKB_MODE,
            AttachMode::Drv => XdpFlags::DRV_MODE,
            AttachMode::Hw => XdpFlags::HW_MODE,
        }
    }
}

/// One loaded + attached eBPF program plus its userspace-managed maps.
/// Owned by the [`PROGRAMS`] registry; each `XdpSocket` holds a strong
/// `Arc` and registers itself via [`bind_port`](Self::bind_port) /
/// [`register_socket`](Self::register_socket).
pub struct XdpProgram {
    ebpf: Ebpf,
    if_index: u32,
    /// Hash of the BPF object bytes; compared in `get_or_load` to detect
    /// version mismatches across calls for the same `if_index`.
    program_hash: u64,
    bound_ports: BTreeSet<u16>,
    registered_queues: BTreeSet<u32>,
}

/// Non-cryptographic hash for detecting accidentally-mismatched BPF objects.
fn hash_program_bytes(bytes: &[u8]) -> u64 {
    let mut h = DefaultHasher::new();
    bytes.hash(&mut h);
    h.finish()
}

impl XdpProgram {
    /// Load `bytes`, validate the contract symbols (`quac_xdp`,
    /// `BOUND_PORTS`, `XSKMAP`) **before** attaching, then attach to
    /// `if_index`. `program_hash` is the precomputed hash of `bytes` so
    /// `get_or_load` doesn't double-hash on the load path.
    fn load_and_attach(
        if_index: u32,
        mode: AttachMode,
        bytes: &[u8],
        program_hash: u64,
    ) -> io::Result<Self> {
        let mut ebpf = Ebpf::load(bytes).map_err(load_err)?;

        // Eagerly type-check the maps so a contract violation surfaces here
        // rather than at first bind_port / register_socket.
        {
            let bound_ports = ebpf
                .map_mut("BOUND_PORTS")
                .ok_or_else(|| io::Error::other(
                    "eBPF object missing required map `BOUND_PORTS` (see crate::program docs for contract)",
                ))?;
            let _: AyaHashMap<_, u16, u8> = AyaHashMap::try_from(bound_ports).map_err(|e| {
                io::Error::other(format!(
                    "eBPF map `BOUND_PORTS` has wrong type (expected HashMap<u16, u8>): {e}"
                ))
            })?;
        }
        {
            let xskmap = ebpf
                .map_mut("XSKMAP")
                .ok_or_else(|| io::Error::other(
                    "eBPF object missing required map `XSKMAP` (see crate::program docs for contract)",
                ))?;
            let _: XskMap<_> = XskMap::try_from(xskmap).map_err(|e| {
                io::Error::other(format!("eBPF map `XSKMAP` has wrong type (expected XskMap): {e}"))
            })?;
        }

        let prog: &mut Xdp = ebpf
            .program_mut("quac_xdp")
            .ok_or_else(|| io::Error::other(
                "eBPF object has no `quac_xdp` program (see crate::program docs for contract)",
            ))?
            .try_into()
            .map_err(load_err)?;

        prog.load().map_err(load_err)?;
        prog.attach_to_if_index(if_index, mode.flags()).map_err(load_err)?;

        Ok(Self {
            ebpf,
            if_index,
            program_hash,
            bound_ports: BTreeSet::new(),
            registered_queues: BTreeSet::new(),
        })
    }

    /// Insert `port` into `BOUND_PORTS`. Future UDP packets with
    /// `dst_port == port` are eligible for redirection.
    pub fn bind_port(&mut self, port: u16) -> io::Result<()> {
        let map = self
            .ebpf
            .map_mut("BOUND_PORTS")
            .ok_or_else(|| io::Error::other("eBPF object has no `BOUND_PORTS` map"))?;
        let mut ports: AyaHashMap<_, u16, u8> = AyaHashMap::try_from(map).map_err(io_err)?;
        ports.insert(port, 1u8, 0).map_err(io_err)?;
        self.bound_ports.insert(port);
        Ok(())
    }

    /// Reverse of [`bind_port`]. Idempotent.
    pub fn unbind_port(&mut self, port: u16) -> io::Result<()> {
        let map = self
            .ebpf
            .map_mut("BOUND_PORTS")
            .ok_or_else(|| io::Error::other("eBPF object has no `BOUND_PORTS` map"))?;
        let mut ports: AyaHashMap<_, u16, u8> = AyaHashMap::try_from(map).map_err(io_err)?;
        // remove() returns Err on missing key -- treat as success.
        let _ = ports.remove(&port);
        self.bound_ports.remove(&port);
        Ok(())
    }

    /// Set `XSKMAP[queue_id] = socket_fd` so the XDP program's
    /// `redirect(ctx->rx_queue_index)` lands on this AF_XDP socket.
    pub fn register_socket(&mut self, queue_id: u32, socket_fd: BorrowedFd<'_>) -> io::Result<()> {
        let map = self
            .ebpf
            .map_mut("XSKMAP")
            .ok_or_else(|| io::Error::other("eBPF object has no `XSKMAP` map"))?;
        let mut xskmap: XskMap<_> = XskMap::try_from(map).map_err(io_err)?;
        xskmap.set(queue_id, socket_fd.as_raw_fd(), 0).map_err(io_err)?;
        self.registered_queues.insert(queue_id);
        Ok(())
    }

    /// Reverse of [`register_socket`]. Drops local tracking only -- the
    /// kernel auto-clears `XSKMAP` entries when the fd closes
    /// (BPF_MAP_TYPE_XSKMAP holds a reference, dropped on `close(2)`).
    /// aya 0.13.x has no `XskMap::remove`.
    pub fn unregister_socket(&mut self, queue_id: u32) -> io::Result<()> {
        self.registered_queues.remove(&queue_id);
        Ok(())
    }

    pub fn if_index(&self) -> u32 {
        self.if_index
    }
}

/// Process-global registry: one program per `if_index`, persisted for the
/// process lifetime (see module docs).
static PROGRAMS: OnceLock<Mutex<HashMap<u32, Arc<Mutex<XdpProgram>>>>> = OnceLock::new();

/// Get the existing program for `if_index`, or load + attach a new one.
/// `program_bytes = None` resolves to the embedded default. The **first**
/// call per `if_index` decides which BPF object is loaded; later calls
/// must supply bytes with a matching content hash (or `None` resolving to
/// the same default), otherwise this errors. The mismatch check catches
/// deployment bugs where two consumers disagree about which program runs.
pub fn get_or_load(
    if_index: u32,
    mode: AttachMode,
    program_bytes: Option<&[u8]>,
) -> io::Result<Arc<Mutex<XdpProgram>>> {
    let bytes: &[u8] = match program_bytes {
        Some(b) => b,
        None => &QUAC_SOCKET_XDP_EBPF_PROGRAM.0,
    };
    let new_hash = hash_program_bytes(bytes);

    let registry = PROGRAMS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut map = registry.lock().expect("XDP program registry mutex poisoned");
    if let Some(existing) = map.get(&if_index) {
        let existing_hash = existing
            .lock()
            .expect("XdpProgram mutex poisoned")
            .program_hash;
        if existing_hash != new_hash {
            return Err(io::Error::other(format!(
                "XDP program mismatch on if_index {if_index}: a program with \
                 content hash {existing_hash:#018x} is already attached, but \
                 the caller supplied a different program (hash \
                 {new_hash:#018x}). The first XdpSocket constructed for an \
                 interface decides which program is loaded; later sockets \
                 must pass either the same bytes or `None`."
            )));
        }
        return Ok(Arc::clone(existing));
    }
    let prog = XdpProgram::load_and_attach(if_index, mode, bytes, new_hash)?;
    let arc = Arc::new(Mutex::new(prog));
    map.insert(if_index, Arc::clone(&arc));
    Ok(arc)
}

/// Embedded BPF bytes, exposed for manual loading (tests, `bpftool`).
pub fn embedded_program_bytes() -> &'static [u8] {
    &QUAC_SOCKET_XDP_EBPF_PROGRAM.0
}

fn io_err<E: std::fmt::Display>(e: E) -> io::Error {
    io::Error::other(e.to_string())
}

/// Like `io_err` but appends a CAP_BPF / CAP_PERFMON hint when the message
/// looks permission-related (substring match -- aya 0.13 surfaces the kernel
/// error string verbatim).
fn load_err<E: std::fmt::Display>(e: E) -> io::Error {
    let msg = e.to_string();
    let lower = msg.to_lowercase();
    if lower.contains("permission denied")
        || lower.contains("operation not permitted")
        || lower.contains("eperm")
        || lower.contains("eacces")
    {
        io::Error::other(format!(
            "{msg}\n\
             hint: loading XDP / AF_XDP requires CAP_BPF + CAP_PERFMON (kernel >= 5.8) \
             or CAP_SYS_ADMIN. Run as root, or grant caps with: \
             `sudo setcap cap_bpf,cap_perfmon,cap_net_raw=eip <binary>`."
        ))
    } else {
        io::Error::other(msg)
    }
}

// Keep `AsFd` / `BorrowedFd` / `RawFd` imports anchored against refactors
// that temporarily drop their call sites.
#[allow(dead_code)]
fn _keep_borrowed_fd<'a>(fd: &'a impl AsFd) -> BorrowedFd<'a> {
    fd.as_fd()
}
#[allow(dead_code)]
const _RAW_FD_USED: RawFd = 0;
