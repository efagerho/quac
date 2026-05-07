//! aya-based loader for the AF_XDP redirect program.
//!
//! By default this loads the program embedded in [`quac-socket-xdp-ebpf`].
//! Callers can supply their own BPF object via
//! [`crate::XdpConfig::program_bytes`] / [`get_or_load`] as long as it
//! follows the contract below.
//!
//! ## Custom-program contract
//!
//! Any program loaded here must export:
//! - A function symbol named **`quac_xdp`** with `BPF_PROG_TYPE_XDP` —
//!   the entry point that gets attached to the NIC.
//! - A `BPF_MAP_TYPE_HASH` named **`BOUND_PORTS`** with
//!   `key=u16, value=u8`. Userspace inserts a port on `bind` and removes
//!   it on socket drop; the program reads membership to gate redirects.
//! - A `BPF_MAP_TYPE_XSKMAP` named **`XSKMAP`**. Userspace inserts an
//!   AF_XDP fd at the socket's `(rx)queue_id` after `bind(2)` succeeds;
//!   the program redirects matching packets to it.
//!
//! Optional:
//! - A `BPF_MAP_TYPE_PERCPU_ARRAY` named **`DROP_COUNTERS`** with
//!   `value=u64`. Read-only from userspace; useful for diagnostics.
//!
//! Map names matter — the loader looks them up by string. Field types and
//! map-type kinds are validated by aya at insert time, not at load.
//!
//! ## Lifecycle
//!
//! - One eBPF program is attached **per NIC**. Multiple `XdpSocket`s on
//!   the same NIC share it and add their own entries to its maps.
//! - The program-bytes are decided by the **first** `get_or_load` call
//!   per `if_index`. Subsequent calls for the same NIC reuse the existing
//!   handle and ignore their own `program_bytes` argument; this matches
//!   today's "one program per NIC" semantics and avoids surprising
//!   re-attaches.
//! - Attach mode defaults to `XdpFlags::default()` (driver chooses) so
//!   this works on veth (SKB mode) and on real NICs (native mode).
//! - The program is **never unloaded** — last `Arc` drop leaves the eBPF
//!   program attached. This is intentional: another process / kernel
//!   subsystem might still want it. Manual cleanup: `ip link set dev <if>
//!   xdpgeneric off` (or `xdpdrv off` for native mode).

use std::collections::{BTreeSet, HashMap};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, RawFd};
use std::sync::{Arc, Mutex, OnceLock};

use aya::Ebpf;
use aya::maps::{HashMap as AyaHashMap, XskMap};
use aya::programs::{Xdp, XdpFlags};

use quac_socket_xdp_ebpf::QUAC_SOCKET_XDP_EBPF_PROGRAM;

/// XDP attach mode override. `Default` lets the kernel pick (DRV mode on
/// drivers that support it, falls back to SKB). `Skb` forces generic XDP
/// (slowest, works everywhere). `Drv` forces native mode (zero-copy
/// requires `Drv`); `Hw` is offload to NIC hardware.
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
/// Ownership: the global [`PROGRAMS`] registry holds the strong `Arc`;
/// each `XdpSocket` clones it and uses [`bind_port`](Self::bind_port) /
/// [`register_socket`](Self::register_socket) to register itself.
pub struct XdpProgram {
    ebpf: Ebpf,
    if_index: u32,
    /// Hash of the BPF object bytes used to load this program. Compared
    /// against the bytes a later `get_or_load` caller supplies to detect
    /// accidental program-version mismatches across the same `if_index`.
    /// Not cryptographic — this is collision detection, not authentication.
    program_hash: u64,
    /// Track which ports we've inserted so we can clean up on drop.
    bound_ports: BTreeSet<u16>,
    /// Track which queues we've registered (= XSKMAP keys we own).
    registered_queues: BTreeSet<u32>,
}

/// Stable non-cryptographic hash over the BPF object bytes. Used by
/// `get_or_load` to detect when two callers supply different programs for
/// the same `if_index`. `DefaultHasher` (SipHash) is sufficient for
/// collision detection; we are not authenticating bytes from an attacker.
fn hash_program_bytes(bytes: &[u8]) -> u64 {
    let mut h = DefaultHasher::new();
    bytes.hash(&mut h);
    h.finish()
}

impl XdpProgram {
    /// Load `bytes` as a BPF object, run the verifier, and attach the
    /// `quac_xdp` program to `if_index` in the requested mode. See the
    /// module docs for the symbol/map contract `bytes` must satisfy.
    ///
    /// Validates the contract symbols (`quac_xdp`, `BOUND_PORTS`, `XSKMAP`)
    /// **before** attaching, so a malformed custom program fails fast with a
    /// clear error rather than surfacing as a confusing failure during the
    /// first `bind_port` / `register_socket` call.
    ///
    /// `program_hash` is the precomputed hash of `bytes` (caller passes it
    /// rather than recomputing here so `get_or_load` can compare without
    /// double-hashing the common path).
    fn load_and_attach(
        if_index: u32,
        mode: AttachMode,
        bytes: &[u8],
        program_hash: u64,
    ) -> io::Result<Self> {
        let mut ebpf = Ebpf::load(bytes).map_err(load_err)?;

        // Eagerly validate the map contract. Type coercions also confirm the
        // map kinds (HashMap<u16,u8>, XskMap) — caught here, not on first use.
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

        // The XDP program function must be named `quac_xdp` (contract).
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

    /// Register `port` as bound — the XDP program will redirect future UDP
    /// packets with `dst_port == port` to whichever AF_XDP socket is
    /// registered for the rx queue they arrive on.
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
        // remove() returns Err on missing key — treat as success.
        let _ = ports.remove(&port);
        self.bound_ports.remove(&port);
        Ok(())
    }

    /// Associate `socket_fd` with `queue_id` in `XSKMAP`. The XDP program
    /// uses this to find the AF_XDP socket to redirect to (the program
    /// keys on `ctx->rx_queue_index`).
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

    /// Reverse of [`register_socket`]. Forgets our local tracking but does
    /// not actively clear the XSKMAP entry — the kernel removes the entry
    /// automatically when the socket fd is closed (BPF_MAP_TYPE_XSKMAP
    /// holds a reference, dropped on `close(2)`). aya's `XskMap` doesn't
    /// expose a remove API on 0.13.x.
    pub fn unregister_socket(&mut self, queue_id: u32) -> io::Result<()> {
        self.registered_queues.remove(&queue_id);
        Ok(())
    }

    pub fn if_index(&self) -> u32 {
        self.if_index
    }
}

/// Process-global registry: one `XdpProgram` per `if_index`. Keeps strong
/// `Arc`s so programs persist for process lifetime — see module docs for why.
static PROGRAMS: OnceLock<Mutex<HashMap<u32, Arc<Mutex<XdpProgram>>>>> = OnceLock::new();

/// Get the existing program handle for `if_index`, or load + attach a new
/// one using `program_bytes` (or the embedded default if `None`). Concurrent
/// callers for the same `if_index` get the same `Arc`; the **first** call
/// per `if_index` decides which BPF object is attached.
///
/// Subsequent callers must supply bytes whose content hash matches the
/// already-attached program (or pass `None`, which resolves to the embedded
/// default and matches if that's what was loaded first). A mismatch returns
/// an error instead of silently reusing the old program — this catches the
/// debugging trap where two consumers in the same process disagree about
/// which BPF object should run on the NIC. See module docs for the
/// symbol/map contract custom programs must satisfy.
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

/// Re-export of the embedded BPF bytes for callers that want to load the
/// program manually (tests, `bpftool prog load`, etc.).
pub fn embedded_program_bytes() -> &'static [u8] {
    &QUAC_SOCKET_XDP_EBPF_PROGRAM.0
}

fn io_err<E: std::fmt::Display>(e: E) -> io::Error {
    io::Error::other(e.to_string())
}

/// Wraps an aya error as `io::Error`, adding a CAP_BPF / CAP_PERFMON hint
/// when the underlying message looks like a permission failure. aya 0.13
/// surfaces the kernel error verbatim, so we substring-match on common
/// wording rather than trying to recover a typed errno.
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

// `BorrowedFd` import suppression: only used in `register_socket` signature.
// Compiler also sees its `as_fd` use, so this `_ = ...` keeps the import live
// even if a refactor temporarily drops the call site.
#[allow(dead_code)]
fn _keep_borrowed_fd<'a>(fd: &'a impl AsFd) -> BorrowedFd<'a> {
    fd.as_fd()
}

// `RawFd` is referenced via `as_raw_fd()` above.
#[allow(dead_code)]
const _RAW_FD_USED: RawFd = 0;
