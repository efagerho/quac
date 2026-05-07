//! [`PacketSocket`] backend over AF_XDP.
//!
//! Lifetime invariants (per CLAUDE.md):
//! - `XdpSocket` is the longest-lived per-tile object: it owns the
//!   [`Umem`], the [`RawXdpSocket`] (which owns the four ring `mmap`s),
//!   the [`XdpTxPool`], and the [`Reclaimer`]. Every buffer wrapper holds
//!   a raw pointer back into one of these and must not outlive the socket.
//! - `XdpSocket` is `Send + !Sync` via the `PhantomData<core::cell::Cell<()>>`
//!   field. The socket can be moved between threads (so a tile factory can
//!   construct it in the spawning thread and hand it off to the worker), but
//!   `&XdpSocket` cannot be shared concurrently — only one thread calls its
//!   methods at a time.
//!
//! ## Address families and traffic policy
//!
//! **IPv4 only, strict UDP only.** The eBPF program splits incoming traffic:
//!
//! - **Non-IPv4** (IPv6, ARP, VLAN-tagged): `XDP_PASS` to the kernel stack.
//! - **IPv4 non-UDP** (TCP, ICMP, IGMP, etc., with or without IP options):
//!   `XDP_PASS`. The kernel handles these normally.
//! - **IPv4 UDP with IP options** (IHL > 5): `XDP_DROP`. Counted in
//!   `DROP_COUNTERS[DROP_REASON_UDP_OPTIONS]`. QUIC peers never set options.
//! - **IPv4 UDP fragments** (MF=1 or fragment offset > 0): `XDP_DROP`.
//!   Counted in `DROP_COUNTERS[DROP_REASON_UDP_FRAGMENT]`. QUIC uses PMTUD
//!   and never fragments.
//! - **IPv4 UDP, IHL=5, unfragmented, port not in `BOUND_PORTS`**: `XDP_PASS`.
//! - **IPv4 UDP, IHL=5, unfragmented, port in `BOUND_PORTS`**: redirect to
//!   `XSKMAP[rx_queue_index]` → reaches userspace.
//!
//! On TX, IPv6 destinations are silently skipped (the `Transmit` is consumed
//! without sending) since [`crate::route::Router`] is IPv4-only.
//!
//! Drop counters are readable via `bpftool map dump name DROP_COUNTERS` for
//! debugging silent packet loss; the indices are documented as
//! `quac_socket_xdp_ebpf::DROP_REASON_*`.

use std::cell::UnsafeCell;
use std::io;
use std::marker::PhantomData;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::fd::BorrowedFd;
use std::slice;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use arc_swap::ArcSwap;
use quac_socket::{
    DrainResult, EcnCodepoint, PacketSocket, RecvMeta, ScatterGather, Transmit,
};

use crate::buffers::{HEADROOM, XdpRxBufMut, XdpRxPool, XdpTxBuf, XdpTxPool};
use crate::iface::if_mac;
use crate::packet::{
    ETH_HEADER_SIZE, IP_HEADER_SIZE, write_eth_header, write_ip_header_for_udp, write_udp_header,
};
use crate::program::{AttachMode, XdpProgram, get_or_load};
use crate::raw_socket::{RawXdpSocket, RingSizes, XdpMode};
use crate::reclaimer::Reclaimer;
use crate::ring::XdpDesc;
use crate::route::{RouteTable, Router};
use crate::route_monitor::RouteMonitor;
use crate::umem::Umem;

const ETH_HDR_LEN: usize = 14;
const IPV4_HDR_LEN: usize = 20; // no options
const UDP_HDR_LEN: usize = 8;
const ETH_TYPE_IPV4: u16 = 0x0800;
const IP_PROTO_UDP: u8 = 17;

/// Per-socket configuration for [`XdpSocket::with_interface`].
///
/// Construct via [`XdpConfig::default`] for the no-knobs case, or
/// [`XdpConfig::builder`] to customize fields. Fields are crate-private; new
/// fields can be added without breaking call sites that use the builder.
#[derive(Debug, Clone, Copy)]
pub struct XdpConfig {
    /// AF_XDP rings sizing. All four sizes must be powers of two.
    pub(crate) ring_sizes: RingSizes,
    /// Total UMEM frame count (powers of two). Half are pre-loaded into
    /// FILL at bind; the other half seed the TX free list.
    pub(crate) frame_count: u32,
    /// Per-frame size (matches `XDP_UMEM_REG.chunk_size`). 2 KiB matches
    /// the existing `MAX_BUF_SIZE` and is the kernel's default chunk size.
    pub(crate) frame_size: u32,
    /// Native AF_XDP zero-copy vs the kernel's emulated copy mode.
    pub(crate) mode: XdpMode,
    /// XDP program attach mode (DRV / SKB / DEFAULT). Native ZC requires
    /// `Drv`; veth supports it on Linux ≥ 5.18, software interfaces (lo)
    /// only on `Skb`.
    pub(crate) attach_mode: AttachMode,
    /// Custom BPF object bytes to load instead of the embedded default
    /// (`quac-socket-xdp-ebpf`). Must follow the symbol/map contract
    /// documented in [`crate::program`]. `None` uses the embedded program.
    ///
    /// Only the **first** `XdpSocket` constructed for a given NIC decides
    /// which program is attached; later sockets on the same `if_index`
    /// share the existing program and ignore their own `program_bytes`.
    pub(crate) program_bytes: Option<&'static [u8]>,
}

impl XdpConfig {
    pub fn builder() -> XdpConfigBuilder {
        XdpConfigBuilder::default()
    }
}

impl Default for XdpConfig {
    fn default() -> Self {
        Self {
            ring_sizes: RingSizes::default(),
            // 4096 frames × 2 KiB = 8 MiB UMEM. Big enough that a 64-batch
            // recv loop never exhausts FILL even under bursty traffic.
            frame_count: 4096,
            frame_size: 2048,
            mode: XdpMode::ZeroCopy,
            attach_mode: AttachMode::Default,
            program_bytes: None,
        }
    }
}

/// Builder for [`XdpConfig`]. See [`XdpConfig::builder`].
#[derive(Debug, Clone, Copy)]
pub struct XdpConfigBuilder(XdpConfig);

impl Default for XdpConfigBuilder {
    fn default() -> Self {
        Self(XdpConfig::default())
    }
}

impl XdpConfigBuilder {
    /// Override [`XdpConfig::ring_sizes`].
    pub fn ring_sizes(mut self, sizes: RingSizes) -> Self {
        self.0.ring_sizes = sizes;
        self
    }

    /// Override [`XdpConfig::frame_count`]. Must be a power of 2.
    pub fn frame_count(mut self, n: u32) -> Self {
        self.0.frame_count = n;
        self
    }

    /// Override [`XdpConfig::frame_size`]. Must accommodate ETH+IPv4+UDP
    /// headers (42 B) plus the largest payload the caller will send/receive.
    pub fn frame_size(mut self, n: u32) -> Self {
        self.0.frame_size = n;
        self
    }

    /// Override [`XdpConfig::mode`] (zero-copy vs copy).
    pub fn mode(mut self, mode: XdpMode) -> Self {
        self.0.mode = mode;
        self
    }

    /// Override [`XdpConfig::attach_mode`] (DRV / SKB / HW / DEFAULT).
    pub fn attach_mode(mut self, mode: AttachMode) -> Self {
        self.0.attach_mode = mode;
        self
    }

    /// Override [`XdpConfig::program_bytes`] — supply a custom BPF object.
    /// See [`crate::program`] for the symbol/map contract.
    pub fn program_bytes(mut self, bytes: &'static [u8]) -> Self {
        self.0.program_bytes = Some(bytes);
        self
    }

    /// Validates and produces the [`XdpConfig`]. Panics on invalid combinations.
    pub fn build(self) -> XdpConfig {
        assert!(
            self.0.frame_count.is_power_of_two() && self.0.frame_count > 0,
            "XdpConfig::frame_count must be a non-zero power of 2 (got {})",
            self.0.frame_count
        );
        assert!(
            self.0.frame_size >= HEADROOM,
            "XdpConfig::frame_size must be >= HEADROOM ({HEADROOM}) (got {})",
            self.0.frame_size
        );
        // The four AF_XDP rings are masked with `size - 1` throughout
        // ring.rs / raw_socket.rs, so non-powers-of-two would silently corrupt
        // descriptor indexing.
        let r = self.0.ring_sizes;
        for (name, n) in [
            ("fill", r.fill),
            ("completion", r.completion),
            ("rx", r.rx),
            ("tx", r.tx),
        ] {
            assert!(
                n.is_power_of_two() && n > 0,
                "XdpConfig::ring_sizes.{name} must be a non-zero power of 2 (got {n})",
            );
        }
        self.0
    }
}

/// AF_XDP `PacketSocket` implementation.
///
/// **IPv4-only.** See module-level docs. Calls into [`PacketSocket::send`]
/// with IPv6 destinations are silently dropped (no error returned, the
/// `Transmit` is consumed). Inbound IPv6 / non-UDP traffic is handled by
/// the kernel stack rather than this socket.
pub struct XdpSocket {
    raw: RawXdpSocket,
    /// `Box`'d so the pointer the buffers hold stays stable. The `Umem`
    /// owns the page-aligned mmap; both pools / buffers index into it.
    umem: Box<Umem>,
    rx_pool: XdpRxPool,
    /// `Box`'d so its address is stable for `XdpTxBuf::pool` raw pointers.
    tx_pool: Box<XdpTxPool>,
    /// `Box`'d so its address is stable for `XdpRxBufMut::Ring::reclaimer`
    /// raw pointers.
    reclaimer: Box<Reclaimer>,
    /// Shared XDP program handle. Other `XdpSocket`s on the same NIC see
    /// the same `Arc<Mutex<…>>` via the global registry. Read on Drop to
    /// remove this socket's entries from BOUND_PORTS / XSKMAP.
    program: Arc<Mutex<XdpProgram>>,

    /// Wait-free snapshot of the kernel routing table. Updated by the
    /// background route monitor; `send` calls `load()` once per batch.
    router: Arc<ArcSwap<Router>>,
    /// Cached interface MAC for the Ethernet src field. Doesn't change
    /// without unbinding, so we read it once at construction.
    if_mac: [u8; 6],
    /// Cached source IPv4 for the IP src field. Falls back to the route's
    /// preferred_src when this is `0.0.0.0`.
    bound_v4: Option<Ipv4Addr>,
    bound_addr: SocketAddr,
    queue_id: u16,

    /// Scratch buffer for per-call RX descriptor reads. Reused across
    /// `recv` calls so the hot path doesn't allocate.
    rx_scratch: UnsafeCell<Vec<XdpDesc>>,
    /// Scratch buffer for per-call COMPLETION reads.
    comp_scratch: UnsafeCell<Vec<u64>>,

    // !Send + !Sync — `PacketSocket` is owned exclusively by the tile thread.
    _not_sync: PhantomData<core::cell::Cell<()>>,
}

impl XdpSocket {
    /// Create an `XdpSocket` bound to a specific interface + queue. The
    /// bind() / route-lookup / SO_REUSEPORT-style helper that figures out
    /// the interface from the address lands in Phase 7.
    pub fn with_interface(
        if_index: u32,
        queue_id: u16,
        bind_ip: IpAddr,
        bind_port: u16,
        cfg: XdpConfig,
    ) -> io::Result<Self> {
        // 1. Load + attach the eBPF program FIRST. Native ZC AF_XDP on
        //    veth (and on most NICs) requires an XDP program already
        //    attached at `bind()` time — the driver's ZC enable hook
        //    inspects program features. Without this we'd get EOPNOTSUPP
        //    on the bind below in ZC mode.
        let program = get_or_load(if_index, cfg.attach_mode, cfg.program_bytes)?;

        // 2. UMEM. Box so the address is stable (TxPool stores a raw ptr).
        let umem = Box::new(Umem::new(cfg.frame_size, cfg.frame_count)?);

        // 3. Split the UMEM 50/50 between the FILL ring (kernel-owned RX
        //    buffers) and the TX pool. The split needn't be exact — frames
        //    can move sides via `from_rx`'s copy — but RX needs enough
        //    pre-fill for the kernel not to drop packets while we ramp up.
        let half = cfg.frame_count / 2;
        let rx_initial: Vec<u64> = (0..half).map(|i| umem.frame_offset(i)).collect();
        let tx_initial: Vec<u64> = (half..cfg.frame_count).map(|i| umem.frame_offset(i)).collect();

        // 4. RawXdpSocket: opens the AF_XDP socket, registers the UMEM,
        //    sizes + mmap's the four rings, pre-fills FILL, and binds.
        let mut umem = umem;
        let raw = RawXdpSocket::new(
            if_index,
            queue_id as u32,
            &mut *umem,
            cfg.ring_sizes,
            cfg.mode,
            rx_initial.iter().copied(),
        )?;

        // 5. Pools + reclaimer. Box for stable addresses (raw ptrs from
        //    buffer wrappers); the reclaimer's MPSC is sized to the total
        //    frame count so cross-thread pushes never overflow.
        let umem_base = umem.as_mut_ptr();
        let rx_pool = XdpRxPool::new(payload_capacity(cfg.frame_size));
        let tx_pool = XdpTxPool::new(
            umem_base,
            cfg.frame_size,
            HEADROOM,
            payload_capacity(cfg.frame_size),
            tx_initial,
            cfg.frame_count as usize,
        );
        let reclaimer = Box::new(Reclaimer::new(
            std::thread::current().id(),
            cfg.frame_count as usize,
        ));

        // 6. Look up routing snapshot + interface MAC **before** touching the
        //    eBPF maps. If either fails we haven't inserted anything into
        //    BOUND_PORTS / XSKMAP, so there's nothing to roll back. The
        //    Drop impl only cleans up after a successful `Ok(Self)` below;
        //    early returns from `?` here can't run it because the socket
        //    doesn't exist yet.
        let router = shared_router()?;
        let if_mac = if_mac(if_index)?;

        // 7. Now register this socket in the eBPF program's maps. Order
        //    matters: XSKMAP first, then BOUND_PORTS. If BOUND_PORTS
        //    were inserted first, the eBPF program would start redirecting
        //    matching packets to an empty XSKMAP[queue_id] — the redirect
        //    would silently downgrade to XDP_PASS and the packets would
        //    leak into the kernel stack until register_socket landed.
        //
        //    If `register_socket` succeeds but `bind_port` fails, we roll
        //    back the XSKMAP entry below so the program isn't left with a
        //    half-registered queue.
        {
            let mut p = program.lock().unwrap();
            // SAFETY: BorrowedFd::borrow_raw asserts the fd is owned (raw
            // socket holds the OwnedFd). `socket_fd` lives only for the
            // duration of the call.
            let fd = unsafe { BorrowedFd::borrow_raw(raw.fd()) };
            p.register_socket(queue_id as u32, fd)?;
            if let Err(e) = p.bind_port(bind_port) {
                // Best-effort rollback; ignore unregister errors so the
                // original `bind_port` error is what the caller sees.
                let _ = p.unregister_socket(queue_id as u32);
                return Err(e);
            }
        }
        let bound_v4 = match bind_ip {
            IpAddr::V4(v4) if !v4.is_unspecified() => Some(v4),
            _ => None,
        };

        Ok(Self {
            raw,
            umem,
            rx_pool,
            tx_pool,
            reclaimer,
            program,
            router,
            if_mac,
            bound_v4,
            bound_addr: SocketAddr::new(bind_ip, bind_port),
            queue_id,
            rx_scratch: UnsafeCell::new(Vec::with_capacity(cfg.ring_sizes.rx as usize)),
            comp_scratch: UnsafeCell::new(Vec::with_capacity(cfg.ring_sizes.completion as usize)),
            _not_sync: PhantomData,
        })
    }

    /// Drain the reclaimer's same-thread + cross-thread bid queues into
    /// the FILL ring so the kernel has frames to fill on the next RX
    /// burst. Called at the top of every `recv`.
    fn replenish_fill(&mut self) {
        // Same-thread frames first — bypass the MPSC entirely.
        // SAFETY: pending is owner-thread-only and we're on the owner thread.
        let pending = unsafe { &mut *self.reclaimer.pending.get() };

        // Only pay the cross-thread atomics when the local list isn't
        // already large enough to keep the FILL ring fed. Steady state for
        // single-tile workloads: engine threads rarely hold buffers, so
        // `remote` is empty and the drain's pop() is wasted work. Threshold
        // of `MAX_BATCH` ensures we always have a full batch's worth of
        // frames available between drains.
        //
        // Starvation-bound argument: every recv submits `pending` to the
        // FILL ring (line below), so `pending` returns to 0 after each
        // successful submission. The only way it stays >= MAX_BATCH across
        // calls is if FILL is saturated (kernel hasn't consumed) — in which
        // case we couldn't write more frames anyway. The cross-thread MPSC
        // is sized to `frame_count` (set in `XdpSocket::with_interface`),
        // which is also the absolute upper bound on in-flight buffers, so
        // it cannot overflow regardless of how long a remote drain is
        // deferred.
        if pending.len() < <Self as PacketSocket>::MAX_BATCH {
            // SAFETY: `drain_into` is single-consumer; we're the consumer.
            unsafe { self.reclaimer.remote.drain_into(pending) };
        }

        if pending.is_empty() {
            return;
        }

        let written = self.raw.replenish_fill(pending.iter().copied()) as usize;
        // Anything not written stays in `pending` for the next call.
        if written == pending.len() {
            pending.clear();
        } else {
            pending.drain(0..written);
        }
    }
}

#[inline]
fn payload_capacity(frame_size: u32) -> usize {
    (frame_size - HEADROOM) as usize
}

/// Parse the IPv4 + UDP headers in `frame` (starting at byte 0) and
/// return `(RecvMeta, payload_offset, payload_len)`. Returns `None` if the
/// packet isn't IPv4/UDP, has options the eBPF program let through anyway,
/// or is shorter than the headers claim.
fn parse_ipv4_udp(frame: &[u8]) -> Option<(RecvMeta, u32, u32)> {
    if frame.len() < ETH_HDR_LEN + IPV4_HDR_LEN + UDP_HDR_LEN {
        return None;
    }
    let ether_type = u16::from_be_bytes([frame[12], frame[13]]);
    if ether_type != ETH_TYPE_IPV4 {
        return None;
    }
    let ip = &frame[ETH_HDR_LEN..];
    let version_ihl = ip[0];
    if version_ihl >> 4 != 4 {
        return None;
    }
    let ihl = (version_ihl & 0x0f) as usize * 4;
    if ihl < IPV4_HDR_LEN || frame.len() < ETH_HDR_LEN + ihl + UDP_HDR_LEN {
        return None;
    }
    let proto = ip[9];
    if proto != IP_PROTO_UDP {
        return None;
    }
    let tos = ip[1];
    let src_ip = Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]);
    let dst_ip = Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]);

    let udp = &frame[ETH_HDR_LEN + ihl..];
    let src_port = u16::from_be_bytes([udp[0], udp[1]]);
    let udp_len = u16::from_be_bytes([udp[4], udp[5]]);
    // The eBPF program filters on dst_port; we don't re-check it here.
    if (udp_len as usize) < UDP_HDR_LEN {
        return None;
    }
    let payload_len = (udp_len as usize - UDP_HDR_LEN) as u32;
    let payload_offset = (ETH_HDR_LEN + ihl + UDP_HDR_LEN) as u32;
    if (payload_offset as usize + payload_len as usize) > frame.len() {
        return None;
    }

    let mut meta = RecvMeta::default();
    meta.src = SocketAddr::new(IpAddr::V4(src_ip), src_port);
    meta.dst_ip = Some(IpAddr::V4(dst_ip));
    meta.ecn = ecn_from_tos(tos);
    // UDP datagram payload is bounded by the 16-bit `udp_len` field minus
    // the 8-byte UDP header, so the cast can never truncate.
    debug_assert!(payload_len <= u16::MAX as u32);
    meta.len = payload_len as u16;
    Some((meta, payload_offset, payload_len))
}

/// Decode the low two bits of the IPv4 TOS byte (== ECN field per RFC 3168).
#[inline]
fn ecn_from_tos(tos: u8) -> Option<EcnCodepoint> {
    match tos & 0b11 {
        0b00 => None, // Not-ECT
        0b01 => Some(EcnCodepoint::Ect1),
        0b10 => Some(EcnCodepoint::Ect0),
        0b11 => Some(EcnCodepoint::Ce),
        _ => unreachable!(), // unreachable: `& 0b11` ≤ 3
    }
}

impl PacketSocket for XdpSocket {
    type RxPool = XdpRxPool;
    type TxPool = XdpTxPool;

    /// AF_XDP delivers / accepts one packet per descriptor; multi-buf
    /// XDP exists but adds non-trivial complexity — punt to a future PR.
    const MAX_SEGMENTS: usize = 1;
    /// AF_XDP doesn't have GSO/GRO at the socket layer.
    const MAX_GSO: u16 = 1;
    const MAX_GRO: u16 = 1;
    const MAX_BATCH: usize = 64;

    fn rx_pool(&self) -> &XdpRxPool {
        &self.rx_pool
    }

    fn tx_pool(&self) -> &XdpTxPool {
        &self.tx_pool
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.bound_addr)
    }

    fn queue_id(&self) -> u16 {
        self.queue_id
    }

    #[cfg(unix)]
    fn rx_fd(&self) -> Option<BorrowedFd<'_>> {
        // Safety: the OwnedFd lives inside RawXdpSocket which lives
        // inside Self; the borrow is bound to &self.
        Some(unsafe { BorrowedFd::borrow_raw(self.raw.fd()) })
    }

    fn send(
        &mut self,
        transmits: &mut [Transmit<ScatterGather<XdpTxBuf>>],
    ) -> io::Result<usize> {
        if transmits.is_empty() {
            return Ok(0);
        }

        // Snapshot the routing table once for the whole batch — wait-free
        // load via ArcSwap. Subsequent route_v4 calls all use this snapshot.
        let router = self.router.load_full();

        // Cap the batch by available TX ring slots.
        let tx_slots = self.raw.tx_available() as usize;
        let n = transmits.len().min(tx_slots);
        if n == 0 {
            return Ok(0);
        }

        let umem_base = self.umem.as_mut_ptr();
        let frame_size = self.umem.frame_size() as usize;
        let src_port = self.bound_addr.port();
        let mut sent = 0usize;

        for slot in transmits.iter_mut().take(n) {
            // Inspect the segment without consuming the transmit yet — we
            // only know if we can submit after a successful route lookup.
            let dst_v4 = match slot.destination.ip() {
                IpAddr::V4(v4) => v4,
                // IPv6 not supported on this backend (see module docs); the
                // caller's `Transmit` is silently consumed without sending.
                IpAddr::V6(_) => continue,
            };
            let dst_port = slot.destination.port();
            let segments = slot.contents.segments();
            // MAX_SEGMENTS = 1: single segment per packet.
            let Some(seg) = segments.first() else { continue };

            let buf: &XdpTxBuf = seg.buf();
            let frame_addr = buf.frame_addr();
            // The TxBufMut hands out `payload_offset = HEADROOM`, so the
            // user's payload starts at frame[HEADROOM]. AF_XDP can only
            // send contiguous frame ranges, so a Segment with `offset > 0`
            // would require an in-frame memcpy — skip; future work.
            if seg.offset() != 0 {
                continue;
            }
            let payload_len = seg.len() as usize;

            // Route lookup. Skip the transmit if no route or no neighbour
            // MAC (kernel hasn't ARP'd the gateway yet).
            let next_hop = match router.route_v4(dst_v4) {
                Ok(nh) => nh,
                Err(_) => continue,
            };
            let Some(dst_mac) = next_hop.mac_addr else { continue };

            // Source IP: caller-supplied src_ip overrides; else our bound
            // IPv4; else the route's preferred_src; else give up.
            let src_v4 = match slot.src_ip {
                Some(IpAddr::V4(v4)) => v4,
                Some(IpAddr::V6(_)) => continue,
                None => self
                    .bound_v4
                    .or(next_hop.preferred_src_ip)
                    .unwrap_or(Ipv4Addr::UNSPECIFIED),
            };

            // Build the full headers in place at frame[0..HEADROOM]. Three
            // disjoint slices over `umem[frame_addr..frame_addr+HEADROOM]`.
            // SAFETY: Caller guaranteed `frame_addr + HEADROOM` fits in the
            // UMEM by construction (buffer was allocated from this socket's
            // pool); the slice doesn't alias `seg.as_slice()` because that
            // sits at `frame_addr + HEADROOM..` (immediately after).
            let frame_ptr = unsafe { umem_base.add(frame_addr as usize) };
            let headers = unsafe { slice::from_raw_parts_mut(frame_ptr, HEADROOM as usize) };

            write_eth_header(&mut headers[..ETH_HEADER_SIZE], &self.if_mac, &dst_mac.0);
            write_ip_header_for_udp(
                &mut headers[ETH_HEADER_SIZE..ETH_HEADER_SIZE + IP_HEADER_SIZE],
                &src_v4,
                &dst_v4,
                (UDP_HDR_LEN + payload_len) as u16,
            );
            write_udp_header(
                &mut headers[ETH_HEADER_SIZE + IP_HEADER_SIZE..],
                &src_v4,
                src_port,
                &dst_v4,
                dst_port,
                payload_len as u16,
                false, // UDP checksum off — most NICs offload, and the kernel
                       // doesn't verify on RX for IPv4 unless explicitly enabled.
            );

            // Hand the frame to the kernel via the TX ring. After this the
            // kernel owns the frame until COMPLETION delivers it back; we
            // mem::forget the buffer below so its Drop doesn't reclaim it
            // prematurely.
            let total_len = HEADROOM as usize + payload_len;
            debug_assert!(total_len <= frame_size);
            let desc = XdpDesc {
                addr: frame_addr,
                len: total_len as u32,
                options: 0,
            };
            if !self.raw.enqueue_tx(desc) {
                // TX ring filled despite the up-front available() check —
                // shouldn't normally happen, but bail safely. The caller
                // sees `sent` ≤ n and retries the rest.
                break;
            }

            // Replace the slot with an empty sentinel and forget the
            // original — XdpTxBuf::Drop must NOT run, the kernel owns
            // the frame until drain_completions reclaims it.
            let original = mem::replace(slot, sentinel_transmit());
            mem::forget(original);
            sent += 1;
        }

        if sent > 0 {
            self.raw.commit_tx();
            // Need-wakeup is set by the kernel when its driver has gone
            // idle — sendto with NULL just nudges it to scan our ring.
            if self.raw.tx_needs_wakeup() {
                let _ = self.raw.wake_tx();
            }
        }

        Ok(sent)
    }

    fn drain_completions(&mut self) -> DrainResult {
        // SAFETY: comp_scratch is owner-thread only.
        let scratch = unsafe { &mut *self.comp_scratch.get() };
        scratch.clear();
        let n = self.raw.drain_completion(scratch);

        // Push completed frame addresses back to the TX pool's local list
        // (we're the owner thread). Use the public `available()` path —
        // but that takes &self and triggers an MPSC drain we don't need.
        // For Phase 6 simplicity, route through reclaim helpers via Drop:
        // synthesise empty XdpTxBuf-like reclamation by directly pushing
        // into the pool's local list. This requires a tiny pool method.
        for &addr in scratch.iter() {
            self.tx_pool.reclaim_completed(addr);
        }

        let mut dr = DrainResult::default();
        dr.completed = n;
        dr
    }

    fn recv(
        &mut self,
        meta: &mut [RecvMeta],
        bufs: &mut [XdpRxBufMut],
    ) -> io::Result<usize> {
        let limit = meta.len().min(bufs.len());
        if limit == 0 {
            return Ok(0);
        }

        // 1. Replenish FILL from any frames that came back since last call.
        self.replenish_fill();

        // 2. Drain RX descriptors into the pre-allocated scratch. The scratch
        //    is sized to the RX ring at construction, so `reserve` is a
        //    no-op past the first call; bounding by `limit` ensures we only
        //    pull what the caller can hold.
        // SAFETY: rx_scratch is owner-thread only.
        let scratch = unsafe { &mut *self.rx_scratch.get() };
        scratch.clear();
        if scratch.capacity() < limit {
            scratch.reserve(limit - scratch.capacity());
        }
        self.raw.drain_rx(scratch, limit);

        // 3. Wrap each desc into an XdpRxBufMut::Ring and write the
        //    matching RecvMeta. Frames whose headers don't parse as IPv4
        //    UDP (shouldn't happen — eBPF filters — but defensive) are
        //    immediately returned to FILL via reclaimer.pending.
        let umem_base = self.umem.as_mut_ptr();
        let cap_per_frame = (self.umem.frame_size() - HEADROOM) as u32;
        let reclaimer_ptr: *const Reclaimer = &*self.reclaimer;
        let mut written = 0usize;
        for desc in scratch.iter() {
            if written >= limit {
                break;
            }
            let frame = self.umem.slice_at(desc.addr, desc.len as usize);
            let Some((parsed_meta, payload_offset, payload_len)) = parse_ipv4_udp(frame) else {
                // Bad packet — drop the frame back to FILL.
                // SAFETY: reclaimer.pending is owner-thread only.
                unsafe { (*self.reclaimer.pending.get()).push(desc.addr) };
                continue;
            };

            let cap = cap_per_frame.min((self.umem.frame_size() - payload_offset) as u32);
            let new_buf = XdpRxBufMut::from_ring_frame(
                umem_base,
                desc.addr,
                payload_offset,
                payload_len,
                cap,
                reclaimer_ptr,
            );
            let _ = mem::replace(&mut bufs[written], new_buf);
            meta[written] = parsed_meta;
            written += 1;
        }

        Ok(written)
    }
}

impl Drop for XdpSocket {
    fn drop(&mut self) {
        // Remove our entries from the shared eBPF program's maps. The
        // program itself is left attached on the NIC — other XdpSockets
        // on this interface (or restarted instances of us) reuse it; see
        // program.rs module docs.
        //
        // Best-effort: a poisoned mutex or a transient map error must not
        // panic, since Drop runs on tile shutdown. The kernel will reap
        // XSKMAP entries automatically when the underlying AF_XDP fd is
        // closed (which happens when `raw` drops below); BOUND_PORTS has
        // no such auto-cleanup, so missing this would leak ports.
        if let Ok(mut p) = self.program.lock() {
            let _ = p.unbind_port(self.bound_addr.port());
            let _ = p.unregister_socket(self.queue_id as u32);
        }
    }
}

// XdpTxPool needs a same-thread reclamation entry point that doesn't go
// through the Drop impl (we're feeding raw frame addresses from the
// COMPLETION ring, not real `XdpTxBuf`s). Add it here; visibility is
// pub(crate) so only this crate uses it.
impl XdpTxPool {
    pub(crate) fn reclaim_completed(&self, addr: u64) {
        // SAFETY: same-thread invariant — caller is XdpSocket on the
        // owner tile thread, and the pool is `!Send + !Sync` so this `&self`
        // can only exist on the owner thread.
        unsafe { (*self.reclaim.local.get()).push(addr) };
    }
}

/// Build an empty `Transmit` to use as a `mem::replace` sentinel after
/// successfully submitting a frame to the TX ring. The empty
/// `ScatterGather` carries no `XdpTxBuf`s, so dropping the sentinel is
/// a no-op.
fn sentinel_transmit() -> Transmit<ScatterGather<XdpTxBuf>> {
    Transmit::new(
        ScatterGather::new(),
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
    )
}

// ── Process-global routing snapshot ─────────────────────────────────────────
//
// The kernel routing table is per-process — same routes for every socket on
// the host. Sharing one `Router` snapshot avoids spawning N route_monitor
// threads when N `XdpSocket`s exist in the same process.
//
// Lifetime: the router and its monitor thread are **process-lifetime**. The
// `OnceLock`s are never reset; the monitor's exit flag is never raised, and
// the join handle is never `take`n. This is intentional — the kernel
// routing table can change at any time, and the monitor must be available
// for as long as any `XdpSocket` exists. On process exit the OS reaps the
// thread; there is no graceful shutdown hook, and none is currently needed
// because the monitor holds no resources that aren't already cleaned up by
// the kernel on `exit(2)`. Tests that exercise multiple monitors per
// process aren't supported.

static ROUTER: OnceLock<Arc<ArcSwap<Router>>> = OnceLock::new();
static ROUTER_INIT: OnceLock<Mutex<RouterInit>> = OnceLock::new();

/// Process-lifetime handle to the route monitor thread. Stored only so the
/// `JoinHandle` and `exit` flag aren't dropped (which would happen if they
/// fell off the end of `shared_router`). The thread runs forever; neither
/// field is read after construction. See module-level note above for why
/// graceful shutdown isn't implemented.
#[allow(dead_code)]
struct RouterInit {
    exit: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

fn shared_router() -> io::Result<Arc<ArcSwap<Router>>> {
    if let Some(r) = ROUTER.get() {
        return Ok(Arc::clone(r));
    }
    // First socket on the process: build a placeholder router; the monitor's
    // start() will subscribe to multicast updates *before* dumping kernel
    // tables, then publish the real Router into the ArcSwap. This closes the
    // race where a route change between dump and subscribe would be lost.
    let arc = Arc::new(ArcSwap::new(Arc::new(Router::empty())));
    let exit = Arc::new(AtomicBool::new(false));
    let handle = RouteMonitor::start(
        Arc::clone(&arc),
        RouteTable::Main,
        Arc::clone(&exit),
        // 50ms publish cadence — the prototype's default. Tradeoff between
        // route-change responsiveness and netlink dump cost.
        Duration::from_millis(50),
        || {},
    )?;
    let _ = ROUTER_INIT.set(Mutex::new(RouterInit { exit, handle: Some(handle) }));
    let _ = ROUTER.set(Arc::clone(&arc));
    Ok(arc)
}
