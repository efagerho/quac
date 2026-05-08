//! [`PacketSocket`] backend over AF_XDP.
//!
//! `XdpSocket` is the longest-lived per-tile object -- it owns the [`Umem`],
//! the [`RawXdpSocket`] (the four ring `mmap`s), the [`XdpTxPool`], and the
//! [`Reclaimer`]. Buffer wrappers hold raw pointers back into these and must
//! not outlive the socket (CLAUDE.md invariant).
//!
//! `Send + !Sync`: a tile factory can construct the socket in one thread and
//! hand it to the worker, but `&XdpSocket` is never shared concurrently.
//!
//! **IPv4-only, strict UDP.** The eBPF program redirects only
//! IPv4/UDP/IHL=5/unfragmented traffic whose dst port is in `BOUND_PORTS`.
//! Anything else falls back to the kernel via `XDP_PASS`, except IP-options
//! and fragmented UDP, which are `XDP_DROP`'d (QUIC never produces them and
//! PASS would leak ICMP port-unreachable for AF_XDP-bound ports). On TX,
//! IPv6 destinations are silently skipped -- [`crate::route::Router`] is v4
//! only. Drop reasons are observable via `bpftool map dump name DROP_COUNTERS`.

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

/// Per-socket configuration for [`XdpSocket::with_interface`]. Build via
/// [`XdpConfig::builder`] or [`XdpConfig::default`].
#[derive(Debug, Clone, Copy)]
pub struct XdpConfig {
    /// FILL / COMPLETION / RX / TX ring sizes. All four must be powers of 2.
    pub(crate) ring_sizes: RingSizes,
    /// Total UMEM frame count, power of 2. Split 50/50 between FILL pre-fill
    /// and the TX free list at construction.
    pub(crate) frame_count: u32,
    /// Per-frame size in bytes. Matches `XDP_UMEM_REG.chunk_size`.
    pub(crate) frame_size: u32,
    /// Zero-copy vs copy mode.
    pub(crate) mode: XdpMode,
    /// XDP attach mode. Native ZC requires `Drv`; software interfaces (`lo`)
    /// require `Skb`; veth supports `Drv` on Linux ≥ 5.18.
    pub(crate) attach_mode: AttachMode,
    /// Custom BPF object. `None` uses the embedded default. See
    /// [`crate::program`] for the symbol/map contract; the first socket
    /// per NIC decides which program is loaded.
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
    pub fn ring_sizes(mut self, sizes: RingSizes) -> Self {
        self.0.ring_sizes = sizes;
        self
    }

    /// Must be a power of 2.
    pub fn frame_count(mut self, n: u32) -> Self {
        self.0.frame_count = n;
        self
    }

    /// Must be ≥ HEADROOM (42 B for ETH+IPv4+UDP) plus any payload.
    pub fn frame_size(mut self, n: u32) -> Self {
        self.0.frame_size = n;
        self
    }

    pub fn mode(mut self, mode: XdpMode) -> Self {
        self.0.mode = mode;
        self
    }

    pub fn attach_mode(mut self, mode: AttachMode) -> Self {
        self.0.attach_mode = mode;
        self
    }

    /// Supply a custom BPF object. See [`crate::program`] for the contract.
    pub fn program_bytes(mut self, bytes: &'static [u8]) -> Self {
        self.0.program_bytes = Some(bytes);
        self
    }

    /// Validate and produce the config. Panics on invalid combinations.
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

/// AF_XDP `PacketSocket`. IPv4-only -- IPv6 destinations on `send` are
/// silently consumed; non-IPv4 / non-UDP RX traffic goes to the kernel
/// stack via XDP_PASS.
pub struct XdpSocket {
    raw: RawXdpSocket,
    /// `Box`'d so buffer pointers into UMEM remain stable across moves.
    umem: Box<Umem>,
    rx_pool: XdpRxPool,
    /// `Box`'d so `XdpTxBuf` raw pointers stay valid.
    tx_pool: Box<XdpTxPool>,
    /// `Box`'d so `XdpRxBufMut::Ring::reclaimer` raw pointers stay valid.
    reclaimer: Box<Reclaimer>,
    /// Shared per-NIC XDP program. Read on Drop to remove our BOUND_PORTS /
    /// XSKMAP entries.
    program: Arc<Mutex<XdpProgram>>,

    /// Wait-free routing snapshot. `send` calls `load()` once per batch;
    /// the route monitor publishes updates in the background.
    router: Arc<ArcSwap<Router>>,
    /// Cached interface MAC for the Ethernet src field.
    if_mac: [u8; 6],
    /// Caller-supplied source IPv4. Falls back to route.preferred_src when
    /// `0.0.0.0`.
    bound_v4: Option<Ipv4Addr>,
    bound_addr: SocketAddr,
    queue_id: u16,

    /// Per-call scratch, reused so `recv` doesn't allocate.
    rx_scratch: UnsafeCell<Vec<XdpDesc>>,
    comp_scratch: UnsafeCell<Vec<u64>>,

    _not_sync: PhantomData<core::cell::Cell<()>>,
}

impl XdpSocket {
    /// Bind to a specific `(if_index, queue_id)` and return the socket.
    pub fn with_interface(
        if_index: u32,
        queue_id: u16,
        bind_ip: IpAddr,
        bind_port: u16,
        cfg: XdpConfig,
    ) -> io::Result<Self> {
        // The XDP program must be attached *before* the AF_XDP bind: native
        // ZC's enable hook in the driver inspects program features and would
        // return EOPNOTSUPP otherwise.
        let program = get_or_load(if_index, cfg.attach_mode, cfg.program_bytes)?;

        let umem = Box::new(Umem::new(cfg.frame_size, cfg.frame_count)?);

        // Split UMEM 50/50: FILL pre-fill vs TX free list. Not strict --
        // `from_rx` can move frames across -- but RX needs enough pre-fill
        // that the kernel doesn't drop while we ramp up.
        let half = cfg.frame_count / 2;
        let rx_initial: Vec<u64> = (0..half).map(|i| umem.frame_offset(i)).collect();
        let tx_initial: Vec<u64> = (half..cfg.frame_count).map(|i| umem.frame_offset(i)).collect();

        let mut umem = umem;
        let raw = RawXdpSocket::new(
            if_index,
            queue_id as u32,
            &mut *umem,
            cfg.ring_sizes,
            cfg.mode,
            rx_initial.iter().copied(),
        )?;
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

        // Look up routing + if_mac BEFORE touching the eBPF maps. The Drop
        // impl only runs on a successful `Ok(Self)`, so an early `?` return
        // after a map insert would leak BOUND_PORTS / XSKMAP entries.
        let router = shared_router()?;
        let if_mac = if_mac(if_index)?;

        // Order matters: XSKMAP must be populated before BOUND_PORTS, else
        // the eBPF program redirects to an empty XSKMAP slot and packets
        // leak to the kernel stack until register_socket lands.
        {
            let mut p = program.lock().unwrap();
            // SAFETY: `raw` owns the AF_XDP fd for the duration of this scope.
            let fd = unsafe { BorrowedFd::borrow_raw(raw.fd()) };
            p.register_socket(queue_id as u32, fd)?;
            if let Err(e) = p.bind_port(bind_port) {
                // Roll back the XSKMAP entry; surface the bind_port error.
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

    /// Push reclaimed frame addresses back to FILL so the kernel has buffers
    /// for the next RX burst. Called at the top of every `recv`.
    fn replenish_fill(&mut self) {
        // SAFETY: pending is owner-thread-only.
        let pending = unsafe { &mut *self.reclaimer.pending.get() };

        // Skip the cross-thread MPSC drain when local already has enough
        // frames. Engine threads rarely hold buffers in steady state, so
        // `remote` is usually empty -- the threshold avoids paying atomics
        // for nothing.
        //
        // Starvation-bound argument: every recv submits `pending` to the
        // FILL ring (line below), so `pending` returns to 0 after each
        // successful submission. The only way it stays >= MAX_BATCH across
        // calls is if FILL is saturated (kernel hasn't consumed) -- in which
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

/// Parse the ETH/IPv4/UDP headers in `frame` and return
/// `(RecvMeta, payload_offset, payload_len)`. Returns `None` for malformed
/// or non-IPv4/UDP frames.
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

    /// One packet per descriptor; multi-buf XDP isn't supported.
    const MAX_SEGMENTS: usize = 1;
    /// AF_XDP has no socket-level GSO/GRO.
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

        // Snapshot the routing table once per batch (wait-free ArcSwap load).
        let router = self.router.load_full();

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
            let dst_v4 = match slot.destination.ip() {
                IpAddr::V4(v4) => v4,
                // IPv6 unsupported -- silently consumed (see module docs).
                IpAddr::V6(_) => continue,
            };
            let dst_port = slot.destination.port();
            let segments = slot.contents.segments();
            let Some(seg) = segments.first() else { continue };

            let buf: &XdpTxBuf = seg.buf();
            let frame_addr = buf.frame_addr();
            // AF_XDP sends contiguous frame ranges; a non-zero segment
            // offset would require an in-frame memcpy. Not currently
            // supported.
            if seg.offset() != 0 {
                continue;
            }
            let payload_len = seg.len() as usize;

            // Skip if no route, or no neighbour MAC (gateway not ARP'd yet).
            let next_hop = match router.route_v4(dst_v4) {
                Ok(nh) => nh,
                Err(_) => continue,
            };
            let Some(dst_mac) = next_hop.mac_addr else { continue };

            // Source IP precedence: caller-supplied → our bound v4 →
            // route.preferred_src → 0.0.0.0.
            let src_v4 = match slot.src_ip {
                Some(IpAddr::V4(v4)) => v4,
                Some(IpAddr::V6(_)) => continue,
                None => self
                    .bound_v4
                    .or(next_hop.preferred_src_ip)
                    .unwrap_or(Ipv4Addr::UNSPECIFIED),
            };

            // SAFETY: `frame_addr + HEADROOM` is in-UMEM by construction
            // (buffer was allocated from this socket's pool); the header
            // slice doesn't alias the payload, which sits at
            // `frame_addr + HEADROOM..`.
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
                // UDP checksum off: most NICs offload it, and the kernel
                // doesn't verify on RX unless explicitly enabled.
                false,
            );

            let total_len = HEADROOM as usize + payload_len;
            debug_assert!(total_len <= frame_size);
            let desc = XdpDesc {
                addr: frame_addr,
                len: total_len as u32,
                options: 0,
            };
            if !self.raw.enqueue_tx(desc) {
                // TX ring full despite the up-front available() check --
                // bail; the caller sees `sent` and retries the rest.
                break;
            }

            // Replace with an empty sentinel and forget the original -- the
            // kernel owns the frame until COMPLETION reclaims it, so
            // XdpTxBuf::Drop must not run.
            let original = mem::replace(slot, sentinel_transmit());
            mem::forget(original);
            sent += 1;
        }

        if sent > 0 {
            self.raw.commit_tx();
            // `wake_tx` is a sendto(NULL) that nudges the driver out of
            // its idle loop; only needed when NEED_WAKEUP is set.
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

        // Bypass the pool's public `available()` (which would drain the
        // cross-thread MPSC) and push directly into the local free list.
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

        self.replenish_fill();

        // SAFETY: rx_scratch is owner-thread only.
        let scratch = unsafe { &mut *self.rx_scratch.get() };
        scratch.clear();
        if scratch.capacity() < limit {
            scratch.reserve(limit - scratch.capacity());
        }
        self.raw.drain_rx(scratch, limit);

        // The eBPF program already filters to IPv4/UDP, so non-parseable
        // frames are unexpected. Return them to FILL defensively.
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
                // Bad packet -- drop the frame back to FILL.
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
        // Remove our BOUND_PORTS / XSKMAP entries; the program itself stays
        // attached for other XdpSockets on this NIC (see program.rs).
        // Best-effort -- a poisoned mutex or transient map error must not
        // panic during tile shutdown. XSKMAP is auto-reaped when `raw`
        // drops below; BOUND_PORTS isn't, so skipping this leaks ports.
        if let Ok(mut p) = self.program.lock() {
            let _ = p.unbind_port(self.bound_addr.port());
            let _ = p.unregister_socket(self.queue_id as u32);
        }
    }
}

impl XdpTxPool {
    /// Same-thread reclamation entry point used by `drain_completions` to
    /// feed raw frame addresses (not real `XdpTxBuf`s) back into the pool.
    pub(crate) fn reclaim_completed(&self, addr: u64) {
        // SAFETY: pool is `!Sync`, so this `&self` is owner-thread-only.
        unsafe { (*self.reclaim.local.get()).push(addr) };
    }
}

/// Empty `Transmit` used as a `mem::replace` sentinel after a frame has been
/// handed to the TX ring. Carries no `XdpTxBuf`s, so dropping is a no-op.
fn sentinel_transmit() -> Transmit<ScatterGather<XdpTxBuf>> {
    Transmit::new(
        ScatterGather::new(),
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
    )
}

// ── Process-global routing snapshot ─────────────────────────────────────────
//
// One Router shared across all XdpSockets in the process; one monitor thread
// keeps it up-to-date. Both are process-lifetime -- neither the OnceLocks nor
// the monitor's exit flag are ever reset. The OS reaps the thread on
// `exit(2)`; no graceful shutdown hook exists.

static ROUTER: OnceLock<Arc<ArcSwap<Router>>> = OnceLock::new();
static ROUTER_INIT: OnceLock<Mutex<RouterInit>> = OnceLock::new();

/// Anchors the monitor's `JoinHandle` and `exit` flag so they aren't
/// dropped. The thread runs for the process lifetime; neither field is
/// read after construction.
#[allow(dead_code)]
struct RouterInit {
    exit: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

fn shared_router() -> io::Result<Arc<ArcSwap<Router>>> {
    if let Some(r) = ROUTER.get() {
        return Ok(Arc::clone(r));
    }
    // Seed the ArcSwap with an empty router. `RouteMonitor::start` subscribes
    // to multicast updates *before* dumping the kernel tables and publishes
    // the populated Router; this closes the race where updates between
    // dump and subscribe would be lost.
    let arc = Arc::new(ArcSwap::new(Arc::new(Router::empty())));
    let exit = Arc::new(AtomicBool::new(false));
    let handle = RouteMonitor::start(
        Arc::clone(&arc),
        RouteTable::Main,
        Arc::clone(&exit),
        // 50ms publish cadence -- tradeoff between responsiveness and dump cost.
        Duration::from_millis(50),
        || {},
    )?;
    let _ = ROUTER_INIT.set(Mutex::new(RouterInit { exit, handle: Some(handle) }));
    let _ = ROUTER.set(Arc::clone(&arc));
    Ok(arc)
}
