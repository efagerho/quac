use std::alloc::{alloc_zeroed, Layout};
use std::cell::UnsafeCell;
use std::collections::VecDeque;
use std::io;
use std::mem::{self, size_of, MaybeUninit};
use std::net::{SocketAddr, UdpSocket};
use std::os::fd::{AsRawFd, BorrowedFd, RawFd};
use std::ptr;
use std::sync::atomic::{AtomicU16, Ordering};
use std::thread::ThreadId;

use io_uring::{cqueue, opcode, squeue, types, IoUring};
use socket2::{Domain, Protocol, Socket, Type};

use quac_socket::net::{sockaddr_from_socketaddr, socketaddr_from_raw};
use quac_socket::{DrainResult, MpscQueue, PacketSocket, RecvMeta, RxPool, ScatterGather, Transmit};

use crate::{
    IoRxBufMut, IoRxPool, IoTxBuf, IoTxPool, IPV4_MAX_UDP_PAYLOAD, IPV6_MAX_UDP_PAYLOAD,
    MAX_BUF_SIZE,
};

// ── Ring / pool constants ─────────────────────────────────────────────────────

// High bit → send CQE; clear → recv CQE.
const SEND_TAG: u64 = 1 << 63;
const RECV_TAG: u64 = 0;
const _: () = assert!(RECV_TAG & SEND_TAG == 0);
// Default SQ size; CQ is 2× this. Larger SQ amortizes per-CQE overhead.
const DEFAULT_RING_ENTRIES: u32 = 1024;
const DEFAULT_SEND_POOL: usize = 128;
/// Compile-time max SG segments per send; stack-allocates the per-send iovec
/// array. Runtime tuning would require const generics or heap allocation.
const MAX_SEND_SGS: usize = 8;
/// CQE drain batch size; keeps stack frame < 1 KiB (64 × 16 B).
const DRAIN_BATCH: usize = 64;
/// Stop re-arming multishot SQE after this many non-ENOBUFS errors (busy-loop
/// guard for ECANCELED/EINVAL/ENOMEM rejections).
const MAX_RECV_ERROR_STREAK: u32 = 8;

// ── Provided buffer ring constants ────────────────────────────────────────────

const BUF_GROUP: u16 = 0;
/// Default size; power of 2, ≤ 32768.
const DEFAULT_BUF_RING_COUNT: usize = 256;
/// `io_uring_recvmsg_out` header size.
const RECV_OUT_SIZE: usize = 16;
/// Max source-address size; also the template `msg_namelen`, so the kernel
/// places cmsg/payload at fixed offsets.
const RECV_NAME_MAX: usize = size_of::<libc::sockaddr_storage>(); // 128
/// CMSG buffer (ECN + dst-IP). Fixed by template `msg_controllen`.
const RECV_CMSG_MAX: usize = 128;
/// Fixed payload offset: header(16) + name(128) + cmsg(128) = 272.
const RECV_PAYLOAD_OFF: usize = RECV_OUT_SIZE + RECV_NAME_MAX + RECV_CMSG_MAX;
/// Per provided buffer: header + name + cmsg + payload = 2320 bytes.
/// Usable payload is bounded by `pool().max_payload_size()` (oversize → drop).
const RECV_BUF_SIZE: usize = RECV_PAYLOAD_OFF + MAX_BUF_SIZE;

// io_uring SQE byte offsets (kernel ABI, include/uapi/linux/io_uring.h).
const SQE_FLAGS_OFF: usize = 1; // u8
const SQE_IOPRIO_OFF: usize = 2; // u16
const SQE_BUF_GROUP_OFF: usize = 40; // u16
const IOSQE_BUFFER_SELECT: u8 = 1 << 5;
const IORING_RECVMSG_CQE_MULTISHOT: u16 = 2;

// Catch crate-layout drift: the offsets above assume 64-byte SQE.
const _: () = assert!(
    size_of::<squeue::Entry>() == 64,
    "io_uring SQE size changed - audit SQE_FLAGS_OFF / SQE_IOPRIO_OFF / SQE_BUF_GROUP_OFF",
);

/// Mirror of `io_uring_recvmsg_out` (16 B, ABI-stable). Layout per buffer:
/// `[0..16) header  [16..144) name  [144..272) cmsg  [272..) payload`.
#[repr(C)]
struct RecvMsgOut {
    namelen: u32,
    controllen: u32,
    payloadlen: u32,
    flags: u32,
}

const _: () = assert!(size_of::<RecvMsgOut>() == RECV_OUT_SIZE);

// ── Per-buffer storage for the provided buffer ring ───────────────────────────

#[repr(align(64))]
struct MultiRecvBuf([u8; RECV_BUF_SIZE]);

fn alloc_multi_recv_buf() -> Box<MultiRecvBuf> {
    let layout = Layout::new::<MultiRecvBuf>();
    let ptr = unsafe { alloc_zeroed(layout) as *mut MultiRecvBuf };
    if ptr.is_null() {
        std::alloc::handle_alloc_error(layout);
    }
    unsafe { Box::from_raw(ptr) }
}

// ── Provided buffer ring ──────────────────────────────────────────────────────

/// Kernel-visible ring of buffer descriptors (mmap'd). Tail lives in
/// entry 0's `resv` field; updated via Release store so descriptor writes
/// are visible to the kernel before the advance.
struct ProvidedBufRing {
    entries: *mut types::BufRingEntry, // mmap'd ring
    entries_len: usize,                // count × 16
    count: u16,                        // ring size (power of 2)
    mask: u16,                         // count − 1
    // Vec<Box<…>> rather than Vec<…> so each buffer's heap address is
    // independent of the Vec's storage. The kernel records raw pointers into
    // these buffers in the BufRingEntry table; they must remain stable for
    // the socket's lifetime, even if Vec internals were ever moved.
    #[allow(clippy::vec_box)]
    bufs: Vec<Box<MultiRecvBuf>>,
    tail: u16, // shadow tail
}

// Safety: raw pointer is stable mmap memory; no concurrent access.
unsafe impl Send for ProvidedBufRing {}

impl ProvidedBufRing {
    /// Allocate a ring of `n` entries; `n` must be a power of 2 and ≤ 32768.
    fn new(n: usize) -> io::Result<Self> {
        debug_assert!(n.is_power_of_two() && n <= 32768);
        let entries_len = n * size_of::<types::BufRingEntry>();
        let ptr = unsafe {
            libc::mmap(
                ptr::null_mut(),
                entries_len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANONYMOUS | libc::MAP_PRIVATE,
                -1,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        // MAP_ANONYMOUS | MAP_PRIVATE pages are zero-initialised by the kernel;
        // an explicit write_bytes here would be redundant.

        let bufs: Vec<Box<MultiRecvBuf>> = (0..n).map(|_| alloc_multi_recv_buf()).collect();
        Ok(Self {
            entries: ptr as *mut types::BufRingEntry,
            entries_len,
            count: n as u16,
            mask: (n - 1) as u16,
            bufs,
            tail: 0,
        })
    }

    fn ring_addr(&self) -> u64 {
        self.entries as u64
    }

    /// Fill all descriptor slots and advance the tail.
    fn fill_all(&mut self) {
        for bid in 0u16..self.count {
            let slot = (self.tail.wrapping_add(bid)) & self.mask;
            let entry = unsafe { &mut *self.entries.add(slot as usize) };
            entry.set_addr(self.bufs[bid as usize].0.as_ptr() as u64);
            entry.set_len(RECV_BUF_SIZE as u32);
            entry.set_bid(bid);
        }
        self.tail = self.tail.wrapping_add(self.count);
        self.store_tail();
    }

    /// Return buffer `bid` to the ring at the current tail slot without flushing
    /// the tail to the kernel. Call [`flush_tail`](Self::flush_tail) after
    /// processing a batch to make all replenished slots visible in one store.
    #[inline]
    fn replenish_raw(&mut self, bid: u16) {
        let slot = self.tail & self.mask;
        let entry = unsafe { &mut *self.entries.add(slot as usize) };
        entry.set_addr(self.bufs[bid as usize].0.as_ptr() as u64);
        entry.set_len(RECV_BUF_SIZE as u32);
        entry.set_bid(bid);
        self.tail = self.tail.wrapping_add(1);
    }

    /// Flush all preceding [`replenish_raw`](Self::replenish_raw) calls to the
    /// kernel with a single Release store.
    #[inline]
    fn flush_tail(&self) {
        self.store_tail();
    }

    /// Release-store the shadow tail into the ring header (entries[0].resv).
    fn store_tail(&self) {
        // entries[0].resv is at byte offset 14 of the ring memory, which is
        // exactly the kernel's tail field.
        let tail_ptr = unsafe { types::BufRingEntry::tail(self.entries) as *mut u16 };
        let tail_atomic = unsafe { &*(tail_ptr as *const AtomicU16) };
        tail_atomic.store(self.tail, Ordering::Release);
    }
}

impl Drop for ProvidedBufRing {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.entries as *mut libc::c_void, self.entries_len);
        }
    }
}

// ── RingReclaimer ─────────────────────────────────────────────────────────────

/// Deferred ring-slot reclamation. Owner-thread drops push to `pending`
/// (no atomics); cross-thread drops push to `remote` (MPSC). Drained at the
/// top of each `drain_cqes_into` batch.
///
/// SAFETY: `ring` and `pending` are owner-thread only; `remote` is `Sync`.
pub(crate) struct RingReclaimer {
    pub(crate) owner:   ThreadId,
    ring:               *mut ProvidedBufRing,   // stable: points into Box<ProvidedBufRing>
    pub(crate) pending: UnsafeCell<Vec<u16>>,   // same-thread deferred bids
    pub(crate) remote:  MpscQueue<u16>,          // cross-thread bid returns
}

// Safety: `ring`/`pending` are owner-thread-only; `remote` is `Sync` via MpscQueue.
unsafe impl Send for RingReclaimer {}
unsafe impl Sync for RingReclaimer {}

impl RingReclaimer {
    /// Drain both return queues into the ring. Returns `true` if any bids
    /// were reclaimed (caller follows with `buf_ring.flush_tail()`).
    ///
    /// # Safety
    /// Owner thread only.
    pub(crate) unsafe fn drain_pending(&self) -> bool {
        debug_assert_eq!(
            std::thread::current().id(),
            self.owner,
            "drain_pending called from non-owner thread"
        );
        let pending = unsafe { &mut *self.pending.get() };
        unsafe { self.remote.drain_into(pending) };
        if pending.is_empty() {
            return false;
        }
        let ring = unsafe { &mut *self.ring };
        for &bid in pending.iter() {
            ring.replenish_raw(bid);
        }
        pending.clear();
        true
    }
}

// Per-slot TX CMSG buffer capacity. Sized for the largest possible combination:
//   IPV6_PKTINFO  → CMSG_SPACE(20) = 40 bytes
//   IPV6_TCLASS   → CMSG_SPACE(1)  = 24 bytes
// Total: 64 bytes (one cache line).
const SEND_CMSG_MAX: usize = 64;

// ── SendSlot ──────────────────────────────────────────────────────────────────

/// Pre-allocated send slot. `hdr` holds raw pointers into `addr` / `iovs` /
/// `cmsg_buf` in the same Box allocation; access via `Box<SendSlot>` so the
/// pointers stay valid.
struct SendSlot {
    addr: libc::sockaddr_storage,
    iovs: [libc::iovec; MAX_SEND_SGS],
    /// Inline CMSG buffer for per-packet ECN and src_ip ancillary data.
    /// Written by `prepare` when the transmit carries these fields.
    cmsg_buf: [u8; SEND_CMSG_MAX],
    hdr: libc::msghdr,
    transmit: Option<Transmit<ScatterGather<IoTxBuf>>>,
}

// Safety: raw pointers in `hdr` are stable intra-Box addresses.
unsafe impl Send for SendSlot {}

impl SendSlot {
    fn new() -> Box<Self> {
        Box::new(Self {
            addr: unsafe { mem::zeroed() },
            iovs: unsafe { mem::zeroed() },
            cmsg_buf: [0u8; SEND_CMSG_MAX],
            hdr: unsafe { mem::zeroed() },
            transmit: None,
        })
    }

    /// # Safety
    ///
    /// `transmit.contents.segments.len()` must be `<= MAX_SEND_SGS`. The caller
    /// (currently [`IoUringSocket::send`]) validates this upfront with `assert!`
    /// so this is a defence-in-depth `debug_assert!` only.
    unsafe fn prepare(
        slot: &mut Box<Self>,
        transmit: Transmit<ScatterGather<IoTxBuf>>,
    ) -> *const libc::msghdr {
        debug_assert!(transmit.contents.segments().len() <= MAX_SEND_SGS);
        let n = transmit.contents.segments().len();
        slot.addr = mem::zeroed();
        let addr_len = sockaddr_from_socketaddr(&transmit.destination, &mut slot.addr);
        for (i, seg) in transmit.contents.segments().iter().enumerate().take(n) {
            let data = seg.as_slice();
            slot.iovs[i] = libc::iovec {
                iov_base: data.as_ptr() as *mut libc::c_void,
                iov_len: data.len(),
            };
        }
        slot.hdr = mem::zeroed();
        slot.hdr.msg_name = &raw mut slot.addr as *mut libc::c_void;
        slot.hdr.msg_namelen = addr_len;
        slot.hdr.msg_iov = slot.iovs.as_mut_ptr();
        slot.hdr.msg_iovlen = n as _;
        if transmit.ecn.is_some() || transmit.src_ip.is_some() {
            let dst_family = match transmit.destination {
                std::net::SocketAddr::V4(_) => libc::AF_INET,
                std::net::SocketAddr::V6(_) => libc::AF_INET6,
            };
            let cmsg_len = quac_socket::net::build_send_cmsgs(
                slot.cmsg_buf.as_mut_ptr(),
                SEND_CMSG_MAX,
                dst_family,
                transmit.ecn,
                transmit.src_ip,
            );
            slot.hdr.msg_control = slot.cmsg_buf.as_mut_ptr() as *mut libc::c_void;
            slot.hdr.msg_controllen = cmsg_len as _;
        }
        // When ecn and src_ip are both None, msg_control / msg_controllen
        // stay zero from the mem::zeroed() above -- no ancillary data.
        slot.transmit = Some(transmit);
        &raw const slot.hdr
    }
}

// ── Pending recv staging ──────────────────────────────────────────────────────

/// Staged packet: payload sits in ring slot `bid` until `recv` wraps it in
/// `IoRxBufMut::Ring`. Slot replenishment is deferred to caller drop.
struct PendingRecv {
    meta: RecvMeta,
    bid: u16,
}

// ── IoUringSocket ─────────────────────────────────────────────────────────────

// Safety: recv_msghdr contains raw pointers that are only accessed from the
// thread that owns IoUringSocket; ProvidedBufRing holds mmap memory with
// no concurrent access.
unsafe impl Send for IoUringSocket {}

/// UDP packet socket backed by a per-socket io_uring instance. Linux ≥ 6.0
/// (uses `IORING_REGISTER_PBUF_RING` + multishot `recvmsg`).
///
/// `Send + !Sync`: single-issuer (one OS thread owns all `send`/`recv`/
/// `drain_completions`). Multi-tile parallelism via `cfg.reuseport`.
///
/// Zero heap allocs on the hot path; buffers, send slots, and receive ring
/// are pre-allocated. PMTUDISC blocks oversize sends; oversize recv packets
/// (> `pool().max_payload_size()`) are dropped.
///
/// `MAX_SEND_SGS` is compile-time (per-send iovec array stays on the stack);
/// const-generic to change.

/// Configuration for [`IoUringSocket::bind`]. Build via [`IoUringConfig::builder`]
/// or [`IoUringConfig::default`]. Fields private -- non-breaking field additions.
#[derive(Debug, Clone, Copy)]
pub struct IoUringConfig {
    /// SQE ring size (power of 2, default 1024); CQ is 2× this.
    ring_entries: u32,
    /// Provided-buffer ring size (power of 2, ≤ 32768, default 256).
    /// Each entry ≈ 2.3 KiB, so 256 ≈ 579 KiB per socket.
    buf_ring_count: usize,
    /// Pre-allocated in-flight send slots (default 128); caps concurrent sends.
    send_pool_size: usize,
    /// Set `SO_REUSEPORT` for multi-tile listeners. Defaults to `false`.
    reuseport: bool,
}

impl IoUringConfig {
    pub fn builder() -> IoUringConfigBuilder {
        IoUringConfigBuilder::default()
    }
}

impl Default for IoUringConfig {
    fn default() -> Self {
        Self {
            ring_entries: DEFAULT_RING_ENTRIES,
            buf_ring_count: DEFAULT_BUF_RING_COUNT,
            send_pool_size: DEFAULT_SEND_POOL,
            reuseport: false,
        }
    }
}

/// Builder for [`IoUringConfig`]. See [`IoUringConfig::builder`].
#[derive(Debug, Clone, Copy)]
pub struct IoUringConfigBuilder(IoUringConfig);

impl Default for IoUringConfigBuilder {
    fn default() -> Self {
        Self(IoUringConfig::default())
    }
}

impl IoUringConfigBuilder {
    /// SQE ring size (must be power of 2; validated in `build`).
    pub fn ring_entries(mut self, n: u32) -> Self {
        self.0.ring_entries = n;
        self
    }

    /// Buffer ring size (must be power of 2, ≤ 32768; validated in `build`).
    pub fn buf_ring_count(mut self, n: usize) -> Self {
        self.0.buf_ring_count = n;
        self
    }

    /// In-flight send slots (must be > 0).
    pub fn send_pool_size(mut self, n: usize) -> Self {
        self.0.send_pool_size = n;
        self
    }

    pub fn reuseport(mut self, enable: bool) -> Self {
        self.0.reuseport = enable;
        self
    }

    /// Validate and produce the config. Panics on invalid combinations.
    pub fn build(self) -> IoUringConfig {
        assert!(
            self.0.ring_entries.is_power_of_two() && self.0.ring_entries > 0,
            "IoUringConfig::ring_entries must be a non-zero power of 2 (got {})",
            self.0.ring_entries
        );
        assert!(
            self.0.buf_ring_count.is_power_of_two()
                && self.0.buf_ring_count > 0
                && self.0.buf_ring_count <= 32768,
            "IoUringConfig::buf_ring_count must be a power of 2 in (0, 32768] (got {})",
            self.0.buf_ring_count
        );
        assert!(
            self.0.send_pool_size > 0,
            "IoUringConfig::send_pool_size must be > 0"
        );
        self.0
    }
}

pub struct IoUringSocket {
    ring: IoUring,
    raw_fd: RawFd,
    socket: UdpSocket,
    rx_pool: Box<IoRxPool>,
    tx_pool: Box<IoTxPool>,
    queue_id: u16,

    // Template msghdr for the multishot recvmsg SQE.  The kernel reads
    // msg_namelen / msg_controllen from it; the pointer must stay valid until
    // the SQE is cancelled and its final CQE is consumed.
    recv_msghdr: Box<libc::msghdr>,
    buf_ring: Box<ProvidedBufRing>,   // boxed to stabilise address for reclaimer raw ptr
    reclaimer: Box<RingReclaimer>,
    recv_armed: bool, // multishot SQE still armed?
    // Counts consecutive non-ENOBUFS errors that disarmed the multishot SQE.
    // Re-arming is suppressed once this reaches MAX_RECV_ERROR_STREAK to
    // prevent a busy-loop when the kernel persistently rejects the SQE.
    // Reset to 0 on every valid received packet.
    recv_error_streak: u32,
    // True whenever SQEs have been pushed to the submission ring but not yet
    // flushed to the kernel via io_uring_enter. recv() and drain_completions()
    // check this flag before calling ring.submit() so that the common hot-path
    // (ring already armed, no sends pending) avoids a no-op syscall.
    sq_dirty: bool,

    // Staged completions waiting for recv() to drain them.
    pending_recvs: VecDeque<PendingRecv>,

    // Send -- pre-allocated pool of pinned Box<SendSlot>s, zero hot-path allocs.
    #[allow(clippy::vec_box)]
    send_slots: Vec<Box<SendSlot>>,
    /// Stack of free send-slot indices. Heap-allocated since `cfg.send_pool_size`
    /// is a runtime knob; one extra deref per push/pop vs the previous
    /// `[usize; SEND_POOL]` array -- negligible next to the io_uring submission
    /// cost on the same path.
    send_free: Box<[usize]>,
    send_free_top: usize,
}

impl IoUringSocket {
    /// Bind a UDP socket and wrap it as an `IoUringSocket`. `cfg` controls
    /// ring sizes and reuseport (use `IoUringConfig::default()` for defaults).
    pub fn bind(addr: SocketAddr, queue_id: u16, cfg: IoUringConfig) -> io::Result<Self> {
        let socket = if cfg.reuseport {
            let domain = if addr.is_ipv4() {
                Domain::IPV4
            } else {
                Domain::IPV6
            };
            let sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
            sock.set_reuse_port(true)?;
            sock.set_nonblocking(true)?;
            sock.bind(&addr.into())?;
            sock.into()
        } else {
            let socket = UdpSocket::bind(addr)?;
            socket.set_nonblocking(true)?;
            socket
        };
        Self::from_udp(socket, queue_id, cfg)
    }

    fn from_udp(socket: UdpSocket, queue_id: u16, cfg: IoUringConfig) -> io::Result<Self> {
        let raw_fd = socket.as_raw_fd();
        let ring = IoUring::new(cfg.ring_entries)?;

        let max_payload = match socket.local_addr() {
            Ok(SocketAddr::V4(_)) => IPV4_MAX_UDP_PAYLOAD,
            _ => IPV6_MAX_UDP_PAYLOAD,
        };
        let rx_pool = Box::new(IoRxPool { max_payload });
        let tx_pool = IoTxPool::with_max_payload(max_payload);

        // Forbid fragmentation (PMTUDISC_DO). Fatal: silent fragmentation would
        // break QUIC's PMTU model and let oversize reassembled payloads hit
        // the recv ring's fixed-size buffers.
        let (level, opt, val) = if max_payload == IPV4_MAX_UDP_PAYLOAD {
            (
                libc::IPPROTO_IP,
                libc::IP_MTU_DISCOVER,
                libc::IP_PMTUDISC_DO,
            )
        } else {
            (
                libc::IPPROTO_IPV6,
                libc::IPV6_MTU_DISCOVER,
                libc::IPV6_PMTUDISC_DO,
            )
        };
        let v: libc::c_int = val;
        let r = unsafe {
            libc::setsockopt(
                raw_fd,
                level,
                opt,
                &v as *const _ as *const libc::c_void,
                mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if r != 0 {
            return Err(io::Error::last_os_error());
        }

        let mut buf_ring = ProvidedBufRing::new(cfg.buf_ring_count)?;
        unsafe {
            ring.submitter()
                .register_buf_ring(buf_ring.ring_addr(), cfg.buf_ring_count as u16, BUF_GROUP)
                .map_err(|e| {
                    io::Error::new(
                        e.kind(),
                        format!("register_buf_ring failed (requires Linux 6.0+): {e}"),
                    )
                })?;
        }
        buf_ring.fill_all();
        let mut buf_ring = Box::new(buf_ring);
        // Derive the raw pointer from `&mut` so its provenance permits later
        // `&mut *ring` reborrows in `RingReclaimer::drain_pending`. Casting from
        // `&` (e.g. via `Box::as_ref`) would tag the pointer SharedReadOnly and
        // make the reborrow UB under Stacked / Tree Borrows.
        let ring_ptr: *mut ProvidedBufRing = Box::as_mut(&mut buf_ring);
        let reclaimer = Box::new(RingReclaimer {
            owner:   std::thread::current().id(),
            ring:    ring_ptr,
            pending: UnsafeCell::new(Vec::with_capacity(cfg.buf_ring_count)),
            // Capacity must be >= buf_ring_count so a cross-thread bid
            // return never fails: every bid in flight is at most one drop
            // away from this queue, and total bids in circulation is bounded
            // by the ring size.
            remote:  MpscQueue::new(cfg.buf_ring_count),
        });

        let send_slots: Vec<Box<SendSlot>> =
            (0..cfg.send_pool_size).map(|_| SendSlot::new()).collect();
        let send_free: Box<[usize]> = (0..cfg.send_pool_size).collect();

        // Enable ECN (IP_TOS / IPV6_TCLASS) and dst-IP (IP_PKTINFO /
        // IPV6_PKTINFO) CMSG delivery. The kernel writes these into the per-slot
        // cmsg area of each ring buffer. Failure is fatal: without these options
        // the CMSG area stays empty and RecvMeta.ecn / .dst_ip are always None,
        // which breaks QUIC ECN and multi-homed path selection.
        {
            let on: libc::c_int = 1;
            let on_ptr = &on as *const _ as *const libc::c_void;
            let on_len = mem::size_of_val(&on) as libc::socklen_t;

            let (ecn_level, ecn_opt, pktinfo_level, pktinfo_opt) =
                if max_payload == IPV4_MAX_UDP_PAYLOAD {
                    (libc::IPPROTO_IP, libc::IP_RECVTOS, libc::IPPROTO_IP, libc::IP_PKTINFO)
                } else {
                    (libc::IPPROTO_IPV6, libc::IPV6_RECVTCLASS, libc::IPPROTO_IPV6, libc::IPV6_RECVPKTINFO)
                };

            let r = unsafe {
                libc::setsockopt(raw_fd, ecn_level, ecn_opt, on_ptr, on_len)
            };
            if r != 0 {
                return Err(io::Error::last_os_error());
            }

            let r = unsafe {
                libc::setsockopt(raw_fd, pktinfo_level, pktinfo_opt, on_ptr, on_len)
            };
            if r != 0 {
                return Err(io::Error::last_os_error());
            }

            // On dual-stack (IPV6_V6ONLY=0) v6 sockets, v4-mapped datagrams arrive
            // and the kernel delivers their ECN via an IPPROTO_IP/IP_TOS CMSG rather
            // than IPV6_TCLASS.  Enable IP_RECVTOS so those cmsgs are generated.
            // Non-fatal: returns EINVAL when IPV6_V6ONLY=1 or not applicable.
            if max_payload != IPV4_MAX_UDP_PAYLOAD {
                unsafe {
                    let _ = libc::setsockopt(
                        raw_fd, libc::IPPROTO_IP, libc::IP_RECVTOS, on_ptr, on_len,
                    );
                }
            }
        }

        let mut recv_msghdr: Box<libc::msghdr> = Box::new(unsafe { mem::zeroed() });
        recv_msghdr.msg_namelen = RECV_NAME_MAX as u32;
        recv_msghdr.msg_controllen = RECV_CMSG_MAX;

        let mut s = Self {
            ring,
            raw_fd,
            socket,
            rx_pool,
            tx_pool,
            queue_id,
            recv_msghdr,
            buf_ring,
            reclaimer,
            recv_armed: false,
            recv_error_streak: 0,
            sq_dirty: false,
            pending_recvs: VecDeque::with_capacity(cfg.buf_ring_count),
            send_slots,
            send_free_top: cfg.send_pool_size,
            send_free,
        };
        s.submit_recv_multishot(); // sets sq_dirty = true
        let _ = s.ring.submit();
        s.sq_dirty = false;
        Ok(s)
    }

    pub fn set_queue_id(&mut self, id: u16) {
        self.queue_id = id;
    }

    // ── Multishot recv SQE ────────────────────────────────────────────────────

    fn submit_recv_multishot(&mut self) {
        let msghdr_ptr = &mut *self.recv_msghdr as *mut libc::msghdr;
        // io-uring 0.6 has no clean multishot+pbuf API; patch SQE bytes
        // directly: flags |= IOSQE_BUFFER_SELECT, ioprio = MULTISHOT,
        // buf_group = BUF_GROUP.
        let mut entry = opcode::RecvMsg::new(types::Fd(self.raw_fd), msghdr_ptr)
            .build()
            .user_data(RECV_TAG);
        unsafe {
            let base = &mut entry as *mut squeue::Entry as *mut u8;
            *base.add(SQE_FLAGS_OFF) |= IOSQE_BUFFER_SELECT;
            ptr::write_unaligned(
                base.add(SQE_IOPRIO_OFF) as *mut u16,
                IORING_RECVMSG_CQE_MULTISHOT,
            );
            ptr::write_unaligned(base.add(SQE_BUF_GROUP_OFF) as *mut u16, BUF_GROUP);
        }
        // Safety: msghdr_ptr stays valid while IoUringSocket is alive.
        unsafe {
            self.ring
                .submission()
                .push(&entry)
                .expect("bug: submit_recv_multishot called with a full SQ ring");
        }
        self.recv_armed = true;
        self.sq_dirty = true;
    }

    // ── CQE drain ────────────────────────────────────────────────────────────

    // Drain CQEs in DRAIN_BATCH chunks. Send CQEs reclaim slots; recv CQEs
    // are written into out_meta/out_bufs up to capacity, the rest staged in
    // pending_recvs. Re-arms multishot when disarmed and slots are free.
    fn drain_cqes_into(
        &mut self,
        out_meta: &mut [RecvMeta],
        out_bufs: &mut [IoRxBufMut],
        valid: &mut usize,
    ) -> DrainResult {
        let limit = out_meta.len().min(out_bufs.len());
        let max_payload = self.rx_pool.max_payload_size();
        let mut dr = DrainResult::default();
        let mut raw: [MaybeUninit<(u64, i32, u32)>; DRAIN_BATCH] =
            [const { MaybeUninit::uninit() }; DRAIN_BATCH];
        loop {
            let mut n_cqes = 0;
            for cqe in self.ring.completion().take(DRAIN_BATCH) {
                raw[n_cqes].write((cqe.user_data(), cqe.result(), cqe.flags()));
                n_cqes += 1;
            }
            if n_cqes == 0 {
                break;
            }

            // Reclaim ring slots dropped by callers since the last call, then
            // track whether any slots were replenished so we flush tail once
            // at the end of the batch.
            let mut replenished = unsafe { self.reclaimer.drain_pending() };

            for &(ud, result, cqe_flags) in
                raw[..n_cqes].iter().map(|m| unsafe { m.assume_init_ref() })
            {
                if ud & SEND_TAG != 0 {
                    // Send completion -- drop IoTxBuf refs and return slot to free stack.
                    let idx = (ud & !SEND_TAG) as usize;
                    if result < 0 {
                        if -result == libc::EMSGSIZE {
                            dr.emsgsize += 1;
                        } else {
                            dr.errors += 1;
                        }
                    } else {
                        dr.completed += 1;
                    }
                    self.send_slots[idx].transmit = None;
                    self.send_free[self.send_free_top] = idx;
                    self.send_free_top += 1;
                } else {
                    // Recv multishot CQE.
                    if !cqueue::more(cqe_flags) {
                        // Kernel has disarmed the SQE (buffer exhaustion or error).
                        self.recv_armed = false;
                        // ENOBUFS means the provided-buffer ring is exhausted --
                        // transient, handled by re-arming once slots are free.
                        // Any other error is counted; re-arming stops at MAX_RECV_ERROR_STREAK
                        // to prevent a busy-loop when the kernel persistently rejects the SQE.
                        if result < 0 && -result != libc::ENOBUFS {
                            self.recv_error_streak =
                                self.recv_error_streak.saturating_add(1);
                        }
                    }

                    if let Some(bid) = cqueue::buffer_select(cqe_flags) {
                        if result > 0 {
                            self.recv_error_streak = 0;
                            // Safety: bid < BUF_RING_COUNT; kernel wrote a valid packet.
                            let buf_data = self.buf_ring.bufs[bid as usize].0.as_ptr();
                            let out = unsafe { &*(buf_data as *const RecvMsgOut) };
                            let payloadlen = out.payloadlen as usize;

                            // Payload is at the fixed offset RECV_PAYLOAD_OFF because
                            // the kernel uses template msg_namelen (128) and
                            // msg_controllen (128) to determine placement, regardless
                            // of the actual received addr/cmsg lengths.
                            let src = unsafe {
                                socketaddr_from_raw(
                                    buf_data.add(RECV_OUT_SIZE) as *const libc::sockaddr,
                                    out.namelen as libc::socklen_t,
                                )
                            };
                            // Enforce the 1500-byte Ethernet MTU: drop any packet whose
                            // UDP payload exceeds `max_payload`. Packets larger than this
                            // could not be transmitted out of this socket either (DF/no-frag
                            // is set via PMTUDISC_DO), so they are not legitimate inputs.
                            //
                            // MSG_TRUNC means the kernel truncated the payload to fit the
                            // ring slot -- already cannot form a valid packet.
                            //
                            // Both checks are required: the payloadlen check catches packets
                            // between `max_payload` and `RECV_BUF_SIZE - RECV_PAYLOAD_OFF`
                            // (which fit in the slot but exceed MTU); MSG_TRUNC catches
                            // packets larger than the slot itself.
                            let trunc = out.flags & libc::MSG_TRUNC as u32 != 0;
                            if payloadlen <= max_payload && !trunc {
                                if let Some(src) = src {
                                    // Parse ECN and dst-IP from the cmsg area that sits
                                    // between the name area and the payload.  Skip if
                                    // MSG_CTRUNC: partial cmsgs would yield wrong values.
                                    let ctrunc = out.flags & libc::MSG_CTRUNC as u32 != 0;
                                    let (dst_ip, ecn) = if ctrunc {
                                        (None, None)
                                    } else {
                                        unsafe {
                                            quac_socket::net::parse_recv_cmsgs(
                                                buf_data.add(RECV_OUT_SIZE + RECV_NAME_MAX)
                                                    as *mut libc::c_void,
                                                out.controllen as usize,
                                            )
                                        }
                                    };

                                    let mut m = RecvMeta::default();
                                    m.src = src;
                                    m.dst_ip = dst_ip;
                                    m.ecn = ecn;
                                    m.len = payloadlen as u16;

                                    if *valid < limit {
                                        // Zero-copy path: wrap the ring slot directly.
                                        // The old heap IoRxBufMut in out_bufs[*valid] drops
                                        // here, recycling its Vec<u8> to IoTxPool.
                                        // Replenishment of `bid` is deferred to the ring
                                        // IoRxBufMut's Drop, via reclaimer.
                                        // `cap` is the MTU-derived usable limit; the ring
                                        // slot has more physical room (~2 KiB) but the
                                        // remainder is reserved for alignment/headroom.
                                        let ring_buf = IoRxBufMut::from_ring_slot(
                                            unsafe { buf_data.add(RECV_PAYLOAD_OFF) },
                                            payloadlen,
                                            max_payload,
                                            bid,
                                            self.reclaimer.as_ref() as *const RingReclaimer,
                                        );
                                        let _ = mem::replace(&mut out_bufs[*valid], ring_buf);
                                        out_meta[*valid] = m;
                                        *valid += 1;
                                    } else {
                                        // Output full; stage for the next recv() call.
                                        self.pending_recvs.push_back(PendingRecv { meta: m, bid });
                                    }
                                } else {
                                    // Unknown address family; drop the packet.
                                    self.buf_ring.replenish_raw(bid);
                                    replenished = true;
                                }
                            } else {
                                // Payload overflows the ring slot or was truncated; drop.
                                self.buf_ring.replenish_raw(bid);
                                replenished = true;
                            }
                        } else {
                            // Error or empty CQE; return slot immediately.
                            self.buf_ring.replenish_raw(bid);
                            replenished = true;
                        }
                    }
                }
            }

            // Drain bids that accumulated during this batch (zero-copy recv
            // drops and send-CQE IoTxBuf drops both push to reclaimer.pending).
            // Without this second drain, those bids would not be flushed until
            // the *next* call, leaving the kernel short of ring slots for up to
            // one batch period and causing ENOBUFS spikes under high load.
            replenished |= unsafe { self.reclaimer.drain_pending() };

            // Flush all replenished slots in one Release store per batch.
            if replenished {
                self.buf_ring.flush_tail();
            }

            if n_cqes < DRAIN_BATCH {
                break; // CQ ring fully drained
            }
        }

        // Re-arm the multishot SQE if the kernel disarmed it and at least one
        // ring buffer slot is available. With provided-buffer rings, re-arming
        // with 0 available slots produces an immediate ENOBUFS CQE and
        // disarms again -- creating an infinite loop.
        //
        // `pending_recvs.len() < BUF_RING_COUNT` is a conservative proxy: it
        // counts staged-but-undelivered packets, not the true number of slots
        // available to the kernel.  Slots held by Ring-variant IoBufMuts in
        // caller hands are not counted here.  This means re-arming is possible
        // even when the ring is fully exhausted by caller-held slots, which
        // produces a benign immediate ENOBUFS CQE rather than a hang.
        //
        // recv_error_streak guards against persistent non-ENOBUFS errors: if the
        // kernel keeps rejecting the SQE, stop trying after MAX_RECV_ERROR_STREAK
        // consecutive failures to prevent a busy-loop.
        if !self.recv_armed
            && !self.ring.submission().is_full()
            && self.pending_recvs.len() < self.buf_ring.count as usize
            && self.recv_error_streak < MAX_RECV_ERROR_STREAK
        {
            self.submit_recv_multishot(); // sets sq_dirty = true
            let _ = self.ring.submit();
            self.sq_dirty = false;
        }
        dr
    }

    fn drain_cqes(&mut self) -> DrainResult {
        let mut valid = 0usize;
        self.drain_cqes_into(&mut [], &mut [], &mut valid)
    }

    // Flush any pending SQEs to the kernel so that completions (multishot
    // recvmsg results, send CQEs) arrive in the CQ ring before drain_cqes reads
    // them.  Only needed on the hot path when a send() was issued since the last
    // call; sq_dirty tracks this to avoid a redundant no-op syscall.
    fn flush_sqes(&mut self) {
        if self.sq_dirty {
            let _ = self.ring.submit();
            self.sq_dirty = false;
        }
    }
}

// ── PacketSocket impl ─────────────────────────────────────────────────────────

impl PacketSocket for IoUringSocket {
    type RxPool = IoRxPool;
    type TxPool = IoTxPool;

    /// Inline iovec count in [`SendSlot`]. Each transmit becomes one
    /// `sendmsg` SQE whose `msg_iov` references at most this many segments.
    const MAX_SEGMENTS: usize = MAX_SEND_SGS;

    /// Bounded by the default provided-buffer ring size. Configs that raise
    /// `buf_ring_count` above this still drain in chunks of at most this many
    /// per `recv()` call -- the trait contract caps the batch even if the
    /// underlying ring is larger.
    const MAX_BATCH: usize = DEFAULT_BUF_RING_COUNT;

    fn rx_pool(&self) -> &IoRxPool {
        &self.rx_pool
    }

    fn tx_pool(&self) -> &IoTxPool {
        &self.tx_pool
    }

    fn send(&mut self, transmits: &mut [Transmit<ScatterGather<IoTxBuf>>]) -> io::Result<usize> {
        if transmits.is_empty() {
            return Ok(0);
        }

        // Pre-compute how many we can accept without overflowing the send-slot
        // pool or the SQ ring.  The SQ free-count is stable here because we
        // haven't submitted yet.
        let sq_free = {
            let sq = self.ring.submission();
            sq.capacity().saturating_sub(sq.len())
        };
        let n = transmits.len().min(self.send_free_top).min(sq_free);

        if n == 0 {
            return Ok(0);
        }

        // Validate segment counts on the prefix we're about to accept. Done
        // before any state is mutated so a panicking caller can fix the bad
        // transmit and retry. Silent truncation in `SendSlot::prepare` would
        // produce a smaller (and wrong) UDP datagram than the caller intended.
        for (i, t) in transmits.iter().take(n).enumerate() {
            let segs = t.contents.segments().len();
            assert!(
                segs <= Self::MAX_SEGMENTS,
                "transmits[{i}] has {segs} segments but IoUringSocket::MAX_SEGMENTS is {}",
                Self::MAX_SEGMENTS,
            );
            if Self::MAX_GSO == 1 {
                assert!(
                    t.segment_size == 0,
                    "transmits[{i}] has segment_size={} but IoUringSocket::MAX_GSO is 1 (GSO not supported)",
                    t.segment_size,
                );
            }
        }

        // Sentinel destination used when replacing consumed slots in the slice.
        // The empty ScatterGather (no IoTxBuf refs) drops harmlessly when the
        // caller discards the first n entries.
        let sentinel_addr = std::net::SocketAddr::V4(
            std::net::SocketAddrV4::new(std::net::Ipv4Addr::UNSPECIFIED, 0),
        );
        for slot in transmits.iter_mut().take(n) {
            self.send_free_top -= 1;
            let idx = self.send_free[self.send_free_top];
            // Move the transmit out of the caller's slice, leaving a sentinel so
            // the caller can safely drop or drain the first n entries.
            let transmit = std::mem::replace(slot, Transmit::new(ScatterGather::new(), sentinel_addr));
            let hdr_ptr = unsafe { SendSlot::prepare(&mut self.send_slots[idx], transmit) };
            let sqe = opcode::SendMsg::new(types::Fd(self.raw_fd), hdr_ptr)
                .build()
                .user_data(SEND_TAG | idx as u64);
            unsafe {
                self.ring
                    .submission()
                    .push(&sqe)
                    .expect("bug: send() accepted more transmits than sq_free allowed");
            };
        }

        // The push loop above made the SQ ring dirty; flush it. We don't set
        // `sq_dirty` first because the unconditional submit on the next line
        // makes the flag's intermediate state irrelevant.
        let _ = self.ring.submit();
        self.sq_dirty = false;
        Ok(n)
    }

    fn drain_completions(&mut self) -> DrainResult {
        self.flush_sqes();
        self.drain_cqes()
    }

    fn recv(&mut self, meta: &mut [RecvMeta], bufs: &mut [IoRxBufMut]) -> io::Result<usize> {
        if meta.is_empty() || bufs.is_empty() {
            return Ok(0);
        }

        self.flush_sqes();

        let mut valid = 0usize;
        let limit = meta.len().min(bufs.len());

        // Drain any packets staged by a prior drain_completions() call first.
        // This path is uncommon on the hot receive-only loop but keeps the
        // contract: packets arrive in order regardless of how CQEs were drained.
        if !self.pending_recvs.is_empty() {
            let max_payload = self.rx_pool.max_payload_size();
            while valid < limit {
                let Some(pr) = self.pending_recvs.pop_front() else {
                    break;
                };
                let buf_data = self.buf_ring.bufs[pr.bid as usize].0.as_ptr();
                let payload_len = pr.meta.len as usize;
                let ring_buf = IoRxBufMut::from_ring_slot(
                    unsafe { buf_data.add(RECV_PAYLOAD_OFF) },
                    payload_len,
                    max_payload,
                    pr.bid,
                    self.reclaimer.as_ref() as *const RingReclaimer,
                );
                let _ = mem::replace(&mut bufs[valid], ring_buf);
                meta[valid] = pr.meta;
                valid += 1;
            }
        }

        // Drain new CQEs into remaining slots; oversize packets dropped
        // (matches OsSocket MSG_TRUNC handling).
        self.drain_cqes_into(meta, bufs, &mut valid);

        Ok(valid)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    fn queue_id(&self) -> u16 {
        self.queue_id
    }

    #[cfg(unix)]
    fn rx_fd(&self) -> Option<BorrowedFd<'_>> {
        Some(unsafe { BorrowedFd::borrow_raw(self.raw_fd) })
    }
}

// ── Drop ──────────────────────────────────────────────────────────────────────

impl Drop for IoUringSocket {
    fn drop(&mut self) {
        // Flush any unflushed SQEs before tearing down the ring.
        if self.sq_dirty {
            let _ = self.ring.submit();
            self.sq_dirty = false;
        }

        // Pre-drain CQEs to get accurate recv_armed / outstanding_sends.
        // Without this, AsyncCancel against an already-disarmed SQE returns
        // 1 CQE (ENOENT) but wait_count expects 2 -- would hang.
        for cqe in self.ring.completion() {
            if cqe.user_data() & SEND_TAG != 0 {
                let idx = (cqe.user_data() & !SEND_TAG) as usize;
                self.send_slots[idx].transmit = None;
                self.send_free[self.send_free_top] = idx;
                self.send_free_top += 1;
            } else if !cqueue::more(cqe.flags()) {
                // Recv multishot was disarmed (no IORING_CQE_F_MORE).
                self.recv_armed = false;
            }
        }

        // Cancel the multishot recv SQE if it is still live after the pre-drain.
        if self.recv_armed {
            // Ensure the SQ has room (sq_dirty was flushed above, so this is
            // defensive for the unlikely case send() filled it just before Drop).
            if self.ring.submission().is_full() {
                let _ = self.ring.submit();
            }
            let sqe = opcode::AsyncCancel::new(RECV_TAG).build();
            if unsafe { self.ring.submission().push(&sqe) }.is_err() {
                // SQ still full -- closing the fd will abort the multishot on the
                // kernel side; adjust wait_count accordingly.
                self.recv_armed = false;
            }
        }

        // Wait for in-flight CQEs before freeing memory:
        //   - 1 CQE per outstanding send.
        //   - 2 CQEs from the recv cancel (ECANCELED + AsyncCancel).
        let outstanding_sends = self.send_slots.len() - self.send_free_top;
        let wait_count = outstanding_sends + 2 * usize::from(self.recv_armed);
        if wait_count > 0 {
            let _ = self.ring.submitter().submit_and_wait(wait_count);
        }
        // Drain remaining CQEs: release send-slot IoTxBuf references so they are
        // freed before the Box<SendSlot>s themselves are dropped.
        for cqe in self.ring.completion() {
            if cqe.user_data() & SEND_TAG != 0 {
                let idx = (cqe.user_data() & !SEND_TAG) as usize;
                self.send_slots[idx].transmit = None;
                self.send_free[self.send_free_top] = idx;
                self.send_free_top += 1;
            }
        }

        // Discard any packets staged by drain_completions() that recv() never
        // consumed.  The bids are not replenished -- the ring is about to be torn
        // down -- but the PendingRecv structs must be dropped to release any
        // associated resources before unregister_buf_ring below.
        self.pending_recvs.clear();

        // Drain the reclaimer queues solely to free the MPSC Box<Node<u16>>
        // allocations.  Replenishing the ring would be a no-op here: the buf
        // ring is unregistered immediately after, so the kernel no longer reads
        // the tail pointer.  Any Ring-variant IoBufMuts still held by callers
        // violate the "bufs don't outlive the socket" contract from CLAUDE.md,
        // so we do not attempt to guard against them.
        //
        // Note: Ring-variant IoBufs that were in send slots and dropped during
        // the CQE pre-drain above already pushed their bids to reclaimer.pending,
        // which is covered by the drain below.
        {
            let pending = unsafe { &mut *self.reclaimer.pending.get() };
            unsafe { self.reclaimer.remote.drain_into(pending) };
            pending.clear();
        }

        // Unregister the buf ring so the kernel stops accessing ring memory.
        // Ignore errors (e.g. if the ring was already torn down).
        let _ = self.ring.submitter().unregister_buf_ring(BUF_GROUP);
        // ProvidedBufRing::drop() will munmap the ring memory.
    }
}

// ── Address helpers (provided by quac_socket::net) ───────────────────────────

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::io;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::time::{Duration, Instant};

    use std::os::fd::AsRawFd;

    use quac_socket::{
        PacketBufMut, PacketSocket, RecvMeta, RxPool, ScatterGather, Segment, Transmit, TxPool,
    };
    use super::{
        IoRxBufMut, IoTxBuf, IoUringConfig, IoUringSocket, IPV4_MAX_UDP_PAYLOAD,
        IPV6_MAX_UDP_PAYLOAD,
    };

    const BATCH: usize = 64;

    fn send_one(sock: &mut IoUringSocket, dest: SocketAddr, payload: &[u8]) -> bool {
        let buf = IoTxBuf::from_slice(payload);
        let len = payload.len();
        let seg = unsafe { Segment::new_unchecked(buf, 0, len as u32) };
        let mut transmits = vec![Transmit::new(ScatterGather::single(seg), dest)];
        sock.send(&mut transmits).unwrap_or(0) >= 1
    }

    fn alloc_recv_bufs(sock: &IoUringSocket) -> Vec<IoRxBufMut> {
        let mut bufs: Vec<IoRxBufMut> = Vec::with_capacity(BATCH);
        sock.rx_pool()
            .alloc(sock.rx_pool().max_payload_size(), BATCH, &mut bufs);
        bufs
    }

    fn recv_batch(sock: &mut IoUringSocket) -> io::Result<Vec<(SocketAddr, Vec<u8>)>> {
        let mut meta = vec![RecvMeta::default(); BATCH];
        let mut bufs = alloc_recv_bufs(sock);
        let n = sock.recv(&mut meta, &mut bufs)?;
        Ok((0..n)
            .map(|i| (meta[i].src, bufs[i].filled().to_vec()))
            .collect())
    }

    fn recv_until(
        sock: &mut IoUringSocket,
        want: &[u8],
        deadline: Instant,
    ) -> io::Result<(SocketAddr, Vec<u8>)> {
        while Instant::now() < deadline {
            for (src, data) in recv_batch(sock)? {
                if data == want {
                    return Ok((src, data));
                }
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        Err(io::Error::new(io::ErrorKind::TimedOut, "timed out"))
    }

    #[test]
    fn send_recv_roundtrip() {
        let mut a = IoUringSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), 0, IoUringConfig::default()).unwrap();
        let mut b = IoUringSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), 0, IoUringConfig::default()).unwrap();
        let b_addr = b.local_addr().unwrap();
        let a_addr = a.local_addr().unwrap();

        let payload = b"hello-iouring-socket";
        assert!(send_one(&mut a, b_addr, payload));

        let deadline = Instant::now() + Duration::from_secs(2);
        let (src, data) = recv_until(&mut b, payload, deadline).unwrap();
        assert_eq!(data, payload);
        assert_eq!(src.ip(), a_addr.ip());
        assert_eq!(src.port(), a_addr.port());
    }

    #[test]
    fn send_recv_multiple_sequential() {
        let mut server = IoUringSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), 0, IoUringConfig::default()).unwrap();
        let mut client = IoUringSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), 0, IoUringConfig::default()).unwrap();
        let server_addr = server.local_addr().unwrap();

        for i in 0u8..16 {
            assert!(send_one(&mut client, server_addr, &[i]));
            let deadline = Instant::now() + Duration::from_secs(2);
            let (_, data) = recv_until(&mut server, &[i], deadline).unwrap();
            assert_eq!(data, [i]);
        }
    }

    #[test]
    fn set_queue_id_round_trips() {
        let mut s = IoUringSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), 0, IoUringConfig::default()).unwrap();
        assert_eq!(s.queue_id(), 0u16);
        s.set_queue_id(7u16);
        assert_eq!(s.queue_id(), 7u16);
    }

    #[test]
    fn pong_roundtrip() {
        let mut server = IoUringSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), 0, IoUringConfig::default()).unwrap();
        let mut client = IoUringSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), 0, IoUringConfig::default()).unwrap();
        let server_addr = server.local_addr().unwrap();
        let client_addr = client.local_addr().unwrap();

        let payload = b"ping";
        assert!(send_one(&mut client, server_addr, payload));

        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let mut meta = vec![RecvMeta::default(); BATCH];
            let mut bufs = alloc_recv_bufs(&server);
            let n = server.recv(&mut meta, &mut bufs).unwrap_or(0);
            if n > 0 {
                let mut transmits: Vec<Transmit<ScatterGather<IoTxBuf>>> = Vec::with_capacity(n);
                for (rx_buf, m) in bufs.drain(..n).zip(meta.iter()) {
                    let len = rx_buf.filled().len() as u32;
                    if let Ok(tx_buf) = server.tx_pool().from_rx(rx_buf) {
                        let frozen = tx_buf.freeze();
                        let seg = unsafe { Segment::new_unchecked(frozen, 0, len) };
                        transmits.push(Transmit::new(ScatterGather::single(seg), m.src));
                    }
                }
                server.send(&mut transmits).ok();
                server.drain_completions();
                break;
            }
            assert!(Instant::now() < deadline, "server recv timeout");
            std::thread::sleep(Duration::from_millis(1));
        }

        let deadline = Instant::now() + Duration::from_secs(2);
        let (src, data) = recv_until(&mut client, payload, deadline).unwrap();
        assert_eq!(data, payload);
        assert_eq!(src.ip(), server_addr.ip());
        let _ = client_addr;
    }

    #[test]
    fn ipv4_socket_pool_reports_ipv4_max_payload() {
        let s = IoUringSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), 0, IoUringConfig::default()).unwrap();
        assert_eq!(s.rx_pool().max_payload_size(), IPV4_MAX_UDP_PAYLOAD);
    }

    #[test]
    fn ipv6_socket_pool_reports_ipv6_max_payload() {
        let s = match IoUringSocket::bind(SocketAddr::from((Ipv6Addr::LOCALHOST, 0)), 0, IoUringConfig::default()) {
            Ok(s) => s,
            Err(_) => return, // skip if IPv6 unavailable
        };
        assert_eq!(s.rx_pool().max_payload_size(), IPV6_MAX_UDP_PAYLOAD);
    }

    // ── Helpers for new tests ─────────────────────────────────────────────────

    fn send_segments(sock: &mut IoUringSocket, dest: SocketAddr, segs: &[&[u8]]) -> bool {
        let mut sg = ScatterGather::new();
        for s in segs {
            let buf = IoTxBuf::from_slice(s);
            sg.push(unsafe { Segment::new_unchecked(buf, 0, s.len() as u32) });
        }
        let mut transmits = vec![Transmit::new(sg, dest)];
        sock.send(&mut transmits).unwrap_or(0) >= 1
    }

    // Known TOCTOU: the port is free at the point we read it but another
    // process could grab it before the test binds. Acceptable in test-only
    // code; the short sleep reduces (but doesn't eliminate) the window.
    fn reserve_loopback_udp_port() -> u16 {
        let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = s.local_addr().unwrap().port();
        drop(s);
        std::thread::sleep(Duration::from_millis(20));
        port
    }

    // ── Group 1: core trait contract ──────────────────────────────────────────

    #[test]
    fn recv_idle_socket_returns_zero() {
        let mut sock = IoUringSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), 0, IoUringConfig::default()).unwrap();
        let mut meta = vec![RecvMeta::default(); 8];
        let mut bufs = alloc_recv_bufs(&sock);
        let n = sock.recv(&mut meta[..], &mut bufs[..]).expect("recv idle");
        assert_eq!(n, 0, "idle socket must return Ok(0), not an error");
    }

    #[test]
    fn recv_empty_slices_returns_zero() {
        let mut sock = IoUringSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), 0, IoUringConfig::default()).unwrap();
        let n = sock.recv(&mut [], &mut []).expect("recv empty");
        assert_eq!(n, 0);
    }

    #[test]
    fn send_empty_vec_returns_zero() {
        let mut sock = IoUringSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), 0, IoUringConfig::default()).unwrap();
        let mut empty: Vec<Transmit<ScatterGather<IoTxBuf>>> = Vec::new();
        let n = sock.send(&mut empty).expect("send empty");
        assert_eq!(n, 0);
        assert!(empty.is_empty());
    }

    #[test]
    fn recv_buffer_reuse_does_not_truncate() {
        // Allocate bufs ONCE, reuse across rounds.  Each round delivers a
        // payload of a distinct length and byte value; after each recv the
        // buffer must contain exactly the new payload -- no stale bytes from
        // the previous round.
        let mut server = IoUringSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), 0, IoUringConfig::default()).unwrap();
        let mut client = IoUringSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), 0, IoUringConfig::default()).unwrap();
        let server_addr = server.local_addr().unwrap();

        let mut bufs: Vec<IoRxBufMut> = Vec::with_capacity(8);
        server.rx_pool().alloc(1452, 8, &mut bufs);
        let mut meta = vec![RecvMeta::default(); 8];

        // Round sizes: 150 bytes, 50 bytes, 100 bytes -- deliberately shrinking
        // in round 2 so stale bytes from round 1 would be visible if not cleared.
        let sizes = [150usize, 50, 100];
        for (round, &size) in sizes.iter().enumerate() {
            let payload = vec![round as u8; size];
            assert!(send_one(&mut client, server_addr, &payload));

            let deadline = Instant::now() + Duration::from_secs(2);
            let mut got = 0;
            while got == 0 && Instant::now() < deadline {
                match server.recv(&mut meta[..], &mut bufs[..]) {
                    Ok(0) => std::thread::sleep(Duration::from_millis(1)),
                    Ok(n) => got = n,
                    Err(e) => panic!("recv error: {e}"),
                }
            }
            assert!(got >= 1, "round {round}: no packet delivered");
            assert_eq!(
                bufs[0].filled(),
                &payload[..],
                "round {round}: recv returned stale or truncated bytes"
            );
        }
    }

    // ── Group 2: scatter-gather send path ─────────────────────────────────────

    #[test]
    fn send_recv_two_segment_scatter_gather() {
        let mut server = IoUringSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), 0, IoUringConfig::default()).unwrap();
        let mut client = IoUringSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), 0, IoUringConfig::default()).unwrap();
        let server_addr = server.local_addr().unwrap();

        assert!(send_segments(&mut client, server_addr, &[b"AB", b"CD"]));

        let deadline = Instant::now() + Duration::from_secs(2);
        let (_, data) = recv_until(&mut server, b"ABCD", deadline).unwrap();
        assert_eq!(data, b"ABCD");
    }

    #[test]
    fn send_recv_five_segment_scatter_gather() {
        // 5 segments: one past the SmallVec inline cap of 4 → spills to heap.
        let mut server = IoUringSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), 0, IoUringConfig::default()).unwrap();
        let mut client = IoUringSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), 0, IoUringConfig::default()).unwrap();
        let server_addr = server.local_addr().unwrap();

        let segs: &[&[u8]] = &[b"S1-", b"S2-", b"S3-", b"S4-", b"END"];
        assert!(send_segments(&mut client, server_addr, segs));

        let want = b"S1-S2-S3-S4-END";
        let deadline = Instant::now() + Duration::from_secs(2);
        let (_, data) = recv_until(&mut server, want, deadline).unwrap();
        assert_eq!(data, want);
    }

    #[test]
    fn send_batch_then_recv_all() {
        // Send 4 transmits in one send() call; verify the return count and that
        // all 4 datagrams arrive at the receiver.
        let mut server = IoUringSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), 0, IoUringConfig::default()).unwrap();
        let mut client = IoUringSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), 0, IoUringConfig::default()).unwrap();
        let server_addr = server.local_addr().unwrap();

        let payloads: &[&[u8]] = &[b"AAA", b"BBBB", b"CCC", b"DDDDD"];
        let mut transmits: Vec<Transmit<ScatterGather<IoTxBuf>>> = payloads
            .iter()
            .map(|p| {
                let buf = IoTxBuf::from_slice(p);
                let len = p.len() as u32;
                let seg = unsafe { Segment::new_unchecked(buf, 0, len) };
                Transmit::new(ScatterGather::single(seg), server_addr)
            })
            .collect();

        let n = client.send(&mut transmits).expect("send batch");
        assert_eq!(n, payloads.len(), "all 4 transmits must be accepted");
        transmits.drain(..n); // caller is responsible for discarding accepted entries
        assert!(transmits.is_empty(), "no transmits should remain after full acceptance");

        let deadline = Instant::now() + Duration::from_secs(2);
        let mut received: Vec<Vec<u8>> = Vec::new();
        while received.len() < payloads.len() && Instant::now() < deadline {
            for (_, data) in recv_batch(&mut server).expect("recv batch") {
                received.push(data);
            }
            if received.len() < payloads.len() {
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        received.sort();
        let mut expected: Vec<Vec<u8>> = payloads.iter().map(|p| p.to_vec()).collect();
        expected.sort();
        assert_eq!(received, expected);
    }

    // ── Group 3: IPv6 and socket clone ────────────────────────────────────────

    #[test]
    fn send_recv_ipv6_loopback() {
        let mut server = match IoUringSocket::bind(SocketAddr::from((Ipv6Addr::LOCALHOST, 0)), 0, IoUringConfig::default()) {
            Ok(s) => s,
            Err(_) => return, // skip if IPv6 unavailable
        };
        let mut client = match IoUringSocket::bind(SocketAddr::from((Ipv6Addr::LOCALHOST, 0)), 0, IoUringConfig::default()) {
            Ok(s) => s,
            Err(_) => return,
        };
        let server_addr = server.local_addr().unwrap();
        let client_addr = client.local_addr().unwrap();
        assert!(matches!(server_addr, SocketAddr::V6(_)));

        let payload = b"hello-v6-iouring";
        assert!(send_one(&mut client, server_addr, payload));

        let deadline = Instant::now() + Duration::from_secs(2);
        let (src, data) = recv_until(&mut server, payload, deadline).unwrap();
        assert_eq!(data, payload);
        assert!(
            matches!(src, SocketAddr::V6(_)),
            "src must be SocketAddr::V6"
        );
        assert_eq!(src.port(), client_addr.port());
    }

    // ── Group 4: boundary inputs / constructors ───────────────────────────────

    #[test]
    fn recv_with_smaller_bufs_than_meta() {
        let mut server = IoUringSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), 0, IoUringConfig::default()).unwrap();
        let mut client = IoUringSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), 0, IoUringConfig::default()).unwrap();
        let server_addr = server.local_addr().unwrap();

        for i in 0u8..4 {
            assert!(send_one(&mut client, server_addr, &[i; 8]));
        }

        // bufs.len() = 2, meta.len() = 8 → recv must cap at 2.
        let mut meta = vec![RecvMeta::default(); 8];
        let mut bufs: Vec<IoRxBufMut> = Vec::with_capacity(2);
        server.rx_pool().alloc(1452, 2, &mut bufs);

        let mut got = 0;
        let deadline = Instant::now() + Duration::from_secs(2);
        while got == 0 && Instant::now() < deadline {
            got = server.recv(&mut meta[..], &mut bufs[..]).expect("recv");
            if got == 0 {
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        assert!(got >= 1, "at least one packet should be available");
        assert!(
            got <= 2,
            "recv must honor min(meta.len, bufs.len)=2; got {got}"
        );
    }

    #[test]
    fn reuseport_two_sockets_share_port() {
        let port = reserve_loopback_udp_port();
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));

        let mut first = IoUringSocket::bind(addr, 0, IoUringConfig::builder().reuseport(true).build()).unwrap();
        let mut second = IoUringSocket::bind(addr, 0, IoUringConfig::builder().reuseport(true).build()).unwrap();
        assert_eq!(first.local_addr().unwrap().port(), port);
        assert_eq!(second.local_addr().unwrap().port(), port);

        let mut sender = IoUringSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), 0, IoUringConfig::default()).unwrap();
        const COUNT: usize = 48;
        for i in 0..COUNT {
            assert!(send_one(&mut sender, addr, &[i as u8]));
        }

        let deadline = Instant::now() + Duration::from_secs(5);
        let mut got = 0;
        while got < COUNT && Instant::now() < deadline {
            for (_, data) in recv_batch(&mut first).expect("recv first") {
                assert_eq!(data.len(), 1);
                got += 1;
            }
            for (_, data) in recv_batch(&mut second).expect("recv second") {
                assert_eq!(data.len(), 1);
                got += 1;
            }
            if got < COUNT {
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        assert_eq!(
            got, COUNT,
            "kernel must deliver all {COUNT} datagrams across both reuseport sockets"
        );
    }

    #[test]
    fn drop_with_pending_recvs_does_not_crash() {
        // Verify that dropping a socket with CQEs staged in pending_recvs
        // (but not yet consumed via recv()) does not crash or UAF.
        let mut receiver = IoUringSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), 0, IoUringConfig::default()).unwrap();
        let mut sender = IoUringSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), 0, IoUringConfig::default()).unwrap();
        let recv_addr = receiver.local_addr().unwrap();

        assert!(send_one(&mut sender, recv_addr, b"staged-drop"));

        // Give the packet time to arrive, then drain CQEs so the packet is
        // staged in pending_recvs -- then drop without calling recv().
        std::thread::sleep(Duration::from_millis(20));
        receiver.drain_completions();

        drop(receiver);
        // Reaching here without crash or ASAN report is the assertion.
    }

    // ── Group 5: io_uring-specific ────────────────────────────────────────────

    #[test]
    fn send_back_pressure_leaves_remainder_in_vec() {
        // Exhaust all SEND_POOL (128) send slots in a single send() call, then
        // verify that one additional send returns Ok(0) and leaves the transmit
        // in the vec rather than panicking or silently dropping it.
        let mut sender = IoUringSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), 0, IoUringConfig::default()).unwrap();
        let sink = IoUringSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), 0, IoUringConfig::default()).unwrap();
        let dest = sink.local_addr().unwrap();

        const SEND_POOL: usize = 128; // matches SEND_POOL in parent module

        let mut full_batch: Vec<Transmit<ScatterGather<IoTxBuf>>> = (0u8..SEND_POOL as u8)
            .map(|i| {
                let buf = IoTxBuf::from_slice(&[i]);
                let seg = unsafe { Segment::new_unchecked(buf, 0, 1) };
                Transmit::new(ScatterGather::single(seg), dest)
            })
            .collect();

        let accepted = sender.send(&mut full_batch).expect("send full batch");
        assert_eq!(
            accepted, SEND_POOL,
            "all {SEND_POOL} slots must be accepted"
        );
        full_batch.drain(..accepted); // caller discards accepted entries
        assert!(full_batch.is_empty(), "no transmits should remain after full acceptance");

        // Without draining completions, send_free_top == 0.
        let buf = IoTxBuf::from_slice(b"overflow");
        let seg = unsafe { Segment::new_unchecked(buf, 0, 8) };
        let mut extra = vec![Transmit::new(ScatterGather::single(seg), dest)];
        let n = sender.send(&mut extra).expect("send when slots full");
        assert_eq!(n, 0, "must be back-pressured when all send slots are taken");
        assert_eq!(extra.len(), 1, "rejected transmit untouched in slice when n=0");
    }

    #[test]
    fn rx_fd_returns_some() {
        let s = IoUringSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), 0, IoUringConfig::default()).unwrap();
        let fd_opt = s.rx_fd();
        assert!(
            fd_opt.is_some(),
            "rx_fd must return Some for an io_uring socket"
        );
        assert!(
            fd_opt.unwrap().as_raw_fd() >= 0,
            "the returned fd must be non-negative"
        );
    }

    // ── Bug-fix regression tests ──────────────────────────────────────────────

    // Bug: re-arm SQE not submitted after multishot disarm.
    // When the kernel disarms the multishot recv SQE (ring buffer exhaustion),
    // submit_recv_multishot() was called inside drain_cqes but the SQE was not
    // flushed until the next recv()/drain_completions() call. Fix: submit()
    // immediately after submit_recv_multishot() inside drain_cqes.
    #[test]
    fn recv_survives_ring_buffer_exhaustion() {
        // Fill all 256 ring slots (BUF_RING_COUNT) with packets to force the
        // kernel to disarm the multishot SQE. After draining the staged packets
        // via recv() the socket must still receive new packets, proving the
        // re-arm SQE was submitted correctly.
        const RING_CAPACITY: usize = 256; // matches BUF_RING_COUNT

        let mut server = IoUringSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), 0, IoUringConfig::default()).unwrap();
        let server_addr = server.local_addr().unwrap();

        // Use a plain UdpSocket as the sender so io_uring send-slot management
        // doesn't interfere with the recv-side ring exhaustion mechanics.
        let client = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();

        // Phase 1: flood the ring -- all 256 slots filled.
        for i in 0..RING_CAPACITY {
            client.send_to(&[i as u8], server_addr).unwrap();
        }
        // Allow all packets to arrive on loopback.
        std::thread::sleep(Duration::from_millis(100));

        // Stage all CQEs into pending_recvs without replenishing. With all 256
        // slots consumed the kernel disarms the multishot; the fix causes
        // submit_recv_multishot + submit() to run immediately inside drain_cqes.
        // Loop to catch any CQEs that arrive after the first sweep.
        for _ in 0..4 {
            server.drain_completions();
        }

        // Phase 2: consume all staged packets via recv(). Each call replenishes
        // the ring slots it processes. recv() also calls drain_cqes internally,
        // so any CQEs not yet staged are picked up here too.
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut drained = 0;
        while drained < RING_CAPACITY && Instant::now() < deadline {
            let mut meta = vec![RecvMeta::default(); BATCH];
            let mut bufs = alloc_recv_bufs(&server);
            match server.recv(&mut meta, &mut bufs) {
                Ok(n) => drained += n,
                Err(e) => panic!("recv error: {e}"),
            }
            if drained < RING_CAPACITY {
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        assert_eq!(
            drained, RING_CAPACITY,
            "all {RING_CAPACITY} packets must arrive"
        );

        // Phase 3: verify the multishot was re-armed -- new packets must arrive.
        let payload = b"post-exhaustion";
        client.send_to(payload, server_addr).unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        let (_, data) = recv_until(&mut server, payload, deadline).unwrap();
        assert_eq!(data, payload);
    }

    // Bug: silent segment truncation when a transmit has more than MAX_SEND_SGS
    // (8) scatter-gather segments. The excess segments were silently dropped and
    // the send appeared to succeed. Fix: debug_assert fires immediately.
    #[test]
    #[should_panic(expected = "transmits[0] has")]
    fn send_with_too_many_segments_panics() {
        let mut sock = IoUringSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), 0, IoUringConfig::default()).unwrap();
        let dest = sock.local_addr().unwrap();

        // 9 segments -- one past MAX_SEND_SGS = 8.
        let mut sg: ScatterGather<IoTxBuf> = ScatterGather::new();
        for i in 0..9u8 {
            let buf = IoTxBuf::from_slice(&[i]);
            sg.push(unsafe { Segment::new_unchecked(buf, 0, 1) });
        }
        let mut transmits = vec![Transmit::new(sg, dest)];
        let _ = sock.send(&mut transmits);
    }

    #[test]
    #[should_panic(expected = "segment_size=1 but IoUringSocket::MAX_GSO is 1")]
    fn send_with_gso_segment_size_panics() {
        let mut sock = IoUringSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), 0, IoUringConfig::default()).unwrap();
        let dest = sock.local_addr().unwrap();
        let buf = IoTxBuf::from_slice(b"hello");
        let seg = unsafe { Segment::new_unchecked(buf, 0, 5) };
        let mut t = Transmit::new(ScatterGather::single(seg), dest);
        t.segment_size = 1; // non-zero segment_size with MAX_GSO == 1 → panic
        let mut transmits = vec![t];
        let _ = sock.send(&mut transmits);
    }

    // Bug: MAX_DATAGRAM was 65535; internal ring buffers wasted ~16 MB.
    // Fix: ring slots are MAX_BUF_SIZE = 2048 bytes (the physical payload area,
    // sized for page alignment and metadata headroom). The usable UDP payload
    // is bounded by the MTU-derived `max_payload_size` (1472 v4 / 1452 v6);
    // IP_PMTUDISC_DO / IPV6_PMTUDISC_DO are set so the kernel rejects any
    // outbound datagram exceeding the MTU, and `drain_cqes_into` drops any
    // received packet whose payload exceeds `max_payload_size`.

    #[test]
    fn ipv4_socket_sets_ip_pmtudisc_do() {
        let s = IoUringSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), 0, IoUringConfig::default()).unwrap();
        let fd = s.rx_fd().unwrap().as_raw_fd();
        let mut val: libc::c_int = 0;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        let ret = unsafe {
            libc::getsockopt(
                fd,
                libc::IPPROTO_IP,
                libc::IP_MTU_DISCOVER,
                &mut val as *mut _ as *mut libc::c_void,
                &mut len,
            )
        };
        assert_eq!(ret, 0, "getsockopt(IP_MTU_DISCOVER) failed");
        assert_eq!(
            val,
            libc::IP_PMTUDISC_DO,
            "IPv4 socket must have IP_PMTUDISC_DO set"
        );
    }

    #[test]
    fn ipv6_socket_sets_ipv6_pmtudisc_do() {
        let s = match IoUringSocket::bind(SocketAddr::from((Ipv6Addr::LOCALHOST, 0)), 0, IoUringConfig::default()) {
            Ok(s) => s,
            Err(_) => return, // skip if IPv6 unavailable
        };
        let fd = s.rx_fd().unwrap().as_raw_fd();
        let mut val: libc::c_int = 0;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        let ret = unsafe {
            libc::getsockopt(
                fd,
                libc::IPPROTO_IPV6,
                libc::IPV6_MTU_DISCOVER,
                &mut val as *mut _ as *mut libc::c_void,
                &mut len,
            )
        };
        assert_eq!(ret, 0, "getsockopt(IPV6_MTU_DISCOVER) failed");
        assert_eq!(
            val,
            libc::IPV6_PMTUDISC_DO,
            "IPv6 socket must have IPV6_PMTUDISC_DO set"
        );
    }

    #[test]
    fn recv_drops_packet_exceeding_mtu_via_msg_trunc() {
        // A datagram much larger than the MTU is truncated by the kernel to fit
        // the ring slot; the resulting MSG_TRUNC flag causes drain_cqes to drop
        // the packet without staging it. A normal-sized packet sent afterwards
        // must still be received.
        let mut server = IoUringSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), 0, IoUringConfig::default()).unwrap();
        let mut client = IoUringSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), 0, IoUringConfig::default()).unwrap();
        let server_addr = server.local_addr().unwrap();

        // 3000 bytes is well above the 1500-byte MTU and the ring slot capacity.
        let oversized = vec![0xABu8; 3000];
        assert!(send_one(&mut client, server_addr, &oversized));
        std::thread::sleep(Duration::from_millis(20));

        let mut meta = vec![RecvMeta::default(); 4];
        let mut bufs = alloc_recv_bufs(&server);
        let n = server.recv(&mut meta, &mut bufs).expect("recv");
        assert_eq!(n, 0, "3000-byte packet must be dropped (MSG_TRUNC)");

        // Verify normal traffic still flows after the drop.
        let normal = b"normal-after-oversize";
        send_one(&mut client, server_addr, normal);
        let deadline = Instant::now() + Duration::from_secs(2);
        let (_, data) = recv_until(&mut server, normal, deadline).unwrap();
        assert_eq!(data, normal);
    }

    #[test]
    fn recv_drops_packet_exceeding_max_payload() {
        // The ring slot has physical room for ~2 KiB but only `max_payload`
        // bytes are usable: any UDP datagram larger than the MTU-derived limit
        // is dropped on receive even when it fits in the slot. This guards
        // against link types that disagree on MTU and prevents the recv path
        // from delivering packets that could never be re-transmitted by a
        // PMTUDISC_DO socket.
        let mut server = IoUringSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), 0, IoUringConfig::default()).unwrap();
        let mut client = IoUringSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), 0, IoUringConfig::default()).unwrap();
        let server_addr = server.local_addr().unwrap();

        let max_payload = server.rx_pool().max_payload_size();
        // Just above max_payload; loopback MTU is 65535 so the kernel will not
        // fragment and the datagram will arrive intact in the ring slot.
        let payload_size = max_payload + 1;
        let oversized = vec![0xCDu8; payload_size];
        assert!(send_one(&mut client, server_addr, &oversized));
        std::thread::sleep(Duration::from_millis(20));

        let mut meta = vec![RecvMeta::default(); 4];
        let mut bufs = alloc_recv_bufs(&server);
        let n = server.recv(&mut meta, &mut bufs).expect("recv");
        assert_eq!(
            n, 0,
            "packet of {payload_size} bytes (> max_payload={max_payload}) must be dropped"
        );

        // Normal traffic still flows after the drop.
        let normal = b"normal-after-mtu-drop";
        send_one(&mut client, server_addr, normal);
        let deadline = Instant::now() + Duration::from_secs(2);
        let (_, data) = recv_until(&mut server, normal, deadline).unwrap();
        assert_eq!(data, normal);
    }

    #[test]
    fn recv_delivers_packet_at_max_payload_boundary() {
        // A datagram exactly at `max_payload_size` is the largest legitimate
        // input and must be delivered intact.
        let mut server = IoUringSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), 0, IoUringConfig::default()).unwrap();
        let mut client = IoUringSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), 0, IoUringConfig::default()).unwrap();
        let server_addr = server.local_addr().unwrap();

        let max_payload = server.rx_pool().max_payload_size();
        let payload = vec![0x42u8; max_payload];
        assert!(send_one(&mut client, server_addr, &payload));

        let deadline = Instant::now() + Duration::from_secs(2);
        let (_, data) = recv_until(&mut server, &payload, deadline).unwrap();
        assert_eq!(data.len(), max_payload);
        assert_eq!(data, payload);
    }

    // ── CMSG field tests (ECN + dst_ip) ──────────────────────────────────────

    fn recv_one_meta(
        server: &mut IoUringSocket,
        client: &mut IoUringSocket,
        payload: &[u8],
    ) -> RecvMeta {
        let server_addr = server.local_addr().unwrap();
        assert!(send_one(client, server_addr, payload));
        let mut meta = vec![RecvMeta::default(); BATCH];
        let mut bufs = alloc_recv_bufs(server);
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let n = server.recv(&mut meta, &mut bufs).unwrap();
            if n >= 1 {
                return meta[0];
            }
            assert!(Instant::now() < deadline, "recv timed out");
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    fn recv_one_meta_raw(server: &mut IoUringSocket) -> RecvMeta {
        let mut meta = vec![RecvMeta::default(); BATCH];
        let mut bufs = alloc_recv_bufs(server);
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let n = server.recv(&mut meta, &mut bufs).unwrap();
            if n >= 1 {
                return meta[0];
            }
            assert!(Instant::now() < deadline, "recv timed out");
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    fn send_with_ecn(
        sock: &mut IoUringSocket,
        dest: SocketAddr,
        payload: &[u8],
        ecn: quac_socket::EcnCodepoint,
    ) -> bool {
        let buf = IoTxBuf::from_slice(payload);
        let seg = unsafe { Segment::new_unchecked(buf, 0, payload.len() as u32) };
        let mut t = Transmit::new(ScatterGather::single(seg), dest);
        t.ecn = Some(ecn);
        let mut transmits = vec![t];
        sock.send(&mut transmits).unwrap_or(0) >= 1
    }

    #[test]
    fn recv_meta_dst_ip_is_populated() {
        let mut server =
            IoUringSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), 0, IoUringConfig::default()).unwrap();
        let mut client =
            IoUringSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), 0, IoUringConfig::default()).unwrap();
        let m = recv_one_meta(&mut server, &mut client, b"dst-ip-test");
        assert_eq!(
            m.dst_ip,
            Some(std::net::IpAddr::V4(Ipv4Addr::LOCALHOST)),
            "dst_ip must be the loopback address the packet was sent to"
        );
    }

    #[test]
    fn recv_meta_ecn_on_loopback_is_none() {
        // Loopback packets carry ECN bits 0b00 (non-ECT) by default, so
        // EcnCodepoint::from_bits(0) == None. Verifies CMSG parsing runs
        // without error even when no ECN codepoint is set.
        let mut server =
            IoUringSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), 0, IoUringConfig::default()).unwrap();
        let mut client =
            IoUringSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), 0, IoUringConfig::default()).unwrap();
        let m = recv_one_meta(&mut server, &mut client, b"ecn-loopback-test");
        assert!(m.ecn.is_none(), "loopback ECN must be None (non-ECT = 0b00)");
    }

    #[test]
    fn send_ecn_ect0_is_received_correctly() {
        let mut server =
            IoUringSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), 0, IoUringConfig::default()).unwrap();
        let mut client =
            IoUringSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), 0, IoUringConfig::default()).unwrap();
        let server_addr = server.local_addr().unwrap();

        assert!(send_with_ecn(
            &mut client,
            server_addr,
            b"ecn-ect0",
            quac_socket::EcnCodepoint::Ect0
        ));
        let m = recv_one_meta_raw(&mut server);
        assert_eq!(
            m.ecn,
            Some(quac_socket::EcnCodepoint::Ect0),
            "ECN codepoint ECT0 must be visible in RecvMeta"
        );
    }

    #[test]
    fn send_ecn_ce_is_received_correctly() {
        let mut server =
            IoUringSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), 0, IoUringConfig::default()).unwrap();
        let mut client =
            IoUringSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), 0, IoUringConfig::default()).unwrap();
        let server_addr = server.local_addr().unwrap();

        assert!(send_with_ecn(
            &mut client,
            server_addr,
            b"ecn-ce",
            quac_socket::EcnCodepoint::Ce
        ));
        let m = recv_one_meta_raw(&mut server);
        assert_eq!(
            m.ecn,
            Some(quac_socket::EcnCodepoint::Ce),
            "ECN codepoint CE must be visible in RecvMeta"
        );
    }

    #[test]
    fn send_with_src_ip_packet_arrives() {
        let mut server =
            IoUringSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), 0, IoUringConfig::default()).unwrap();
        let mut client =
            IoUringSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), 0, IoUringConfig::default()).unwrap();
        let server_addr = server.local_addr().unwrap();

        let payload = b"src-ip-test";
        let buf = IoTxBuf::from_slice(payload);
        let seg = unsafe { Segment::new_unchecked(buf, 0, payload.len() as u32) };
        let mut t = Transmit::new(ScatterGather::single(seg), server_addr);
        t.src_ip = Some(std::net::IpAddr::V4(Ipv4Addr::LOCALHOST));
        let n = client.send(&mut vec![t]).expect("send with src_ip");
        assert_eq!(n, 1);

        let deadline = Instant::now() + Duration::from_secs(2);
        let (src, data) = recv_until(&mut server, payload, deadline).unwrap();
        assert_eq!(data, payload);
        assert_eq!(
            src.ip(),
            std::net::IpAddr::V4(Ipv4Addr::LOCALHOST),
            "source IP must match the src_ip hint"
        );
    }

    // ── IPv6 CMSG tests ───────────────────────────────────────────────────────

    #[test]
    fn recv_meta_dst_ip_is_populated_ipv6() {
        let mut server = match IoUringSocket::bind(SocketAddr::from((Ipv6Addr::LOCALHOST, 0)), 0, IoUringConfig::default()) {
            Ok(s) => s,
            Err(_) => return,
        };
        let mut client = match IoUringSocket::bind(SocketAddr::from((Ipv6Addr::LOCALHOST, 0)), 0, IoUringConfig::default()) {
            Ok(s) => s,
            Err(_) => return,
        };
        let m = recv_one_meta(&mut server, &mut client, b"dst-ip-test-v6");
        assert_eq!(
            m.dst_ip,
            Some(std::net::IpAddr::V6(Ipv6Addr::LOCALHOST)),
            "dst_ip must be the IPv6 loopback address the packet was sent to"
        );
    }

    #[test]
    fn recv_meta_ecn_on_loopback_is_none_ipv6() {
        let mut server = match IoUringSocket::bind(SocketAddr::from((Ipv6Addr::LOCALHOST, 0)), 0, IoUringConfig::default()) {
            Ok(s) => s,
            Err(_) => return,
        };
        let mut client = match IoUringSocket::bind(SocketAddr::from((Ipv6Addr::LOCALHOST, 0)), 0, IoUringConfig::default()) {
            Ok(s) => s,
            Err(_) => return,
        };
        let m = recv_one_meta(&mut server, &mut client, b"ecn-loopback-test-v6");
        assert!(m.ecn.is_none(), "IPv6 loopback ECN must be None (non-ECT = 0b00)");
    }

    #[test]
    fn send_ecn_ect0_is_received_correctly_ipv6() {
        let mut server = match IoUringSocket::bind(SocketAddr::from((Ipv6Addr::LOCALHOST, 0)), 0, IoUringConfig::default()) {
            Ok(s) => s,
            Err(_) => return,
        };
        let mut client = match IoUringSocket::bind(SocketAddr::from((Ipv6Addr::LOCALHOST, 0)), 0, IoUringConfig::default()) {
            Ok(s) => s,
            Err(_) => return,
        };
        let server_addr = server.local_addr().unwrap();
        assert!(send_with_ecn(
            &mut client,
            server_addr,
            b"ecn-ect0-v6",
            quac_socket::EcnCodepoint::Ect0
        ));
        let m = recv_one_meta_raw(&mut server);
        assert_eq!(
            m.ecn,
            Some(quac_socket::EcnCodepoint::Ect0),
            "IPv6 ECN codepoint ECT0 must be visible in RecvMeta"
        );
    }

    #[test]
    fn send_ecn_ce_is_received_correctly_ipv6() {
        let mut server = match IoUringSocket::bind(SocketAddr::from((Ipv6Addr::LOCALHOST, 0)), 0, IoUringConfig::default()) {
            Ok(s) => s,
            Err(_) => return,
        };
        let mut client = match IoUringSocket::bind(SocketAddr::from((Ipv6Addr::LOCALHOST, 0)), 0, IoUringConfig::default()) {
            Ok(s) => s,
            Err(_) => return,
        };
        let server_addr = server.local_addr().unwrap();
        assert!(send_with_ecn(
            &mut client,
            server_addr,
            b"ecn-ce-v6",
            quac_socket::EcnCodepoint::Ce
        ));
        let m = recv_one_meta_raw(&mut server);
        assert_eq!(
            m.ecn,
            Some(quac_socket::EcnCodepoint::Ce),
            "IPv6 ECN codepoint CE must be visible in RecvMeta"
        );
    }

    #[test]
    fn send_with_src_ip_packet_arrives_ipv6() {
        let mut server = match IoUringSocket::bind(SocketAddr::from((Ipv6Addr::LOCALHOST, 0)), 0, IoUringConfig::default()) {
            Ok(s) => s,
            Err(_) => return,
        };
        let mut client = match IoUringSocket::bind(SocketAddr::from((Ipv6Addr::LOCALHOST, 0)), 0, IoUringConfig::default()) {
            Ok(s) => s,
            Err(_) => return,
        };
        let server_addr = server.local_addr().unwrap();

        let payload = b"src-ip-test-v6";
        let buf = IoTxBuf::from_slice(payload);
        let seg = unsafe { Segment::new_unchecked(buf, 0, payload.len() as u32) };
        let mut t = Transmit::new(ScatterGather::single(seg), server_addr);
        t.src_ip = Some(std::net::IpAddr::V6(Ipv6Addr::LOCALHOST));
        let n = client.send(&mut vec![t]).expect("send with src_ip v6");
        assert_eq!(n, 1);

        let deadline = Instant::now() + Duration::from_secs(2);
        let (src, data) = recv_until(&mut server, payload, deadline).unwrap();
        assert_eq!(data, payload);
        assert_eq!(
            src.ip(),
            std::net::IpAddr::V6(Ipv6Addr::LOCALHOST),
            "source IP must match the IPv6 src_ip hint"
        );
    }

    // ── Drop with in-flight sends ─────────────────────────────────────────────

    #[test]
    fn drop_with_in_flight_sends_does_not_crash() {
        // Fill the send pool and drop the socket without calling drain_completions.
        // Verifies that the Drop impl correctly cancels in-flight SQEs and frees
        // send slot memory without use-after-free or double-free.
        let mut sender = IoUringSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), 0, IoUringConfig::default()).unwrap();
        let sink = IoUringSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), 0, IoUringConfig::default()).unwrap();
        let dest = sink.local_addr().unwrap();

        const SEND_POOL: usize = 128;
        let mut transmits: Vec<Transmit<ScatterGather<IoTxBuf>>> = (0u8..SEND_POOL as u8)
            .map(|i| {
                let buf = IoTxBuf::from_slice(&[i]);
                let seg = unsafe { Segment::new_unchecked(buf, 0, 1) };
                Transmit::new(ScatterGather::single(seg), dest)
            })
            .collect();

        let n = sender.send(&mut transmits).expect("fill send pool");
        assert_eq!(n, SEND_POOL, "all send slots must be accepted");

        // Drop with SQEs submitted but CQEs not drained.
        drop(sender);
        // Reaching here without crash or ASAN report is the assertion.
    }
}
