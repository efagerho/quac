use std::alloc::{alloc_zeroed, Layout};
use std::collections::VecDeque;
use std::io;
use std::mem::{self, size_of, MaybeUninit};
use std::net::{SocketAddr, UdpSocket};
use std::os::fd::{AsRawFd, BorrowedFd, RawFd};
use std::ptr;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;

use io_uring::{cqueue, opcode, squeue, types, IoUring};
use socket2::{Domain, Protocol, Socket, Type};

use quac_socket::{PacketBufMut, PacketSocket, RecvMeta, ScatterGather, Transmit};

use crate::{IoBuf, IoBufMut, IoPool, IPV4_MAX_UDP_PAYLOAD, IPV6_MAX_UDP_PAYLOAD};

// ── Ring / pool constants ─────────────────────────────────────────────────────

// Max payload kept in each ring buffer slot. With IP_PMTUDISC_DO and MTU 1500
// the largest UDP payload is 1472 (IPv4) or 1452 (IPv6); 2 KiB gives headroom
// while preventing memory inflation from IP-reassembled fragments. Analogous
// to MAX_BUF_SIZE in quac-socket-os.
const RECV_PAYLOAD_MAX: usize = 2048;
// High bit set → send CQE; clear → recv CQE.
const SEND_TAG: u64 = 1 << 63;
// 1024 gives a CQ ring of 2048 entries (2 × SQ). Larger batches reduce the
// per-CQE overhead of llist_reverse_order (the kernel's task-work list
// reversal that runs on every io_uring_enter return path).
const RING_ENTRIES: u32 = 1024;
const SEND_POOL: usize = 128;
const MAX_SEND_SGS: usize = 8;
// Snapshot size for one CQE drain. Must comfortably exceed the realistic
// peak per call: BUF_RING_COUNT (256) recv CQEs + SEND_POOL (128) send CQEs
// = 384. 512 leaves headroom; the iterator uses .take(MAX_CQES) so any extra
// CQEs stay in the CQ ring and get drained on the next call. The CQ ring
// itself still holds 2 × RING_ENTRIES = 2048 entries, so kernel-side
// overflow is impossible at this size.
const MAX_CQES: usize = 512;

// ── Provided buffer ring constants ────────────────────────────────────────────

const BUF_GROUP: u16 = 0;
// Must be a power of 2 and ≤ 32768.
const BUF_RING_COUNT: usize = 256;
// sizeof(io_uring_recvmsg_out): {namelen, controllen, payloadlen, flags} each u32.
const RECV_OUT_SIZE: usize = 16;
// Max source address size (sizeof(sockaddr_storage)).  This is also the value
// the template msghdr passes as msg_namelen, so the kernel always places the
// payload at RECV_OUT_SIZE + RECV_NAME_MAX regardless of the actual addr length.
const RECV_NAME_MAX: usize = size_of::<libc::sockaddr_storage>(); // 128
                                                                  // Fixed offset at which the kernel writes the payload (= header + template namelen).
const RECV_PAYLOAD_OFF: usize = RECV_OUT_SIZE + RECV_NAME_MAX; // 144
                                                               // Each provided buffer: header + name space + payload.
const RECV_BUF_SIZE: usize = RECV_PAYLOAD_OFF + RECV_PAYLOAD_MAX;

// user_data for the one multishot recv SQE (must not overlap with SEND_TAG).
const RECV_MULTISHOT_UD: u64 = 0;

// io_uring_sqe byte offsets (stable kernel ABI).
const SQE_FLAGS_OFF: usize = 1; // u8
const SQE_IOPRIO_OFF: usize = 2; // u16
const SQE_BUF_GROUP_OFF: usize = 40; // u16
                                     // IOSQE_BUFFER_SELECT = 1 << IOSQE_BUFFER_SELECT_BIT (bit 5).
const IOSQE_BUFFER_SELECT: u8 = 1 << 5;
// IORING_RECVMSG_CQE_MULTISHOT — same value as IORING_RECV_MULTISHOT = 2.
const IORING_RECVMSG_CQE_MULTISHOT: u16 = 2;

// The offsets above are only correct when the SQE wrapper has the same 64-byte
// ABI as the kernel struct. Catch crate-layout drift at compile time.
const _: () = assert!(
    size_of::<squeue::Entry>() == 64,
    "io_uring SQE size changed — audit SQE_FLAGS_OFF / SQE_IOPRIO_OFF / SQE_BUF_GROUP_OFF",
);

// ── io_uring_recvmsg_out ──────────────────────────────────────────────────────

/// Mirror of the kernel's `io_uring_recvmsg_out` (16 bytes, ABI-stable).
///
/// Layout in each provided buffer when multishot recvmsg delivers a packet:
/// ```text
/// [0..16)                  io_uring_recvmsg_out header
/// [16..16+out.namelen)     source address (actual bytes written by kernel)
/// [16+out.namelen ..)      payload (out.payloadlen bytes)
/// ```
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

/// Kernel-visible ring of buffer descriptors + backing data buffers.
///
/// Ring layout (BUF_RING_COUNT × 16 bytes, mmap'd):
/// - Entry 0 contains `tail` in its `resv` field (bytes 14-15); the same memory
///   also holds the first buffer descriptor when tail wraps to slot 0.
/// - The tail is updated with a Release store so the kernel sees descriptor
///   writes before the tail advance.
struct ProvidedBufRing {
    entries: *mut types::BufRingEntry, // mmap'd ring
    entries_len: usize,                // BUF_RING_COUNT × 16
    mask: u16,                         // BUF_RING_COUNT − 1
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
    fn new() -> io::Result<Self> {
        let n = BUF_RING_COUNT;
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
            mask: (n - 1) as u16,
            bufs,
            tail: 0,
        })
    }

    fn ring_addr(&self) -> u64 {
        self.entries as u64
    }

    /// Fill all BUF_RING_COUNT descriptor slots and advance the tail.
    fn fill_all(&mut self) {
        for bid in 0u16..BUF_RING_COUNT as u16 {
            let slot = (self.tail.wrapping_add(bid)) & self.mask;
            let entry = unsafe { &mut *self.entries.add(slot as usize) };
            entry.set_addr(self.bufs[bid as usize].0.as_ptr() as u64);
            entry.set_len(RECV_BUF_SIZE as u32);
            entry.set_bid(bid);
        }
        self.tail = self.tail.wrapping_add(BUF_RING_COUNT as u16);
        self.store_tail();
    }

    /// Return buffer `bid` to the ring at the current tail slot.
    fn replenish(&mut self, bid: u16) {
        let slot = self.tail & self.mask;
        let entry = unsafe { &mut *self.entries.add(slot as usize) };
        entry.set_addr(self.bufs[bid as usize].0.as_ptr() as u64);
        entry.set_len(RECV_BUF_SIZE as u32);
        entry.set_bid(bid);
        self.tail = self.tail.wrapping_add(1);
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

// ── SendSlot ──────────────────────────────────────────────────────────────────

/// Pre-allocated, pinned send slot with inline iovec and address storage.
///
/// `hdr` holds raw pointers into `addr` and `iovs` within the *same* Box
/// allocation.  The slot must not be moved after [`prepare`] is called —
/// always access through `Box<SendSlot>`.
struct SendSlot {
    addr: libc::sockaddr_storage,
    iovs: [libc::iovec; MAX_SEND_SGS],
    hdr: libc::msghdr,
    transmit: Option<Transmit<ScatterGather<IoBuf>>>,
}

// Safety: raw pointers in `hdr` are stable intra-Box addresses.
unsafe impl Send for SendSlot {}

impl SendSlot {
    fn new() -> Box<Self> {
        Box::new(Self {
            addr: unsafe { mem::zeroed() },
            iovs: unsafe { mem::zeroed() },
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
        transmit: Transmit<ScatterGather<IoBuf>>,
    ) -> *const libc::msghdr {
        debug_assert!(transmit.contents.segments.len() <= MAX_SEND_SGS);
        let n = transmit.contents.segments.len();
        slot.addr = mem::zeroed();
        let addr_len = sockaddr_from_socketaddr(&transmit.destination, &mut slot.addr);
        for (i, seg) in transmit.contents.segments.iter().enumerate().take(n) {
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
        slot.transmit = Some(transmit);
        &raw const slot.hdr
    }
}

// ── Pending recv staging ──────────────────────────────────────────────────────

/// Staged receive: the payload lives in the provided buffer ring slot `bid`
/// until [`IoUringSocket::recv`] copies it into the caller's `IoBufMut` and
/// calls [`ProvidedBufRing::replenish`] to return the slot to the kernel.
///
/// `meta.len` (= `out.payloadlen` cast to u16) is the authoritative payload
/// length used by [`IoUringSocket::recv`] for both the size check and the copy.
struct PendingRecv {
    meta: RecvMeta,
    bid: u16,
}

// ── IoUringSocket ─────────────────────────────────────────────────────────────

// Safety: recv_msghdr contains raw pointers that are only accessed from the
// thread that owns IoUringSocket; ProvidedBufRing holds mmap memory with
// no concurrent access.
unsafe impl Send for IoUringSocket {}

/// UDP packet socket backed by a per-socket io_uring instance.
///
/// **Kernel requirement:** Linux **6.0** or newer — uses
/// `IORING_REGISTER_PBUF_RING` (ring-mapped provided-buffer rings) for the
/// receive path and multishot `recvmsg`. Construction returns
/// [`io::ErrorKind::InvalidInput`] / `Other` on older kernels.
///
/// **Threading:** `Send` but not `Sync`. One ring per socket is single-issuer:
/// the same OS thread must own all calls to [`send`](PacketSocket::send),
/// [`recv`](PacketSocket::recv), and [`drain_completions`](PacketSocket::drain_completions).
/// Independent sockets on independent threads are the supported parallelism
/// model — use [`bind_reuseport`](IoUringSocket::bind_reuseport) for kernel
/// load-balancing across rings.
///
/// **Hot path:** zero heap allocations on [`send`] / [`recv`] / `drain_completions`.
/// All buffers, send slots, and the receive ring are pre-allocated at
/// construction.
pub struct IoUringSocket {
    ring: IoUring,
    raw_fd: RawFd,
    socket: UdpSocket,
    pool: Arc<IoPool>,
    queue_id: u16,

    // Template msghdr for the multishot recvmsg SQE.  The kernel reads
    // msg_namelen / msg_controllen from it; the pointer must stay valid until
    // the SQE is cancelled and its final CQE is consumed.
    recv_msghdr: Box<libc::msghdr>,
    buf_ring: ProvidedBufRing,
    recv_armed: bool, // multishot SQE still armed?
    // True whenever SQEs have been pushed to the submission ring but not yet
    // flushed to the kernel via io_uring_enter. recv() and drain_completions()
    // check this flag before calling ring.submit() so that the common hot-path
    // (ring already armed, no sends pending) avoids a no-op syscall.
    sq_dirty: bool,

    // Staged completions waiting for recv() to drain them.
    pending_recvs: VecDeque<PendingRecv>,

    // Send — pre-allocated pool of pinned Box<SendSlot>s, zero hot-path allocs.
    #[allow(clippy::vec_box)]
    send_slots: Vec<Box<SendSlot>>,
    send_free: [usize; SEND_POOL],
    send_free_top: usize,
}

impl IoUringSocket {
    pub fn bind(addr: SocketAddr) -> io::Result<Self> {
        let socket = UdpSocket::bind(addr)?;
        socket.set_nonblocking(true)?;
        Self::from_udp(socket)
    }

    pub fn bind_reuseport(addr: SocketAddr) -> io::Result<Self> {
        let domain = if addr.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        };
        let sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
        sock.set_reuse_port(true)?;
        sock.set_nonblocking(true)?;
        sock.bind(&addr.into())?;
        Self::from_udp(sock.into())
    }

    fn from_udp(socket: UdpSocket) -> io::Result<Self> {
        let raw_fd = socket.as_raw_fd();
        let ring = IoUring::new(RING_ENTRIES)?;

        let max_payload = match socket.local_addr() {
            Ok(SocketAddr::V4(_)) => IPV4_MAX_UDP_PAYLOAD,
            _ => IPV6_MAX_UDP_PAYLOAD,
        };
        let pool = IoPool::with_max_payload(max_payload);

        // Forbid IP fragmentation: DF bit on IPv4, no fragment header on IPv6.
        // The kernel returns EMSGSIZE instead of fragmenting outgoing datagrams,
        // and incoming reassembled fragments produce oversized payloads that the
        // recv path drops (analogous to MSG_TRUNC in OsSocket::recv).
        //
        // Failure here is fatal: without PMTUDISC the send path would silently
        // fragment outgoing datagrams (breaking QUIC's path-MTU model) and the
        // recv ring's fixed-size buffers could be hit by oversized reassembled
        // payloads.
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

        let mut buf_ring = ProvidedBufRing::new()?;
        unsafe {
            ring.submitter()
                .register_buf_ring(buf_ring.ring_addr(), BUF_RING_COUNT as u16, BUF_GROUP)
                .map_err(|e| {
                    io::Error::new(
                        e.kind(),
                        format!("register_buf_ring failed (requires Linux 6.0+): {e}"),
                    )
                })?;
        }
        buf_ring.fill_all();

        let send_slots: Vec<Box<SendSlot>> = (0..SEND_POOL).map(|_| SendSlot::new()).collect();
        let mut send_free = [0usize; SEND_POOL];
        for (i, f) in send_free.iter_mut().enumerate() {
            *f = i;
        }

        let mut recv_msghdr: Box<libc::msghdr> = Box::new(unsafe { mem::zeroed() });
        recv_msghdr.msg_namelen = RECV_NAME_MAX as u32;
        recv_msghdr.msg_controllen = 0;

        let mut s = Self {
            ring,
            raw_fd,
            socket,
            pool,
            queue_id: 0,
            recv_msghdr,
            buf_ring,
            recv_armed: false,
            sq_dirty: false,
            pending_recvs: VecDeque::with_capacity(BUF_RING_COUNT),
            send_slots,
            send_free,
            send_free_top: SEND_POOL,
        };
        s.submit_recv_multishot(); // sets sq_dirty = true
        let _ = s.ring.submit();
        s.sq_dirty = false;
        Ok(s)
    }

    pub fn set_queue_id(&mut self, id: u16) {
        self.queue_id = id;
    }

    /// Clone this socket, sharing the underlying kernel socket (duplicated fd).
    ///
    /// The original and the clone share the same kernel socket and compete for
    /// incoming packets non-deterministically — each datagram is delivered to
    /// exactly one of them. Use `bind_reuseport` instead if you need independent
    /// sockets that are load-balanced by the kernel.
    pub fn try_clone(&self) -> io::Result<Self> {
        let cloned = self.socket.try_clone()?;
        let mut s = Self::from_udp(cloned)?;
        s.queue_id = self.queue_id;
        Ok(s)
    }

    // ── Multishot recv SQE ────────────────────────────────────────────────────

    fn submit_recv_multishot(&mut self) {
        let msghdr_ptr = &mut *self.recv_msghdr as *mut libc::msghdr;
        // Build a standard RecvMsg SQE and patch three fields to enable
        // multishot mode with provided buffers (no clean API in io-uring 0.6):
        //   SQE byte  1 (flags u8)  |= IOSQE_BUFFER_SELECT (bit 5)
        //   SQE bytes 2-3 (ioprio)   = IORING_RECVMSG_CQE_MULTISHOT (= 2)
        //   SQE bytes 40-41 (buf_group) = BUF_GROUP
        let mut entry = opcode::RecvMsg::new(types::Fd(self.raw_fd), msghdr_ptr)
            .build()
            .user_data(RECV_MULTISHOT_UD);
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

    fn drain_cqes(&mut self) {
        // Snapshot up to MAX_CQES pending CQEs into a stack array (no heap alloc).
        // `.take(MAX_CQES)` stops the iterator before it advances past the
        // snapshot capacity — any extra CQEs stay in the CQ ring for the next
        // call. The MaybeUninit array avoids zero-filling unused slots.
        let mut raw: [MaybeUninit<(u64, i32, u32)>; MAX_CQES] =
            unsafe { MaybeUninit::uninit().assume_init() };
        let mut n_cqes = 0;
        for cqe in self.ring.completion().take(MAX_CQES) {
            raw[n_cqes].write((cqe.user_data(), cqe.result(), cqe.flags()));
            n_cqes += 1;
        }

        for &(ud, result, cqe_flags) in raw[..n_cqes].iter().map(|m| unsafe { m.assume_init_ref() })
        {
            if ud & SEND_TAG != 0 {
                // Send completion — drop IoBuf refs and return slot to free stack.
                let idx = (ud & !SEND_TAG) as usize;
                self.send_slots[idx].transmit = None;
                self.send_free[self.send_free_top] = idx;
                self.send_free_top += 1;
            } else {
                // Recv multishot CQE.
                if !cqueue::more(cqe_flags) {
                    // Kernel has disarmed the SQE (buffer exhaustion or error).
                    self.recv_armed = false;
                }

                if let Some(bid) = cqueue::buffer_select(cqe_flags) {
                    if result > 0 {
                        // Safety: bid < BUF_RING_COUNT; kernel wrote a valid packet.
                        let buf_data = self.buf_ring.bufs[bid as usize].0.as_ptr();
                        let out = unsafe { &*(buf_data as *const RecvMsgOut) };
                        let payloadlen = out.payloadlen as usize;

                        // Payload is at the fixed offset RECV_PAYLOAD_OFF because
                        // the kernel respects the template msg_namelen (128) for
                        // placement, regardless of the actual received addr length.
                        let src = socketaddr_from_raw(
                            unsafe { buf_data.add(RECV_OUT_SIZE) as *const libc::sockaddr },
                            out.namelen as libc::socklen_t,
                        );
                        if RECV_PAYLOAD_OFF + payloadlen <= RECV_BUF_SIZE {
                            if let Some(src) = src {
                                let mut m = RecvMeta::default();
                                m.src = src;
                                m.len = payloadlen as u16;
                                m.stride = payloadlen as u16;

                                // Stage the recv — the buf_ring slot stays consumed
                                // until recv() copies the payload and calls replenish.
                                self.pending_recvs.push_back(PendingRecv { meta: m, bid });
                            } else {
                                // Unknown address family; drop the packet.
                                self.buf_ring.replenish(bid);
                            }
                        } else {
                            // Payload overflows the ring buffer slot; drop the packet.
                            self.buf_ring.replenish(bid);
                        }
                    } else {
                        // Error or empty CQE; return slot immediately.
                        self.buf_ring.replenish(bid);
                    }
                }
            }
        }

        // Re-arm the multishot SQE if the kernel disarmed it and at least one
        // ring buffer slot is available. With provided-buffer rings, re-arming
        // with 0 available slots produces an immediate ENOBUFS CQE and
        // disarms again — creating an infinite loop. When all slots are in
        // pending_recvs (ring exhaustion), defer the re-arm to recv() which
        // replenishes slots before checking.
        if !self.recv_armed
            && !self.ring.submission().is_full()
            && self.pending_recvs.len() < BUF_RING_COUNT
        {
            self.submit_recv_multishot(); // sets sq_dirty = true
            let _ = self.ring.submit();
            self.sq_dirty = false;
        }
    }

    // Flush any pending SQEs to the kernel so that completions (multishot
    // recvmsg results, send CQEs) arrive in the CQ ring before drain_cqes reads
    // them.  Only needed on the hot path when a send() was issued since the last
    // call; sq_dirty tracks this to avoid a redundant no-op syscall.
    fn flush_and_get_events(&mut self) {
        if self.sq_dirty {
            let _ = self.ring.submit();
            self.sq_dirty = false;
        }
    }
}

// ── PacketSocket impl ─────────────────────────────────────────────────────────

impl PacketSocket for IoUringSocket {
    type Pool = IoPool;

    /// Inline iovec count in [`SendSlot`]. Each transmit becomes one
    /// `sendmsg` SQE whose `msg_iov` references at most this many segments.
    const MAX_SEGMENTS: usize = MAX_SEND_SGS;

    fn pool(&self) -> &Arc<IoPool> {
        &self.pool
    }

    fn send(&mut self, transmits: &mut Vec<Transmit<ScatterGather<IoBuf>>>) -> io::Result<usize> {
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
            let segs = t.contents.segments.len();
            assert!(
                segs <= Self::MAX_SEGMENTS,
                "transmit has {segs} segments but IoUringSocket::MAX_SEGMENTS is {} (transmits[{i}])",
                Self::MAX_SEGMENTS,
            );
        }

        for transmit in transmits.drain(..n) {
            self.send_free_top -= 1;
            let idx = self.send_free[self.send_free_top];
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

    fn drain_completions(&mut self) {
        self.flush_and_get_events();
        self.drain_cqes();
    }

    fn recv(&mut self, meta: &mut [RecvMeta], bufs: &mut [IoBufMut]) -> io::Result<usize> {
        if meta.is_empty() || bufs.is_empty() {
            return Ok(0);
        }

        self.flush_and_get_events();
        self.drain_cqes();

        let n = meta.len().min(bufs.len()).min(self.pending_recvs.len());
        if n == 0 {
            return Ok(0);
        }

        // Reset fill to 0 first so uninit_mut() covers [0..capacity) rather
        // than [prior_fill..capacity). Without this, a reused buffer that was
        // previously filled to N bytes would write the new payload starting at
        // offset N, and the subsequent set_filled(fill) would expose old bytes
        // in [0..N) as part of the new packet.
        //
        // Packets whose payload exceeds the caller's buffer capacity are dropped
        // (not truncated) — matching OsSocket::recv's MSG_TRUNC drop policy.
        // The buf ring slot is replenished immediately in both cases.
        let mut valid = 0;
        for _ in 0..n {
            let pr = self
                .pending_recvs
                .pop_front()
                .expect("n <= pending_recvs.len()");

            let buf_data = self.buf_ring.bufs[pr.bid as usize].0.as_ptr();
            unsafe { bufs[valid].set_filled(0) };
            let dst = bufs[valid].uninit_mut();

            let payload_len = pr.meta.len as usize;
            if payload_len > dst.len() {
                self.buf_ring.replenish(pr.bid);
                continue;
            }

            unsafe {
                ptr::copy_nonoverlapping(
                    buf_data.add(RECV_PAYLOAD_OFF),
                    dst.as_mut_ptr() as *mut u8,
                    payload_len,
                );
                bufs[valid].set_filled(payload_len);
            }
            meta[valid] = pr.meta;
            self.buf_ring.replenish(pr.bid);
            valid += 1;
        }

        // Re-arm the multishot if it was deferred because no ring slots were
        // available when drain_cqes ran. Replenishment above returns slots to
        // the ring, so we can now safely re-arm without an immediate ENOBUFS.
        if !self.recv_armed
            && !self.ring.submission().is_full()
            && self.pending_recvs.len() < BUF_RING_COUNT
        {
            self.submit_recv_multishot(); // sets sq_dirty = true
            let _ = self.ring.submit();
            self.sq_dirty = false;
        }

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
        // Cancel the armed multishot SQE so the kernel stops referencing
        // recv_msghdr and buf_ring memory before we free them below.
        if self.recv_armed {
            let sqe = opcode::AsyncCancel::new(RECV_MULTISHOT_UD).build();
            unsafe {
                let _ = self.ring.submission().push(&sqe);
            }
        }

        // Wait for every in-flight CQE before freeing owned memory:
        //   - Each outstanding send produces 1 CQE (sendmsg complete).
        //   - The recv cancel produces at least 1 CQE (the recv's -ECANCELED);
        //     the cancel op itself may produce a second. Waiting for 1 is
        //     sufficient to guarantee recv_msghdr is no longer accessed.
        // This ensures the kernel is done with all SendSlot msghdr/iov pointers
        // and with recv_msghdr before those allocations are freed below.
        let outstanding_sends = SEND_POOL - self.send_free_top;
        let wait_count = outstanding_sends + usize::from(self.recv_armed);
        if wait_count > 0 {
            let _ = self.ring.submitter().submit_and_wait(wait_count);
        }
        // Drain the CQ ring and release send-slot IoBuf references so they are
        // freed before the Box<SendSlot>s themselves are dropped.
        for cqe in self.ring.completion() {
            if cqe.user_data() & SEND_TAG != 0 {
                let idx = (cqe.user_data() & !SEND_TAG) as usize;
                self.send_slots[idx].transmit = None;
            }
        }

        // Replenish any bid slots staged but never consumed by recv().
        while let Some(pr) = self.pending_recvs.pop_front() {
            self.buf_ring.replenish(pr.bid);
        }
        // Unregister the buf ring so the kernel stops accessing ring memory.
        // Ignore errors (e.g. if the ring was already torn down).
        let _ = self.ring.submitter().unregister_buf_ring(BUF_GROUP);
        // ProvidedBufRing::drop() will munmap the ring memory.
    }
}

// ── Address helpers ───────────────────────────────────────────────────────────

fn sockaddr_from_socketaddr(
    addr: &SocketAddr,
    storage: &mut libc::sockaddr_storage,
) -> libc::socklen_t {
    unsafe {
        match addr {
            SocketAddr::V4(v4) => {
                let sin = storage as *mut _ as *mut libc::sockaddr_in;
                (*sin).sin_family = libc::AF_INET as libc::sa_family_t;
                (*sin).sin_port = v4.port().to_be();
                (*sin).sin_addr.s_addr = u32::from_ne_bytes(v4.ip().octets());
                size_of::<libc::sockaddr_in>() as libc::socklen_t
            }
            SocketAddr::V6(v6) => {
                let sin6 = storage as *mut _ as *mut libc::sockaddr_in6;
                (*sin6).sin6_family = libc::AF_INET6 as libc::sa_family_t;
                (*sin6).sin6_port = v6.port().to_be();
                (*sin6).sin6_addr.s6_addr = v6.ip().octets();
                (*sin6).sin6_flowinfo = v6.flowinfo();
                (*sin6).sin6_scope_id = v6.scope_id();
                size_of::<libc::sockaddr_in6>() as libc::socklen_t
            }
        }
    }
}

fn socketaddr_from_raw(sa: *const libc::sockaddr, len: libc::socklen_t) -> Option<SocketAddr> {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
    unsafe {
        match (*sa).sa_family as libc::c_int {
            libc::AF_INET if len as usize >= size_of::<libc::sockaddr_in>() => {
                let sin = &*(sa as *const libc::sockaddr_in);
                let ip = Ipv4Addr::from(sin.sin_addr.s_addr.to_ne_bytes());
                Some(SocketAddr::V4(SocketAddrV4::new(
                    ip,
                    u16::from_be(sin.sin_port),
                )))
            }
            libc::AF_INET6 if len as usize >= size_of::<libc::sockaddr_in6>() => {
                let sin6 = &*(sa as *const libc::sockaddr_in6);
                let ip = Ipv6Addr::from(sin6.sin6_addr.s6_addr);
                Some(SocketAddr::V6(SocketAddrV6::new(
                    ip,
                    u16::from_be(sin6.sin6_port),
                    sin6.sin6_flowinfo,
                    sin6.sin6_scope_id,
                )))
            }
            _ => None,
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::io;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::time::{Duration, Instant};

    use std::os::fd::AsRawFd;

    use quac_socket::{
        BufferPool, PacketBufMut, PacketSocket, RecvMeta, ScatterGather, Segment, Transmit,
    };
    use smallvec::{smallvec, SmallVec};

    use super::{IoBuf, IoBufMut, IoUringSocket, IPV4_MAX_UDP_PAYLOAD, IPV6_MAX_UDP_PAYLOAD};

    const BATCH: usize = 64;

    fn send_one(sock: &mut IoUringSocket, dest: SocketAddr, payload: &[u8]) -> bool {
        let buf = IoBuf::from_slice(payload);
        let len = payload.len();
        let seg = unsafe { Segment::new_unchecked(buf, 0, len as u32) };
        let mut transmits = vec![Transmit::new(
            ScatterGather {
                segments: smallvec![seg],
            },
            dest,
        )];
        sock.send(&mut transmits).unwrap_or(0) >= 1
    }

    fn alloc_recv_bufs(sock: &IoUringSocket) -> Vec<IoBufMut> {
        let mut bufs: Vec<IoBufMut> = Vec::with_capacity(BATCH);
        sock.pool()
            .alloc(sock.pool().max_payload_size(), BATCH, &mut bufs);
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
        let mut a = IoUringSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
        let mut b = IoUringSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
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
        let mut server = IoUringSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
        let mut client = IoUringSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
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
        let mut s = IoUringSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
        assert_eq!(s.queue_id(), 0u16);
        s.set_queue_id(7u16);
        assert_eq!(s.queue_id(), 7u16);
    }

    #[test]
    fn pong_roundtrip() {
        let mut server = IoUringSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
        let mut client = IoUringSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
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
                let mut transmits: Vec<Transmit<ScatterGather<IoBuf>>> = Vec::with_capacity(n);
                for (buf, m) in bufs.drain(..n).zip(meta.iter()) {
                    let len = buf.filled().len();
                    let frozen = buf.freeze();
                    let seg = unsafe { Segment::new_unchecked(frozen, 0, len as u32) };
                    transmits.push(Transmit::new(
                        ScatterGather {
                            segments: smallvec![seg],
                        },
                        m.src,
                    ));
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
        let s = IoUringSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
        assert_eq!(s.pool().max_payload_size(), IPV4_MAX_UDP_PAYLOAD);
    }

    #[test]
    fn ipv6_socket_pool_reports_ipv6_max_payload() {
        let s = match IoUringSocket::bind(SocketAddr::from((Ipv6Addr::LOCALHOST, 0))) {
            Ok(s) => s,
            Err(_) => return, // skip if IPv6 unavailable
        };
        assert_eq!(s.pool().max_payload_size(), IPV6_MAX_UDP_PAYLOAD);
    }

    // ── Helpers for new tests ─────────────────────────────────────────────────

    fn send_segments(sock: &mut IoUringSocket, dest: SocketAddr, segs: &[&[u8]]) -> bool {
        let mut sv: SmallVec<[Segment<IoBuf>; 4]> = SmallVec::new();
        for s in segs {
            let buf = IoBuf::from_slice(s);
            sv.push(unsafe { Segment::new_unchecked(buf, 0, s.len() as u32) });
        }
        let mut transmits = vec![Transmit::new(ScatterGather { segments: sv }, dest)];
        sock.send(&mut transmits).unwrap_or(0) >= 1
    }

    fn reserve_loopback_udp_port() -> u16 {
        // Bind an ephemeral port, record it, drop it, return it.
        // There is a narrow TOCTOU window but it is negligible in tests.
        let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        s.local_addr().unwrap().port()
    }

    // ── Group 1: core trait contract ──────────────────────────────────────────

    #[test]
    fn recv_idle_socket_returns_zero() {
        let mut sock = IoUringSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
        let mut meta = vec![RecvMeta::default(); 8];
        let mut bufs = alloc_recv_bufs(&sock);
        let n = sock.recv(&mut meta[..], &mut bufs[..]).expect("recv idle");
        assert_eq!(n, 0, "idle socket must return Ok(0), not an error");
    }

    #[test]
    fn recv_empty_slices_returns_zero() {
        let mut sock = IoUringSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
        let n = sock.recv(&mut [], &mut []).expect("recv empty");
        assert_eq!(n, 0);
    }

    #[test]
    fn send_empty_vec_returns_zero() {
        let mut sock = IoUringSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
        let mut empty: Vec<Transmit<ScatterGather<IoBuf>>> = Vec::new();
        let n = sock.send(&mut empty).expect("send empty");
        assert_eq!(n, 0);
        assert!(empty.is_empty());
    }

    #[test]
    fn recv_buffer_reuse_does_not_truncate() {
        // Allocate bufs ONCE, reuse across rounds.  Each round delivers a
        // payload of a distinct length and byte value; after each recv the
        // buffer must contain exactly the new payload — no stale bytes from
        // the previous round.
        let mut server = IoUringSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
        let mut client = IoUringSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
        let server_addr = server.local_addr().unwrap();

        let mut bufs: Vec<IoBufMut> = Vec::with_capacity(8);
        server.pool().alloc(1452, 8, &mut bufs);
        let mut meta = vec![RecvMeta::default(); 8];

        // Round sizes: 150 bytes, 50 bytes, 100 bytes — deliberately shrinking
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
        let mut server = IoUringSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
        let mut client = IoUringSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
        let server_addr = server.local_addr().unwrap();

        assert!(send_segments(&mut client, server_addr, &[b"AB", b"CD"]));

        let deadline = Instant::now() + Duration::from_secs(2);
        let (_, data) = recv_until(&mut server, b"ABCD", deadline).unwrap();
        assert_eq!(data, b"ABCD");
    }

    #[test]
    fn send_recv_five_segment_scatter_gather() {
        // 5 segments: one past the SmallVec inline cap of 4 → spills to heap.
        let mut server = IoUringSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
        let mut client = IoUringSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
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
        let mut server = IoUringSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
        let mut client = IoUringSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
        let server_addr = server.local_addr().unwrap();

        let payloads: &[&[u8]] = &[b"AAA", b"BBBB", b"CCC", b"DDDDD"];
        let mut transmits: Vec<Transmit<ScatterGather<IoBuf>>> = payloads
            .iter()
            .map(|p| {
                let buf = IoBuf::from_slice(p);
                let len = p.len() as u32;
                let seg = unsafe { Segment::new_unchecked(buf, 0, len) };
                Transmit::new(
                    ScatterGather {
                        segments: smallvec![seg],
                    },
                    server_addr,
                )
            })
            .collect();

        let n = client.send(&mut transmits).expect("send batch");
        assert_eq!(n, payloads.len(), "all 4 transmits must be accepted");
        assert!(
            transmits.is_empty(),
            "accepted transmits must be drained from vec"
        );

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
        let mut server = match IoUringSocket::bind(SocketAddr::from((Ipv6Addr::LOCALHOST, 0))) {
            Ok(s) => s,
            Err(_) => return, // skip if IPv6 unavailable
        };
        let mut client = match IoUringSocket::bind(SocketAddr::from((Ipv6Addr::LOCALHOST, 0))) {
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

    #[test]
    fn try_clone_inherits_queue_id() {
        let mut original = IoUringSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
        original.set_queue_id(7u16);

        let mut clone = original.try_clone().expect("try_clone");
        assert_eq!(clone.queue_id(), 7u16, "clone must inherit queue_id");
        assert_eq!(clone.local_addr().unwrap(), original.local_addr().unwrap());

        // A packet sent to the shared port must be receivable via the clone.
        let mut sender = IoUringSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
        let dest = original.local_addr().unwrap();
        let payload = b"try-clone-test";
        assert!(send_one(&mut sender, dest, payload));

        let deadline = Instant::now() + Duration::from_secs(2);
        let (_, data) = recv_until(&mut clone, payload, deadline).unwrap();
        assert_eq!(data, payload);
    }

    // ── Group 4: boundary inputs / constructors ───────────────────────────────

    #[test]
    fn recv_with_smaller_bufs_than_meta() {
        let mut server = IoUringSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
        let mut client = IoUringSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
        let server_addr = server.local_addr().unwrap();

        for i in 0u8..4 {
            assert!(send_one(&mut client, server_addr, &[i; 8]));
        }

        // bufs.len() = 2, meta.len() = 8 → recv must cap at 2.
        let mut meta = vec![RecvMeta::default(); 8];
        let mut bufs: Vec<IoBufMut> = Vec::with_capacity(2);
        server.pool().alloc(1452, 2, &mut bufs);

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

        let mut first = IoUringSocket::bind_reuseport(addr).unwrap();
        let mut second = IoUringSocket::bind_reuseport(addr).unwrap();
        assert_eq!(first.local_addr().unwrap().port(), port);
        assert_eq!(second.local_addr().unwrap().port(), port);

        let mut sender = IoUringSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
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
        let mut receiver = IoUringSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
        let mut sender = IoUringSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
        let recv_addr = receiver.local_addr().unwrap();

        assert!(send_one(&mut sender, recv_addr, b"staged-drop"));

        // Give the packet time to arrive, then drain CQEs so the packet is
        // staged in pending_recvs — then drop without calling recv().
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
        let mut sender = IoUringSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
        let sink = IoUringSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
        let dest = sink.local_addr().unwrap();

        const SEND_POOL: usize = 128; // matches SEND_POOL in parent module

        let mut full_batch: Vec<Transmit<ScatterGather<IoBuf>>> = (0u8..SEND_POOL as u8)
            .map(|i| {
                let buf = IoBuf::from_slice(&[i]);
                let seg = unsafe { Segment::new_unchecked(buf, 0, 1) };
                Transmit::new(
                    ScatterGather {
                        segments: smallvec![seg],
                    },
                    dest,
                )
            })
            .collect();

        let accepted = sender.send(&mut full_batch).expect("send full batch");
        assert_eq!(
            accepted, SEND_POOL,
            "all {SEND_POOL} slots must be accepted"
        );
        assert!(full_batch.is_empty(), "accepted transmits must be drained");

        // Without draining completions, send_free_top == 0.
        let buf = IoBuf::from_slice(b"overflow");
        let seg = unsafe { Segment::new_unchecked(buf, 0, 8) };
        let mut extra = vec![Transmit::new(
            ScatterGather {
                segments: smallvec![seg],
            },
            dest,
        )];
        let n = sender.send(&mut extra).expect("send when slots full");
        assert_eq!(n, 0, "must be back-pressured when all send slots are taken");
        assert_eq!(extra.len(), 1, "rejected transmit must remain in vec");
    }

    #[test]
    fn rx_fd_returns_some() {
        let s = IoUringSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
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

        let mut server = IoUringSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
        let server_addr = server.local_addr().unwrap();

        // Use a plain UdpSocket as the sender so io_uring send-slot management
        // doesn't interfere with the recv-side ring exhaustion mechanics.
        let client = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();

        // Phase 1: flood the ring — all 256 slots filled.
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

        // Phase 3: verify the multishot was re-armed — new packets must arrive.
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
    #[should_panic(expected = "transmit has")]
    fn send_with_too_many_segments_panics() {
        let mut sock = IoUringSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
        let dest = sock.local_addr().unwrap();

        // 9 segments — one past MAX_SEND_SGS = 8.
        let sv: SmallVec<[Segment<IoBuf>; 4]> = (0..9u8)
            .map(|i| {
                let buf = IoBuf::from_slice(&[i]);
                unsafe { Segment::new_unchecked(buf, 0, 1) }
            })
            .collect();
        let mut transmits = vec![Transmit::new(ScatterGather { segments: sv }, dest)];
        let _ = sock.send(&mut transmits);
    }

    // Bug: MAX_DATAGRAM was 65535; internal ring buffers wasted ~16 MB.
    // Fix: RECV_PAYLOAD_MAX = 2048 (2 KiB per slot, matching MAX_BUF_SIZE in
    // quac-socket-os). IP_PMTUDISC_DO / IPV6_PMTUDISC_DO are now set on the
    // socket to forbid fragmentation. Packets exceeding the internal buffer or
    // the caller's buffer capacity are dropped (not truncated).

    #[test]
    fn ipv4_socket_sets_ip_pmtudisc_do() {
        let s = IoUringSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
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
        let s = match IoUringSocket::bind(SocketAddr::from((Ipv6Addr::LOCALHOST, 0))) {
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
    fn recv_drops_packet_exceeding_internal_ring_buffer() {
        // A datagram larger than RECV_PAYLOAD_MAX (2048) is delivered into a
        // ring slot but the kernel reports payloadlen > 2048. drain_cqes
        // detects RECV_PAYLOAD_OFF + payloadlen > RECV_BUF_SIZE and replenishes
        // the slot without staging the packet. A normal-sized packet sent
        // afterwards must still be received.
        let mut server = IoUringSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
        let mut client = IoUringSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
        let server_addr = server.local_addr().unwrap();

        let oversized = vec![0xABu8; 3000]; // 3000 > RECV_PAYLOAD_MAX = 2048
        assert!(send_one(&mut client, server_addr, &oversized));
        std::thread::sleep(Duration::from_millis(20));

        let mut meta = vec![RecvMeta::default(); 4];
        let mut bufs = alloc_recv_bufs(&server);
        let n = server.recv(&mut meta, &mut bufs).expect("recv");
        assert_eq!(n, 0, "3000-byte packet must be dropped at the ring level");

        // Verify normal traffic still flows after the drop.
        let normal = b"normal-after-oversize";
        send_one(&mut client, server_addr, normal);
        let deadline = Instant::now() + Duration::from_secs(2);
        let (_, data) = recv_until(&mut server, normal, deadline).unwrap();
        assert_eq!(data, normal);
    }

    #[test]
    fn recv_drops_packet_exceeding_caller_buffer() {
        // A datagram that fits in the internal ring slot (≤ 2048) but exceeds
        // the caller's buffer capacity must be dropped — not truncated —
        // matching OsSocket's MSG_TRUNC policy. payload_size is
        // max_payload_size + 28, which is > 1472 (IPv4) but ≤ 2048, so it
        // passes drain_cqes and is caught in recv().
        let mut server = IoUringSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
        let mut client = IoUringSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
        let server_addr = server.local_addr().unwrap();

        let max_payload = server.pool().max_payload_size();
        let oversized = vec![0xCDu8; max_payload + 28]; // fits in ring, not in caller buf
        assert!(send_one(&mut client, server_addr, &oversized));
        std::thread::sleep(Duration::from_millis(20));

        let mut meta = vec![RecvMeta::default(); 4];
        let mut bufs: Vec<IoBufMut> = Vec::new();
        server.pool().alloc(max_payload, 4, &mut bufs); // exactly max_payload capacity
        let n = server.recv(&mut meta, &mut bufs).expect("recv");
        assert_eq!(
            n, 0,
            "packet exceeding caller buffer must be dropped, not truncated"
        );

        // Verify a properly-sized packet still flows.
        let normal = b"ok-after-caller-drop";
        send_one(&mut client, server_addr, normal);
        let deadline = Instant::now() + Duration::from_secs(2);
        let (_, data) = recv_until(&mut server, normal, deadline).unwrap();
        assert_eq!(data, normal);
    }
}
