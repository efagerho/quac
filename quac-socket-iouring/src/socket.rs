use std::alloc::{alloc_zeroed, Layout};
use std::collections::VecDeque;
use std::io;
use std::mem::{self, size_of};
use std::net::{SocketAddr, UdpSocket};
use std::os::fd::{AsRawFd, RawFd};
use std::ptr;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;

use io_uring::{cqueue, opcode, squeue, types, IoUring};
use smallvec::smallvec;
use socket2::{Domain, Protocol, Socket, Type};

use quac_socket::{BufferPool, PacketSocket, RecvMeta, ScatterGather, Segment, Transmit};
use quac_socket_os::{OsBuf, OsBufMut, OsPool};

// ── Ring / pool constants ─────────────────────────────────────────────────────

const MAX_DATAGRAM: usize = 65535;
// High bit set → send CQE; clear → recv CQE.
const SEND_TAG: u64 = 1 << 63;
const RING_ENTRIES: u32 = 256;
const SEND_POOL: usize = 128;
const MAX_SEND_SGS: usize = 8;
const MAX_CQES: usize = RING_ENTRIES as usize;

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
const RECV_BUF_SIZE: usize = RECV_PAYLOAD_OFF + MAX_DATAGRAM;

// user_data for the one multishot recv SQE (must not overlap with SEND_TAG).
const RECV_MULTISHOT_UD: u64 = 0;

// io_uring_sqe byte offsets (stable kernel ABI).
const SQE_FLAGS_OFF: usize = 1;  // u8
const SQE_IOPRIO_OFF: usize = 2; // u16
const SQE_BUF_GROUP_OFF: usize = 40; // u16
// IOSQE_BUFFER_SELECT = 1 << IOSQE_BUFFER_SELECT_BIT (bit 5).
const IOSQE_BUFFER_SELECT: u8 = 1 << 5;
// IORING_RECVMSG_CQE_MULTISHOT — same value as IORING_RECV_MULTISHOT = 2.
const IORING_RECVMSG_CQE_MULTISHOT: u16 = 2;

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
    namelen:    u32,
    controllen: u32,
    payloadlen: u32,
    flags:      u32,
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
    entries:     *mut types::BufRingEntry, // mmap'd ring
    entries_len: usize,                    // BUF_RING_COUNT × 16
    mask:        u16,                      // BUF_RING_COUNT − 1
    bufs:        Vec<Box<MultiRecvBuf>>,   // BUF_RING_COUNT data buffers
    tail:        u16,                      // shadow tail
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
        unsafe { ptr::write_bytes(ptr as *mut u8, 0, entries_len) };

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
        let tail_ptr =
            unsafe { types::BufRingEntry::tail(self.entries) as *mut u16 };
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
    addr:     libc::sockaddr_storage,
    iovs:     [libc::iovec; MAX_SEND_SGS],
    hdr:      libc::msghdr,
    transmit: Option<Transmit<ScatterGather<OsBuf>>>,
}

// Safety: raw pointers in `hdr` are stable intra-Box addresses.
unsafe impl Send for SendSlot {}

impl SendSlot {
    fn new() -> Box<Self> {
        Box::new(Self {
            addr:     unsafe { mem::zeroed() },
            iovs:     unsafe { mem::zeroed() },
            hdr:      unsafe { mem::zeroed() },
            transmit: None,
        })
    }

    unsafe fn prepare(
        slot: &mut Box<Self>,
        transmit: Transmit<ScatterGather<OsBuf>>,
    ) -> *const libc::msghdr {
        let n = transmit.contents.segments.len().min(MAX_SEND_SGS);
        let addr_len = sockaddr_from_socketaddr(&transmit.destination, &mut slot.addr);
        for (i, seg) in transmit.contents.segments.iter().enumerate().take(n) {
            let data = &seg.buf.as_ref()[seg.offset..seg.offset + seg.len];
            slot.iovs[i] = libc::iovec {
                iov_base: data.as_ptr() as *mut libc::c_void,
                iov_len:  data.len(),
            };
        }
        slot.hdr = mem::zeroed();
        slot.hdr.msg_name    = &raw mut slot.addr as *mut libc::c_void;
        slot.hdr.msg_namelen = addr_len;
        slot.hdr.msg_iov     = slot.iovs.as_mut_ptr();
        slot.hdr.msg_iovlen  = n as _;
        slot.transmit = Some(transmit);
        &raw const slot.hdr
    }
}

// ── Pending recv result ───────────────────────────────────────────────────────

struct PendingRecv {
    meta: RecvMeta,
    buf:  ScatterGather<OsBufMut>,
}

// ── IoUringSocket ─────────────────────────────────────────────────────────────

// Safety: recv_msghdr contains raw pointers that are only accessed from the
// thread that owns IoUringSocket; ProvidedBufRing holds mmap memory with
// no concurrent access.
unsafe impl Send for IoUringSocket {}

pub struct IoUringSocket {
    ring:     IoUring,
    raw_fd:   RawFd,
    socket:   UdpSocket,
    pool:     Arc<OsPool>,
    queue_id: u32,

    // Template msghdr for the multishot recvmsg SQE.  The kernel reads
    // msg_namelen / msg_controllen from it; the pointer must stay valid until
    // the SQE is cancelled and its final CQE is consumed.
    recv_msghdr: Box<libc::msghdr>,
    buf_ring:    ProvidedBufRing,
    recv_armed:  bool, // multishot SQE still armed?

    pending_recvs: VecDeque<PendingRecv>,

    // Send — pre-allocated pool of pinned Box<SendSlot>s, zero hot-path allocs.
    #[allow(clippy::vec_box)]
    send_slots:    Vec<Box<SendSlot>>,
    send_free:     [usize; SEND_POOL],
    send_free_top: usize,

    // Reused scratch for pool.alloc() — avoids one Vec alloc per received packet.
    alloc_scratch: Vec<OsBufMut>,
}

impl IoUringSocket {
    pub fn bind(addr: SocketAddr) -> io::Result<Self> {
        let socket = UdpSocket::bind(addr)?;
        socket.set_nonblocking(true)?;
        Self::from_udp(socket)
    }

    pub fn bind_reuseport(addr: SocketAddr) -> io::Result<Self> {
        let domain = if addr.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
        let sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
        sock.set_reuse_port(true)?;
        sock.set_nonblocking(true)?;
        sock.bind(&addr.into())?;
        Self::from_udp(sock.into())
    }

    fn from_udp(socket: UdpSocket) -> io::Result<Self> {
        let raw_fd = socket.as_raw_fd();
        let ring   = IoUring::new(RING_ENTRIES)?;
        let pool   = OsPool::new();

        let mut buf_ring = ProvidedBufRing::new()?;
        unsafe {
            ring.submitter()
                .register_buf_ring(buf_ring.ring_addr(), BUF_RING_COUNT as u16, BUF_GROUP)?;
        }
        buf_ring.fill_all();

        let send_slots: Vec<Box<SendSlot>> = (0..SEND_POOL).map(|_| SendSlot::new()).collect();
        let mut send_free = [0usize; SEND_POOL];
        for (i, f) in send_free.iter_mut().enumerate() {
            *f = i;
        }

        let mut recv_msghdr: Box<libc::msghdr> = Box::new(unsafe { mem::zeroed() });
        recv_msghdr.msg_namelen    = RECV_NAME_MAX as u32;
        recv_msghdr.msg_controllen = 0;

        let mut s = Self {
            ring,
            raw_fd,
            socket,
            pool,
            queue_id: 0,
            recv_msghdr,
            buf_ring,
            recv_armed:    false,
            pending_recvs: VecDeque::with_capacity(64),
            send_slots,
            send_free,
            send_free_top: SEND_POOL,
            alloc_scratch: Vec::with_capacity(1),
        };
        s.submit_recv_multishot();
        let _ = s.ring.submit();
        Ok(s)
    }

    pub fn set_queue_id(&mut self, id: u32) {
        self.queue_id = id;
    }

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
        unsafe { self.ring.submission().push(&entry).expect("SQ not full") };
        self.recv_armed = true;
    }

    // ── CQE drain ────────────────────────────────────────────────────────────

    fn drain_cqes(&mut self) {
        let pool = Arc::clone(&self.pool);

        // Snapshot all pending CQEs into a stack array (no heap alloc).
        let mut raw = [(0u64, 0i32, 0u32); MAX_CQES];
        let mut n_cqes = 0;
        for cqe in self.ring.completion() {
            if n_cqes < MAX_CQES {
                raw[n_cqes] = (cqe.user_data(), cqe.result(), cqe.flags());
                n_cqes += 1;
            }
        }

        for &(ud, result, cqe_flags) in &raw[..n_cqes] {
            if ud & SEND_TAG != 0 {
                // Send completion — drop OsBuf refs and return slot to free stack.
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
                        if RECV_PAYLOAD_OFF + payloadlen <= RECV_BUF_SIZE {
                            let src = socketaddr_from_raw(
                                unsafe {
                                    buf_data.add(RECV_OUT_SIZE) as *const libc::sockaddr
                                },
                                out.namelen as libc::socklen_t,
                            );

                            self.alloc_scratch.clear();
                            pool.alloc(payloadlen, 1, &mut self.alloc_scratch);
                            let mut pbuf =
                                self.alloc_scratch.pop().expect("pool alloc succeeded");
                            pbuf.as_mut().copy_from_slice(unsafe {
                                std::slice::from_raw_parts(
                                    buf_data.add(RECV_PAYLOAD_OFF),
                                    payloadlen,
                                )
                            });

                            self.pending_recvs.push_back(PendingRecv {
                                meta: RecvMeta {
                                    src,
                                    len:    payloadlen,
                                    stride: payloadlen,
                                    ..RecvMeta::default()
                                },
                                buf: ScatterGather {
                                    segments: smallvec![Segment {
                                        buf:    pbuf,
                                        offset: 0,
                                        len:    payloadlen,
                                    }],
                                },
                            });
                        }
                    }
                    // Return the provided buffer to the ring whether or not the
                    // packet was valid (always replenish to avoid exhaustion).
                    self.buf_ring.replenish(bid);
                }
            }
        }

        // Re-arm the multishot SQE if the kernel disarmed it.
        if !self.recv_armed && !self.ring.submission().is_full() {
            self.submit_recv_multishot();
        }
    }
}

// ── PacketSocket impl ─────────────────────────────────────────────────────────

impl PacketSocket for IoUringSocket {
    type Pool = OsPool;

    fn pool(&self) -> Arc<OsPool> {
        Arc::clone(&self.pool)
    }

    fn send(
        &mut self,
        transmits: Vec<Transmit<ScatterGather<OsBuf>>>,
    ) -> Vec<Transmit<ScatterGather<OsBuf>>> {
        if transmits.is_empty() {
            return transmits;
        }

        let mut unsent = Vec::new();

        for transmit in transmits {
            if self.send_free_top == 0 || self.ring.submission().is_full() {
                unsent.push(transmit);
                continue;
            }

            self.send_free_top -= 1;
            let idx = self.send_free[self.send_free_top];

            let hdr_ptr = unsafe { SendSlot::prepare(&mut self.send_slots[idx], transmit) };

            let sqe = opcode::SendMsg::new(types::Fd(self.raw_fd), hdr_ptr)
                .build()
                .user_data(SEND_TAG | idx as u64);

            unsafe { self.ring.submission().push(&sqe).expect("SQ not full") };
        }

        let _ = self.ring.submit();
        unsent
    }

    fn drain_completions(&mut self) {
        let _ = self.ring.submit();
        self.drain_cqes();
    }

    fn recv(
        &mut self,
        meta: &mut [RecvMeta],
        bufs: &mut Vec<ScatterGather<OsBufMut>>,
    ) -> io::Result<usize> {
        if meta.is_empty() {
            return Ok(0);
        }

        let _ = self.ring.submit();
        self.drain_cqes();

        let n = meta.len().min(self.pending_recvs.len());
        if n == 0 {
            return Err(io::Error::from(io::ErrorKind::WouldBlock));
        }

        for m in meta.iter_mut().take(n) {
            let pr = self.pending_recvs.pop_front().expect("n <= len");
            *m = pr.meta;
            bufs.push(pr.buf);
        }

        Ok(n)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    fn queue_id(&self) -> u32 {
        self.queue_id
    }

    fn rx_fd(&self) -> Option<RawFd> {
        Some(self.raw_fd)
    }
}

// ── Drop ──────────────────────────────────────────────────────────────────────

impl Drop for IoUringSocket {
    fn drop(&mut self) {
        if self.recv_armed {
            // Cancel the armed multishot SQE so the kernel stops referencing
            // recv_msghdr and buf_ring memory.
            let sqe = opcode::AsyncCancel::new(RECV_MULTISHOT_UD).build();
            unsafe {
                let _ = self.ring.submission().push(&sqe);
            }
            // Wait for at least the cancel CQE (the cancelled recv may also produce
            // a final CQE, so drain all remaining entries).
            let _ = self.ring.submitter().submit_and_wait(1);
            for _ in self.ring.completion() {}
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
                (*sin).sin_port   = v4.port().to_be();
                (*sin).sin_addr.s_addr = u32::from_ne_bytes(v4.ip().octets());
                size_of::<libc::sockaddr_in>() as libc::socklen_t
            }
            SocketAddr::V6(v6) => {
                let sin6 = storage as *mut _ as *mut libc::sockaddr_in6;
                (*sin6).sin6_family   = libc::AF_INET6 as libc::sa_family_t;
                (*sin6).sin6_port     = v6.port().to_be();
                (*sin6).sin6_addr.s6_addr = v6.ip().octets();
                (*sin6).sin6_flowinfo = v6.flowinfo();
                (*sin6).sin6_scope_id = v6.scope_id();
                size_of::<libc::sockaddr_in6>() as libc::socklen_t
            }
        }
    }
}

fn socketaddr_from_raw(sa: *const libc::sockaddr, len: libc::socklen_t) -> SocketAddr {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
    unsafe {
        match (*sa).sa_family as libc::c_int {
            libc::AF_INET if len as usize >= size_of::<libc::sockaddr_in>() => {
                let sin = &*(sa as *const libc::sockaddr_in);
                let ip = Ipv4Addr::from(sin.sin_addr.s_addr.to_ne_bytes());
                SocketAddr::V4(SocketAddrV4::new(ip, u16::from_be(sin.sin_port)))
            }
            libc::AF_INET6 if len as usize >= size_of::<libc::sockaddr_in6>() => {
                let sin6 = &*(sa as *const libc::sockaddr_in6);
                let ip   = Ipv6Addr::from(sin6.sin6_addr.s6_addr);
                SocketAddr::V6(SocketAddrV6::new(
                    ip,
                    u16::from_be(sin6.sin6_port),
                    sin6.sin6_flowinfo,
                    sin6.sin6_scope_id,
                ))
            }
            _ => "0.0.0.0:0".parse().unwrap(),
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::io;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::time::{Duration, Instant};

    use quac_socket::{PacketSocket, RecvMeta, ScatterGather, Segment, Transmit};
    use quac_socket_os::OsBuf;
    use smallvec::smallvec;

    use super::{IoUringSocket, OsBufMut};

    fn send_one(sock: &mut IoUringSocket, dest: SocketAddr, payload: &[u8]) -> bool {
        let buf = OsBuf::from_slice(payload);
        let len = payload.len();
        sock.send(vec![Transmit {
            destination: dest,
            ecn: None,
            contents: ScatterGather {
                segments: smallvec![Segment { buf, offset: 0, len }],
            },
            segment_size: None,
            src_ip: None,
        }])
        .is_empty()
    }

    fn recv_batch(sock: &mut IoUringSocket) -> io::Result<Vec<(SocketAddr, Vec<u8>)>> {
        let mut meta = vec![RecvMeta::default(); 64];
        let mut bufs: Vec<ScatterGather<OsBufMut>> = Vec::new();
        match sock.recv(&mut meta, &mut bufs) {
            Ok(n) => {
                let mut out = Vec::with_capacity(n);
                for i in 0..n {
                    let payload = bufs[i].as_contiguous().expect("single-segment").to_vec();
                    out.push((meta[i].src, payload));
                }
                Ok(out)
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(Vec::new()),
            Err(e) => Err(e),
        }
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
        assert_eq!(s.queue_id(), 0);
        s.set_queue_id(7);
        assert_eq!(s.queue_id(), 7);
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
            let mut meta = vec![RecvMeta::default(); 64];
            let mut bufs: Vec<ScatterGather<OsBufMut>> = Vec::new();
            match server.recv(&mut meta, &mut bufs) {
                Ok(n) => {
                    let transmits: Vec<_> = bufs.drain(..n)
                        .zip(meta.iter())
                        .map(|(sg, m)| Transmit {
                            destination: m.src,
                            ecn:          None,
                            contents:     sg.freeze(),
                            segment_size: None,
                            src_ip:       None,
                        })
                        .collect();
                    server.send(transmits);
                    server.drain_completions();
                    break;
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => panic!("server recv: {e}"),
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
}
