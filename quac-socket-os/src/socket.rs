use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;

use socket2::{Domain, Protocol, Socket, Type};

#[cfg(unix)]
use std::os::fd::{AsFd, BorrowedFd};
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, RawFd};

use quac_socket::{PacketBufMut, PacketSocket, RecvMeta, ScatterGather, Transmit};

#[cfg(not(target_os = "linux"))]
use crate::buffers::{alloc_recv_buf, RecvBuf};
use crate::buffers::{OsBuf, OsBufMut, OsPool, IPV4_MAX_UDP_PAYLOAD, IPV6_MAX_UDP_PAYLOAD};
#[cfg(target_os = "linux")]
use crate::debug::zc_log_enabled;
use crate::debug::{hex_prefix, log_enabled, log_socket_send_datagram};
#[cfg(target_os = "linux")]
use quac_socket::net::{sockaddr_from_socketaddr, socketaddr_from_raw};

/// Initial inline-segment guess used to size the cached `tx_iovs` Vec.
/// Real TX is typically 1–2 segments per packet; the SmallVec inline cap is 4.
/// `send` re-`reserve`s up front for any batch with more, so this is just the
/// steady-state lower bound.
#[cfg(target_os = "linux")]
const TX_IOV_INLINE: usize = 4;

// `SO_EE_ORIGIN_ZEROCOPY` and `SO_EE_CODE_ZEROCOPY_COPIED` come from
// <linux/errqueue.h> and aren't exposed by `libc` at the time of writing
// (only `SO_EE_ORIGIN_ICMP` and friends are). Hardcode them; values are
// stable kernel UAPI.
#[cfg(target_os = "linux")]
const SO_EE_ORIGIN_ZEROCOPY: u8 = 5;
#[cfg(target_os = "linux")]
const SO_EE_CODE_ZEROCOPY_COPIED: u8 = 1;

#[cfg(target_os = "linux")]
#[repr(C)]
struct SockExtendedErr {
    ee_errno: u32,
    ee_origin: u8,
    ee_type: u8,
    ee_code: u8,
    ee_pad: u8,
    ee_info: u32,
    ee_data: u32,
}

/// Build the recvmmsg / sendmmsg parallel-array state. All collections have
/// heap-stable backing addresses, and `*_hdrs[i].msg_hdr` is wired once here
/// to point at the matching `*_iovs[i]` / `*_addrs[i]`. The pointers stay
/// valid for the OsSocket's lifetime — none of the targets ever move on the
/// heap.
///
/// `recv_iovs[i].iov_base` and `iov_len` are NOT wired here: each `recv()`
/// call rewires them to point directly at the caller-supplied `OsBufMut`
/// storage, so the kernel deposits datagrams straight into user buffers
/// (no staging copy) and the kernel itself enforces `iov_len` against the
/// caller's capacity (no overflow risk).
#[cfg(target_os = "linux")]
#[allow(clippy::type_complexity)]
fn build_recv_state(batch: usize) -> (
    Box<[libc::sockaddr_storage]>,
    Box<[libc::iovec]>,
    Box<[libc::mmsghdr]>,
) {
    let mut recv_addrs: Box<[libc::sockaddr_storage]> =
        (0..batch).map(|_| unsafe { std::mem::zeroed() }).collect();
    let mut recv_iovs: Box<[libc::iovec]> = (0..batch)
        .map(|_| libc::iovec {
            iov_base: std::ptr::null_mut(),
            iov_len: 0,
        })
        .collect();
    let mut recv_hdrs: Box<[libc::mmsghdr]> =
        (0..batch).map(|_| unsafe { std::mem::zeroed() }).collect();

    // Wire msg_hdr → iov + addr. msg_iov / msg_name take *mutable* raw
    // pointers because the kernel writes through them on each `recvmmsg`.
    // Deriving them via `&raw mut` (rather than `&raw const … as *mut`)
    // keeps the write permission in the pointer's provenance, which Stacked
    // / Tree Borrows require for the kernel write to be sound. The targets
    // are heap-stable boxed slices held in the same `OsSocket`, so moving
    // the struct preserves these addresses.
    for i in 0..batch {
        let h = &mut recv_hdrs[i].msg_hdr;
        h.msg_iov = &raw mut recv_iovs[i];
        h.msg_iovlen = 1;
        h.msg_name = &raw mut recv_addrs[i] as *mut libc::c_void;
        h.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as u32;
    }

    (recv_addrs, recv_iovs, recv_hdrs)
}

/// Build the sendmmsg parallel-array state. Same idea as recv: heap-stable
/// boxed slices, wired once. Per `send()` call, only the leading `n` slots'
/// iov pointers, addresses, and namelen are overwritten — the other mmsghdr
/// fields (msg_control/msg_controllen/msg_flags) stay at the zero values
/// the kernel expects for sendmmsg.
///
/// `tx_iov_ranges` holds `(iov_start, iov_count)` per outgoing message —
/// indices into the variable-length `tx_iovs` Vec. Fixed-size since at most
/// `MAX_BATCH` messages are sent per call.
#[cfg(target_os = "linux")]
#[allow(clippy::type_complexity)]
fn build_send_state(batch: usize) -> (
    Box<[libc::sockaddr_storage]>,
    Box<[libc::mmsghdr]>,
    Box<[(usize, usize)]>,
) {
    let tx_addrs: Box<[libc::sockaddr_storage]> =
        (0..batch).map(|_| unsafe { std::mem::zeroed() }).collect();
    let tx_hdrs: Box<[libc::mmsghdr]> = (0..batch).map(|_| unsafe { std::mem::zeroed() }).collect();
    let tx_iov_ranges: Box<[(usize, usize)]> = (0..batch).map(|_| (0, 0)).collect();
    (tx_addrs, tx_hdrs, tx_iov_ranges)
}

/// Field declaration order is defensive: every `OsBuf`/`OsBufMut` carries
/// its own strong `Arc<OsPool>` inside its node (see `OsBufNode::pool`), so
/// the pool stays alive for as long as any buffer exists regardless of
/// struct field order. We still declare any field that may transitively
/// own an `OsBuf`/`OsBufMut` (today: `zc_in_flight`) before `pool` so the
/// drop sequence is "buffers first, pool second" by inspection — belt and
/// braces, not load-bearing for soundness.
pub struct OsSocket {
    socket: UdpSocket,
    queue_id: u16,
    /// Fallback single-datagram recv buffer (non-Linux).
    #[cfg(not(target_os = "linux"))]
    recv_buf: Box<RecvBuf>,
    /// Per-slot sender-address storage. `recv_hdrs[i].msg_hdr.msg_name`
    /// points at `recv_addrs[i]`; the kernel writes the source sockaddr
    /// here on each `recvmmsg`.
    #[cfg(target_os = "linux")]
    recv_addrs: Box<[libc::sockaddr_storage]>,
    /// Per-slot iovec; `recv_hdrs[i].msg_hdr.msg_iov` points at `recv_iovs[i]`.
    /// `iov_base` and `iov_len` are rewritten per `recv()` call to point
    /// directly into the caller-supplied `OsBufMut`s — no staging copy.
    #[cfg(target_os = "linux")]
    recv_iovs: Box<[libc::iovec]>,
    /// Contiguous `mmsghdr[]` passed directly to `recvmmsg`. Pre-wired in
    /// `build_recv_state`; only `msg_namelen` is reset before each call.
    #[cfg(target_os = "linux")]
    recv_hdrs: Box<[libc::mmsghdr]>,
    /// Raw fd cached to avoid a lock in every syscall.
    #[cfg(target_os = "linux")]
    raw_fd: RawFd,
    /// Whether SO_ZEROCOPY was successfully enabled on this socket.
    #[cfg(target_os = "linux")]
    zerocopy_enabled: bool,
    // ── send-side state. Long-lived addr / hdr / range storage (heap-stable
    // boxed slices, sized to BATCH at construction); per-call scratch only
    // for the variable-length iov array since segment counts are unbounded.
    #[cfg(target_os = "linux")]
    tx_iovs: Vec<libc::iovec>,
    #[cfg(target_os = "linux")]
    tx_iov_ranges: Box<[(usize, usize)]>,
    #[cfg(target_os = "linux")]
    tx_addrs: Box<[libc::sockaddr_storage]>,
    #[cfg(target_os = "linux")]
    tx_hdrs: Box<[libc::mmsghdr]>,
    /// Accepted transmit buffers held alive until zerocopy completion.
    /// Defensively declared before `pool` (see struct doc).
    #[cfg(target_os = "linux")]
    zc_in_flight: std::collections::VecDeque<Transmit<ScatterGather<OsBuf>>>,
    /// Buffer pool. Each `OsBuf`/`OsBufMut` carries its own `Arc<OsPool>`
    /// strong ref inside its node, so this field is not load-bearing for
    /// keeping the pool alive while buffers exist — see struct doc.
    pool: Arc<OsPool>,
}

// Safety: `iovec`/`mmsghdr` make several fields auto-derived `!Send`.
// * TX scratch (`tx_iovs` and the leading `n` slots of `tx_hdrs`/`tx_addrs`):
//   raw pointers are meaningful only during one `send` call, into either
//   caller-owned slices (segment iov bases) or this `OsSocket`'s own
//   heap-stable boxed slices (`tx_addrs`/`tx_hdrs` themselves).
// * RX long-lived state (`recv_hdrs`): each `recv_hdrs[i].msg_hdr` carries
//   a `msg_iov` pointer to `recv_iovs[i]` and an `msg_name` pointer to
//   `recv_addrs[i]`. `recv_iovs` and `recv_addrs` are heap-stable boxed
//   slices held in the same `OsSocket`, so moving the struct preserves the
//   heap addresses those pointers target.
// * RX per-call state (`recv_iovs[i].iov_base`/`iov_len`): rewritten on
//   every `recv()` call to point at the caller-supplied `OsBufMut`'s spare
//   capacity. The values are only meaningful within the duration of one
//   `recv()` call, similarly to the TX scratch case.
// The trait is `Send` but not `Sync`, so no in-flight pointer is ever
// observed across threads concurrently.
unsafe impl Send for OsSocket {}

impl OsSocket {
    pub fn bind(addr: SocketAddr, queue_id: u16) -> io::Result<Self> {
        let socket = UdpSocket::bind(addr)?;
        socket.set_nonblocking(true)?;
        Ok(Self::from_udp(socket, queue_id))
    }

    pub fn bind_reuseport(addr: SocketAddr, queue_id: u16) -> io::Result<Self> {
        let domain = if addr.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        };
        let sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
        #[cfg(unix)]
        sock.set_reuse_port(true)?;
        #[cfg(not(unix))]
        sock.set_reuse_address(true)?;
        sock.set_nonblocking(true)?;
        sock.bind(&addr.into())?;
        Ok(Self::from_udp(sock.into(), queue_id))
    }

    fn from_udp(socket: UdpSocket, queue_id: u16) -> Self {
        // Determine the max UDP payload from the socket's bound address family.
        // IPv4: 1500 − 20 − 8 = 1472; IPv6: 1500 − 40 − 8 = 1452.
        // Falls back to the conservative IPv6 value if local_addr fails.
        let max_payload = match socket.local_addr() {
            Ok(SocketAddr::V4(_)) => IPV4_MAX_UDP_PAYLOAD,
            _ => IPV6_MAX_UDP_PAYLOAD,
        };

        #[cfg(target_os = "linux")]
        let raw_fd = socket.as_raw_fd();

        #[cfg(target_os = "linux")]
        let zerocopy_enabled = {
            let val: libc::c_int = 1;
            unsafe {
                libc::setsockopt(
                    raw_fd,
                    libc::SOL_SOCKET,
                    libc::SO_ZEROCOPY,
                    &val as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&val) as libc::socklen_t,
                ) == 0
            }
        };

        // Forbid IP fragmentation on outgoing datagrams. With
        // `IP_PMTUDISC_DO` the kernel sets DF on every IPv4 packet and
        // returns `EMSGSIZE` instead of fragmenting; `IPV6_PMTUDISC_DO`
        // is the equivalent for v6 (no fragment header inserted). On the
        // recv side, oversized arrivals (which reassembled IP fragments
        // produce) trip `MSG_TRUNC` and are dropped in the recv loop, so
        // fragments are invisible to callers in both directions.
        //
        // Only the matching protocol level is configured: setting an IPv6
        // option on an IPv4-bound socket returns ENOPROTOOPT on Linux,
        // and vice versa. Skipping the inapplicable call avoids the
        // spurious log message that the "log all non-EAFNOSUPPORT errors"
        // policy would otherwise emit.
        #[cfg(target_os = "linux")]
        unsafe {
            if max_payload == IPV4_MAX_UDP_PAYLOAD {
                let v4: libc::c_int = libc::IP_PMTUDISC_DO;
                let r = libc::setsockopt(
                    raw_fd,
                    libc::IPPROTO_IP,
                    libc::IP_MTU_DISCOVER,
                    &v4 as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&v4) as libc::socklen_t,
                );
                if r != 0 {
                    let e = io::Error::last_os_error();
                    eprintln!("[quac-socket] IP_PMTUDISC_DO failed: {e}");
                }
            } else {
                let v6: libc::c_int = libc::IPV6_PMTUDISC_DO;
                let r = libc::setsockopt(
                    raw_fd,
                    libc::IPPROTO_IPV6,
                    libc::IPV6_MTU_DISCOVER,
                    &v6 as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&v6) as libc::socklen_t,
                );
                if r != 0 {
                    let e = io::Error::last_os_error();
                    eprintln!("[quac-socket] IPV6_PMTUDISC_DO failed: {e}");
                }
            }
        }

        #[cfg(target_os = "linux")]
        let batch = <OsSocket as PacketSocket>::MAX_BATCH;
        #[cfg(target_os = "linux")]
        let (recv_addrs, recv_iovs, recv_hdrs) = build_recv_state(batch);
        #[cfg(target_os = "linux")]
        let (tx_addrs, tx_hdrs, tx_iov_ranges) = build_send_state(batch);

        Self {
            socket,
            queue_id,
            #[cfg(not(target_os = "linux"))]
            recv_buf: alloc_recv_buf(),
            #[cfg(target_os = "linux")]
            recv_addrs,
            #[cfg(target_os = "linux")]
            recv_iovs,
            #[cfg(target_os = "linux")]
            recv_hdrs,
            #[cfg(target_os = "linux")]
            raw_fd,
            #[cfg(target_os = "linux")]
            zerocopy_enabled,
            #[cfg(target_os = "linux")]
            tx_iovs: Vec::with_capacity(batch * TX_IOV_INLINE),
            #[cfg(target_os = "linux")]
            tx_iov_ranges,
            #[cfg(target_os = "linux")]
            tx_addrs,
            #[cfg(target_os = "linux")]
            tx_hdrs,
            #[cfg(target_os = "linux")]
            zc_in_flight: std::collections::VecDeque::new(),
            pool: OsPool::with_max_payload(max_payload),
        }
    }

    /// Override the RX queue index used for QUIC-LB CID encoding / steering.
    pub fn set_queue_id(&mut self, queue_id: u16) {
        self.queue_id = queue_id;
    }

    /// Duplicate the underlying file descriptor so that the reader and writer
    /// threads can each hold their own [`OsSocket`] backed by the same kernel
    /// socket. Both halves share the SO_REUSEPORT slot; only the reader half
    /// calls `recv` and only the writer half calls `send`.
    pub fn try_clone(&self) -> io::Result<Self> {
        let cloned = self.socket.try_clone()?;
        Ok(Self::from_udp(cloned, self.queue_id))
    }
}

impl PacketSocket for OsSocket {
    type Pool = OsPool;

    /// Comfortable practical ceiling for `sendmmsg` scatter-gather. Linux's
    /// kernel limit is `UIO_MAXIOV = 1024`, but no QUIC workload realistically
    /// builds anywhere near that many segments per datagram. 64 is plenty of
    /// headroom while still letting callers detect contract violations early.
    const MAX_SEGMENTS: usize = 64;

    /// Linux recv caps at `BATCH = 64` (size of the pre-allocated `mmsghdr`
    /// array). Non-Linux recv loops up to `min(meta.len(), bufs.len())`
    /// packets but 64 is a reasonable suggestion.
    const MAX_BATCH: usize = 64;

    fn pool(&self) -> &Arc<OsPool> {
        &self.pool
    }

    #[cfg(target_os = "linux")]
    fn send(&mut self, transmits: &mut Vec<Transmit<ScatterGather<OsBuf>>>) -> io::Result<usize> {
        if transmits.is_empty() {
            return Ok(0);
        }
        check_transmit_invariants::<Self>(transmits);

        let mut total_sent = 0;

        while !transmits.is_empty() {
            // Recompute every iteration so the ENOBUFS recovery path
            // (which sets `zerocopy_enabled = false` then `continue`s) actually
            // disables MSG_ZEROCOPY on the retry.
            let flags = libc::MSG_DONTWAIT
                | if self.zerocopy_enabled {
                    libc::MSG_ZEROCOPY
                } else {
                    0
                };
            let n = transmits.len().min(Self::MAX_BATCH);
            let chunk = &transmits[..n];

            // Pass 1: flat iov array — one entry per segment across all messages.
            // Reserve up front so `as_mut_ptr()` stays stable for the whole call.
            let total_segs: usize = chunk.iter().map(|t| t.contents.segments.len()).sum();
            self.tx_iovs.clear();
            self.tx_iovs.reserve(total_segs);

            for (i, t) in chunk.iter().enumerate() {
                let start = self.tx_iovs.len();
                for seg in &t.contents.segments {
                    let slice = seg.as_slice();
                    self.tx_iovs.push(libc::iovec {
                        iov_base: slice.as_ptr() as *mut libc::c_void,
                        iov_len: slice.len(),
                    });
                }
                self.tx_iov_ranges[i] = (start, self.tx_iovs.len() - start);
            }
            debug_assert!(self.tx_iovs.len() == total_segs);

            // Pass 2: write the leading `n` slots of the pre-allocated
            // tx_addrs / tx_hdrs / tx_iov_ranges Box<[T]>. msg_control /
            // msg_controllen / msg_flags stay at their initial zero, which
            // is what the kernel expects for sendmmsg.
            let iov_base = self.tx_iovs.as_mut_ptr();
            let ranges = &self.tx_iov_ranges[..n];
            let addrs = &mut self.tx_addrs[..n];
            let hdrs = &mut self.tx_hdrs[..n];
            for (((t, &(iov_start, iov_count)), addr), hdr) in chunk
                .iter()
                .zip(ranges.iter())
                .zip(addrs.iter_mut())
                .zip(hdrs.iter_mut())
            {
                let addr_len = sockaddr_from_socketaddr(&t.destination, addr);
                let addr_ptr: *mut libc::sockaddr_storage = addr;
                let m = &mut hdr.msg_hdr;
                m.msg_iov = unsafe { iov_base.add(iov_start) };
                m.msg_iovlen = iov_count as _;
                m.msg_name = addr_ptr as *mut libc::c_void;
                m.msg_namelen = addr_len;
            }

            let ret = unsafe {
                libc::sendmmsg(
                    self.raw_fd,
                    self.tx_hdrs.as_mut_ptr(),
                    n as libc::c_uint,
                    flags,
                )
            };

            if ret < 0 {
                let e = io::Error::last_os_error();
                if log_enabled() {
                    eprintln!("[quic-socket send] sendmmsg error: {e}");
                }
                if zc_log_enabled() {
                    eprintln!(
                        "[zc] send: sendmmsg ret=-1 errno={} ({e})",
                        e.raw_os_error().unwrap_or(0)
                    );
                }
                // ENOBUFS with MSG_ZEROCOPY: the kernel's zerocopy notification
                // queue is exhausted (e.g. memlock pin limits hit). Disable
                // zerocopy and retry without MSG_ZEROCOPY so connections don't
                // stall forever. Nothing was sent on this iteration, so no
                // drain is needed before retrying.
                if self.zerocopy_enabled && e.raw_os_error() == Some(libc::ENOBUFS) {
                    self.zerocopy_enabled = false;
                    if zc_log_enabled() {
                        eprintln!("[zc] ENOBUFS: disabling zerocopy, retrying batch plain");
                    }
                    continue;
                }
                break;
            }

            let sent = ret as usize;
            for t in chunk.iter().take(sent) {
                log_socket_send_datagram(t);
            }

            // Drain accepted entries from the front. For zerocopy mode they
            // move into `zc_in_flight` (kernel still owns the bytes until
            // completion); for plain mode they drop (kernel has already copied).
            if self.zerocopy_enabled {
                for t in transmits.drain(..sent) {
                    self.zc_in_flight.push_back(t);
                }
            } else {
                transmits.drain(..sent);
            }

            total_sent += sent;
            if sent < n {
                // Kernel signaled a soft limit (e.g. WouldBlock on subsequent
                // packets). Don't loop further this call; caller can retry.
                break;
            }
        }

        if zc_log_enabled() {
            eprintln!(
                "[zc] send: sent={} unsent={} zc_in_flight={} zerocopy={}",
                total_sent,
                transmits.len(),
                self.zc_in_flight.len(),
                self.zerocopy_enabled,
            );
        }

        Ok(total_sent)
    }

    #[cfg(not(target_os = "linux"))]
    fn send(&mut self, transmits: &mut Vec<Transmit<ScatterGather<OsBuf>>>) -> io::Result<usize> {
        if transmits.is_empty() {
            return Ok(0);
        }
        check_transmit_invariants::<Self>(transmits);
        let mut sent = 0;
        for t in transmits.iter() {
            let result = if t.contents.segments.len() == 1 {
                let data = t.contents.segments[0].as_slice();
                self.socket.send_to(data, t.destination)
            } else {
                let mut tmp = Vec::with_capacity(t.contents.total_len());
                for seg in &t.contents.segments {
                    tmp.extend_from_slice(seg.as_slice());
                }
                self.socket.send_to(&tmp, t.destination)
            };
            match result {
                Ok(_) => {
                    log_socket_send_datagram(t);
                    sent += 1;
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => {
                    if log_enabled() {
                        eprintln!("[quic-socket send] send_to error: {e}");
                    }
                    break;
                }
            }
        }
        // Kernel already copied the sent datagrams; drop them.
        transmits.drain(..sent);
        Ok(sent)
    }

    fn drain_completions(&mut self) {
        #[cfg(target_os = "linux")]
        {
            if self.zc_in_flight.is_empty() {
                return;
            }
            let before = self.zc_in_flight.len();
            // Each recvmsg on MSG_ERRQUEUE delivers a sock_extended_err covering
            // a range [ee_info, ee_data] (inclusive) of zerocopy notification IDs.
            // Pop that many transmits from the front of the in-flight queue; the
            // IDs are assigned in submission order so the front is always oldest.
            //
            // If the kernel signals SO_EE_CODE_ZEROCOPY_COPIED (it fell back to
            // copying — e.g. loopback, or small packets), disable zerocopy for all
            // future sends. There is no benefit from paying the page-pinning and
            // error-queue overhead when the kernel copies anyway.
            let mut msg_buf = [0u8; 1];
            let mut iov = libc::iovec {
                iov_base: msg_buf.as_mut_ptr() as *mut libc::c_void,
                iov_len: 1,
            };
            let mut cmsg_buf = [0u8; 64];
            loop {
                let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
                msg.msg_iov = &mut iov;
                msg.msg_iovlen = 1;
                msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
                msg.msg_controllen = cmsg_buf.len() as _;
                let ret = unsafe {
                    libc::recvmsg(
                        self.raw_fd,
                        &mut msg,
                        libc::MSG_ERRQUEUE | libc::MSG_DONTWAIT,
                    )
                };
                if ret < 0 {
                    break;
                }
                let cm = unsafe { libc::CMSG_FIRSTHDR(&msg) };
                if cm.is_null() {
                    continue;
                }
                // Read the sock_extended_err payload via read_unaligned: the
                // kernel ABI aligns control-message payloads, but Rust's
                // pointer-deref UB rules don't take that on faith.
                let serr: SockExtendedErr = unsafe {
                    std::ptr::read_unaligned(libc::CMSG_DATA(cm) as *const SockExtendedErr)
                };
                if serr.ee_origin == SO_EE_ORIGIN_ZEROCOPY {
                    let was_zc = self.zerocopy_enabled;
                    if serr.ee_code == SO_EE_CODE_ZEROCOPY_COPIED {
                        // Kernel is copying; zerocopy yields no benefit here.
                        self.zerocopy_enabled = false;
                    }
                    let lo = serr.ee_info;
                    let hi = serr.ee_data;
                    let count = hi.wrapping_sub(lo).wrapping_add(1) as usize;
                    for _ in 0..count {
                        self.zc_in_flight.pop_front();
                    }
                    if zc_log_enabled() {
                        eprintln!(
                            "[zc] drain: freed={} (ids {}..={}) zc_in_flight_before={} after={} zerocopy_was={} now={}",
                            count, lo, hi, before, self.zc_in_flight.len(), was_zc, self.zerocopy_enabled,
                        );
                    }
                }
            }
        }
    }

    /// Receive a batch of UDP datagrams.
    ///
    /// Returns the number of valid datagrams written into the leading slots of
    /// `meta` and `bufs`. This is a **post-compaction** count: datagrams that
    /// the kernel flagged `MSG_TRUNC` (oversized relative to the caller's buffer
    /// capacity, e.g. IP-reassembled fragments) are dropped silently and do not
    /// contribute to the returned count. The valid datagrams are always packed
    /// into slots `[0..n)`.
    #[cfg(target_os = "linux")]
    fn recv(&mut self, meta: &mut [RecvMeta], bufs: &mut [OsBufMut]) -> io::Result<usize> {
        let count = meta.len().min(bufs.len()).min(self.recv_hdrs.len());
        if count == 0 {
            return Ok(0);
        }

        // Pre-loop: wire the matching iov from each `OsBufMut`'s cached
        // `(data_ptr, data_cap)` — set in `OsPool::alloc` after any capacity
        // grow and stable for the wrapper's lifetime. We do NOT need to
        // `set_filled(0)` first: the iov points at the slab start with
        // `iov_len = capacity`, so the kernel writes from offset 0
        // regardless of any prior `data.len`, and the post-recv
        // `set_filled(msg_len)` overwrites the length. The kernel's iov
        // bound prevents writes past `data_cap`, so a too-small caller
        // buffer is kernel-truncated (MSG_TRUNC handled below) rather
        // than overflowing.
        //
        // This loop touches only the wrapper struct (no heap-scattered
        // `OsBufNode` deref) — sequential reads + writes, prefetcher-friendly.
        let iovs = &mut self.recv_iovs[..count];
        for (b, iov) in bufs[..count].iter().zip(iovs.iter_mut()) {
            iov.iov_base = b.data_ptr() as *mut libc::c_void;
            iov.iov_len = b.capacity();
        }

        // Reset msg_namelen so the kernel knows the input size of each address
        // buffer (it writes back the actual length used). msg_len is pure
        // kernel output — no reset needed. The pre-wired msg_iov / msg_iovlen
        // / msg_name / msg_control fields stay valid across calls.
        for hdr in &mut self.recv_hdrs[..count] {
            hdr.msg_hdr.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as u32;
        }

        let ret = unsafe {
            libc::recvmmsg(
                self.raw_fd,
                self.recv_hdrs.as_mut_ptr(),
                count as libc::c_uint,
                libc::MSG_DONTWAIT,
                std::ptr::null_mut(),
            )
        };

        if ret < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::WouldBlock {
                return Ok(0);
            }
            return Err(e);
        }

        let received = ret as usize;

        if log_enabled() {
            if received > 0 {
                eprintln!("[quic-socket] recv(recvmmsg): got {received} datagram(s)");
            } else {
                eprintln!("[quic-socket] recv(recvmmsg): no datagram (empty batch)");
            }
        }

        if zc_log_enabled() && received > 0 {
            eprintln!("[zc] recv: {received} datagram(s)");
        }

        // Walk the leading `received` slots, dropping any datagram the
        // kernel marked MSG_TRUNC (oversized for our `iov_len`, including
        // any IP-fragmented arrival the kernel reassembled into something
        // larger than our MTU-sized buffer). Valid packets are compacted
        // to the leading slots of `meta` / `bufs` via slice swaps; the
        // returned count is the post-compaction valid count.
        let hdrs = &self.recv_hdrs[..received];
        let addrs = &self.recv_addrs[..received];

        let mut valid = 0;
        for i in 0..received {
            let hdr = &hdrs[i];
            if hdr.msg_hdr.msg_flags & libc::MSG_TRUNC != 0 {
                // The kernel wrote to bufs[i]'s backing slab via the iov
                // wired in the pre-loop, but we never call set_filled for
                // this slot. bufs[i]'s length is unchanged from before this
                // recv call: 0 for a freshly-allocated buffer (pool alloc
                // calls data.clear()), or the previous recv round's msg_len
                // for a reused buffer. Either way the slot is not placed in
                // the [0..valid) range so the caller will never observe it.
                continue;
            }
            let msg_len = hdr.msg_len as usize;
            // Unreachable for UDP `recvmmsg` in normal operation: the kernel
            // always writes a v4 or v6 sockaddr. If we ever do see something
            // unrecognised (kernel bug, raw-socket re-injection, etc.), drop
            // the slot and keep the rest of the batch.
            let src = match socketaddr_from_raw(
                &addrs[i] as *const _ as *const libc::sockaddr,
                hdr.msg_hdr.msg_namelen,
            ) {
                Some(s) => s,
                None => continue,
            };

            // Bring this packet's buffer into the contiguous valid prefix.
            // The OsBufMut wrapper that received the kernel's bytes was at
            // slot i; after swap it sits at slot `valid`.
            if valid != i {
                bufs.swap(valid, i);
            }
            // Kernel wrote msg_len bytes into the wrapper now at slot `valid`;
            // commit the length.
            unsafe { bufs[valid].set_filled(msg_len) };

            let mut new_m = RecvMeta::default();
            new_m.src = src;
            new_m.len = msg_len as u16;
            new_m.stride = msg_len as u16;
            meta[valid] = new_m;

            valid += 1;
        }

        if log_enabled() {
            if valid < received {
                eprintln!(
                    "[quic-socket recv] dropped {} oversized/fragment datagram(s)",
                    received - valid,
                );
            }
            for (m, b) in meta.iter().zip(bufs.iter()).take(valid) {
                let payload = b.filled();
                eprintln!(
                    "[quic-socket recv] from {} len={} bytes=[{}]",
                    m.src,
                    m.len,
                    hex_prefix(payload, 24),
                );
            }
        }

        Ok(valid)
    }

    #[cfg(not(target_os = "linux"))]
    fn recv(&mut self, meta: &mut [RecvMeta], bufs: &mut [OsBufMut]) -> io::Result<usize> {
        let batch = meta.len().min(bufs.len());
        if batch == 0 {
            return Ok(0);
        }
        let mut count = 0;
        // `total` caps the number of recv_from syscalls per call to `batch`,
        // regardless of how many datagrams are truncated and discarded. Without
        // this cap a flood of oversized packets would cause unbounded draining
        // of the kernel receive queue on each recv() call (DoS, P1).
        let mut total = 0usize;
        while count < batch {
            if total >= batch {
                break;
            }
            total += 1;
            match self.socket.recv_from(&mut self.recv_buf.0) {
                Ok((len, src)) => {
                    let b = &mut bufs[count];
                    // See Linux recv: reset filled length so spare covers the
                    // whole slab, even on recycled buffers.
                    unsafe { b.set_filled(0) };
                    let dst = b.uninit_mut();
                    // Mirror the Linux MSG_TRUNC drop policy: if the datagram
                    // doesn't fit in the caller's buffer, drop it without
                    // surfacing a partial copy. Closes the heap-overflow
                    // window the previous `debug_assert!` left open in
                    // release builds, and matches the "no fragments" stance
                    // (any UDP datagram bigger than the caller's MTU-sized
                    // buffer is treated as oversize / fragment-derived).
                    if len > dst.len() {
                        continue;
                    }
                    unsafe {
                        std::ptr::copy_nonoverlapping(
                            self.recv_buf.0.as_ptr(),
                            dst.as_mut_ptr() as *mut u8,
                            len,
                        );
                        b.set_filled(len);
                    }
                    let mut m = RecvMeta::default();
                    m.src = src;
                    m.len = len as u16;
                    m.stride = len as u16;
                    meta[count] = m;
                    count += 1;
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e),
            }
        }
        if log_enabled() {
            if count > 0 {
                eprintln!("[quic-socket] recv(recv_from): got {count} datagram(s)");
                for (m, b) in meta.iter().zip(bufs.iter()).take(count) {
                    let payload = b.filled();
                    eprintln!(
                        "[quic-socket recv] from {} len={} bytes=[{}]",
                        m.src,
                        m.len,
                        hex_prefix(payload, 24),
                    );
                }
            } else {
                eprintln!("[quic-socket] recv(recv_from): no datagram (would block)");
            }
        }
        Ok(count)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    fn queue_id(&self) -> u16 {
        self.queue_id
    }

    #[cfg(unix)]
    fn rx_fd(&self) -> Option<BorrowedFd<'_>> {
        Some(self.socket.as_fd())
    }
}

/// Panic if any transmit violates `S::MAX_SEGMENTS` or `S::MAX_GSO`. Catches
/// caller contract violations before any I/O state is mutated, so retries
/// with a corrected batch are still possible.
#[inline]
fn check_transmit_invariants<S: PacketSocket>(
    transmits: &[Transmit<ScatterGather<<S::Pool as quac_socket::BufferPool>::Buf>>],
) {
    for (i, t) in transmits.iter().enumerate() {
        let n = t.contents.segments.len();
        assert!(
            n <= S::MAX_SEGMENTS,
            "transmits[{i}] has {n} segments but {ty}::MAX_SEGMENTS is {max}",
            ty = std::any::type_name::<S>(),
            max = S::MAX_SEGMENTS,
        );
        if S::MAX_GSO == 1 {
            assert!(
                t.segment_size == 0,
                "transmits[{i}] has segment_size={} but {ty}::MAX_GSO is 1 (GSO not supported)",
                t.segment_size,
                ty = std::any::type_name::<S>(),
            );
        }
    }
}


#[cfg(test)]
mod tests {
    use std::io;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
    use std::time::{Duration, Instant};

    use quac_socket::{
        BufferPool, EcnCodepoint, PacketBufMut, PacketSocket, RecvMeta, ScatterGather, Segment,
        Transmit,
    };
    use smallvec::{smallvec, SmallVec};

    use super::OsSocket;
    use crate::buffers::{IPV4_MAX_UDP_PAYLOAD, IPV6_MAX_UDP_PAYLOAD};
    use crate::{OsBuf, OsBufMut};

    fn send_one(sock: &mut OsSocket, dest: SocketAddr, payload: &[u8]) -> bool {
        let buf = OsBuf::from_slice(payload);
        let len = payload.len() as u32;
        let mut transmits = vec![Transmit::new(
            ScatterGather {
                segments: smallvec![Segment::new(buf, 0, len).expect("valid segment")],
            },
            dest,
        )];
        sock.send(&mut transmits).map(|n| n == 1).unwrap_or(false)
    }

    fn recv_batch(sock: &mut OsSocket) -> io::Result<Vec<(SocketAddr, Vec<u8>)>> {
        let mut meta = vec![RecvMeta::default(); 64];
        let mut bufs = Vec::new();
        sock.pool().alloc(2048, 64, &mut bufs);
        let n = sock.recv(&mut meta, &mut bufs)?;
        let mut out = Vec::with_capacity(n);
        for i in 0..n {
            let m = &meta[i];
            let payload = bufs[i].filled().to_vec();
            assert_eq!(m.len as usize, payload.len());
            out.push((m.src, payload));
        }
        Ok(out)
    }

    fn recv_until(
        sock: &mut OsSocket,
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
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "timed out waiting for datagram",
        ))
    }

    /// Best-effort: free an ephemeral UDP port on loopback for reuseport binds.
    fn reserve_loopback_udp_port() -> u16 {
        let s = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind probe");
        let port = s.local_addr().expect("local_addr").port();
        drop(s);
        std::thread::sleep(Duration::from_millis(20));
        port
    }

    #[test]
    fn send_recv_roundtrip() {
        let mut a = OsSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), 0).unwrap();
        let mut b = OsSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), 0).unwrap();
        let b_addr = b.local_addr().unwrap();
        let a_addr = a.local_addr().unwrap();

        let payload = b"hello-quic-socket";
        assert!(send_one(&mut a, b_addr, payload));

        let deadline = Instant::now() + Duration::from_secs(2);
        let (src, data) = recv_until(&mut b, payload, deadline).unwrap();
        assert_eq!(data, payload);
        assert_eq!(src.ip(), a_addr.ip());
        assert_eq!(src.port(), a_addr.port());

        b.drain_completions();
        a.drain_completions();
    }

    #[test]
    fn send_recv_multiple_datagrams_sequential() {
        let mut server = OsSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), 0).unwrap();
        let mut client = OsSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), 0).unwrap();
        let server_addr = server.local_addr().unwrap();

        for i in 0u8..16 {
            assert!(send_one(&mut client, server_addr, &[i]));
            let deadline = Instant::now() + Duration::from_secs(2);
            let (_, data) = recv_until(&mut server, &[i], deadline).unwrap();
            assert_eq!(data, [i]);
        }
    }

    #[test]
    fn open_close_many_sockets() {
        for _ in 0..32 {
            let sock = OsSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), 0).unwrap();
            let _ = sock.local_addr().unwrap();
        }
    }

    #[test]
    fn sequential_bind_same_ephemeral_pattern() {
        // Repeated bind to ephemeral ports (different port each time) exercises drop + open.
        let mut ports = Vec::new();
        for _ in 0..8 {
            let s = OsSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), 0).unwrap();
            ports.push(s.local_addr().unwrap().port());
        }
        assert_eq!(
            ports.len(),
            ports.iter().collect::<std::collections::HashSet<_>>().len()
        );
    }

    #[test]
    fn set_queue_id_round_trips_via_trait() {
        // queue_id set at construction
        let s = OsSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), 42).unwrap();
        assert_eq!(PacketSocket::queue_id(&s), 42);
        // post-construction override via setter
        let mut s = OsSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), 0).unwrap();
        s.set_queue_id(7);
        assert_eq!(PacketSocket::queue_id(&s), 7);
    }

    /// Two sockets may share one UDP port when `SO_REUSEPORT` is set (Unix).
    #[cfg(unix)]
    #[test]
    fn reuseport_two_sockets_receive_datagrams() {
        let port = reserve_loopback_udp_port();
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));

        let mut first = OsSocket::bind_reuseport(addr, 0).unwrap();
        let mut second = OsSocket::bind_reuseport(addr, 0).unwrap();
        assert_eq!(first.local_addr().unwrap().port(), port);
        assert_eq!(second.local_addr().unwrap().port(), port);

        let mut sender = OsSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), 0).unwrap();
        const COUNT: usize = 48;
        for i in 0..COUNT {
            let payload = [i as u8];
            assert!(send_one(&mut sender, addr, &payload), "send {i}");
        }

        let deadline = Instant::now() + Duration::from_secs(5);
        let mut got = 0usize;
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
            "kernel should deliver all datagrams across reuseport listeners"
        );
    }

    /// Regression for the OsSocket field drop-order fix (§1.1):
    /// dropping a socket with non-empty `zc_in_flight` must not UAF on the
    /// freed pool. Without the fix, the OsBufs would call `(*pool).push(..)`
    /// on already-freed memory.
    #[cfg(target_os = "linux")]
    #[test]
    fn drop_does_not_uaf_with_in_flight_zerocopy() {
        // Drop the receiver first; sends to its closed port go into the kernel
        // queue and (if zerocopy was negotiated) accumulate in `zc_in_flight`.
        let recv_addr = {
            let receiver =
                OsSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), 0).expect("bind receiver");
            receiver.local_addr().unwrap()
        };

        let mut sender =
            OsSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), 0).expect("bind sender");
        for i in 0u8..16 {
            let _ = send_one(&mut sender, recv_addr, &[i; 64]);
        }

        // Drop without calling drain_completions. Test passes if the process
        // doesn't crash; ASan/valgrind will catch a regression.
        drop(sender);
    }

    /// Regression for the recv buffer-reuse fix: reusing a `bufs` slice across
    /// multiple `recv` calls must not return stale bytes. On Linux the iov is
    /// always wired to offset 0 of the data allocation so the kernel overwrites
    /// from the start regardless of prior fill; `set_filled(msg_len)` then
    /// commits the correct length. On non-Linux `set_filled(0)` resets the fill
    /// before the copy. Either way, `filled()` must return only the new payload.
    #[test]
    fn recv_buffer_reuse_does_not_truncate() {
        let mut server = OsSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), 0).unwrap();
        let mut client = OsSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), 0).unwrap();
        let server_addr = server.local_addr().unwrap();

        // Allocate bufs ONCE, reuse across rounds.
        let mut bufs: Vec<OsBufMut> = Vec::with_capacity(8);
        server.pool().alloc(2048, 8, &mut bufs);
        let mut meta = vec![RecvMeta::default(); 8];

        for round in 0..3u8 {
            let payload = vec![round; 100];
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

    // ── Multi-segment scatter-gather (P1) ─────────────────────────────────────

    fn send_segments(sock: &mut OsSocket, dest: SocketAddr, segs: &[&[u8]]) -> bool {
        let mut sv: SmallVec<[Segment<OsBuf>; 4]> = SmallVec::new();
        for s in segs {
            let buf = OsBuf::from_slice(s);
            let len = s.len() as u32;
            sv.push(Segment::new(buf, 0, len).expect("valid segment"));
        }
        let mut transmits = vec![Transmit::new(ScatterGather { segments: sv }, dest)];
        sock.send(&mut transmits).map(|n| n == 1).unwrap_or(false)
    }

    #[test]
    fn send_recv_two_segment_scatter_gather() {
        let mut server = OsSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), 0).unwrap();
        let mut client = OsSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), 0).unwrap();
        let server_addr = server.local_addr().unwrap();

        assert!(send_segments(&mut client, server_addr, &[b"AB", b"CD"]));

        let deadline = Instant::now() + Duration::from_secs(2);
        let (_, data) = recv_until(&mut server, b"ABCD", deadline).unwrap();
        assert_eq!(data, b"ABCD");
    }

    #[test]
    fn send_recv_five_segment_scatter_gather() {
        // 5 segments: one beyond the SmallVec inline cap of 4 → spills to heap.
        let mut server = OsSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), 0).unwrap();
        let mut client = OsSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), 0).unwrap();
        let server_addr = server.local_addr().unwrap();

        let segs: &[&[u8]] = &[b"S1-", b"S2-", b"S3-", b"S4-", b"END"];
        assert!(send_segments(&mut client, server_addr, segs));

        let want = b"S1-S2-S3-S4-END";
        let deadline = Instant::now() + Duration::from_secs(2);
        let (_, data) = recv_until(&mut server, want, deadline).unwrap();
        assert_eq!(data, want);
    }

    #[test]
    fn send_batch_mixed_segment_counts() {
        // Batch of 4 transmits with seg counts {1, 2, 1, 3} stresses the
        // tx_iov_ranges accounting.
        let mut server = OsSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), 0).unwrap();
        let mut client = OsSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), 0).unwrap();
        let server_addr = server.local_addr().unwrap();

        let groups: &[&[&[u8]]] = &[
            &[b"AAA"],
            &[b"BB", b"BB"],
            &[b"CCC"],
            &[b"D", b"DD", b"DDD"],
        ];
        let expected: Vec<Vec<u8>> = groups.iter().map(|g| g.concat()).collect();

        let mut transmits: Vec<Transmit<ScatterGather<OsBuf>>> = Vec::with_capacity(groups.len());
        for g in groups {
            let mut sv: SmallVec<[Segment<OsBuf>; 4]> = SmallVec::new();
            for s in *g {
                let buf = OsBuf::from_slice(s);
                let len = s.len() as u32;
                sv.push(Segment::new(buf, 0, len).expect("valid segment"));
            }
            transmits.push(Transmit::new(ScatterGather { segments: sv }, server_addr));
        }
        let n = client.send(&mut transmits).expect("send batch");
        assert_eq!(
            n,
            expected.len(),
            "all transmits should be accepted on loopback"
        );

        // Collect (datagram order is not strictly guaranteed across recvmmsg).
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut received: Vec<Vec<u8>> = Vec::new();
        while received.len() < expected.len() && Instant::now() < deadline {
            for (_, data) in recv_batch(&mut server).expect("recv batch") {
                received.push(data);
            }
            if received.len() < expected.len() {
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        received.sort();
        let mut sorted_expected = expected.clone();
        sorted_expected.sort();
        assert_eq!(received, sorted_expected);
    }

    // ── IPv6 + clone (P2) ────────────────────────────────────────────────────

    #[test]
    fn send_recv_ipv6_loopback() {
        let mut server = match OsSocket::bind(SocketAddr::from((Ipv6Addr::LOCALHOST, 0)), 0) {
            Ok(s) => s,
            // Skip the test if v6 is not configured in this environment.
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::AddrNotAvailable | io::ErrorKind::Unsupported
                ) =>
            {
                return
            }
            Err(e) => panic!("v6 bind: {e}"),
        };
        let mut client = OsSocket::bind(SocketAddr::from((Ipv6Addr::LOCALHOST, 0)), 0).unwrap();
        let server_addr = server.local_addr().unwrap();
        let client_addr = client.local_addr().unwrap();
        assert!(matches!(server_addr, SocketAddr::V6(_)));

        let payload = b"hello-v6";
        assert!(send_one(&mut client, server_addr, payload));

        let deadline = Instant::now() + Duration::from_secs(2);
        let (src, data) = recv_until(&mut server, payload, deadline).unwrap();
        assert_eq!(data, payload);
        assert!(matches!(src, SocketAddr::V6(_)), "v6 src expected");
        assert_eq!(src.port(), client_addr.port());
    }

    #[test]
    fn try_clone_shares_kernel_socket() {
        let mut sender = OsSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), 0).unwrap();
        let receiver = OsSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), 0).unwrap();
        let recv_addr = receiver.local_addr().unwrap();

        let mut clone = receiver.try_clone().expect("try_clone");
        assert_eq!(clone.local_addr().unwrap(), recv_addr);

        // Send via sender; recv via the cloned half — both halves share the fd.
        let payload = b"clone-routes";
        assert!(send_one(&mut sender, recv_addr, payload));

        let deadline = Instant::now() + Duration::from_secs(2);
        let (_, data) = recv_until(&mut clone, payload, deadline).unwrap();
        assert_eq!(data, payload);
    }

    // ── Edge inputs (P2) ─────────────────────────────────────────────────────

    #[test]
    fn recv_with_smaller_bufs_slice() {
        let mut server = OsSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), 0).unwrap();
        let mut client = OsSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), 0).unwrap();
        let server_addr = server.local_addr().unwrap();

        for i in 0u8..4 {
            assert!(send_one(&mut client, server_addr, &[i; 8]));
        }

        // bufs.len() = 2, meta.len() = 8 → recv must cap at 2.
        let mut meta = vec![RecvMeta::default(); 8];
        let mut bufs: Vec<OsBufMut> = Vec::with_capacity(2);
        server.pool().alloc(2048, 2, &mut bufs);

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
    fn send_empty_vec_returns_zero() {
        let mut sock = OsSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), 0).unwrap();
        let mut empty: Vec<Transmit<ScatterGather<OsBuf>>> = Vec::new();
        let n = sock.send(&mut empty).expect("send empty");
        assert_eq!(n, 0);
        assert!(empty.is_empty());
    }

    #[test]
    fn recv_empty_slices_returns_zero() {
        let mut sock = OsSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), 0).unwrap();
        let n = sock.recv(&mut [], &mut []).expect("recv empty");
        assert_eq!(n, 0);
    }

    #[test]
    fn recv_idle_socket_returns_zero() {
        let mut sock = OsSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), 0).unwrap();
        let mut meta = vec![RecvMeta::default(); 8];
        let mut bufs: Vec<OsBufMut> = Vec::new();
        sock.pool().alloc(2048, 8, &mut bufs);
        let n = sock.recv(&mut meta[..], &mut bufs[..]).expect("recv idle");
        assert_eq!(n, 0, "idle socket must return Ok(0), not an error");
    }

    /// Regression for the "always forbid IP fragments" policy: an oversized
    /// datagram (the on-the-wire signature of an IP-fragmented arrival the
    /// kernel reassembled) must be dropped — not surfaced as a truncated
    /// prefix — so QUIC packets that span fragments never reach auth code
    /// and the heap-overflow window from the original S1 stays closed even
    /// for callers that allocate sub-MTU buffers.
    #[test]
    fn recv_drops_oversized_datagram_as_fragment() {
        let mut server = OsSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), 0).unwrap();
        let mut client = OsSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), 0).unwrap();
        let server_addr = server.local_addr().unwrap();

        // Ship 1500B into a 100B buffer → kernel sets MSG_TRUNC on delivery.
        let oversized = vec![0xABu8; 1500];
        assert!(send_one(&mut client, server_addr, &oversized));

        let small_cap = 100;
        let mut meta = vec![RecvMeta::default(); 4];
        let mut bufs: Vec<OsBufMut> = Vec::with_capacity(4);
        server.pool().alloc(small_cap, 4, &mut bufs);

        // Drain anything that arrives within a brief window. The oversize
        // must be dropped and not contribute to `total`.
        let deadline = Instant::now() + Duration::from_millis(500);
        let mut total = 0usize;
        while Instant::now() < deadline {
            total += server.recv(&mut meta[..], &mut bufs[..]).expect("recv");
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(total, 0, "oversized datagram must be dropped silently");
        for b in &bufs {
            assert!(b.filled().is_empty(), "no buffer should be surfaced");
        }

        // Sanity: a properly-sized datagram still flows. Use a fresh
        // larger-cap pool draw via the helper so we exercise the normal path.
        let small = b"ok";
        assert!(send_one(&mut client, server_addr, small));
        let deadline2 = Instant::now() + Duration::from_secs(2);
        let (_, data) = recv_until(&mut server, small, deadline2).expect("small ok");
        assert_eq!(data, small);
    }

    // ── max_payload_size per address family (P3) ─────────────────────────────

    #[test]
    fn ipv4_socket_pool_reports_ipv4_max_payload() {
        let s = OsSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), 0).unwrap();
        assert_eq!(s.pool().max_payload_size(), IPV4_MAX_UDP_PAYLOAD);
    }

    #[test]
    fn ipv6_socket_pool_reports_ipv6_max_payload() {
        let s = match OsSocket::bind(SocketAddr::from((Ipv6Addr::LOCALHOST, 0)), 0) {
            Ok(s) => s,
            Err(_) => return, // skip if IPv6 is unavailable in this environment
        };
        assert_eq!(s.pool().max_payload_size(), IPV6_MAX_UDP_PAYLOAD);
    }

    // ── Lock-in for currently-no-op fields (P3) ──────────────────────────────

    #[test]
    fn recv_meta_ecn_dst_ip_currently_none() {
        // Regression guard: until we wire IP_PKTINFO/RECVTOS CMSGs, these
        // fields stay None. A future CMSG implementation will need to update
        // this test alongside.
        let mut server = OsSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), 0).unwrap();
        let mut client = OsSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), 0).unwrap();
        let server_addr = server.local_addr().unwrap();

        let payload = b"meta-fields";
        assert!(send_one(&mut client, server_addr, payload));

        let mut meta = vec![RecvMeta::default(); 1];
        let mut bufs: Vec<OsBufMut> = Vec::new();
        server.pool().alloc(2048, 1, &mut bufs);
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut got = 0;
        while got == 0 && Instant::now() < deadline {
            got = server.recv(&mut meta[..], &mut bufs[..]).unwrap();
            if got == 0 {
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        assert!(got >= 1);
        assert!(meta[0].ecn.is_none(), "ecn currently no-op");
        assert!(meta[0].dst_ip.is_none(), "dst_ip currently no-op");
    }

    #[test]
    fn transmit_ecn_src_ip_currently_ignored() {
        // Setting ecn/src_ip on a Transmit must not break the send — the
        // fields are silently dropped by the OS impl today. Receiver still
        // gets the bytes.
        let mut server = OsSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), 0).unwrap();
        let mut client = OsSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), 0).unwrap();
        let server_addr = server.local_addr().unwrap();

        let payload = b"ecn-srcip-ignored";
        let buf = OsBuf::from_slice(payload);
        let len = payload.len() as u32;
        let mut t = Transmit::new(
            ScatterGather {
                segments: smallvec![Segment::new(buf, 0, len).expect("seg")],
            },
            server_addr,
        );
        t.ecn = Some(EcnCodepoint::Ect0);
        t.src_ip = Some(IpAddr::V4(Ipv4Addr::LOCALHOST));
        let mut transmits = vec![t];
        let n = client.send(&mut transmits).expect("send");
        assert_eq!(n, 1);

        let deadline = Instant::now() + Duration::from_secs(2);
        let (_, data) = recv_until(&mut server, payload, deadline).unwrap();
        assert_eq!(data, payload);
    }

    #[test]
    #[should_panic(expected = "segment_size=1 but")]
    fn send_with_gso_segment_size_panics() {
        let mut sock = OsSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), 0).unwrap();
        let dest = sock.local_addr().unwrap();
        let buf = OsBuf::from_slice(b"hello");
        let len = b"hello".len() as u32;
        let mut t = Transmit::new(
            ScatterGather {
                segments: smallvec![Segment::new(buf, 0, len).unwrap()],
            },
            dest,
        );
        t.segment_size = 1; // non-zero segment_size with MAX_GSO == 1 → panic
        let mut transmits = vec![t];
        let _ = sock.send(&mut transmits);
    }
}
