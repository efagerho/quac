use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;

use socket2::{Domain, Protocol, Socket, Type};

#[cfg(unix)]
use std::os::fd::{AsRawFd, RawFd};

use smallvec::smallvec;

use quac_socket::{PacketSocket, RecvMeta, ScatterGather, Segment, Transmit};

use crate::buffers::{alloc_recv_buf, pop_recv_buf, OsBuf, OsBufMut, OsPool, RecvBuf};
#[cfg(target_os = "linux")]
use crate::buffers::MAX_DATAGRAM;
use crate::debug::{
    debug_socket_recv_enabled, hex_prefix, log_socket_send_datagram, socket_recv_log_enabled,
    trace_socket_enabled,
};
#[cfg(target_os = "linux")]
use crate::debug::zc_debug_enabled;

#[cfg(target_os = "linux")]
const BATCH: usize = 64;

#[cfg(target_os = "linux")]
const SO_ZEROCOPY: libc::c_int = 60;
#[cfg(target_os = "linux")]
const MSG_ZEROCOPY: libc::c_int = 0x4000000;
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

/// Per-slot storage for one in-flight recvmmsg datagram.
///
/// Each field must remain at a stable address for the lifetime of a recvmmsg
/// call: `iov` points into `buf`, and `hdr` points into both `iov` and `addr`.
/// Keeping them together in a pinned Box satisfies that invariant.
#[cfg(target_os = "linux")]
struct RecvSlot {
    /// Receive staging area.  `#[repr(align(64))]` ensures the first byte is
    /// 64-byte aligned so `OsBuf::from_aligned_slice` may assume src alignment.
    buf: Box<RecvBuf>,
    /// sockaddr storage for the sender address.
    addr: libc::sockaddr_storage,
    /// iovec pointing into `buf`.
    iov: libc::iovec,
    /// mmsghdr wrapping `iov` and `addr`.
    hdr: libc::mmsghdr,
}

// Safety: the raw pointers inside RecvSlot point only into the slot's own
// pinned allocation and are never accessed concurrently.
#[cfg(target_os = "linux")]
unsafe impl Send for RecvSlot {}

#[cfg(target_os = "linux")]
impl RecvSlot {
    fn new() -> Box<Self> {
        let buf = alloc_recv_buf();
        // Safety: the Box address is stable; we wire up the raw pointers below
        // and never move the Box after construction.
        let mut slot = Box::new(RecvSlot {
            buf,
            addr: unsafe { std::mem::zeroed() },
            iov: libc::iovec { iov_base: std::ptr::null_mut(), iov_len: 0 },
            hdr: unsafe { std::mem::zeroed() },
        });
        // Wire iov → buf
        slot.iov.iov_base = slot.buf.0.as_mut_ptr() as *mut libc::c_void;
        slot.iov.iov_len = MAX_DATAGRAM;
        // Wire hdr → iov + addr
        slot.hdr.msg_hdr.msg_iov = &raw mut slot.iov;
        slot.hdr.msg_hdr.msg_iovlen = 1;
        slot.hdr.msg_hdr.msg_name = &raw mut slot.addr as *mut libc::c_void;
        slot.hdr.msg_hdr.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as u32;
        slot
    }
}

pub struct OsSocket {
    socket: UdpSocket,
    pool: Arc<OsPool>,
    queue_id: u32,
    /// Fallback single-datagram recv buffer (non-Linux or batch disabled).
    #[cfg(not(target_os = "linux"))]
    recv_buf: Box<RecvBuf>,
    /// Pre-allocated recvmmsg slots (Linux).
    #[cfg(target_os = "linux")]
    recv_slots: Vec<Box<RecvSlot>>,
    /// Raw fd cached to avoid a lock in every syscall.
    #[cfg(target_os = "linux")]
    raw_fd: RawFd,
    /// Accepted transmit buffers held alive until zerocopy completion.
    #[cfg(target_os = "linux")]
    zc_in_flight: std::collections::VecDeque<Transmit<ScatterGather<OsBuf>>>,
    /// Whether SO_ZEROCOPY was successfully enabled on this socket.
    #[cfg(target_os = "linux")]
    zerocopy_enabled: bool,
}

impl OsSocket {
    pub fn bind(addr: SocketAddr) -> io::Result<Self> {
        let socket = UdpSocket::bind(addr)?;
        socket.set_nonblocking(true)?;
        Ok(Self::from_udp(socket))
    }

    pub fn bind_reuseport(addr: SocketAddr) -> io::Result<Self> {
        let domain = if addr.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
        let sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
        #[cfg(unix)]
        sock.set_reuse_port(true)?;
        #[cfg(not(unix))]
        sock.set_reuse_address(true)?;
        sock.set_nonblocking(true)?;
        sock.bind(&addr.into())?;
        Ok(Self::from_udp(sock.into()))
    }

    fn from_udp(socket: UdpSocket) -> Self {
        #[cfg(target_os = "linux")]
        let raw_fd = socket.as_raw_fd();

        #[cfg(target_os = "linux")]
        let zerocopy_enabled = {
            let val: libc::c_int = 1;
            unsafe {
                libc::setsockopt(
                    raw_fd,
                    libc::SOL_SOCKET,
                    SO_ZEROCOPY,
                    &val as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&val) as libc::socklen_t,
                ) == 0
            }
        };

        Self {
            #[cfg(target_os = "linux")]
            raw_fd,
            #[cfg(target_os = "linux")]
            recv_slots: (0..BATCH).map(|_| RecvSlot::new()).collect(),
            #[cfg(not(target_os = "linux"))]
            recv_buf: alloc_recv_buf(),
            pool: Arc::new(OsPool),
            queue_id: 0,
            socket,
            #[cfg(target_os = "linux")]
            zc_in_flight: std::collections::VecDeque::new(),
            #[cfg(target_os = "linux")]
            zerocopy_enabled,
        }
    }

    pub fn pool_handle(&self) -> Arc<OsPool> {
        Arc::clone(&self.pool)
    }

    /// Override the RX queue index used for QUIC-LB CID encoding / steering.
    pub fn set_queue_id(&mut self, queue_id: u32) {
        self.queue_id = queue_id;
    }

    /// Duplicate the underlying file descriptor so that the reader and writer
    /// threads can each hold their own [`OsSocket`] backed by the same kernel
    /// socket.  Both halves share the SO_REUSEPORT slot; only the reader half
    /// calls `recv` and only the writer half calls `send`.
    pub fn try_clone(&self) -> io::Result<Self> {
        let cloned = self.socket.try_clone()?;
        let mut s = Self::from_udp(cloned);
        s.queue_id = self.queue_id;
        Ok(s)
    }
}

impl PacketSocket for OsSocket {
    type Pool = OsPool;

    fn pool(&self) -> &OsPool {
        &self.pool
    }

    #[cfg(target_os = "linux")]
    fn send(
        &mut self,
        mut transmits: Vec<Transmit<ScatterGather<OsBuf>>>,
    ) -> Vec<Transmit<ScatterGather<OsBuf>>> {
        if transmits.is_empty() {
            return transmits;
        }

        let flags =
            libc::MSG_DONTWAIT | if self.zerocopy_enabled { MSG_ZEROCOPY } else { 0 };
        let mut total_sent = 0;
        let mut offset = 0;

        while offset < transmits.len() {
            let n = (transmits.len() - offset).min(BATCH);
            let chunk = &transmits[offset..offset + n];

            // Pass 1: flat iov array — one entry per segment across all messages.
            // Pre-allocate to the exact size so the Vec never reallocates, keeping
            // the pointers wired into hdrs stable for the duration of sendmmsg.
            let total_segs: usize = chunk.iter().map(|t| t.contents.segments.len()).sum();
            let mut all_iovs: Vec<libc::iovec> = Vec::with_capacity(total_segs);
            let mut iov_ranges: Vec<(usize, usize)> = Vec::with_capacity(n);

            for t in chunk.iter() {
                let start = all_iovs.len();
                for seg in &t.contents.segments {
                    let slice = &seg.buf.as_ref()[seg.offset..seg.offset + seg.len];
                    all_iovs.push(libc::iovec {
                        iov_base: slice.as_ptr() as *mut libc::c_void,
                        iov_len: slice.len(),
                    });
                }
                iov_ranges.push((start, all_iovs.len() - start));
            }

            // Pass 2: build mmsghdr array; all_iovs is fully populated and stable.
            let iov_base = all_iovs.as_mut_ptr();
            let mut addrs: Vec<libc::sockaddr_storage> =
                vec![unsafe { std::mem::zeroed() }; n];
            let mut hdrs: Vec<libc::mmsghdr> = vec![unsafe { std::mem::zeroed() }; n];
            for i in 0..n {
                let (iov_start, iov_count) = iov_ranges[i];
                let addr_len =
                    sockaddr_from_socketaddr(&chunk[i].destination, &mut addrs[i]);
                hdrs[i].msg_hdr.msg_iov = unsafe { iov_base.add(iov_start) };
                hdrs[i].msg_hdr.msg_iovlen = iov_count as _;
                hdrs[i].msg_hdr.msg_name = &raw mut addrs[i] as *mut libc::c_void;
                hdrs[i].msg_hdr.msg_namelen = addr_len;
            }

            let ret = unsafe {
                libc::sendmmsg(self.raw_fd, hdrs.as_mut_ptr(), n as libc::c_uint, flags)
            };

            if ret < 0 {
                let e = io::Error::last_os_error();
                if trace_socket_enabled() {
                    eprintln!("[quic-socket send] sendmmsg error: {e}");
                }
                if zc_debug_enabled() {
                    eprintln!("[zc] send: sendmmsg ret=-1 errno={} ({e})", e.raw_os_error().unwrap_or(0));
                }
                // ENOBUFS with MSG_ZEROCOPY means the kernel's zerocopy notification
                // queue is exhausted (e.g. under perf, or when pin limits are hit).
                // Disable zerocopy and retry this batch with plain MSG_DONTWAIT so
                // the server can still respond and connections don't stall forever.
                if self.zerocopy_enabled && e.raw_os_error() == Some(libc::ENOBUFS) {
                    self.zerocopy_enabled = false;
                    // Drain any in-flight zerocopy buffers before switching modes.
                    for t in transmits.drain(..total_sent) {
                        self.zc_in_flight.push_back(t);
                    }
                    if zc_debug_enabled() {
                        eprintln!("[zc] ENOBUFS: disabling zerocopy, retrying batch plain");
                    }
                    // Retry the remaining batch without MSG_ZEROCOPY.
                    // Re-enter the outer while loop with the updated flags.
                    continue;
                }
                break;
            }

            let sent = ret as usize;
            for i in 0..sent {
                log_socket_send_datagram(&chunk[i]);
            }
            total_sent += sent;
            offset += sent;
            if sent < n {
                break;
            }
        }

        // Move accepted transmits into in-flight storage to keep OsBuf alive until
        // the kernel signals zerocopy completion via the error queue. For non-zerocopy
        // mode the drain drops them immediately (kernel already has its own copy).
        if self.zerocopy_enabled {
            for t in transmits.drain(..total_sent) {
                self.zc_in_flight.push_back(t);
            }
        } else {
            transmits.drain(..total_sent);
        }

        if zc_debug_enabled() {
            eprintln!(
                "[zc] send: submitted={} sent={} unsent={} zc_in_flight={} zerocopy={}",
                total_sent + transmits.len(),
                total_sent,
                transmits.len(),
                self.zc_in_flight.len(),
                self.zerocopy_enabled,
            );
        }

        transmits
    }

    #[cfg(not(target_os = "linux"))]
    fn send(
        &mut self,
        mut transmits: Vec<Transmit<ScatterGather<OsBuf>>>,
    ) -> Vec<Transmit<ScatterGather<OsBuf>>> {
        let mut sent = 0;
        for t in transmits.iter() {
            let result = if t.contents.segments.len() == 1 {
                let seg = &t.contents.segments[0];
                let data = &seg.buf.as_ref()[seg.offset..seg.offset + seg.len];
                self.socket.send_to(data, t.destination)
            } else {
                let mut tmp = Vec::with_capacity(t.contents.total_len());
                for seg in &t.contents.segments {
                    tmp.extend_from_slice(&seg.buf.as_ref()[seg.offset..seg.offset + seg.len]);
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
                    if trace_socket_enabled() {
                        eprintln!("[quic-socket send] send_to error: {e}");
                    }
                    break;
                }
            }
        }
        // Kernel already copied the sent datagrams; drop them.
        transmits.drain(..sent);
        transmits
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
                let serr = unsafe { libc::CMSG_DATA(cm) as *const SockExtendedErr };
                if unsafe { (*serr).ee_origin } == SO_EE_ORIGIN_ZEROCOPY {
                    let was_zc = self.zerocopy_enabled;
                    if unsafe { (*serr).ee_code } == SO_EE_CODE_ZEROCOPY_COPIED {
                        // Kernel is copying; zerocopy yields no benefit here.
                        self.zerocopy_enabled = false;
                    }
                    let lo = unsafe { (*serr).ee_info };
                    let hi = unsafe { (*serr).ee_data };
                    let count = hi.wrapping_sub(lo).wrapping_add(1) as usize;
                    for _ in 0..count {
                        self.zc_in_flight.pop_front();
                    }
                    if zc_debug_enabled() {
                        eprintln!(
                            "[zc] drain: freed={} (ids {}..={}) zc_in_flight_before={} after={} zerocopy_was={} now={}",
                            count, lo, hi, before, self.zc_in_flight.len(), was_zc, self.zerocopy_enabled,
                        );
                    }
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn recv(
        &mut self,
        meta: &mut [RecvMeta],
        bufs: &mut Vec<ScatterGather<OsBufMut>>,
    ) -> io::Result<usize> {
        if meta.is_empty() {
            return Ok(0);
        }

        let count = meta.len().min(self.recv_slots.len());

        // Reset name lengths so the kernel fills them in.
        for slot in &mut self.recv_slots[..count] {
            slot.hdr.msg_hdr.msg_namelen =
                std::mem::size_of::<libc::sockaddr_storage>() as u32;
            slot.hdr.msg_len = 0;
        }

        // Build a contiguous mmsghdr slice pointing into the pre-allocated slots.
        // Safety: the slot Boxes are pinned (never moved between calls), so the
        // raw pointers inside each mmsghdr remain valid across the syscall.
        let mut mmsghdrs: Vec<libc::mmsghdr> =
            self.recv_slots[..count].iter().map(|s| s.hdr).collect();

        let ret = unsafe {
            libc::recvmmsg(
                self.raw_fd,
                mmsghdrs.as_mut_ptr(),
                count as libc::c_uint,
                libc::MSG_DONTWAIT,
                std::ptr::null_mut(),
            )
        };

        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        let received = ret as usize;

        if debug_socket_recv_enabled() {
            if received > 0 {
                eprintln!("[quic-socket] recv(recvmmsg): got {received} datagram(s)");
            } else {
                eprintln!("[quic-socket] recv(recvmmsg): no datagram (empty batch)");
            }
        }

        if zc_debug_enabled() && received > 0 {
            eprintln!("[zc] recv: {received} datagram(s)");
        }

        for i in 0..received {
            let msg_len = mmsghdrs[i].msg_len as usize;
            let slot = &self.recv_slots[i];

            let src = socketaddr_from_raw(
                &slot.addr as *const _ as *const libc::sockaddr,
                mmsghdrs[i].msg_hdr.msg_namelen,
            );

            let mut data = pop_recv_buf(msg_len);
            data.0.extend_from_slice(&slot.buf.0[..msg_len]);
            bufs.push(ScatterGather {
                segments: smallvec![Segment { buf: data, offset: 0, len: msg_len }],
            });
            meta[i] = RecvMeta {
                src,
                len: msg_len,
                stride: msg_len,
                ..RecvMeta::default()
            };
        }

        if trace_socket_enabled() && received > 0 {
            let first_payload = bufs
                .get(0)
                .and_then(|g| g.as_contiguous())
                .unwrap_or(&[]);
            eprintln!(
                "[quic-socket] recv recvmmsg: n={received} first_src={} first_len={} first_bytes=[{}]",
                meta[0].src,
                meta[0].len,
                hex_prefix(first_payload, 32),
            );
        }

        if socket_recv_log_enabled() {
            for i in 0..received {
                let payload = bufs[i].as_contiguous().unwrap_or(&[]);
                eprintln!(
                    "[quic-socket recv] from {} len={} bytes=[{}]",
                    meta[i].src,
                    meta[i].len,
                    hex_prefix(payload, 24),
                );
            }
        }

        if received > 0 {
            Ok(received)
        } else {
            Err(io::Error::from(io::ErrorKind::WouldBlock))
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn recv(
        &mut self,
        meta: &mut [RecvMeta],
        bufs: &mut Vec<ScatterGather<OsBufMut>>,
    ) -> io::Result<usize> {
        if meta.is_empty() {
            return Ok(0);
        }
        let mut count = 0;
        while count < meta.len() {
            match self.socket.recv_from(&mut self.recv_buf.0) {
                Ok((len, src)) => {
                    let mut data = pop_recv_buf(len);
                    data.0.extend_from_slice(&self.recv_buf.0[..len]);
                    bufs.push(ScatterGather {
                        segments: smallvec![Segment { buf: data, offset: 0, len }],
                    });
                    meta[count] = RecvMeta { src, len, stride: len, ..RecvMeta::default() };
                    count += 1;
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e),
            }
        }
        if debug_socket_recv_enabled() {
            if count > 0 {
                eprintln!("[quic-socket] recv(recv_from): got {count} datagram(s)");
            } else {
                eprintln!("[quic-socket] recv(recv_from): no datagram (would block)");
            }
        }
        if trace_socket_enabled() && count > 0 {
            for i in 0..count {
                let payload = bufs[i].as_contiguous().unwrap_or(&[]);
                eprintln!(
                    "[quic-socket] recv recv_from: i={i}/{count} src={} len={} bytes=[{}]",
                    meta[i].src,
                    meta[i].len,
                    hex_prefix(payload, 32),
                );
            }
        }
        if socket_recv_log_enabled() {
            for i in 0..count {
                let payload = bufs[i].as_contiguous().unwrap_or(&[]);
                eprintln!(
                    "[quic-socket recv] from {} len={} bytes=[{}]",
                    meta[i].src,
                    meta[i].len,
                    hex_prefix(payload, 24),
                );
            }
        }
        if count > 0 {
            Ok(count)
        } else {
            Err(io::Error::from(io::ErrorKind::WouldBlock))
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    fn queue_id(&self) -> u32 {
        self.queue_id
    }

    #[cfg(unix)]
    fn rx_fd(&self) -> Option<RawFd> {
        Some(self.socket.as_raw_fd())
    }
}

#[cfg(target_os = "linux")]
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
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t
            }
            SocketAddr::V6(v6) => {
                let sin6 = storage as *mut _ as *mut libc::sockaddr_in6;
                (*sin6).sin6_family = libc::AF_INET6 as libc::sa_family_t;
                (*sin6).sin6_port = v6.port().to_be();
                (*sin6).sin6_addr.s6_addr = v6.ip().octets();
                (*sin6).sin6_flowinfo = v6.flowinfo();
                (*sin6).sin6_scope_id = v6.scope_id();
                std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn socketaddr_from_raw(sa: *const libc::sockaddr, len: libc::socklen_t) -> SocketAddr {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
    unsafe {
        match (*sa).sa_family as libc::c_int {
            libc::AF_INET if len as usize >= std::mem::size_of::<libc::sockaddr_in>() => {
                let sin = &*(sa as *const libc::sockaddr_in);
                let ip = Ipv4Addr::from(sin.sin_addr.s_addr.to_ne_bytes());
                SocketAddr::V4(SocketAddrV4::new(ip, u16::from_be(sin.sin_port)))
            }
            libc::AF_INET6 if len as usize >= std::mem::size_of::<libc::sockaddr_in6>() => {
                let sin6 = &*(sa as *const libc::sockaddr_in6);
                let ip = Ipv6Addr::from(sin6.sin6_addr.s6_addr);
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

#[cfg(test)]
mod tests {
    use std::io;
    use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
    use std::time::{Duration, Instant};

    use quac_socket::{PacketSocket, RecvMeta, ScatterGather, Segment, Transmit};
    use smallvec::smallvec;

    use crate::{OsBuf, OsBufMut};
    use super::OsSocket;

    fn send_one(sock: &mut OsSocket, dest: SocketAddr, payload: &[u8]) -> bool {
        let buf = OsBuf::from_slice(payload);
        let len = payload.len();
        let transmits = vec![Transmit {
            destination: dest,
            ecn: None,
            contents: ScatterGather {
                segments: smallvec![Segment {
                    buf,
                    offset: 0,
                    len,
                }],
            },
            segment_size: None,
            src_ip: None,
        }];
        sock.send(transmits).is_empty()
    }

    /// Non-blocking recv of up to `meta.len()` datagrams (Linux may fill several slots per call).
    fn recv_batch(sock: &mut OsSocket) -> io::Result<Vec<(SocketAddr, Vec<u8>)>> {
        let mut meta = vec![RecvMeta::default(); 64];
        let mut bufs: Vec<ScatterGather<OsBufMut>> = Vec::new();
        match sock.recv(&mut meta, &mut bufs) {
            Ok(n) => {
                let mut out = Vec::with_capacity(n);
                for i in 0..n {
                    let m = &meta[i];
                    let payload = bufs[i]
                        .as_contiguous()
                        .expect("single-segment recv")
                        .to_vec();
                    assert_eq!(m.len, payload.len());
                    out.push((m.src, payload));
                }
                Ok(out)
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(Vec::new()),
            Err(e) => Err(e),
        }
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
        let mut a = OsSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
        let mut b = OsSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
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
        let mut server = OsSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
        let mut client = OsSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
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
            let sock = OsSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
            let _ = sock.local_addr().unwrap();
        }
    }

    #[test]
    fn sequential_bind_same_ephemeral_pattern() {
        // Repeated bind to ephemeral ports (different port each time) exercises drop + open.
        let mut ports = Vec::new();
        for _ in 0..8 {
            let s = OsSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
            ports.push(s.local_addr().unwrap().port());
        }
        assert_eq!(ports.len(), ports.iter().collect::<std::collections::HashSet<_>>().len());
    }

    #[test]
    fn set_queue_id_round_trips_via_trait() {
        let mut s = OsSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
        assert_eq!(PacketSocket::queue_id(&s), 0);
        s.set_queue_id(42);
        assert_eq!(PacketSocket::queue_id(&s), 42);
    }

    /// Two sockets may share one UDP port when `SO_REUSEPORT` is set (Unix).
    #[cfg(unix)]
    #[test]
    fn reuseport_two_sockets_receive_datagrams() {
        let port = reserve_loopback_udp_port();
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));

        let mut first = OsSocket::bind_reuseport(addr).unwrap();
        let mut second = OsSocket::bind_reuseport(addr).unwrap();
        assert_eq!(first.local_addr().unwrap().port(), port);
        assert_eq!(second.local_addr().unwrap().port(), port);

        let mut sender = OsSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
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
}
