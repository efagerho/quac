//! Network constants and platform address helpers shared by all backends.
//!
//! The MTU constants assume a standard 1500-byte Ethernet link. Backends for
//! jumbo frames or other link types should derive `max_payload_size` from the
//! actual interface MTU rather than these values.

// ── MTU constants ─────────────────────────────────────────────────────────────

const ETHERNET_MTU: usize = 1500;
const IPV4_HEADER: usize = 20;
const IPV6_HEADER: usize = 40;
const UDP_HEADER: usize = 8;

/// Maximum UDP payload over an Ethernet link (MTU 1500) for an IPv4 socket:
/// 1500 − 20 (IPv4) − 8 (UDP) = 1472 bytes.
pub const IPV4_MAX_UDP_PAYLOAD: usize = ETHERNET_MTU - IPV4_HEADER - UDP_HEADER;

/// Maximum UDP payload over an Ethernet link (MTU 1500) for an IPv6 socket:
/// 1500 − 40 (IPv6) − 8 (UDP) = 1452 bytes. Also the conservative default
/// for unknown / dual-stack contexts: any socket can safely send this many
/// bytes without exceeding the MTU regardless of IP version.
pub const IPV6_MAX_UDP_PAYLOAD: usize = ETHERNET_MTU - IPV6_HEADER - UDP_HEADER;

// ── Sockaddr helpers (Unix) ───────────────────────────────────────────────────

/// Encode a [`std::net::SocketAddr`] into `storage`, returning the actual
/// address length for use as `msg_namelen` in a `msghdr`.
///
/// # Safety
/// `storage` must point to a valid, writable, zero-initialised
/// `sockaddr_storage`.
#[cfg(unix)]
pub fn sockaddr_from_socketaddr(
    addr: &std::net::SocketAddr,
    storage: &mut libc::sockaddr_storage,
) -> libc::socklen_t {
    use std::mem::size_of;
    use std::net::SocketAddr;
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

/// Parse UDP ancillary data (CMSGs) written by the kernel into a `msg_control` buffer.
///
/// Returns `(dst_ip, ecn)`:
/// - `dst_ip`: wire-destination IP from `IP_PKTINFO`/`IPV6_PKTINFO`/`IP_RECVDSTADDR`
///   (the address the sender targeted; needed on multi-homed hosts for path selection
///   and reply routing).
/// - `ecn`: ECN codepoint from `IP_TOS`/`IPV6_TCLASS`, or `None` when the codepoint is
///   non-ECT (0b00) or the CMSG is absent.
///
/// Linux: requires `IP_RECVTOS`/`IPV6_RECVTCLASS` and `IP_PKTINFO`/`IPV6_RECVPKTINFO`.
/// BSD/macOS: requires `IP_RECVTOS`/`IPV6_RECVTCLASS` and `IP_RECVDSTADDR`/`IPV6_RECVPKTINFO`.
/// Without these socket options the kernel delivers no CMSGs and this function returns
/// `(None, None)`.
///
/// # Safety
/// `ctrl` must point to `controllen` bytes of valid, readable CMSG data as written by the
/// kernel into `msg_control` after a `recvmsg`/`recvmmsg` call.
#[cfg(unix)]
pub unsafe fn parse_recv_cmsgs(
    ctrl: *mut libc::c_void,
    controllen: usize,
) -> (Option<std::net::IpAddr>, Option<crate::EcnCodepoint>) {
    use std::mem::size_of;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    if controllen == 0 {
        return (None, None);
    }

    let mut msg: libc::msghdr = std::mem::zeroed();
    msg.msg_control = ctrl;
    msg.msg_controllen = controllen as _;

    let mut dst_ip: Option<IpAddr> = None;
    let mut ecn: Option<crate::EcnCodepoint> = None;

    let mut cm = libc::CMSG_FIRSTHDR(&msg);
    while !cm.is_null() {
        let level = (*cm).cmsg_level;
        let ty = (*cm).cmsg_type;
        let data = libc::CMSG_DATA(cm);
        let data_len = (*cm).cmsg_len as usize
            - std::mem::size_of::<libc::cmsghdr>();

        match (level, ty) {
            // Linux: IP_PKTINFO carries in_pktinfo; use ipi_addr (wire destination).
            #[cfg(target_os = "linux")]
            (libc::IPPROTO_IP, libc::IP_PKTINFO)
                if data_len >= size_of::<libc::in_pktinfo>() =>
            {
                let info: libc::in_pktinfo =
                    std::ptr::read_unaligned(data as *const libc::in_pktinfo);
                // ipi_addr is the IP header destination (the wire address the sender
                // targeted); ipi_spec_dst is the routing-level local address and can
                // diverge under IP_TRANSPARENT / non-local bind, so we use ipi_addr.
                dst_ip = Some(IpAddr::V4(Ipv4Addr::from(
                    info.ipi_addr.s_addr.to_ne_bytes(),
                )));
            }
            // BSD/macOS: IP_RECVDSTADDR carries in_addr directly (no in_pktinfo wrapper).
            #[cfg(any(
                target_os = "macos",
                target_os = "ios",
                target_os = "freebsd",
                target_os = "dragonfly",
                target_os = "netbsd",
                target_os = "openbsd",
            ))]
            (libc::IPPROTO_IP, libc::IP_RECVDSTADDR)
                if data_len >= size_of::<libc::in_addr>() =>
            {
                let addr: libc::in_addr =
                    std::ptr::read_unaligned(data as *const libc::in_addr);
                dst_ip = Some(IpAddr::V4(Ipv4Addr::from(addr.s_addr.to_ne_bytes())));
            }
            (libc::IPPROTO_IPV6, libc::IPV6_PKTINFO)
                if data_len >= size_of::<libc::in6_pktinfo>() =>
            {
                let info: libc::in6_pktinfo =
                    std::ptr::read_unaligned(data as *const libc::in6_pktinfo);
                dst_ip = Some(IpAddr::V6(Ipv6Addr::from(info.ipi6_addr.s6_addr)));
            }
            // IP_TOS cmsg payload is 1 byte on all platforms.
            (libc::IPPROTO_IP, libc::IP_TOS) if data_len >= 1 => {
                let tos: u8 = std::ptr::read_unaligned(data as *const u8);
                ecn = crate::EcnCodepoint::from_bits(tos);
            }
            // FreeBSD delivers ECN as IP_RECVTOS CMSG type (not IP_TOS).
            #[cfg(any(
                target_os = "freebsd",
                target_os = "dragonfly",
                target_os = "netbsd",
            ))]
            (libc::IPPROTO_IP, libc::IP_RECVTOS) if data_len >= 1 => {
                let tos: u8 = std::ptr::read_unaligned(data as *const u8);
                ecn = crate::EcnCodepoint::from_bits(tos);
            }
            // IPV6_TCLASS: standard payload is sizeof(int), but some macOS versions
            // deliver only 1 byte (broken ABI). Branch on data_len to handle both.
            (libc::IPPROTO_IPV6, libc::IPV6_TCLASS) if data_len >= 1 => {
                if data_len == 1 {
                    // macOS broken ABI: 1-byte payload.
                    let tc: u8 = std::ptr::read_unaligned(data as *const u8);
                    ecn = crate::EcnCodepoint::from_bits(tc);
                } else if data_len >= size_of::<libc::c_int>() {
                    // Standard: int payload; cast to u8 extracts the low byte.
                    let tc: libc::c_int =
                        std::ptr::read_unaligned(data as *const libc::c_int);
                    ecn = crate::EcnCodepoint::from_bits(tc as u8);
                }
            }
            _ => {}
        }

        cm = libc::CMSG_NXTHDR(&msg, cm);
    }

    (dst_ip, ecn)
}

/// Build send-path control messages (CMSGs) for per-packet ECN and source-IP
/// override into `buf`.
///
/// Returns the total bytes written, for use as `msg_controllen`. Returns 0
/// when both `ecn` and `src_ip` are `None` (fast path: no CMSG needed).
///
/// CMSGs written:
/// | Field      | Linux (IPv4)                    | BSD/macOS (IPv4)                 | IPv6 (all)                       |
/// |------------|---------------------------------|----------------------------------|----------------------------------|
/// | `src_ip`   | `IP_PKTINFO` (`ipi_spec_dst`)   | `IP_RECVDSTADDR` (`in_addr`)     | `IPV6_PKTINFO` (`ipi6_addr`)     |
/// | `ecn`      | `IP_TOS` (1-byte u8 payload)    | `IP_TOS` (1-byte u8 payload)     | `IPV6_TCLASS` (1-byte u8 payload)|
///
/// # Safety
/// `buf` must point to at least `buf_len` bytes of writable memory. `buf_len`
/// must be at least 64 bytes to avoid truncation.
#[cfg(unix)]
pub unsafe fn build_send_cmsgs(
    buf: *mut u8,
    buf_len: usize,
    dst_family: libc::c_int,
    ecn: Option<crate::EcnCodepoint>,
    src_ip: Option<std::net::IpAddr>,
) -> usize {
    use std::mem::size_of;
    use std::net::IpAddr;

    if ecn.is_none() && src_ip.is_none() {
        return 0;
    }

    let mut msg: libc::msghdr = std::mem::zeroed();
    msg.msg_control = buf as *mut libc::c_void;
    msg.msg_controllen = buf_len as _;
    let mut cm = libc::CMSG_FIRSTHDR(&msg);
    let mut total = 0usize;

    // src_ip → IP_PKTINFO (Linux) / IP_RECVDSTADDR (BSD) / IPV6_PKTINFO (both)
    if let Some(src) = src_ip {
        match (dst_family, src) {
            (libc::AF_INET, IpAddr::V4(v4)) => {
                #[cfg(target_os = "linux")]
                {
                    let space = libc::CMSG_SPACE(size_of::<libc::in_pktinfo>() as u32) as usize;
                    if !cm.is_null() && total + space <= buf_len {
                        (*cm).cmsg_level = libc::IPPROTO_IP;
                        (*cm).cmsg_type = libc::IP_PKTINFO;
                        (*cm).cmsg_len =
                            libc::CMSG_LEN(size_of::<libc::in_pktinfo>() as u32) as _;
                        let info = libc::CMSG_DATA(cm) as *mut libc::in_pktinfo;
                        *info = std::mem::zeroed();
                        (*info).ipi_spec_dst.s_addr = u32::from_ne_bytes(v4.octets());
                        total += space;
                        msg.msg_controllen = total as _;
                        cm = libc::CMSG_NXTHDR(&msg, cm);
                    }
                }
                // BSD/macOS: use IP_RECVDSTADDR with bare in_addr (== IP_SENDSRCADDR on FreeBSD).
                #[cfg(not(target_os = "linux"))]
                {
                    let space = libc::CMSG_SPACE(size_of::<libc::in_addr>() as u32) as usize;
                    if !cm.is_null() && total + space <= buf_len {
                        (*cm).cmsg_level = libc::IPPROTO_IP;
                        (*cm).cmsg_type = libc::IP_RECVDSTADDR;
                        (*cm).cmsg_len =
                            libc::CMSG_LEN(size_of::<libc::in_addr>() as u32) as _;
                        let dst = libc::CMSG_DATA(cm) as *mut libc::in_addr;
                        (*dst).s_addr = u32::from_ne_bytes(v4.octets());
                        total += space;
                        msg.msg_controllen = total as _;
                        cm = libc::CMSG_NXTHDR(&msg, cm);
                    }
                }
            }
            (libc::AF_INET6, IpAddr::V6(v6)) => {
                let space = libc::CMSG_SPACE(size_of::<libc::in6_pktinfo>() as u32) as usize;
                if !cm.is_null() && total + space <= buf_len {
                    (*cm).cmsg_level = libc::IPPROTO_IPV6;
                    (*cm).cmsg_type = libc::IPV6_PKTINFO;
                    (*cm).cmsg_len = libc::CMSG_LEN(size_of::<libc::in6_pktinfo>() as u32) as _;
                    let info = libc::CMSG_DATA(cm) as *mut libc::in6_pktinfo;
                    *info = std::mem::zeroed();
                    (*info).ipi6_addr.s6_addr = v6.octets();
                    total += space;
                    msg.msg_controllen = total as _;
                    cm = libc::CMSG_NXTHDR(&msg, cm);
                }
            }
            _ => {} // address-family mismatch — skip
        }
    }

    // ecn → IP_TOS (1-byte u8) / IPV6_TCLASS (1-byte u8)
    if let Some(ecn_cp) = ecn {
        let tos: u8 = ecn_cp.bits();
        let space = libc::CMSG_SPACE(size_of::<u8>() as u32) as usize;
        if !cm.is_null() && total + space <= buf_len {
            match dst_family {
                libc::AF_INET => {
                    (*cm).cmsg_level = libc::IPPROTO_IP;
                    (*cm).cmsg_type = libc::IP_TOS;
                }
                libc::AF_INET6 => {
                    (*cm).cmsg_level = libc::IPPROTO_IPV6;
                    (*cm).cmsg_type = libc::IPV6_TCLASS;
                }
                _ => return total,
            }
            (*cm).cmsg_len = libc::CMSG_LEN(size_of::<u8>() as u32) as _;
            *(libc::CMSG_DATA(cm) as *mut u8) = tos;
            total += space;
        }
    }

    total
}

/// Decode a raw `sockaddr` pointer into a [`std::net::SocketAddr`].
/// Returns `None` for unrecognised address families or undersized buffers.
///
/// # Safety
/// `sa` must point to at least `len` bytes of readable, valid memory
/// containing a `sockaddr`-family struct (as written by the kernel after a
/// `recvmsg`/`recvmmsg` call with a suitably-sized `msg_name` buffer).
#[cfg(unix)]
pub fn socketaddr_from_raw(
    sa: *const libc::sockaddr,
    len: libc::socklen_t,
) -> Option<std::net::SocketAddr> {
    use std::mem::size_of;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
    unsafe {
        match (*sa).sa_family as libc::c_int {
            libc::AF_INET if len as usize >= size_of::<libc::sockaddr_in>() => {
                let sin = &*(sa as *const libc::sockaddr_in);
                let ip = Ipv4Addr::from(sin.sin_addr.s_addr.to_ne_bytes());
                Some(SocketAddr::V4(SocketAddrV4::new(ip, u16::from_be(sin.sin_port))))
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
