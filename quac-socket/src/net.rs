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

// ── Sockaddr helpers (Linux only) ─────────────────────────────────────────────

/// Encode a [`std::net::SocketAddr`] into `storage`, returning the actual
/// address length for use as `msg_namelen` in a `msghdr`.
///
/// # Safety
/// `storage` must point to a valid, writable, zero-initialised
/// `sockaddr_storage`.
#[cfg(target_os = "linux")]
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

/// Decode a raw `sockaddr` pointer into a [`std::net::SocketAddr`].
/// Returns `None` for unrecognised address families or undersized buffers.
///
/// # Safety
/// `sa` must point to at least `len` bytes of readable, valid memory
/// containing a `sockaddr`-family struct (as written by the kernel after a
/// `recvmsg`/`recvmmsg` call with a suitably-sized `msg_name` buffer).
#[cfg(target_os = "linux")]
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
