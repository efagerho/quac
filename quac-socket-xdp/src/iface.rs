//! Tiny interface-attribute helpers — only what the AF_XDP socket needs
//! (the MAC for the Ethernet src field). The full `NetworkDevice` from
//! the prototype `xdp/` crate also queries IPv4, driver name, ring sizes;
//! we don't need any of that on the hot path.

use std::ffi::{CString, c_char};
use std::io;
use std::mem;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use libc::{IF_NAMESIZE, SIOCGIFHWADDR, SOCK_DGRAM, SYS_ioctl, ifreq, syscall};

/// Resolve an `if_index` to its name (e.g. `lo`, `eth0`, `vqrx`).
pub fn if_name(if_index: u32) -> io::Result<String> {
    let mut buf = [0u8; IF_NAMESIZE];
    let ret = unsafe { libc::if_indextoname(if_index, buf.as_mut_ptr() as *mut c_char) };
    if ret.is_null() {
        return Err(io::Error::last_os_error());
    }
    let cstr = unsafe { std::ffi::CStr::from_ptr(ret) };
    Ok(String::from_utf8_lossy(cstr.to_bytes()).into_owned())
}

/// Query the L2 (Ethernet) MAC address of `if_index` via `SIOCGIFHWADDR`.
/// Used as the source MAC for outbound packets we craft into UMEM frames.
pub fn if_mac(if_index: u32) -> io::Result<[u8; 6]> {
    let name = if_name(if_index)?;
    let cname =
        CString::new(name.as_bytes()).map_err(|_| io::Error::other("interface name has NUL"))?;

    // Opening any AF_INET socket lets us issue SIOCGIFHWADDR — no actual
    // network operation is performed, just an ioctl on the kernel's
    // interface table.
    let fd = unsafe { libc::socket(libc::AF_INET, SOCK_DGRAM, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };

    let mut req: ifreq = unsafe { mem::zeroed() };
    let bytes = cname.as_bytes_with_nul();
    let len = bytes.len().min(IF_NAMESIZE);
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr() as *const c_char, req.ifr_name.as_mut_ptr(), len);
    }

    let rc = unsafe { syscall(SYS_ioctl, fd.as_raw_fd(), SIOCGIFHWADDR, &mut req) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }

    let raw = unsafe {
        std::slice::from_raw_parts(req.ifr_ifru.ifru_hwaddr.sa_data.as_ptr() as *const u8, 6)
    };
    let mut out = [0u8; 6];
    out.copy_from_slice(raw);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_is_resolvable() {
        // `lo` is `if_index = 1` on every Linux system since the kernel's
        // built-in loopback. Its MAC is all zeros; we just check the call
        // doesn't error.
        let name = if_name(1).expect("if_indextoname(1)");
        assert_eq!(name, "lo");
        let mac = if_mac(1).expect("SIOCGIFHWADDR for lo");
        assert_eq!(mac, [0u8; 6]);
    }
}
