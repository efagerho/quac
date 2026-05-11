//! Interface-attribute helpers (MAC address only).

use std::ffi::{c_char, CString};
use std::io;
use std::mem;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use libc::{ifreq, syscall, SYS_ioctl, IF_NAMESIZE, SIOCGIFHWADDR, SOCK_DGRAM};

/// Resolve `if_index` to interface name (`lo`, `eth0`, …).
pub fn if_name(if_index: u32) -> io::Result<String> {
    let mut buf = [0u8; IF_NAMESIZE];
    let ret = unsafe { libc::if_indextoname(if_index, buf.as_mut_ptr() as *mut c_char) };
    if ret.is_null() {
        return Err(io::Error::last_os_error());
    }
    let cstr = unsafe { std::ffi::CStr::from_ptr(ret) };
    Ok(String::from_utf8_lossy(cstr.to_bytes()).into_owned())
}

/// L2 MAC address via `SIOCGIFHWADDR`. Used as the TX src MAC.
pub fn if_mac(if_index: u32) -> io::Result<[u8; 6]> {
    let name = if_name(if_index)?;
    let cname =
        CString::new(name.as_bytes()).map_err(|_| io::Error::other("interface name has NUL"))?;

    // Any AF_INET socket allows SIOCGIFHWADDR; no network op happens.
    let fd = unsafe { libc::socket(libc::AF_INET, SOCK_DGRAM, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };

    let mut req: ifreq = unsafe { mem::zeroed() };
    let bytes = cname.as_bytes_with_nul();
    let len = bytes.len().min(IF_NAMESIZE);
    unsafe {
        std::ptr::copy_nonoverlapping(
            bytes.as_ptr() as *const c_char,
            req.ifr_name.as_mut_ptr(),
            len,
        );
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
        // lo is if_index=1 on every Linux system; MAC is all zeros.
        let name = if_name(1).expect("if_indextoname(1)");
        assert_eq!(name, "lo");
        let mac = if_mac(1).expect("SIOCGIFHWADDR for lo");
        assert_eq!(mac, [0u8; 6]);
    }
}
