use quac_socket::{ScatterGather, Transmit};

use super::OsBuf;

// `QUAC_*` stderr tracing and diagnostics: **debug builds only** — no `getenv` / logging on
// `OsSocket` hot paths in `--release` (see `trace_socket_enabled` etc.).

// `QUAC_SOCKET_ZC_DEBUG=1`: zerocopy send diagnostics (debug builds only).
#[cfg(all(target_os = "linux", debug_assertions))]
pub(super) fn zc_debug_enabled() -> bool {
    use std::sync::OnceLock;
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var_os("QUAC_SOCKET_ZC_DEBUG").is_some())
}
#[cfg(all(target_os = "linux", not(debug_assertions)))]
#[inline(always)]
pub(super) fn zc_debug_enabled() -> bool {
    false
}

#[cfg(debug_assertions)]
#[inline]
pub(super) fn trace_socket_enabled() -> bool {
    std::env::var_os("QUAC_TRACE_SOCKET").is_some()
}
#[cfg(not(debug_assertions))]
#[inline(always)]
pub(super) fn trace_socket_enabled() -> bool {
    false
}

#[cfg(debug_assertions)]
#[inline]
pub(super) fn debug_socket_recv_enabled() -> bool {
    std::env::var_os("QUAC_DEBUG_SOCKET_RECV").is_some()
}
#[cfg(not(debug_assertions))]
#[inline(always)]
pub(super) fn debug_socket_recv_enabled() -> bool {
    false
}

#[cfg(debug_assertions)]
#[inline]
pub(super) fn socket_recv_log_enabled() -> bool {
    std::env::var_os("QUAC_SOCKET_RECV_LOG").is_some()
}
#[cfg(not(debug_assertions))]
#[inline(always)]
pub(super) fn socket_recv_log_enabled() -> bool {
    false
}

#[cfg(debug_assertions)]
pub(super) fn socket_send_log_enabled() -> bool {
    std::env::var_os("QUAC_SOCKET_SEND_LOG").is_some()
}

#[cfg(debug_assertions)]
pub(super) fn hex_prefix_from_transmit(
    t: &Transmit<ScatterGather<OsBuf>>,
    capture: usize,
    hex_max: usize,
) -> (usize, String) {
    let total = t.contents.total_len();
    let mut buf = Vec::with_capacity(capture.min(total));
    for seg in &t.contents.segments {
        let s = &seg.buf.as_ref()[seg.offset..seg.offset + seg.len];
        let room = capture.saturating_sub(buf.len());
        if room == 0 {
            break;
        }
        buf.extend_from_slice(&s[..room.min(s.len())]);
    }
    (total, hex_prefix(&buf, hex_max))
}

#[cfg(debug_assertions)]
pub(super) fn log_socket_send_datagram(t: &Transmit<ScatterGather<OsBuf>>) {
    if !socket_send_log_enabled() {
        return;
    }
    let (len, hx) = hex_prefix_from_transmit(t, 256, 24);
    eprintln!("[quic-socket send] to {} len={len} bytes=[{hx}]", t.destination);
}

#[cfg(not(debug_assertions))]
#[inline(always)]
pub(super) fn log_socket_send_datagram(_t: &Transmit<ScatterGather<OsBuf>>) {}

pub(super) fn hex_prefix(data: &[u8], max: usize) -> String {
    use std::fmt::Write;
    let mut s = String::new();
    for b in data.iter().take(max) {
        if !s.is_empty() {
            s.push(' ');
        }
        let _ = write!(s, "{b:02x}");
    }
    if data.len() > max {
        let _ = write!(s, " …");
    }
    s
}
