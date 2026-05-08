use quac_socket::{ScatterGather, Transmit};

use super::OsBuf;

// QUAC_LOG* env-vars enable stderr tracing (debug builds only; release: const
// false → dead-code eliminated).
//   QUAC_LOG    -- per-packet hex + summaries + errors.
//   QUAC_LOG_ZC -- zerocopy completion / ENOBUFS (Linux only).

/// `pub(super) fn $name() -> bool` caching one env-var probe.
/// Debug: `OnceLock<bool>`; release: const `false`.
macro_rules! log_flag {
    ($name:ident, $env:literal) => {
        #[cfg(debug_assertions)]
        #[inline]
        pub(super) fn $name() -> bool {
            use std::sync::OnceLock;
            static ENABLED: OnceLock<bool> = OnceLock::new();
            *ENABLED.get_or_init(|| std::env::var_os($env).is_some())
        }
        #[cfg(not(debug_assertions))]
        #[inline(always)]
        pub(super) fn $name() -> bool {
            false
        }
    };
}

log_flag!(log_enabled, "QUAC_LOG");

#[cfg(target_os = "linux")]
log_flag!(zc_log_enabled, "QUAC_LOG_ZC");

#[cfg(debug_assertions)]
pub(super) fn log_socket_send_datagram(t: &Transmit<ScatterGather<OsBuf>>) {
    if !log_enabled() {
        return;
    }
    let total = t.contents.total_len();
    let mut buf = Vec::with_capacity(256.min(total));
    for seg in t.contents.segments() {
        let s = seg.as_slice();
        let room = 256_usize.saturating_sub(buf.len());
        if room == 0 {
            break;
        }
        buf.extend_from_slice(&s[..room.min(s.len())]);
    }
    eprintln!(
        "[quac-socket send] to {} len={total} bytes=[{}]",
        t.destination,
        hex_prefix(&buf, 24),
    );
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
