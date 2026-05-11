//! Userspace-facing surface: exposes the pre-built BPF object bytes plus
//! contract constants. The eBPF program source lives in `src/main.rs` and
//! is only built with the `ebpf` feature on the `bpfel-unknown-none` target.

#![no_std]

/// Max `(rx_queue_index → AF_XDP fd)` entries in `XSKMAP`. Covers typical
/// high-queue-count server NICs (32–64 queues per port).
pub const MAX_QUEUES: u32 = 64;

/// Number of UDP destination-port membership slots in `BOUND_PORTS`.
/// The eBPF program indexes this array directly by the 16-bit UDP port.
pub const BOUND_PORTS_LEN: u32 = 1 << 16;

/// Backwards-compatible alias for older callers that used this as the
/// `BOUND_PORTS` map length.
pub const MAX_BOUND_PORTS: u32 = BOUND_PORTS_LEN;

//
// Read via `bpftool map dump name DROP_COUNTERS`. Per-CPU monotonic counters;
// aggregate by summing across CPUs.

/// Number of drop-reason buckets in the `DROP_COUNTERS` map.
pub const DROP_COUNTERS_LEN: u32 = 2;

/// IPv4 UDP with IHL > 5 (IP options). Dropped -- QUIC peers never set them;
/// also avoids leaking ICMP port-unreachable for bound ports.
pub const DROP_REASON_UDP_OPTIONS: u32 = 0;

/// IPv4 UDP fragment (MF=1 or offset>0). Dropped -- QUIC uses PMTUD and
/// never fragments; fragments are also a reassembly-DoS vector.
pub const DROP_REASON_UDP_FRAGMENT: u32 = 1;

/// 8-byte-aligned wrapper so the kernel verifier can reinterpret the
/// embedded BPF object without a copy.
#[repr(C, align(8))]
pub struct Aligned<Bytes: ?Sized>(pub Bytes);

impl<Bytes: ?Sized> core::ops::Deref for Aligned<Bytes> {
    type Target = Bytes;
    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Pre-built BPF object, embedded so the userspace loader doesn't need to
/// touch the filesystem. Rebuild via `build-ebpf.sh` after editing `main.rs`.
#[cfg(all(target_os = "linux", not(target_arch = "bpf")))]
pub static QUAC_SOCKET_XDP_EBPF_PROGRAM: &Aligned<[u8]> = &Aligned(*include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/quac-socket-xdp-prog"
)));
