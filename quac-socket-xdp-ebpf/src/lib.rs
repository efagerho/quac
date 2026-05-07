//! Userspace-facing surface of the `quac-socket-xdp-ebpf` crate.
//!
//! The eBPF program itself lives in `src/main.rs` and is only built when the
//! `ebpf` feature is enabled (which requires nightly + bpfel-unknown-none).
//! For everyone else this crate just exposes the pre-built BPF object as a
//! byte slice that `quac-socket-xdp::program` loads via aya at runtime.

#![no_std]

/// Maximum number of `(rx_queue_index → AF_XDP fd)` entries in `XSKMAP`.
/// One slot per HW queue on the NIC; 64 covers all common multi-queue
/// configurations including high-end server NICs (Mellanox CX5/6 typically
/// run with 32–64 queues per port).
pub const MAX_QUEUES: u32 = 64;

/// Maximum number of UDP destination ports the program will redirect.
/// One entry per `bind()`ed port on the NIC. 1024 is comfortably above any
/// realistic per-process bind count for a QUIC server (typically < 32).
pub const MAX_BOUND_PORTS: u32 = 1024;

// ── Drop-reason counters ─────────────────────────────────────────────────────
//
// The eBPF program exposes a `PerCpuArray<u64>` named `DROP_COUNTERS` that
// userspace (or `bpftool map dump`) can read to see why packets were dropped.
// Each index below names one bucket. Counters are monotonically increasing
// per-CPU; aggregate by summing across all CPU values for an index.

/// Number of distinct drop-reason buckets exposed by the eBPF program.
pub const DROP_COUNTERS_LEN: u32 = 2;

/// IPv4 UDP packet with IHL > 5 (header carried IP options). Legitimate QUIC
/// peers never set options; dropping avoids the IHL-aware parsing path and
/// avoids leaking ICMP port-unreachable from the kernel for bound ports.
pub const DROP_REASON_UDP_OPTIONS: u32 = 0;

/// IPv4 UDP packet that is a fragment (More-Fragments=1 or fragment-offset>0).
/// QUIC uses Path MTU Discovery and never fragments; fragments are also a
/// known DoS vector against reassembly logic.
pub const DROP_REASON_UDP_FRAGMENT: u32 = 1;

/// Force 8-byte alignment for the embedded BPF object so the kernel verifier
/// can reinterpret it directly without a copy.
#[repr(C, align(8))]
pub struct Aligned<Bytes: ?Sized>(pub Bytes);

impl<Bytes: ?Sized> core::ops::Deref for Aligned<Bytes> {
    type Target = Bytes;
    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Pre-built BPF object embedded as `static` so the userspace loader can
/// `bpf_prog_load(2)` it without touching the filesystem.
///
/// In Phase 1 this is a placeholder (empty slice). Phase 5 replaces the
/// `quac-socket-xdp-prog` file with the real object emitted by building
/// `src/main.rs` for the `bpfel-unknown-none` target.
#[cfg(all(target_os = "linux", not(target_arch = "bpf")))]
pub static QUAC_SOCKET_XDP_EBPF_PROGRAM: &Aligned<[u8]> = &Aligned(*include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/quac-socket-xdp-prog"
)));
