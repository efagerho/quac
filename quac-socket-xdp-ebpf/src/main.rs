//! XDP redirect program: parse Ethernet → IPv4 → UDP, look up the destination
//! port in `BOUND_PORTS`, and `XDP_REDIRECT` matching packets to the AF_XDP
//! socket registered in `XSKMAP[ctx->rx_queue_index]`.
//!
//! Loaded by `quac-socket-xdp::program::XdpProgram` via aya. Userspace
//! populates the maps as `XdpSocket`s are created/dropped.
//!
//! ## Decision tree
//!
//! ```text
//! Eth → if !IPv4                              → XDP_PASS (kernel)
//! IPv4 → if proto != UDP                      → XDP_PASS (kernel handles
//!                                                 TCP/ICMP/ARP normally,
//!                                                 with or without options)
//! UDP  → if IHL != 5                          → XDP_DROP + DROP_COUNTERS[UDP_OPTIONS]
//!      → if MF=1 or fragment offset > 0       → XDP_DROP + DROP_COUNTERS[UDP_FRAGMENT]
//!      → if dport ∉ BOUND_PORTS               → XDP_PASS (kernel)
//!      → else                                 → XDP_REDIRECT to XSKMAP[queue]
//! ```
//!
//! ## Why DROP and not PASS for malformed UDP
//!
//! - QUIC peers never set IP options nor send fragmented UDP — anything
//!   matching is malformed or hostile.
//! - PASS-ing it to the kernel for a port we've bound via AF_XDP would
//!   cause an ICMP port-unreachable (no kernel listener on that port),
//!   leaking our setup and possibly tripping the peer's state machine.
//! - DROP keeps the policy uniform for "unparseable UDP".
//!
//! ## Not handled (XDP_PASS by omission)
//!
//! - **IPv6** and **VLAN-tagged (802.1Q)** frames — the outer EtherType
//!   check fails and they pass straight to the kernel.
//! - **Non-UDP IPv4 fragments** — the proto check on the first fragment
//!   sees `IpProto::*` other than UDP, so PASS; fragments after the first
//!   carry no L4 header but they're not UDP either (proto field still
//!   reflects the L4 protocol of the original datagram).

#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{HashMap, PerCpuArray, XskMap},
    programs::XdpContext,
};
use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    udp::UdpHdr,
};
use quac_socket_xdp_ebpf::{
    DROP_COUNTERS_LEN, DROP_REASON_UDP_FRAGMENT, DROP_REASON_UDP_OPTIONS, MAX_BOUND_PORTS,
    MAX_QUEUES,
};

/// `dst_port (host order) → 1`. Userspace inserts a port when a socket
/// `bind()`s it; removes on socket drop. Membership = "redirect".
#[map]
static BOUND_PORTS: HashMap<u16, u8> =
    HashMap::<u16, u8>::with_max_entries(MAX_BOUND_PORTS, 0);

/// `rx_queue_index → AF_XDP socket fd`. Userspace inserts via
/// `XskMap::set(qid, sock_fd, 0)` after `bind(2)` succeeds. The XDP
/// `redirect_map` helper consults this to find the socket to deliver to.
#[map]
static XSKMAP: XskMap = XskMap::with_max_entries(MAX_QUEUES, 0);

/// Per-CPU drop counters indexed by `DROP_REASON_*`. Each per-CPU slot is
/// incremented locklessly. Userspace aggregates by summing across CPUs;
/// `bpftool map dump name DROP_COUNTERS` shows raw values per CPU.
#[map]
static DROP_COUNTERS: PerCpuArray<u64> = PerCpuArray::with_max_entries(DROP_COUNTERS_LEN, 0);

#[xdp]
pub fn quac_xdp(ctx: XdpContext) -> u32 {
    match try_redirect(&ctx) {
        Ok(action) => action,
        // Any parse / bounds failure → let the kernel handle it normally.
        // Returning XDP_DROP would silently lose ARP / ICMP / etc.
        Err(()) => xdp_action::XDP_PASS,
    }
}

#[inline(always)]
fn try_redirect(ctx: &XdpContext) -> Result<u32, ()> {
    // Bounds-check + parse Ethernet.
    let eth = unsafe { ptr_at::<EthHdr>(ctx, 0)? };
    if unsafe { (*eth).ether_type } != EtherType::Ipv4 {
        return Ok(xdp_action::XDP_PASS);
    }

    // Bounds-check + parse IPv4 base header (20 bytes).
    let ip = unsafe { ptr_at::<Ipv4Hdr>(ctx, EthHdr::LEN)? };

    // Non-UDP traffic is the kernel's problem — TCP, ICMP, ARP, IGMP, etc.
    // Pass regardless of options or fragmentation; the kernel deals with
    // both correctly.
    if unsafe { (*ip).proto } != IpProto::Udp {
        return Ok(xdp_action::XDP_PASS);
    }

    // ── UDP from here on. Strict validation (see module docs). ──────────────

    // 1. Reject IPv4 options. The first byte of the IP header is
    //    `[version (4 bits) | IHL (4 bits)]`. We've already bounds-checked
    //    `Ipv4Hdr` (20 bytes), so the first byte is safe to dereference.
    //    QUIC clients never send IP options; presence implies malformed or
    //    hostile traffic.
    let vihl = unsafe { *(ip as *const u8) };
    if (vihl & 0x0f) != 5 {
        bump_drop(DROP_REASON_UDP_OPTIONS);
        return Ok(xdp_action::XDP_DROP);
    }

    // 2. Reject fragments. Bytes 6-7 of the IP header carry
    //    `[reserved(1) | DF(1) | MF(1) | frag_offset(13)]`. A packet is a
    //    fragment iff `MF = 1` or `frag_offset != 0`; mask 0x3fff covers
    //    both while ignoring DF and reserved.
    let frag_off = u16::from_be(unsafe { (*ip).frag_off });
    if frag_off & 0x3fff != 0 {
        bump_drop(DROP_REASON_UDP_FRAGMENT);
        return Ok(xdp_action::XDP_DROP);
    }

    // 3. UDP header sits at the fixed offset because we've ruled out
    //    options. Bounds-check + parse.
    let udp = unsafe { ptr_at::<UdpHdr>(ctx, EthHdr::LEN + Ipv4Hdr::LEN)? };
    let dport = u16::from_be(unsafe { (*udp).dest });

    // 4. Hash-map lookup: not in BOUND_PORTS → kernel handles it normally
    //    (e.g. another userspace listener via socket(2) on a different port).
    if unsafe { BOUND_PORTS.get(&dport) }.is_none() {
        return Ok(xdp_action::XDP_PASS);
    }

    // 5. Redirect to the XSK socket bound to the rx queue this packet
    //    arrived on. `XskMap::redirect` returns Ok(XDP_REDIRECT) on success,
    //    Err(XDP_ABORTED) on failure (no socket for this queue, ring full,
    //    etc.). On failure fall back to XDP_PASS so the kernel still gets it.
    let qid = unsafe { (*ctx.ctx).rx_queue_index };
    Ok(XSKMAP.redirect(qid, 0).unwrap_or(xdp_action::XDP_PASS))
}

/// Increment the per-CPU drop counter at `idx`. No-op if `idx` is out of
/// range (defensive — should never happen with the named constants).
#[inline(always)]
fn bump_drop(idx: u32) {
    if let Some(ctr) = DROP_COUNTERS.get_ptr_mut(idx) {
        unsafe { *ctr = (*ctr).wrapping_add(1) };
    }
}

/// Bounds-checked typed read at byte `offset` from `ctx->data`. Returns
/// `Err(())` if the kernel's data window doesn't contain `sizeof::<T>()`
/// bytes at that offset — the verifier requires every dereferenced ptr to
/// have been compared against `data_end`.
#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let size = mem::size_of::<T>();
    if start + offset + size > end {
        return Err(());
    }
    Ok((start + offset) as *const T)
}

#[cfg(target_arch = "bpf")]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // BPF programs can't actually panic — the verifier rejects unbounded
    // loops. This handler exists only to satisfy `#![no_std]` compilation.
    loop {}
}
