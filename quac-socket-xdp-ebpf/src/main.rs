//! XDP redirect program. Parses Eth → IPv4 → UDP, looks up the dst port in
//! `BOUND_PORTS`, and `XDP_REDIRECT`s matching packets to the AF_XDP socket
//! registered in `XSKMAP[rx_queue_index]`.
//!
//! ```text
//! Eth → if !IPv4                          → XDP_PASS
//! IPv4 → if proto != UDP                  → XDP_PASS
//! UDP  → if IHL != 5                      → XDP_DROP + DROP_COUNTERS[UDP_OPTIONS]
//!      → if MF=1 or frag_offset > 0       → XDP_DROP + DROP_COUNTERS[UDP_FRAGMENT]
//!      → if dport ∉ BOUND_PORTS           → XDP_PASS
//!      → else                             → XDP_REDIRECT to XSKMAP[queue]
//! ```
//!
//! Malformed UDP (options / fragments) is dropped rather than passed: QUIC
//! peers never produce it, and PASS-ing to a bound port would leak ICMP
//! port-unreachable (no kernel listener exists on a port bound via AF_XDP).
//!
//! IPv6 and 802.1Q VLAN frames fall through to PASS via the outer EtherType
//! check; non-UDP fragments PASS via the proto check on the first fragment.

#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{Array, PerCpuArray, XskMap},
    programs::XdpContext,
};
use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    udp::UdpHdr,
};
use quac_socket_xdp_ebpf::{
    BOUND_PORTS_LEN, DROP_COUNTERS_LEN, DROP_REASON_UDP_FRAGMENT, DROP_REASON_UDP_OPTIONS,
    MAX_QUEUES,
};

/// `dst_port (host order) → enabled flag`. Userspace toggles on bind/drop.
#[map]
static BOUND_PORTS: Array<u8> = Array::<u8>::with_max_entries(BOUND_PORTS_LEN, 0);

/// `rx_queue_index → AF_XDP socket fd`. Userspace inserts after `bind(2)`.
#[map]
static XSKMAP: XskMap = XskMap::with_max_entries(MAX_QUEUES, 0);

/// Per-CPU monotonic drop counters indexed by `DROP_REASON_*`.
#[map]
static DROP_COUNTERS: PerCpuArray<u64> = PerCpuArray::with_max_entries(DROP_COUNTERS_LEN, 0);

#[xdp]
pub fn quac_xdp(ctx: XdpContext) -> u32 {
    match try_redirect(&ctx) {
        Ok(action) => action,
        // Bounds-check / parse failures fall back to PASS so we don't silently
        // lose ARP / ICMP / unrelated traffic.
        Err(()) => xdp_action::XDP_PASS,
    }
}

#[inline(always)]
fn try_redirect(ctx: &XdpContext) -> Result<u32, ()> {
    let eth = unsafe { ptr_at::<EthHdr>(ctx, 0)? };
    if unsafe { (*eth).ether_type } != EtherType::Ipv4 {
        return Ok(xdp_action::XDP_PASS);
    }

    let ip = unsafe { ptr_at::<Ipv4Hdr>(ctx, EthHdr::LEN)? };
    if unsafe { (*ip).proto } != IpProto::Udp {
        return Ok(xdp_action::XDP_PASS);
    }

    // UDP: strict validation. First byte of the IP header is [version(4) | IHL(4)].
    let vihl = unsafe { *(ip as *const u8) };
    if (vihl & 0x0f) != 5 {
        bump_drop(DROP_REASON_UDP_OPTIONS);
        return Ok(xdp_action::XDP_DROP);
    }

    // Fragment-word bytes 6-7: [reserved(1) | DF(1) | MF(1) | offset(13)].
    // Mask 0x3fff matches MF=1 or offset>0 while ignoring DF/reserved.
    let frag_off = u16::from_be(unsafe { (*ip).frag_off });
    if frag_off & 0x3fff != 0 {
        bump_drop(DROP_REASON_UDP_FRAGMENT);
        return Ok(xdp_action::XDP_DROP);
    }

    let udp = unsafe { ptr_at::<UdpHdr>(ctx, EthHdr::LEN + Ipv4Hdr::LEN)? };
    let dport = u16::from_be(unsafe { (*udp).dest }) as u32;
    let Some(enabled) = BOUND_PORTS.get(dport) else {
        return Ok(xdp_action::XDP_PASS);
    };
    if *enabled == 0 {
        return Ok(xdp_action::XDP_PASS);
    }

    // `redirect` returns Err(XDP_ABORTED) if no socket is registered for the
    // queue or the ring is full; fall back to PASS in that case.
    let qid = unsafe { (*ctx.ctx).rx_queue_index };
    Ok(XSKMAP.redirect(qid, 0).unwrap_or(xdp_action::XDP_PASS))
}

#[inline(always)]
fn bump_drop(idx: u32) {
    if let Some(ctr) = DROP_COUNTERS.get_ptr_mut(idx) {
        unsafe { *ctr = (*ctr).wrapping_add(1) };
    }
}

/// Bounds-checked typed read at `offset` from `ctx->data`. The verifier
/// requires every dereferenced pointer to have been compared against
/// `data_end`; this helper performs that check.
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
    // Unreachable: the verifier rejects unbounded loops. Exists only to
    // satisfy `#![no_std]`.
    loop {}
}
