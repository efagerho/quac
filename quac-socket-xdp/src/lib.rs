//! AF_XDP zero-copy [`PacketSocket`](quac_socket::PacketSocket) backend.
//!
//! Build prereqs for the eBPF program:
//! - `rustup toolchain install nightly`
//! - `rustup component add rust-src --toolchain nightly`
//! - `rustup target add bpfel-unknown-none --toolchain nightly`
//! - kernel ≥ 5.18 for veth `XDP_ZEROCOPY`
//! - `CAP_BPF` + `CAP_PERFMON` (or `CAP_SYS_ADMIN`) to load
//! - `CAP_NET_RAW` to open the AF_XDP socket

#[cfg(target_os = "linux")]
pub mod buffers;
#[cfg(target_os = "linux")]
pub mod iface;
#[cfg(target_os = "linux")]
pub mod lpm;
#[cfg(target_os = "linux")]
pub mod netlink;
#[cfg(target_os = "linux")]
pub mod packet;
#[cfg(target_os = "linux")]
pub mod program;
#[cfg(target_os = "linux")]
pub mod raw_socket;
#[cfg(target_os = "linux")]
mod reclaimer;
#[cfg(target_os = "linux")]
pub mod ring;
#[cfg(target_os = "linux")]
pub mod route;
#[cfg(target_os = "linux")]
pub mod route_monitor;
#[cfg(target_os = "linux")]
pub mod socket;
#[cfg(target_os = "linux")]
pub mod umem;

#[cfg(target_os = "linux")]
pub use buffers::{HEADROOM, XdpRxBuf, XdpRxBufMut, XdpRxPool, XdpTxBuf, XdpTxBufMut, XdpTxPool};
#[cfg(target_os = "linux")]
pub use program::{AttachMode, XdpProgram, get_or_load as load_xdp_program};
#[cfg(target_os = "linux")]
pub use raw_socket::{RawXdpSocket, RingSizes, XdpMode};
#[cfg(target_os = "linux")]
pub use ring::{RingConsumer, RingMmap, RingProducer, XdpDesc, mmap_ring};
#[cfg(target_os = "linux")]
pub use socket::{XdpConfig, XdpConfigBuilder, XdpSocket};
#[cfg(target_os = "linux")]
pub use umem::{AllocError, PageAlignedMemory, Umem};
