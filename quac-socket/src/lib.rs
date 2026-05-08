//! Runtime-agnostic packet I/O traits: [`RxPool`], [`TxPool`], [`PacketSocket`], and buffer types.
//!
//! Backends (`quac-socket-os`, `quac-socket-iouring`, …) implement
//! [`PacketSocket`] over their own pool types; higher layers in the QUIC
//! engine consume the trait without knowing which backend is in use.

pub mod buffer;
pub mod mpsc;
pub mod net;
pub mod socket;

#[cfg(target_os = "linux")]
pub mod cpu;
#[cfg(target_os = "linux")]
pub mod nic;

pub use buffer::{PacketBuf, PacketBufMut, RxPool, ScatterGather, Segment, TxPool};
pub use mpsc::MpscQueue;
pub use socket::{DrainResult, EcnCodepoint, PacketSocket, RecvMeta, Transmit};

#[cfg(target_os = "linux")]
pub use cpu::pin_current_thread_to_cpu;
#[cfg(target_os = "linux")]
pub use nic::{
    bond_slaves, coalesce_by_cpu, cpu_for_rx_queue, enumerate_rx_queues, iface_name,
    interface_for_addr, nic_queue_count, RxQueue,
};
