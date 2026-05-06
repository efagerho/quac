//! Runtime-agnostic packet I/O traits: [`RxPool`], [`TxPool`], [`PacketSocket`], and buffer types.
//!
//! Backends (`quac-socket-os`, `quac-socket-iouring`, …) implement
//! [`PacketSocket`] over their own pool types; higher layers in the QUIC
//! engine consume the trait without knowing which backend is in use.

pub mod buffer;
pub mod mpsc;
pub mod net;
pub mod socket;

pub use buffer::{PacketBuf, PacketBufMut, RxPool, ScatterGather, Segment, TxPool};
pub use mpsc::MpscQueue;
pub use socket::{DrainResult, EcnCodepoint, PacketSocket, RecvMeta, Transmit};
