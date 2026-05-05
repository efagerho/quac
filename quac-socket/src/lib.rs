//! Runtime-agnostic packet I/O traits: [`BufferPool`], [`PacketSocket`], and buffer types.
//!
//! Backends (`quac-socket-os`, `quac-socket-iouring`, …) implement
//! [`PacketSocket`] over their own [`BufferPool`]; higher layers in the QUIC
//! engine consume the trait without knowing which backend is in use.

pub mod buffer;
pub mod net;
pub mod socket;

pub use buffer::{BufferPool, PacketBuf, PacketBufMut, ScatterGather, Segment};
pub use socket::{DrainResult, EcnCodepoint, PacketSocket, RecvMeta, Transmit};
