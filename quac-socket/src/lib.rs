//! Runtime-agnostic packet I/O traits: [`BufferPool`], [`PacketSocket`], and buffer types.
//!
//! This crate is the single source of truth for the abstraction described in the quac book
//! (`book/src/socket.md`). Backends (`quac-socket-os`, `quac-socket-iouring`, …) implement [`PacketSocket`];

pub mod buffer;
pub mod socket;

pub use buffer::{BufferPool, PacketBuf, PacketBufMut, ScatterGather, Segment};
pub use socket::{EcnCodepoint, PacketSocket, RecvMeta, Transmit};
