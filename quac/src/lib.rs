//! Tile-based async QUIC engine.
//!
//! A [`TileSet`] owns M network tiles and N engine tiles.
//! Each network tile is a pair of threads (reader, writer) bound to the same
//! UDP port via `SO_REUSEPORT`. The engine tiles drive the QUIC protocol
//! state machine and deliver stream data to async application handles.
//!
//! Packets flow through bounded lock-free SPSC queues:
//!
//! ```text
//! NIC RX → Reader → rx[i][j] → Engine → tx[j] → Writer → NIC TX
//! ```
//!
//! See `book/src/tile.md` for the full design document.

pub mod app;
pub mod bridge;
pub mod engine_tile;
pub mod tile_engine;
pub mod tileset;

pub use app::{Connection, Endpoint, RecvStream, SendStream};
pub use tileset::TileSet;
