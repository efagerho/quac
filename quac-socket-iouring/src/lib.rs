#[cfg(not(target_os = "linux"))]
compile_error!("quac-socket-iouring requires Linux 6.0 or newer");

mod buffers;
mod socket;

pub use buffers::{IoBuf, IoBufMut, IoPool, IPV4_MAX_UDP_PAYLOAD, IPV6_MAX_UDP_PAYLOAD};
pub use socket::IoUringSocket;
