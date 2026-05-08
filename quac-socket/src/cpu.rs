//! Linux-only thread-pinning helper used by the per-queue alignment story
//! described in [`docs/SOCKETS.md`](../../docs/SOCKETS.md). See [`crate::nic`]
//! for the NIC-side introspection that picks which CPU to pin to.

use std::io;

/// Pin the calling thread to a single CPU via `sched_setaffinity(0, ...)`.
///
/// Used to align a tile's recv loop with the CPU that handles the NIC RX
/// queue's IRQ — together with `SO_INCOMING_CPU` on the socket, this keeps
/// the per-socket receive-queue spinlock cache-line warm.
pub fn pin_current_thread_to_cpu(cpu: u32) -> io::Result<()> {
    let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    unsafe {
        libc::CPU_ZERO(&mut set);
        libc::CPU_SET(cpu as usize, &mut set);
    }
    let r = unsafe {
        libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set)
    };
    if r != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pin_to_cpu0_then_readback() {
        // Pin to CPU 0 (every Linux box has one) and verify sched_getaffinity
        // shows exactly that.
        pin_current_thread_to_cpu(0).expect("pin_to_cpu(0)");

        let mut got: libc::cpu_set_t = unsafe { std::mem::zeroed() };
        let r = unsafe {
            libc::sched_getaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &mut got)
        };
        assert_eq!(r, 0, "sched_getaffinity: {}", io::Error::last_os_error());
        assert!(unsafe { libc::CPU_ISSET(0, &got) }, "CPU 0 must be in the set");
        let count = unsafe { libc::CPU_COUNT(&got) };
        assert_eq!(count, 1, "expected affinity to contain exactly CPU 0, got count={count}");
    }
}
