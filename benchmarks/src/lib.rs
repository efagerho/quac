//! Shared helpers for benchmark binaries (listen address parsing).

pub mod listen;
pub mod quinn_client;

/// Tokio worker thread count: CLI override or available parallelism (capped), same policy as
/// `quic_bench`.
pub fn tokio_worker_threads(threads: Option<usize>) -> usize {
    threads
        .unwrap_or_else(|| {
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(4)
        })
        .max(1)
        .min(256)
}
