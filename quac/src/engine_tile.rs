//! Engine tile runner: spin-then-park loop with `AtomicBool` wakeup.

use std::time::Instant;

use crate::tile_engine::TileEngine;

/// Number of spin iterations before the engine commits to parking.
///
/// Set to `usize::MAX` for DPDK deployments where the core is dedicated
/// (the `park()` path is never reached).
const SPIN_ITERS: usize = 200;

/// Spawn the engine thread for `engine` and return when the thread exits
/// (it doesn't in practice — call from `std::thread::spawn`).
pub fn run_engine(mut engine: TileEngine) {
    // Publish the thread handle so ConnState::wake_engine can unpark us.
    let _ = engine.engine_thread.set(std::thread::current());

    loop {
        let now = Instant::now();
        let (_deadline, did_work) = engine.run_once(now);
        if did_work {
            continue;
        }

        // All queues empty after first check. Spin briefly before committing to sleep.
        let mut idle = 0usize;
        let mut any_work = false;
        while idle < SPIN_ITERS {
            std::hint::spin_loop();
            let (_, dw) = engine.run_once(Instant::now());
            if dw {
                any_work = true;
                idle = 0;
            } else {
                idle += 1;
            }
        }
        if any_work {
            continue;
        }

        // Commit to park. Set flag BEFORE park() so producers see it.
        engine.is_parked.store(true, std::sync::atomic::Ordering::Release);

        // Re-check queues after setting the flag to close the TOCTOU window.
        // A producer that pushed just before we set is_parked=true will either:
        //   (a) see is_parked=false → engine processes the item on the next iteration, or
        //   (b) see is_parked=true → calls unpark(), whose token causes park() to return immediately.
        let (deadline2, did_work2) = engine.run_once(Instant::now());
        if !did_work2 {
            match deadline2 {
                Some(t) => {
                    let dur = t.saturating_duration_since(Instant::now());
                    std::thread::park_timeout(dur);
                }
                None => std::thread::park(),
            }
        }

        engine.is_parked.store(false, std::sync::atomic::Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::Duration;

    use crossbeam_queue::ArrayQueue;
    use futures_util::task::AtomicWaker;

    use quac_tile::{RxPacket, TxPacket, QUEUE_CAP};

    fn dummy_engine() -> TileEngine {
        use quic_proto::{EndpointConfig, ServerConfig};
        use std::sync::Arc;

        let (cert, key) = gen_tls();
        let server_config = Arc::new(
            ServerConfig::with_single_cert(vec![cert], key).expect("server config"),
        );
        let endpoint_config = Arc::new(EndpointConfig::default());

        let rx_queues: Vec<Arc<ArrayQueue<RxPacket>>> =
            vec![Arc::new(ArrayQueue::new(QUEUE_CAP))];
        let tx_queue: Arc<ArrayQueue<TxPacket>> = Arc::new(ArrayQueue::new(QUEUE_CAP));
        let incoming: Arc<ArrayQueue<crate::app::Connection>> =
            Arc::new(ArrayQueue::new(QUEUE_CAP));
        let incoming_waker = Arc::new(AtomicWaker::new());

        TileEngine::new(
            rx_queues,
            tx_queue,
            incoming,
            incoming_waker,
            endpoint_config,
            server_config,
        )
    }

    fn gen_tls() -> (rustls::pki_types::CertificateDer<'static>, rustls::pki_types::PrivateKeyDer<'static>) {
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        (
            rustls::pki_types::CertificateDer::from(certified.cert),
            rustls::pki_types::PrivateKeyDer::Pkcs8(
                certified.signing_key.serialize_der().into(),
            ),
        )
    }

    #[test]
    fn engine_thread_sets_handle_and_parks() {
        let engine = dummy_engine();
        let is_parked = Arc::clone(&engine.is_parked);
        let engine_thread_ref = Arc::clone(&engine.engine_thread);

        std::thread::spawn(move || run_engine(engine));

        // Wait for the thread to start and park (queues are empty).
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while !is_parked.load(std::sync::atomic::Ordering::Acquire) {
            if std::time::Instant::now() > deadline {
                panic!("engine did not park within 2s");
            }
            std::thread::sleep(Duration::from_millis(10));
        }

        // engine_thread OnceLock should be set.
        assert!(engine_thread_ref.get().is_some(), "engine_thread handle not set");

        // Unpark the engine thread so it can exit cleanly (it won't — daemon thread,
        // but at least verify unpark doesn't panic).
        if let Some(t) = engine_thread_ref.get() {
            t.unpark();
        }
    }
}
