//! Application-level smoke tests using the in-tree [`Pair`] harness (`util.rs`).
//!
//! These mirror the scenarios covered by `quic-engine` UDP integration tests—one TLS handshake,
//! opening a client-initiated bidirectional stream, and echoing bytes on that stream—but run
//! entirely in memory with deterministic `Pair` delivery (no real sockets).

use assert_matches::assert_matches;

use super::*;

#[test]
fn pair_single_connection_established() {
    let _guard = subscribe();
    let mut pair = Pair::default();
    let (client_ch, server_ch) = pair.connect();

    assert_eq!(pair.client.open_connections(), 1);
    assert_eq!(pair.server.open_connections(), 1);
    assert!(!pair.client_conn_mut(client_ch).is_handshaking());
    assert!(!pair.server_conn_mut(server_ch).is_handshaking());
}

#[test]
fn pair_client_opens_bidi_stream() {
    let _guard = subscribe();
    let mut pair = Pair::default();
    let (client_ch, _) = pair.connect();

    assert!(
        pair.client_streams(client_ch).open(Dir::Bi).is_some(),
        "expected default limits to allow a client-initiated bidi stream"
    );
}

#[test]
fn pair_bidi_stream_send_recv_echo() {
    let _guard = subscribe();
    let mut pair = Pair::default();
    let (client_ch, server_ch) = pair.connect();

    let sid = pair
        .client_streams(client_ch)
        .open(Dir::Bi)
        .expect("open bidi stream");
    const PAYLOAD: &[u8] = b"hello-quic-proto-harness";

    pair.client_send(client_ch, sid).write(PAYLOAD).unwrap();
    pair.drive();

    assert_matches!(
        pair.server_conn_mut(server_ch).poll(),
        Some(Event::Stream(StreamEvent::Opened { dir: Dir::Bi }))
    );
    assert_matches!(
        pair.server_streams(server_ch).accept(Dir::Bi),
        Some(id) if id == sid
    );

    let mut recv = pair.server_recv(server_ch, sid);
    let mut chunks = recv.read(true).unwrap();
    let mut got = Vec::new();
    loop {
        match chunks.next(256 * 1024) {
            Ok(Some(c)) => got.extend_from_slice(&c.bytes),
            Ok(None) => break,
            Err(ReadError::Blocked) => break,
            Err(e) => panic!("server read: {e:?}"),
        }
    }
    let _ = chunks.finalize();
    assert_eq!(&got[..], PAYLOAD);

    pair.server_send(server_ch, sid).write(&got).unwrap();
    pair.drive();

    let mut recv = pair.client_recv(client_ch, sid);
    let mut chunks = recv.read(true).unwrap();
    let mut echo = Vec::new();
    loop {
        match chunks.next(256 * 1024) {
            Ok(Some(c)) => echo.extend_from_slice(&c.bytes),
            Ok(None) => break,
            Err(ReadError::Blocked) => break,
            Err(e) => panic!("client read: {e:?}"),
        }
    }
    let _ = chunks.finalize();
    assert_eq!(&echo[..], PAYLOAD);
}
