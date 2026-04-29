//! In-memory paired [`PacketSocket`](quac_socket::PacketSocket): two endpoints share no kernel
//! UDP; a [`send`](quac_socket::PacketSocket::send) on one side enqueues datagrams for
//! [`recv`](quac_socket::PacketSocket::recv) on the other, and vice versa.
//!
//! [`PairSocket::pair`] always assigns [`PAIR_FIRST_LOCAL`] to the first returned socket and
//! [`PAIR_SECOND_LOCAL`] to the second (no kernel binds).
//!
//! In **debug** builds only: set **`QUAC_TRACE_TEST_SOCKET`** to print each datagram send/recv to
//! stderr; **`QUAC_DEBUG_TEST_SOCKET_RECV`** logs every recv outcome (count or `WouldBlock`).
//! Release builds compile these checks out.

use std::fmt::Write;
use std::collections::VecDeque;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::{Arc, Mutex};

use smallvec::smallvec;

use quac_socket::{
    BufferPool, PacketBuf, PacketBufMut, PacketSocket, RecvMeta, ScatterGather, Segment, Transmit,
};

/// [`SocketAddr`] reported by [`PacketSocket::local_addr`] on the **first** value from [`PairSocket::pair`].
pub const PAIR_FIRST_LOCAL: SocketAddr =
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 4000));

/// [`SocketAddr`] reported by [`PacketSocket::local_addr`] on the **second** value from [`PairSocket::pair`].
pub const PAIR_SECOND_LOCAL: SocketAddr =
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 4001));

#[cfg(debug_assertions)]
#[inline]
fn trace_test_socket_enabled() -> bool {
    std::env::var_os("QUAC_TRACE_TEST_SOCKET").is_some()
}
#[cfg(not(debug_assertions))]
#[inline(always)]
fn trace_test_socket_enabled() -> bool {
    false
}

#[cfg(debug_assertions)]
#[inline]
fn debug_test_socket_recv_enabled() -> bool {
    std::env::var_os("QUAC_DEBUG_TEST_SOCKET_RECV").is_some()
}
#[cfg(not(debug_assertions))]
#[inline(always)]
fn debug_test_socket_recv_enabled() -> bool {
    false
}

fn hex_prefix(data: &[u8], max: usize) -> String {
    let mut s = String::new();
    for b in data.iter().take(max) {
        if !s.is_empty() {
            s.push(' ');
        }
        let _ = write!(s, "{b:02x}");
    }
    if data.len() > max {
        let _ = write!(s, " …");
    }
    s
}

// ── Buffer types ──────────────────────────────────────────────────────────────

/// Immutable heap buffer for transmit segments.
pub struct TestBuf(Vec<u8>);

impl AsRef<[u8]> for TestBuf {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl PacketBuf for TestBuf {}

impl TestBuf {
    pub fn from_bytes(data: &[u8]) -> Self {
        TestBuf(data.to_vec())
    }
}

/// Mutable heap buffer used by the pool.
pub struct TestBufMut(Vec<u8>);

impl AsRef<[u8]> for TestBufMut {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for TestBufMut {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl PacketBufMut for TestBufMut {
    type Frozen = TestBuf;

    fn freeze(self) -> TestBuf {
        TestBuf(self.0)
    }

    fn resize(&mut self, new_len: usize) {
        self.0.resize(new_len, 0);
    }
}

/// Heap pool used by [`PairSocket`].
#[derive(Debug)]
pub struct TestPool;

impl BufferPool for TestPool {
    type Buf = TestBuf;
    type BufMut = TestBufMut;
    fn alloc(&self, capacity: usize, count: usize, bufs: &mut Vec<TestBufMut>) -> usize {
        for _ in 0..count {
            bufs.push(TestBufMut(vec![0u8; capacity]));
        }
        count
    }

    fn zerocopy_threshold(&self) -> usize {
        usize::MAX
    }
}

// ── Pair state ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum End {
    A,
    B,
}

#[derive(Debug)]
struct PairInner {
    a_addr: SocketAddr,
    b_addr: SocketAddr,
    /// Datagrams whose destination is `a_addr` (written by B).
    to_a: VecDeque<(SocketAddr, Vec<u8>)>,
    /// Datagrams whose destination is `b_addr` (written by A).
    to_b: VecDeque<(SocketAddr, Vec<u8>)>,
}

/// Two [`PairSocket`] values returned from [`PairSocket::pair`]; each implements [`PacketSocket`].
pub struct PairSocket {
    inner: Arc<Mutex<PairInner>>,
    end: End,
    pool: Arc<TestPool>,
}

impl PairSocket {
    /// Build a connected pair of dummy sockets: first side is [`PAIR_FIRST_LOCAL`], second is
    /// [`PAIR_SECOND_LOCAL`] (no real UDP sockets are opened).
    pub fn pair() -> (PairSocket, PairSocket) {
        let inner = Arc::new(Mutex::new(PairInner {
            a_addr: PAIR_FIRST_LOCAL,
            b_addr: PAIR_SECOND_LOCAL,
            to_a: VecDeque::new(),
            to_b: VecDeque::new(),
        }));
        let pool = Arc::new(TestPool);
        (
            PairSocket {
                inner: Arc::clone(&inner),
                end: End::A,
                pool: Arc::clone(&pool),
            },
            PairSocket {
                inner,
                end: End::B,
                pool,
            },
        )
    }

    fn my_addr(g: &PairInner, end: End) -> SocketAddr {
        match end {
            End::A => g.a_addr,
            End::B => g.b_addr,
        }
    }

    fn flatten_transmit(
        t: &Transmit<ScatterGather<TestBuf>>,
    ) -> Result<Vec<u8>, io::Error> {
        let mut out = Vec::with_capacity(t.contents.total_len());
        for seg in &t.contents.segments {
            let slice = &seg.buf.as_ref()[seg.offset..seg.offset + seg.len];
            out.extend_from_slice(slice);
        }
        Ok(out)
    }
}

impl PacketSocket for PairSocket {
    type Pool = TestPool;

    fn pool(&self) -> Arc<TestPool> {
        Arc::clone(&self.pool)
    }

    fn send(
        &mut self,
        transmits: Vec<Transmit<ScatterGather<TestBuf>>>,
    ) -> Vec<Transmit<ScatterGather<TestBuf>>> {
        if transmits.is_empty() {
            return transmits;
        }
        let mut g = match self.inner.lock() {
            Ok(g) => g,
            Err(e) => {
                eprintln!("[quic-test-socket] send: mutex poisoned: {e}");
                return transmits;
            }
        };
        let src = Self::my_addr(&g, self.end);
        let who = match self.end {
            End::A => "pair-first",
            End::B => "pair-second",
        };
        for t in transmits.iter() {
            let payload = match Self::flatten_transmit(t) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("[quic-test-socket] send: flatten error: {e}");
                    continue;
                }
            };
            let dst = t.destination;
            if trace_test_socket_enabled() {
                eprintln!(
                    "[quic-test-socket] send {who}: src={src} dst={dst} len={} bytes=[{}]",
                    payload.len(),
                    hex_prefix(&payload, 32),
                );
            }
            if dst == g.a_addr {
                g.to_a.push_back((src, payload));
            } else if dst == g.b_addr {
                g.to_b.push_back((src, payload));
            } else {
                match self.end {
                    End::A => g.to_b.push_back((src, payload)),
                    End::B => g.to_a.push_back((src, payload)),
                }
            }
        }
        // All packets accepted and copied into the peer queue; return empty unsent.
        vec![]
    }

    fn drain_completions(&mut self) {}

    fn recv(
        &mut self,
        meta: &mut [RecvMeta],
        bufs: &mut Vec<ScatterGather<TestBufMut>>,
    ) -> io::Result<usize> {
        if meta.is_empty() {
            return Ok(0);
        }
        let mut g = self.inner.lock().map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("pair socket mutex poisoned: {e}"),
            )
        })?;
        let who = match self.end {
            End::A => "pair-first",
            End::B => "pair-second",
        };
        let my = Self::my_addr(&g, self.end);
        let q = match self.end {
            End::A => &mut g.to_a,
            End::B => &mut g.to_b,
        };
        let mut count = 0usize;
        while count < meta.len() {
            let Some((src, payload)) = q.pop_front() else {
                break;
            };
            if trace_test_socket_enabled() {
                eprintln!(
                    "[quic-test-socket] recv {who}: src={src} dst_local={my} len={} bytes=[{}]",
                    payload.len(),
                    hex_prefix(&payload, 32),
                );
            }
            let len = payload.len();
            let mut buf = TestBufMut(Vec::with_capacity(len));
            buf.0.extend_from_slice(&payload);
            bufs.push(ScatterGather {
                segments: smallvec![Segment {
                    buf,
                    offset: 0,
                    len,
                }],
            });
            meta[count] = RecvMeta {
                src,
                dst_ip: None,
                ecn: None,
                len,
                stride: len,
            };
            count += 1;
        }
        if count > 0 {
            if debug_test_socket_recv_enabled() {
                eprintln!("[quic-test-socket] recv {who}: ok n={count} datagram(s)");
            }
            Ok(count)
        } else {
            if debug_test_socket_recv_enabled() {
                eprintln!("[quic-test-socket] recv {who}: WouldBlock (queue empty)");
            }
            Err(io::Error::from(io::ErrorKind::WouldBlock))
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        let g = self.inner.lock().map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("pair socket mutex poisoned: {e}"),
            )
        })?;
        Ok(Self::my_addr(&g, self.end))
    }

    fn queue_id(&self) -> u32 {
        match self.end {
            End::A => 0,
            End::B => 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::ErrorKind;

    fn transmit_to(
        destination: SocketAddr,
        payload: &[u8],
    ) -> Transmit<ScatterGather<TestBuf>> {
        let buf = TestBuf::from_bytes(payload);
        let len = payload.len();
        Transmit {
            destination,
            ecn: None,
            contents: ScatterGather {
                segments: smallvec![Segment {
                    buf,
                    offset: 0,
                    len,
                }],
            },
            segment_size: None,
            src_ip: None,
        }
    }

    #[test]
    fn pair_first_and_second_local_addrs_are_fixed() {
        let (a, b) = PairSocket::pair();
        assert_eq!(a.local_addr().unwrap(), PAIR_FIRST_LOCAL);
        assert_eq!(b.local_addr().unwrap(), PAIR_SECOND_LOCAL);
    }

    #[test]
    fn pair_send_recv_roundtrip_a_to_b() {
        let (mut a, mut b) = PairSocket::pair();
        let transmits = vec![transmit_to(PAIR_SECOND_LOCAL, b"hello-pair")];
        let unsent = a.send(transmits);
        assert!(unsent.is_empty());

        let mut meta = vec![RecvMeta::default(); 4];
        let mut bufs: Vec<ScatterGather<TestBufMut>> = Vec::new();
        let n = b.recv(&mut meta, &mut bufs).unwrap();
        assert_eq!(n, 1);
        assert_eq!(meta[0].src, PAIR_FIRST_LOCAL);
        assert_eq!(bufs[0].as_contiguous().unwrap(), b"hello-pair");
    }

    #[test]
    fn pair_send_recv_roundtrip_b_to_a() {
        let (mut a, mut b) = PairSocket::pair();
        let transmits = vec![transmit_to(PAIR_FIRST_LOCAL, b"reply")];
        let unsent = b.send(transmits);
        assert!(unsent.is_empty());

        let mut meta = vec![RecvMeta::default(); 2];
        let mut bufs: Vec<ScatterGather<TestBufMut>> = Vec::new();
        let n = a.recv(&mut meta, &mut bufs).unwrap();
        assert_eq!(n, 1);
        assert_eq!(meta[0].src, PAIR_SECOND_LOCAL);
        assert_eq!(bufs[0].as_contiguous().unwrap(), b"reply");
    }

    #[test]
    fn recv_empty_returns_would_block() {
        let (mut a, _b) = PairSocket::pair();
        let mut meta = [RecvMeta::default()];
        let mut bufs = Vec::new();
        let err = a.recv(&mut meta, &mut bufs).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::WouldBlock);
    }

    #[test]
    fn unknown_destination_routes_to_peer_queue() {
        let (mut a, mut b) = PairSocket::pair();
        let other = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9));
        let transmits = vec![transmit_to(other, b"fallback")];
        let unsent = a.send(transmits);
        assert!(unsent.is_empty());

        let mut meta = vec![RecvMeta::default(); 1];
        let mut bufs: Vec<ScatterGather<TestBufMut>> = Vec::new();
        let n = b.recv(&mut meta, &mut bufs).unwrap();
        assert_eq!(n, 1);
        assert_eq!(meta[0].src, PAIR_FIRST_LOCAL);
        assert_eq!(bufs[0].as_contiguous().unwrap(), b"fallback");
    }

    #[test]
    fn scatter_gather_send_concatenates_segments() {
        let (mut a, mut b) = PairSocket::pair();
        let p1 = b"foo";
        let p2 = b"bar";
        let b1 = TestBuf::from_bytes(p1);
        let b2 = TestBuf::from_bytes(p2);
        let transmits = vec![Transmit {
            destination: PAIR_SECOND_LOCAL,
            ecn: None,
            contents: ScatterGather {
                segments: smallvec![
                    Segment {
                        buf: b1,
                        offset: 0,
                        len: p1.len(),
                    },
                    Segment {
                        buf: b2,
                        offset: 0,
                        len: p2.len(),
                    },
                ],
            },
            segment_size: None,
            src_ip: None,
        }];
        let unsent = a.send(transmits);
        assert!(unsent.is_empty());

        let mut meta = vec![RecvMeta::default()];
        let mut bufs: Vec<ScatterGather<TestBufMut>> = Vec::new();
        assert_eq!(b.recv(&mut meta, &mut bufs).unwrap(), 1);
        assert_eq!(bufs[0].as_contiguous().unwrap(), b"foobar");
        assert_eq!(meta[0].len, b"foobar".len());
    }

    #[test]
    fn batch_recv_respects_meta_len() {
        let (mut a, mut b) = PairSocket::pair();
        let t = vec![
            transmit_to(PAIR_SECOND_LOCAL, b"one"),
            transmit_to(PAIR_SECOND_LOCAL, b"two"),
        ];
        let unsent = a.send(t);
        assert!(unsent.is_empty());

        let mut meta = vec![RecvMeta::default(); 1];
        let mut bufs: Vec<ScatterGather<TestBufMut>> = Vec::new();
        assert_eq!(b.recv(&mut meta, &mut bufs).unwrap(), 1);
        assert_eq!(bufs[0].as_contiguous().unwrap(), b"one");

        let mut meta = vec![RecvMeta::default(); 4];
        let mut bufs: Vec<ScatterGather<TestBufMut>> = Vec::new();
        assert_eq!(b.recv(&mut meta, &mut bufs).unwrap(), 1);
        assert_eq!(bufs[0].as_contiguous().unwrap(), b"two");
    }

    #[test]
    fn queue_ids_differ_per_end() {
        let (a, b) = PairSocket::pair();
        assert_eq!(a.queue_id(), 0);
        assert_eq!(b.queue_id(), 1);
    }

    #[test]
    fn pair_sides_share_one_pool_arc() {
        let (a, b) = PairSocket::pair();
        assert!(Arc::ptr_eq(&a.pool(), &b.pool()));
    }
}
