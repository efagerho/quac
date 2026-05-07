//! AF_XDP socket setup: setsockopt + mmap + bind sequence.
//!
//! Adapted from `xdp/src/socket.rs`. Stripped of the `Umem`-generic
//! `Socket<U>` wrapper, the Tx/Rx-only constructors, and the
//! `Frame`-generic ring wrappers — we always have all four rings, the
//! frame address is a plain `u64`, and the higher-level `PacketSocket` impl
//! drives the rings directly.
//!
//! `RawXdpSocket::new` returns the bound socket plus the four mmap'd rings'
//! producer/consumer indexes; the caller (in `socket.rs`) wires them into
//! the send/recv hot paths.
//!
//! References:
//! - kernel docs: Documentation/networking/af_xdp.rst
//! - `man 7 af_xdp`

use std::io;
use std::mem;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::ptr;
use std::sync::atomic::Ordering;

use libc::{
    AF_XDP, MSG_DONTWAIT, SOCK_RAW, SOL_XDP, XDP_COPY, XDP_MMAP_OFFSETS, XDP_PGOFF_RX_RING,
    XDP_PGOFF_TX_RING, XDP_RING_NEED_WAKEUP, XDP_RX_RING, XDP_TX_RING, XDP_UMEM_COMPLETION_RING,
    XDP_UMEM_FILL_RING, XDP_UMEM_PGOFF_COMPLETION_RING, XDP_UMEM_PGOFF_FILL_RING,
    XDP_USE_NEED_WAKEUP, XDP_ZEROCOPY, sa_family_t, sockaddr, sockaddr_xdp, socklen_t,
    xdp_mmap_offsets, xdp_umem_reg,
};

use crate::ring::{RingConsumer, RingMmap, RingProducer, XdpDesc, mmap_ring};
use crate::umem::Umem;

/// Ring capacities. All four must be powers of two. Typical defaults match
/// the kernel's `XSK_RING_*_DFLT` constants.
#[derive(Debug, Clone, Copy)]
pub struct RingSizes {
    pub fill: u32,
    pub completion: u32,
    pub rx: u32,
    pub tx: u32,
}

impl Default for RingSizes {
    /// 2048 descriptors per ring — kernel default. Big enough that a single
    /// hot-loop iteration can drain a busy NIC without backing up the rings.
    fn default() -> Self {
        Self { fill: 2048, completion: 2048, rx: 2048, tx: 2048 }
    }
}

/// Wire-mode requested at `bind()`. The kernel may reject `ZeroCopy` on
/// drivers that don't implement it; the caller can then fall back to `Copy`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XdpMode {
    /// `XDP_ZEROCOPY` — DMA buffers map straight into UMEM. Driver support
    /// required; veth got it in Linux 5.18.
    ZeroCopy,
    /// `XDP_COPY` — kernel copies between its skb and UMEM. Slower, but
    /// works on every interface.
    Copy,
}

impl XdpMode {
    fn flag(self) -> u16 {
        match self {
            XdpMode::ZeroCopy => XDP_ZEROCOPY,
            XdpMode::Copy => XDP_COPY,
        }
    }
}

/// AF_XDP socket bound to a `(if_index, queue_id)` pair, with the four
/// kernel rings mmap'd and tracked by per-ring producer/consumer indexes.
///
/// Higher-level state (UMEM frame free-list, RxBuf/TxBuf wrappers, the
/// `PacketSocket` impl) lives in `socket.rs` — this struct is intentionally
/// just the kernel-facing surface.
//
// Several fields aren't read yet — phased construction. Phase 6 wires up
// the RX/COMP rings (`recv` / `drain_completions`) and Phase 7 wires up
// the TX ring producer (`send`). Suppress the dead-code warning until then.
#[allow(dead_code)]
pub struct RawXdpSocket {
    fd: OwnedFd,
    if_index: u32,
    queue_id: u32,
    sizes: RingSizes,
    mode: XdpMode,

    // Ring memory — drops via `munmap` when `Self` drops (RingMmap::Drop).
    pub(crate) fill_mmap: RingMmap<u64>,
    pub(crate) comp_mmap: RingMmap<u64>,
    pub(crate) rx_mmap: RingMmap<XdpDesc>,
    pub(crate) tx_mmap: RingMmap<XdpDesc>,

    // Producer/consumer index trackers. Userspace owns the producer side of
    // FILL+TX (we hand frames/descriptors to the kernel) and the consumer
    // side of COMP+RX (we take completed/received frames from the kernel).
    pub(crate) fill_prod: RingProducer,
    pub(crate) comp_cons: RingConsumer,
    pub(crate) rx_cons: RingConsumer,
    pub(crate) tx_prod: RingProducer,
}

impl RawXdpSocket {
    /// Open an AF_XDP socket, register the UMEM, size all four rings, mmap
    /// them, pre-fill the FILL ring with `pre_fill_frames`, and `bind()` to
    /// `(if_index, queue_id)` with `XDP_USE_NEED_WAKEUP` plus the requested
    /// mode.
    ///
    /// `pre_fill_frames` must yield UMEM frame byte-offsets (`umem.frame_offset(i)`)
    /// the caller wants the kernel to use for incoming packets. The FILL
    /// ring **must** contain at least one frame before `bind()` in
    /// `ZeroCopy` mode (most drivers — i40e in particular — misbehave
    /// otherwise). Empty pre-fill is allowed in `Copy` mode but means RX
    /// won't deliver anything until the caller writes into the FILL ring
    /// post-bind via [`Self::pre_fill`].
    pub fn new(
        if_index: u32,
        queue_id: u32,
        umem: &mut Umem,
        sizes: RingSizes,
        mode: XdpMode,
        pre_fill_frames: impl IntoIterator<Item = u64>,
    ) -> io::Result<Self> {
        debug_assert!(sizes.fill.is_power_of_two());
        debug_assert!(sizes.completion.is_power_of_two());
        debug_assert!(sizes.rx.is_power_of_two());
        debug_assert!(sizes.tx.is_power_of_two());

        // 1. Open the AF_XDP socket.
        let fd = unsafe { libc::socket(AF_XDP, SOCK_RAW, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };

        // 2. Register the UMEM. `flags` and `tx_metadata_len` are zero for
        //    the basic single-UMEM single-socket setup; `headroom` is zero
        //    because we'll write headers at `[0..HEADROOM]` of each frame
        //    ourselves rather than asking the kernel to leave space.
        let reg = xdp_umem_reg {
            addr: umem.as_ptr() as u64,
            len: umem.len() as u64,
            chunk_size: umem.frame_size(),
            headroom: 0,
            flags: 0,
            tx_metadata_len: 0,
        };
        setsockopt(
            fd.as_raw_fd(),
            SOL_XDP,
            libc::XDP_UMEM_REG,
            &reg as *const _ as *const libc::c_void,
            mem::size_of::<xdp_umem_reg>() as socklen_t,
        )?;

        // 3. Size the four rings. Order matters only insofar as completion
        //    and fill are "UMEM rings" and need both ends of the UMEM
        //    registration; RX/TX are per-socket.
        for (opt, size) in [
            (XDP_UMEM_COMPLETION_RING, sizes.completion),
            (XDP_UMEM_FILL_RING, sizes.fill),
            (XDP_TX_RING, sizes.tx),
            (XDP_RX_RING, sizes.rx),
        ] {
            setsockopt(
                fd.as_raw_fd(),
                SOL_XDP,
                opt,
                &size as *const _ as *const libc::c_void,
                mem::size_of::<u32>() as socklen_t,
            )?;
        }

        // 4. Discover the ring layout in the mmap'd memory.
        let mut offsets: xdp_mmap_offsets = unsafe { mem::zeroed() };
        let mut optlen = mem::size_of::<xdp_mmap_offsets>() as socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                fd.as_raw_fd(),
                SOL_XDP,
                XDP_MMAP_OFFSETS,
                &mut offsets as *mut _ as *mut libc::c_void,
                &mut optlen,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }

        // 5. mmap each ring. FILL/COMP descriptors are u64 frame offsets;
        //    RX/TX are full XdpDesc records.
        let fill_mmap = unsafe {
            mmap_ring::<u64>(
                fd.as_raw_fd(),
                (sizes.fill as usize) * mem::size_of::<u64>(),
                &offsets.fr,
                XDP_UMEM_PGOFF_FILL_RING,
            )?
        };
        let comp_mmap = unsafe {
            mmap_ring::<u64>(
                fd.as_raw_fd(),
                (sizes.completion as usize) * mem::size_of::<u64>(),
                &offsets.cr,
                XDP_UMEM_PGOFF_COMPLETION_RING,
            )?
        };
        let rx_mmap = unsafe {
            mmap_ring::<XdpDesc>(
                fd.as_raw_fd(),
                (sizes.rx as usize) * mem::size_of::<XdpDesc>(),
                &offsets.rx,
                XDP_PGOFF_RX_RING as u64,
            )?
        };
        let tx_mmap = unsafe {
            mmap_ring::<XdpDesc>(
                fd.as_raw_fd(),
                (sizes.tx as usize) * mem::size_of::<XdpDesc>(),
                &offsets.tx,
                XDP_PGOFF_TX_RING as u64,
            )?
        };

        let mut fill_prod = RingProducer::new(fill_mmap.producer, fill_mmap.consumer, sizes.fill);
        let comp_cons = RingConsumer::new(comp_mmap.producer, comp_mmap.consumer);
        let rx_cons = RingConsumer::new(rx_mmap.producer, rx_mmap.consumer);
        let tx_prod = RingProducer::new(tx_mmap.producer, tx_mmap.consumer, sizes.tx);

        // 6. Pre-fill the FILL ring before bind. ZC drivers reject bind()
        //    if FILL is empty; copy mode allows empty but we still take the
        //    caller's frames so RX can start delivering immediately.
        let fill_mask = sizes.fill.saturating_sub(1);
        let mut written = 0u32;
        for addr in pre_fill_frames {
            let Some(idx) = fill_prod.produce() else { break };
            unsafe { fill_mmap.desc.add((idx & fill_mask) as usize).write(addr) };
            written += 1;
        }
        if written > 0 {
            fill_prod.commit();
        }

        // 7. bind(). Note the `XDP_USE_NEED_WAKEUP` — without it the kernel
        //    spins on the rings; with it, it sets a flag we test before
        //    issuing a `sendto` wake nudge.
        let sxdp = sockaddr_xdp {
            sxdp_family: AF_XDP as sa_family_t,
            sxdp_flags: XDP_USE_NEED_WAKEUP | mode.flag(),
            sxdp_ifindex: if_index,
            sxdp_queue_id: queue_id,
            sxdp_shared_umem_fd: 0,
        };
        let rc = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                &sxdp as *const _ as *const sockaddr,
                mem::size_of::<sockaddr_xdp>() as socklen_t,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }

        // Suppress unused-field warning for `umem` — we only borrow it for
        // the duration of `XDP_UMEM_REG`; the kernel keeps its own reference
        // via the registration.
        let _ = umem;

        Ok(Self {
            fd,
            if_index,
            queue_id,
            sizes,
            mode,
            fill_mmap,
            comp_mmap,
            rx_mmap,
            tx_mmap,
            fill_prod,
            comp_cons,
            rx_cons,
            tx_prod,
        })
    }

    /// Push as many of the supplied frame addresses into the FILL ring as
    /// it has free slots for; commits the producer index in one Release
    /// store. Returns the number actually written; the caller keeps any
    /// addresses past the FILL capacity for the next call.
    pub fn replenish_fill<I: IntoIterator<Item = u64>>(&mut self, addrs: I) -> u32 {
        // Pull the kernel's consumer index forward so we know how much
        // space is free.
        self.fill_prod.sync(false);
        let mut written = 0u32;
        let mask = self.sizes.fill.saturating_sub(1);
        for addr in addrs {
            let Some(idx) = self.fill_prod.produce() else { break };
            unsafe { self.fill_mmap.desc.add((idx & mask) as usize).write(addr) };
            written += 1;
        }
        if written > 0 {
            self.fill_prod.commit();
        }
        written
    }

    /// Drain up to `out.capacity()` completed TX frame addresses from the
    /// COMPLETION ring into `out`. Returns the count appended. Caller is
    /// expected to push these back to its TX free list.
    pub fn drain_completion(&mut self, out: &mut Vec<u64>) -> usize {
        self.comp_cons.sync(false);
        let mask = self.sizes.completion.saturating_sub(1);
        let mut n = 0usize;
        let want = out.capacity().saturating_sub(out.len());
        while n < want {
            let Some(idx) = self.comp_cons.consume() else { break };
            let addr = unsafe { *self.comp_mmap.desc.add((idx & mask) as usize) };
            out.push(addr);
            n += 1;
        }
        if n > 0 {
            self.comp_cons.commit();
        }
        n
    }

    /// Drain up to `max` RX descriptors into `out` (which must have spare
    /// capacity for them — `out.reserve(max)` first if unsure). Returns the
    /// count appended. Caller wraps each into an `XdpRxBufMut::Ring` after
    /// parsing headers.
    pub fn drain_rx(&mut self, out: &mut Vec<XdpDesc>, max: usize) -> usize {
        self.rx_cons.sync(false);
        let mask = self.sizes.rx.saturating_sub(1);
        let mut n = 0usize;
        let want = max.min(out.capacity().saturating_sub(out.len()));
        while n < want {
            let Some(idx) = self.rx_cons.consume() else { break };
            let desc = unsafe { *self.rx_mmap.desc.add((idx & mask) as usize) };
            out.push(desc);
            n += 1;
        }
        if n > 0 {
            self.rx_cons.commit();
        }
        n
    }

    /// Push a TX descriptor onto the TX ring. Returns `false` if the ring
    /// is full (caller should retry after the kernel has drained some
    /// completions). The caller is responsible for calling
    /// [`Self::commit_tx`] + [`Self::wake_tx`] after a batch.
    pub fn enqueue_tx(&mut self, desc: XdpDesc) -> bool {
        let Some(idx) = self.tx_prod.produce() else { return false };
        let mask = self.sizes.tx.saturating_sub(1);
        unsafe { self.tx_mmap.desc.add((idx & mask) as usize).write(desc) };
        true
    }

    pub fn commit_tx(&mut self) {
        self.tx_prod.commit();
    }

    /// Free slots in the TX ring (after the latest sync).
    pub fn tx_available(&mut self) -> u32 {
        self.tx_prod.sync(false);
        self.tx_prod.available()
    }

    pub fn fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    pub fn if_index(&self) -> u32 {
        self.if_index
    }

    pub fn queue_id(&self) -> u32 {
        self.queue_id
    }

    pub fn sizes(&self) -> RingSizes {
        self.sizes
    }

    pub fn mode(&self) -> XdpMode {
        self.mode
    }

    /// True when the kernel has set `XDP_RING_NEED_WAKEUP` on the TX ring —
    /// the next `sendto()` nudge will pick the driver up out of idle.
    pub fn tx_needs_wakeup(&self) -> bool {
        unsafe { (*self.tx_mmap.flags).load(Ordering::Relaxed) & XDP_RING_NEED_WAKEUP != 0 }
    }

    /// Same flag but for the FILL ring — `recvfrom`/`poll` are the usual
    /// nudges on the RX side.
    pub fn fill_needs_wakeup(&self) -> bool {
        unsafe { (*self.fill_mmap.flags).load(Ordering::Relaxed) & XDP_RING_NEED_WAKEUP != 0 }
    }

    /// Wake the TX driver. `sendto` with a NULL buffer just nudges the
    /// kernel to scan our TX ring; `MSG_DONTWAIT` ensures we never block.
    pub fn wake_tx(&self) -> io::Result<()> {
        let rc = unsafe {
            libc::sendto(self.fd.as_raw_fd(), ptr::null(), 0, MSG_DONTWAIT, ptr::null(), 0)
        };
        if rc < 0 {
            let err = io::Error::last_os_error();
            // EAGAIN/EBUSY just mean the driver was already awake; ignore.
            match err.raw_os_error() {
                Some(libc::EAGAIN) | Some(libc::EBUSY) | Some(libc::ENOBUFS) => Ok(()),
                _ => Err(err),
            }
        } else {
            Ok(())
        }
    }
}

impl AsFd for RawXdpSocket {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

#[inline]
fn setsockopt(
    fd: RawFd,
    level: i32,
    name: i32,
    val: *const libc::c_void,
    len: socklen_t,
) -> io::Result<()> {
    let rc = unsafe { libc::setsockopt(fd, level, name, val, len) };
    if rc < 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
}
