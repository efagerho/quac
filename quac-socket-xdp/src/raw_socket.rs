//! AF_XDP socket setup: setsockopt + mmap + bind. References:
//! kernel docs `Documentation/networking/af_xdp.rst`, `man 7 af_xdp`.

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

/// Ring capacities. All four must be powers of 2.
#[derive(Debug, Clone, Copy)]
pub struct RingSizes {
    pub fill: u32,
    pub completion: u32,
    pub rx: u32,
    pub tx: u32,
}

impl Default for RingSizes {
    /// 2048 per ring (kernel `XSK_RING_*_DFLT`).
    fn default() -> Self {
        Self { fill: 2048, completion: 2048, rx: 2048, tx: 2048 }
    }
}

/// Wire mode for `bind()`. Kernel may reject `ZeroCopy`; caller falls back to `Copy`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XdpMode {
    /// DMA into UMEM (driver support required; veth on Linux ≥ 5.18).
    ZeroCopy,
    /// Kernel copies between skb and UMEM.
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

/// AF_XDP socket bound to `(if_index, queue_id)` with all four rings mmap'd.
/// Kernel-facing surface only; UMEM free-list, buffer wrappers and the
/// `PacketSocket` impl live in `socket.rs`.
#[allow(dead_code)]
pub struct RawXdpSocket {
    fd: OwnedFd,
    if_index: u32,
    queue_id: u32,
    sizes: RingSizes,
    mode: XdpMode,

    // Ring memory (munmap'd on drop).
    pub(crate) fill_mmap: RingMmap<u64>,
    pub(crate) comp_mmap: RingMmap<u64>,
    pub(crate) rx_mmap: RingMmap<XdpDesc>,
    pub(crate) tx_mmap: RingMmap<XdpDesc>,

    // Userspace owns producer side of FILL+TX, consumer side of COMP+RX.
    pub(crate) fill_prod: RingProducer,
    pub(crate) comp_cons: RingConsumer,
    pub(crate) rx_cons: RingConsumer,
    pub(crate) tx_prod: RingProducer,
}

impl RawXdpSocket {
    /// Open the socket, register UMEM, size + mmap all four rings, pre-fill
    /// FILL, and bind. `pre_fill_frames` are UMEM frame byte-offsets
    /// (`umem.frame_offset(i)`). FILL must be non-empty before bind in
    /// `ZeroCopy` mode (some drivers misbehave otherwise).
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

        // 2. Register the UMEM. `headroom` is zero -- we write headers in
        //    `[0..HEADROOM]` of each frame ourselves.
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

        // 3. Size the four rings.
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

        // 4. Query ring layout.
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

        // 5. mmap each ring.
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

        // 6. Pre-fill FILL before bind (ZC drivers reject empty FILL).
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

        // 7. bind() with XDP_USE_NEED_WAKEUP so the driver sets a flag we
        //    can test before issuing a sendto wake nudge.
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

        // umem is borrowed only for XDP_UMEM_REG; kernel holds its own ref.
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

    /// Push frame addresses into FILL up to its free capacity. Returns the
    /// count written; caller retries with the rest later.
    pub fn replenish_fill<I: IntoIterator<Item = u64>>(&mut self, addrs: I) -> u32 {
        // Refresh kernel consumer index.
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

    /// Drain completed TX frame addresses from COMPLETION into `out`.
    /// Caller pushes them back to its TX free list.
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

    /// Drain up to `max` RX descriptors into `out` (must have spare capacity).
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

    /// Enqueue a TX descriptor; returns `false` if the ring is full. Caller
    /// must `commit_tx` + `wake_tx` after the batch.
    pub fn enqueue_tx(&mut self, desc: XdpDesc) -> bool {
        let Some(idx) = self.tx_prod.produce() else { return false };
        let mask = self.sizes.tx.saturating_sub(1);
        unsafe { self.tx_mmap.desc.add((idx & mask) as usize).write(desc) };
        true
    }

    pub fn commit_tx(&mut self) {
        self.tx_prod.commit();
    }

    /// Free slots in the TX ring (after sync).
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

    /// Kernel set `XDP_RING_NEED_WAKEUP` on TX -- caller should `wake_tx`.
    pub fn tx_needs_wakeup(&self) -> bool {
        unsafe { (*self.tx_mmap.flags).load(Ordering::Relaxed) & XDP_RING_NEED_WAKEUP != 0 }
    }

    /// Same as `tx_needs_wakeup` but for the FILL ring (RX side).
    pub fn fill_needs_wakeup(&self) -> bool {
        unsafe { (*self.fill_mmap.flags).load(Ordering::Relaxed) & XDP_RING_NEED_WAKEUP != 0 }
    }

    /// Nudge the TX driver via `sendto(NULL, MSG_DONTWAIT)`.
    pub fn wake_tx(&self) -> io::Result<()> {
        let rc = unsafe {
            libc::sendto(self.fd.as_raw_fd(), ptr::null(), 0, MSG_DONTWAIT, ptr::null(), 0)
        };
        if rc < 0 {
            let err = io::Error::last_os_error();
            // EAGAIN/EBUSY just mean the driver was already awake; ignore.
            // ENOBUFS signals kernel TX queue full -- propagate so the caller
            // can back off rather than silently dropping packets.
            match err.raw_os_error() {
                Some(libc::EAGAIN) | Some(libc::EBUSY) => Ok(()),
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
