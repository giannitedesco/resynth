use std::cell::RefCell;
use std::fmt;
use std::ops::{Deref, DerefMut};

use bytemuck::Pod;

pub struct RefMut<'a, T> {
    buf: std::cell::RefMut<'a, Vec<u8>>,
    off: usize,
    phantom: std::marker::PhantomData<T>,
}

impl<T> RefMut<'_, T> {
    pub fn size_of() -> usize {
        std::mem::size_of::<T>()
    }

    pub fn len(&self) -> usize {
        Self::size_of()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl<T> DerefMut for RefMut<'_, T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut T {
        let off = self.off;
        let bytes = &mut self.buf[off..off + Self::size_of()];

        unsafe { &mut *(bytes.as_mut_ptr() as *mut T) }
    }
}

impl<T> Deref for RefMut<'_, T> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &T {
        let off = self.off;
        let bytes = &self.buf[off..off + Self::size_of()];

        unsafe { &*(bytes.as_ptr() as *const T) }
    }
}

pub struct Ref<'a, T> {
    buf: std::cell::Ref<'a, Vec<u8>>,
    off: usize,
    phantom: std::marker::PhantomData<T>,
}

impl<T> Ref<'_, T> {
    pub fn size_of() -> usize {
        std::mem::size_of::<T>()
    }

    pub fn len(&self) -> usize {
        Self::size_of()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl<T> Deref for Ref<'_, T> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &T {
        let off = self.off;
        let len = Self::size_of();
        let bytes = &self.buf[off..off + len];

        unsafe { &*(bytes.as_ptr() as *const T) }
    }
}

pub struct SliceRefMut<'a> {
    buf: std::cell::RefMut<'a, Vec<u8>>,
    off: usize,
    len: usize,
}

impl DerefMut for SliceRefMut<'_> {
    #[inline]
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.buf[self.off..self.off + self.len]
    }
}

impl Deref for SliceRefMut<'_> {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &[u8] {
        &self.buf[self.off..self.off + self.len]
    }
}

pub struct SliceRef<'a> {
    buf: std::cell::Ref<'a, Vec<u8>>,
    off: usize,
    len: usize,
}

impl AsRef<[u8]> for SliceRef<'_> {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.deref()
    }
}

impl Deref for SliceRef<'_> {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &[u8] {
        &self.buf[self.off..self.off + self.len]
    }
}

#[derive(Debug, Copy, Clone)]
pub struct Hdr<T> {
    off: usize,
    phantom: std::marker::PhantomData<T>,
}

impl<T: Pod> Hdr<T> {
    fn new(off: usize) -> Self {
        Self {
            off,
            phantom: std::marker::PhantomData,
        }
    }

    pub fn off(&self) -> usize {
        self.off
    }

    pub fn size_of() -> usize {
        std::mem::size_of::<T>()
    }

    pub fn len(&self) -> usize {
        Self::size_of()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn get<'a>(&self, pkt: &'a Packet) -> Ref<'a, T> {
        Ref {
            buf: pkt.buf.borrow(),
            off: self.off,
            phantom: self.phantom,
        }
    }

    pub fn get_mut<'a>(&self, pkt: &'a Packet) -> RefMut<'a, T> {
        RefMut {
            buf: pkt.buf.borrow_mut(),
            off: self.off,
            phantom: self.phantom,
        }
    }

    pub fn mutate<F>(&self, pkt: &Packet, f: F)
    where
        F: FnOnce(&mut T),
    {
        let mut buf = pkt.buf.borrow_mut();
        let off = self.off;
        let bytes = &mut buf[off..off + Self::size_of()];

        f(unsafe { &mut *(bytes.as_mut_ptr() as *mut T) });
    }

    pub fn mutate_as_bytes<F>(&self, pkt: &Packet, f: F)
    where
        F: FnOnce(&mut [u8]),
    {
        let mut buf = pkt.buf.borrow_mut();
        let off = self.off;
        let bytes = &mut buf[off..off + Self::size_of()];

        f(bytes);
    }

    /// Get this header as a PktSlice
    pub fn as_slice(&self) -> PktSlice {
        PktSlice {
            off: self.off(),
            len: Self::size_of(),
        }
    }

    /// Get n bytes in the packet, after this header
    pub fn payload(&self, n: usize) -> PktSlice {
        let begin = self.off() + Self::size_of();

        PktSlice { off: begin, len: n }
    }

    /// Get bytes in this header, and then n bytes after
    pub fn packet(&self, n: usize) -> PktSlice {
        let begin = self.off();

        PktSlice { off: begin, len: n }
    }

    /// Immutable reference to the bytes of this header
    pub fn as_bytes<'a>(&self, pkt: &'a Packet) -> SliceRef<'a> {
        self.as_slice().get(pkt)
    }

    /// Mutable reference to the bytes of this header
    pub fn as_bytes_mut<'a>(&self, pkt: &'a Packet) -> SliceRefMut<'a> {
        self.as_slice().get_mut(pkt)
    }

    /// Immutable reference to the bytes of the payload
    pub fn bytes_after<'a>(&self, pkt: &'a Packet, n: usize) -> SliceRef<'a> {
        self.payload(n).get(pkt)
    }

    /// Mutable reference to the bytes of the payload
    pub fn bytes_after_mut<'a>(&self, pkt: &'a Packet, n: usize) -> SliceRefMut<'a> {
        self.payload(n).get_mut(pkt)
    }

    /// Immutable reference to the bytes of header and payload
    pub fn packet_bytes<'a>(&self, pkt: &'a Packet, n: usize) -> SliceRef<'a> {
        self.packet(n).get(pkt)
    }

    /// Mutable reference to the bytes of header and payload
    pub fn packet_bytes_mut<'a>(&self, pkt: &'a Packet, n: usize) -> SliceRefMut<'a> {
        self.packet(n).get_mut(pkt)
    }

    pub fn len_from(&self, pkt: &Packet) -> usize {
        pkt.len_from(self.off)
    }

    pub fn len_after(&self, pkt: &Packet) -> usize {
        pkt.len_from(self.off + Self::size_of())
    }
}

#[derive(Debug, Copy, Clone)]
pub struct PktSlice {
    off: usize,
    len: usize,
}

impl PktSlice {
    fn new(off: usize, len: usize) -> Self {
        Self { off, len }
    }

    pub fn off(&self) -> usize {
        self.off
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn get<'a>(&self, pkt: &'a Packet) -> SliceRef<'a> {
        SliceRef {
            buf: pkt.buf.borrow(),
            off: self.off,
            len: self.len,
        }
    }

    pub fn get_mut<'a>(&self, pkt: &'a Packet) -> SliceRefMut<'a> {
        SliceRefMut {
            buf: pkt.buf.borrow_mut(),
            off: self.off,
            len: self.len,
        }
    }

    pub fn mutate<F>(&self, pkt: &Packet, f: F)
    where
        F: FnOnce(&mut [u8]),
    {
        let mut buf = pkt.buf.borrow_mut();
        let off = self.off;
        let bytes = &mut buf[off..off + self.len()];

        f(bytes);
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct Packet {
    buf: RefCell<Vec<u8>>,
    headroom: usize,
}

impl fmt::Debug for Packet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            self.alt_fmt(f, 16)
        } else {
            f.write_fmt(format_args!("Packet<{} bytes>", self.len()))?;
            Ok(())
        }
    }
}

impl Default for Packet {
    fn default() -> Self {
        Packet::new(Self::DEFAULT_HEADROOM, Self::DEFAULT_CAPACITY)
    }
}

impl Packet {
    /// enough for pcap header
    const DEFAULT_HEADROOM: usize = 16;

    /// enough for: eth/ip/tcp/10 bytes payload
    const DEFAULT_CAPACITY: usize = 64;

    pub fn new(headroom: usize, capacity: usize) -> Self {
        let new: Self = Self {
            buf: RefCell::new(Vec::with_capacity(headroom + capacity)),
            headroom,
        };

        new.expand(headroom);

        new
    }

    pub fn with_headroom(headroom: usize) -> Self {
        Packet::new(headroom, Self::DEFAULT_CAPACITY)
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Packet::new(Self::DEFAULT_HEADROOM, capacity)
    }

    pub fn headroom(&self) -> usize {
        self.headroom
    }

    pub fn len(&self) -> usize {
        let buf = self.buf.borrow();

        assert!(buf.len() >= self.headroom);

        buf.len() - self.headroom
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn len_from(&self, off: usize) -> usize {
        let buf = self.buf.borrow();
        let end = buf.len();

        assert!(end >= off);

        end - off
    }

    fn expand(&self, len: usize) -> usize {
        let mut buf = self.buf.borrow_mut();
        let prev_len = buf.len();
        let new_len = prev_len + len;

        buf.resize(new_len, 0);

        prev_len
    }

    /// Append a new header to the packet
    pub fn push_hdr<T: Pod>(&self) -> Hdr<T> {
        let off = self.expand(std::mem::size_of::<T>());

        Hdr::new(off)
    }

    /// Append a new header to the packet and initialize it
    pub fn push<T: Pod>(&self, item: T) -> Hdr<T> {
        let hdr: Hdr<T> = self.push_hdr();
        let mut buf = hdr.get_mut(self);

        *buf = item;

        hdr
    }

    /// Append a bunch of bytes and return their offset
    pub fn push_bytes<T: AsRef<[u8]>>(&self, bytes: T) -> PktSlice {
        let mut buf = self.buf.borrow_mut();
        let off = buf.len();
        let s = bytes.as_ref();

        buf.extend_from_slice(s);

        PktSlice::new(off, s.len())
    }

    /// Expand the packet by len bytes and return a handle to the bytes
    pub fn push_slice(&self, len: usize) -> PktSlice {
        PktSlice::new(self.expand(len), len)
    }

    /// Return the entire packet as a slice handle
    pub fn as_slice(&self) -> PktSlice {
        assert!(self.len() >= self.headroom);

        PktSlice::new(self.headroom, self.len())
    }

    /// Prepend a new header into the packet headroom
    pub fn lower_headroom<T: Pod>(&mut self) -> Hdr<T> {
        let sz = std::mem::size_of::<T>();

        assert!(sz <= self.headroom);

        self.headroom -= sz;

        Hdr::new(self.headroom)
    }

    /// Prepend a new header into the packet headroom
    pub fn lower_headroom_for<T: Pod>(&mut self, item: T) -> Hdr<T> {
        let hdr: Hdr<T> = self.lower_headroom();
        let mut buf = hdr.get_mut(self);

        *buf = item;

        hdr
    }

    /// Return headroom to the packet. Header must start at the first byte of packet buffer
    pub fn return_headroom<T: Pod>(&mut self, hdr: Hdr<T>) {
        assert!(hdr.off() == self.headroom);
        assert!(Hdr::<T>::size_of() <= self.len());

        self.headroom += Hdr::<T>::size_of();
    }

    pub fn to_vec(&self) -> Vec<u8> {
        let buf = self.buf.borrow();

        if self.headroom == 0 {
            buf.clone()
        } else {
            let s = &buf[self.headroom..self.headroom + self.len()];

            s.to_owned()
        }
    }

    pub fn to_vec_from(&self, ps: PktSlice) -> Vec<u8> {
        let buf = self.buf.borrow();

        assert!(ps.off >= self.headroom);

        if ps.off == self.headroom && ps.len == self.len() {
            buf.clone()
        } else {
            let s = &buf[ps.off..ps.off + ps.len];

            s.to_owned()
        }
    }

    pub fn into_vec_from(self, ps: PktSlice) -> Vec<u8> {
        assert!(ps.off >= self.headroom);

        if ps.off == self.headroom && ps.len == self.len() {
            self.buf.into_inner()
        } else {
            let buf = self.buf.borrow();
            let s = &buf[ps.off..ps.off + ps.len];

            s.to_owned()
        }
    }

    fn fmt_hex_dump(&self, f: &mut fmt::Formatter<'_>, width: usize) -> fmt::Result {
        let mut pos = self.headroom;
        let buf = self.buf.borrow();
        let len = buf.len();

        while pos < len {
            let valid = if pos + width < buf.len() {
                width
            } else {
                buf.len() - pos
            };

            let bytes = &buf[pos..pos + valid];

            f.write_fmt(format_args!("{:05x} |", pos))?;

            for b in bytes[0..valid].iter() {
                f.write_fmt(format_args!(" {:02x}", b))?;
            }

            for _ in valid..width {
                f.write_str("   ")?;
            }

            f.write_str(" ")?;

            for b in bytes[0..valid].iter() {
                let chr = *b as char;

                if chr.is_ascii_graphic() {
                    f.write_fmt(format_args!("{}", chr))?;
                } else {
                    f.write_str(".")?
                }
            }

            f.write_str("\n")?;
            pos += width;
        }

        Ok(())
    }

    fn alt_fmt(&self, f: &mut fmt::Formatter<'_>, width: usize) -> fmt::Result {
        f.write_fmt(format_args!("{} byte packet:\n", self.len()))?;
        self.fmt_hex_dump(f, width)
    }

    #[inline(always)]
    fn ethernet_overhead(&self) -> u64 {
        /* preamble, framce check byte, CRC, inter packet gap */
        24
    }

    #[inline(always)]
    fn timing_overhead(&self) -> u64 {
        self.ethernet_overhead()
    }

    #[inline(always)]
    pub fn bit_time(&self) -> u64 {
        let len: u64 = self.len() as u64;
        let bytes = len + self.timing_overhead();

        /* timestamp is ns, so assuming 1Gbps, 1ns = 1bit, for 10gbps we're goin to need to switch
         * to picoseconds.
         */
        bytes * 8
    }
}

impl From<Packet> for Vec<u8> {
    fn from(p: Packet) -> Self {
        p.to_vec()
    }
}
