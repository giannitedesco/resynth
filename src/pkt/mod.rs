#![allow(unused)]

mod util;

pub mod eth;
pub mod ipv4;

mod pcap;

pub use pcap::PcapWriter;

use std::fmt;
use std::fmt::Write;

use crate::val::Val;
use crate::str::BytesObj;

#[derive(Debug)]
pub struct Hdr<T> {
    off: u16,
    len: u16,
    phantom: std::marker::PhantomData<T>,
}

impl<T> Hdr<T> {
    fn new(off: usize) -> Self {
        Self {
            off: off as u16,
            len: std::mem::size_of::<T>() as u16,
            phantom: std::marker::PhantomData,
        }
    }

    fn off(&self) -> usize {
        self.off as usize
    }

    pub fn len(&self) -> usize {
        self.len as usize
    }
}

pub struct Packet {
    buf: Vec<u8>,
    headroom: usize,
}

impl fmt::Debug for Packet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            f.write_fmt(format_args!("{} byte packet:\n", self.len()));
            for line in self.hex_dump() {
                f.write_str(&line)?;
                f.write_str("\n")?;
            }
        } else {
            f.write_str("Packet<>")?;
        }
        Ok(())
    }
}

/// enough for pcap header
const DEFAULT_HEADROOM: usize = 16;

/// enough for: eth/ip/tcp/10 bytes payload
const DEFAULT_CAPACITY: usize = 64;

impl Default for Packet {
    fn default() -> Self {
        Packet::new(DEFAULT_HEADROOM, DEFAULT_CAPACITY)
    }
}

impl Packet {
    pub fn new(headroom: usize, capacity: usize) -> Self {
        let mut new: Self = Self {
            buf: Vec::with_capacity(headroom + capacity),
            headroom,
        };

        new.expand(headroom);

        new
    }
    pub fn with_headroom(headroom: usize, capacity: usize) -> Self {
        Packet::new(headroom, DEFAULT_CAPACITY)
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Packet::new(DEFAULT_HEADROOM, capacity)
    }

    pub fn len(&self) -> usize {
        assert!(self.buf.len() > self.headroom);
        self.buf.len() - self.headroom
    }

    fn expand(&mut self, len: usize) -> usize {
        let ret = self.buf.len();
        self.buf.resize(self.buf.len() + len, 0);
        ret
    }

    /// Take an existing header (which must be at the tail-end of the packet) and extend it. Useful
    /// for adding things like IP or TCP options or any other variable-length trailer.
    pub fn extend_hdr<T>(&mut self, hdr: &mut Hdr<T>, len: usize) {
        let tot_len = hdr.off() + hdr.len();
        assert!(tot_len == self.buf.len());
        self.expand(len);
        hdr.len += len as u16;
    }

    /// Append a new header on to the packet
    pub fn push_hdr<T>(&mut self) -> Hdr<T> {
        let hdr = Hdr::new(self.buf.len());
        self.expand(hdr.len());
        hdr
    }

    /// Apped a bunch of bytes
    pub fn push_bytes(&mut self, buf: &[u8]) {
        self.buf.extend_from_slice(buf);
    }

    /// Prepend a new header into the packet headroom
    pub fn lower_headroom<T>(&mut self) -> Hdr<T> {
        let sz = std::mem::size_of::<T>();

        assert!(sz <= self.headroom);

        self.headroom -= sz;

        Hdr::new(self.headroom)
    }

    /// Return headroom to the packet. Header must start at the first byte of packet buffer
    pub fn return_headroom<T>(&mut self, hdr: Hdr<T>) {
        assert!(hdr.off() == self.headroom);
        assert!(hdr.len() <= self.len());
        self.headroom += hdr.len();
    }

    /// Get a reference to the part of the buffer corresponding to this header
    pub fn get_hdr<T>(&self, hdr: &Hdr<T>) -> &T {
        let sz = std::mem::size_of::<T>();
        let off = hdr.off as usize;
        let bytes = &self.buf[off..off + sz];
        assert!(off >= self.headroom);
        unsafe {
            &*(bytes.as_ptr() as *const T)
        }
    }

    /// Get a mutable reference to the part of the buffer corresponding to this header
    pub fn get_mut_hdr<T>(&mut self, hdr: &Hdr<T>) -> &mut T {
        let sz = std::mem::size_of::<T>();
        let off = hdr.off as usize;
        let bytes = &mut self.buf[off..off + sz];
        assert!(off >= self.headroom);
        unsafe {
            &mut *(bytes.as_mut_ptr() as *mut T)
        }
    }

    pub fn get_mut_slice(&mut self, off: usize, len: usize) -> Option<&mut [u8]> {
        let end = off + len;
        if off < self.headroom {
            return None
        }
        if off > self.buf.len() {
            return None
        }
        let bytes = &mut self.buf[off..end];
        Some(bytes)
    }

    pub fn get_buf(&mut self, off: usize, len: usize) -> &mut [u8] {
        &mut self.buf[off..off + len]
    }

    pub fn bytes_from<T>(&mut self, hdr: &Hdr<T>, len: usize) -> &mut [u8] {
        let off = hdr.off();
        &mut self.buf[off..off + len]
    }

    pub fn bytes_after<T>(&mut self, hdr: &Hdr<T>, len: usize) -> &mut [u8] {
        let off = hdr.off();
        let start = off + hdr.len();
        let end = off + len;
        &mut self.buf[start..end]
    }

    pub fn hex_dump_line(&self, pos: usize, width: usize) -> String {
        let mut s = String::new();
        let valid = if pos + width < self.buf.len() {
            width
        } else {
            self.buf.len() - pos
        };
        let bytes = &self.buf[pos..pos + valid];

        write!(s, "{:05x} |", pos);

        for b in bytes[0..valid].iter() {
            write!(s, " {:02x}", b);
        }

        for i in valid..width {
            write!(s, "   ");
        }

        write!(s, " ");

        for b in bytes[0..valid].iter() {
            let chr = *b as char;

            if chr.is_ascii_graphic() {
                write!(s, "{}", chr);
            } else {
                write!(s, ".");
            }
        }

        s
    }

    pub fn hex_dump_width(&self, width: usize) -> Vec<String> {
        let mut lines: Vec<String> = Vec::new();
        let mut pos = self.headroom;
        let len = self.buf.len();

        while pos < len {
            lines.push(self.hex_dump_line(pos, width));
            pos += width;
        }

        lines
    }

    pub fn hex_dump(&self) -> Vec<String> {
        self.hex_dump_width(16)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[self.headroom..]
    }
}

impl From<Packet> for BytesObj {
    fn from (pkt: Packet) -> Self {
        Self::new(pkt.buf)
    }
}

impl From<Packet> for Val {
    fn from(pkt: Packet) -> Self {
        Self::Pkt(pkt.into())
    }
}

impl From<Vec<Packet>> for Val {
    fn from(pkts: Vec<Packet>) -> Self {
        Self::PktGen(pkts.into())
    }
}
