use pkt::dhcp::{MAGIC, dhcp_hdr, dhcp_opt};
use pkt::{Hdr, Packet};

use bytemuck::bytes_of;

const MIN_CAPACITY: usize = std::mem::size_of::<dhcp_hdr>();
const DEFAULT_CAPACITY: usize = 3 + 3 + 6;

pub struct Dhcp {
    pkt: Packet,
    dhcp: Hdr<dhcp_hdr>,
}

impl Default for Dhcp {
    fn default() -> Self {
        Self::with_capacity(DEFAULT_CAPACITY)
    }
}

impl Dhcp {
    pub fn with_capacity(capacity: usize) -> Self {
        let pkt = Packet::with_capacity(MIN_CAPACITY + capacity);
        let dhcp: Hdr<dhcp_hdr> = pkt.push_hdr();

        dhcp.mutate(&pkt, |hdr| hdr.magic = MAGIC.to_be());

        Self { pkt, dhcp }
    }

    pub fn min_capacity() -> Self {
        Self::with_capacity(0)
    }

    #[must_use]
    pub fn op(self, op: u8) -> Self {
        self.dhcp.mutate(&self.pkt, |hdr| hdr.op = op);
        self
    }

    #[must_use]
    pub fn htype(self, htype: u8) -> Self {
        self.dhcp.mutate(&self.pkt, |hdr| hdr.htype = htype);
        self
    }

    #[must_use]
    pub fn hlen(self, hlen: u8) -> Self {
        self.dhcp.mutate(&self.pkt, |hdr| hdr.hlen = hlen);
        self
    }

    #[must_use]
    pub fn hops(self, hops: u8) -> Self {
        self.dhcp.mutate(&self.pkt, |hdr| hdr.hops = hops);
        self
    }

    #[must_use]
    pub fn xid(self, xid: u32) -> Self {
        self.dhcp.mutate(&self.pkt, |hdr| hdr.xid = xid.to_be());
        self
    }

    #[must_use]
    pub fn secs(self, secs: u16) -> Self {
        self.dhcp.mutate(&self.pkt, |hdr| hdr.secs = secs.to_be());
        self
    }

    #[must_use]
    pub fn flags(self, flags: u16) -> Self {
        self.dhcp.mutate(&self.pkt, |hdr| hdr.flags = flags.to_be());
        self
    }

    #[must_use]
    pub fn ciaddr(self, ciaddr: u32) -> Self {
        self.dhcp
            .mutate(&self.pkt, |hdr| hdr.ciaddr = ciaddr.to_be());
        self
    }

    #[must_use]
    pub fn yiaddr(self, yiaddr: u32) -> Self {
        self.dhcp
            .mutate(&self.pkt, |hdr| hdr.yiaddr = yiaddr.to_be());
        self
    }

    #[must_use]
    pub fn siaddr(self, siaddr: u32) -> Self {
        self.dhcp
            .mutate(&self.pkt, |hdr| hdr.siaddr = siaddr.to_be());
        self
    }

    #[must_use]
    pub fn giaddr(self, giaddr: u32) -> Self {
        self.dhcp
            .mutate(&self.pkt, |hdr| hdr.giaddr = giaddr.to_be());
        self
    }

    #[must_use]
    pub fn chaddr<T: AsRef<[u8]>>(self, chaddr: T) -> Self {
        self.dhcp.mutate(&self.pkt, |hdr| {
            hdr.set_chaddr(chaddr);
        });

        self
    }

    #[must_use]
    pub fn sname<T: AsRef<[u8]>>(self, sname: T) -> Self {
        self.dhcp.mutate(&self.pkt, |hdr| {
            hdr.set_sname(sname);
        });

        self
    }

    #[must_use]
    pub fn file<T: AsRef<[u8]>>(self, file: T) -> Self {
        self.dhcp.mutate(&self.pkt, |hdr| {
            hdr.set_file(file);
        });

        self
    }

    #[must_use]
    pub fn magic(self, magic: u32) -> Self {
        self.dhcp.mutate(&self.pkt, |hdr| hdr.magic = magic.to_be());
        self
    }

    #[must_use]
    pub fn opt<T: AsRef<[u8]>>(self, opt: u8, buf: T) -> Self {
        self.pkt
            .push_bytes(bytes_of(&dhcp_opt::from_buf(opt, &buf)));
        self.pkt.push_bytes(buf);
        self
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.pkt.into()
    }
}
