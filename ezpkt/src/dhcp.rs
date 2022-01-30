use pkt::{Packet, Hdr, AsBytes};
use pkt::dhcp::{dhcp_hdr, dhcp_opt, MAGIC};


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
        let mut pkt = Packet::with_capacity(MIN_CAPACITY + capacity);
        let dhcp: Hdr<dhcp_hdr> = pkt.push_hdr();

        pkt.get_mut_hdr(dhcp).magic = MAGIC.to_be();

        Self {
            pkt,
            dhcp,
        }
    }

    pub fn min_capacity() -> Self {
        Self::with_capacity(0)
    }

    #[must_use]
    pub fn op(mut self, op: u8) -> Self {
        self.pkt.get_mut_hdr(self.dhcp).op = op;
        self
    }

    #[must_use]
    pub fn htype(mut self, htype: u8) -> Self {
        self.pkt.get_mut_hdr(self.dhcp).htype = htype;
        self
    }

    #[must_use]
    pub fn hlen(mut self, hlen: u8) -> Self {
        self.pkt.get_mut_hdr(self.dhcp).hlen = hlen;
        self
    }

    #[must_use]
    pub fn hops(mut self, hops: u8) -> Self {
        self.pkt.get_mut_hdr(self.dhcp).hops = hops;
        self
    }

    #[must_use]
    pub fn xid(mut self, xid: u32) -> Self {
        self.pkt.get_mut_hdr(self.dhcp).xid = xid.to_be();
        self
    }

    #[must_use]
    pub fn secs(mut self, secs: u16) -> Self {
        self.pkt.get_mut_hdr(self.dhcp).secs = secs.to_be();
        self
    }

    #[must_use]
    pub fn flags(mut self, flags: u16) -> Self {
        self.pkt.get_mut_hdr(self.dhcp).flags = flags.to_be();
        self
    }

    #[must_use]
    pub fn ciaddr(mut self, ciaddr: u32) -> Self {
        self.pkt.get_mut_hdr(self.dhcp).ciaddr = ciaddr.to_be();
        self
    }

    #[must_use]
    pub fn yiaddr(mut self, yiaddr: u32) -> Self {
        self.pkt.get_mut_hdr(self.dhcp).yiaddr = yiaddr.to_be();
        self
    }

    #[must_use]
    pub fn siaddr(mut self, siaddr: u32) -> Self {
        self.pkt.get_mut_hdr(self.dhcp).siaddr = siaddr.to_be();
        self
    }

    #[must_use]
    pub fn giaddr(mut self, giaddr: u32) -> Self {
        self.pkt.get_mut_hdr(self.dhcp).giaddr = giaddr.to_be();
        self
    }

    #[must_use]
    pub fn chaddr<T: AsRef<[u8]>>(mut self, chaddr: T) -> Self {
        let dhcp = self.pkt.get_mut_hdr(self.dhcp);
        let buf = chaddr.as_ref();
        let cplen = std::cmp::min(buf.len(), dhcp.chaddr.len());
        dhcp.chaddr[..cplen].copy_from_slice(&buf[..cplen]);
        self
    }

    #[must_use]
    pub fn sname<T: AsRef<[u8]>>(mut self, sname: T) -> Self {
        let dhcp = self.pkt.get_mut_hdr(self.dhcp);
        let buf = sname.as_ref();
        let cplen = std::cmp::min(buf.len(), dhcp.sname.len());
        dhcp.sname[..cplen].copy_from_slice(&buf[..cplen]);
        self
    }

    #[must_use]
    pub fn file<T: AsRef<[u8]>>(mut self, file: T) -> Self {
        let dhcp = self.pkt.get_mut_hdr(self.dhcp);
        let buf = file.as_ref();
        let cplen = std::cmp::min(buf.len(), dhcp.file.len());
        dhcp.file[..cplen].copy_from_slice(&buf[..cplen]);
        self
    }

    #[must_use]
    pub fn magic(mut self, magic: u32) -> Self {
        self.pkt.get_mut_hdr(self.dhcp).magic = magic.to_be();
        self
    }

    #[must_use]
    pub fn opt<T: AsRef<[u8]>>(mut self, opt: u8, buf: T) -> Self {
        self.pkt.push_bytes(dhcp_opt::from_buf(opt, &buf).as_bytes());
        self.pkt.push_bytes(buf);
        self
    }
}

impl AsRef<[u8]> for Dhcp {
    fn as_ref(&self) -> &[u8] {
        self.pkt.as_ref()
    }
}
