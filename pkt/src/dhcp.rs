use bytemuck::{Pod, Zeroable, bytes_of};

pub mod opcode {
    pub const REQUEST: u8 = 1;
    pub const REPLY: u8 = 2;
}

pub mod message {
    pub const DISCOVER: u8 = 1;
    pub const OFFER: u8 = 2;
    pub const REQUEST: u8 = 3;
    pub const DECLINE: u8 = 4;
    pub const ACK: u8 = 5;
    pub const NACK: u8 = 6;
    pub const RELEASE: u8 = 7;
    pub const INFORM: u8 = 8;
    pub const FORCERENEW: u8 = 9;
    pub const LEASEQUERY: u8 = 10;
    pub const LEASEUNASSIGNED: u8 = 11;
    pub const LEASEUNKNOWN: u8 = 12;
    pub const LEASEACTIVE: u8 = 13;
    pub const BULKLEASEQUERY: u8 = 14;
    pub const LEASEQUERYDONE: u8 = 15;
    pub const ACTIVELEASEQUERY: u8 = 16;
    pub const LEASEQUERYSTATUS: u8 = 17;
    pub const TLS: u8 = 18;
}

pub mod opt {
    pub const PADDING: u8 = 0;
    pub const SUBNET_MASK: u8 = 1;
    pub const CLIENT_HOSTNAME: u8 = 12;
    pub const VENDOR_SPECIFIC: u8 = 43;
    pub const REQUESTED_ADDRESS: u8 = 50;
    pub const ADDRESS_LEASE_TIME: u8 = 51;
    pub const MESSAGE_TYPE: u8 = 53;
    pub const SERVER_ID: u8 = 54;
    pub const PARAM_REQUEST_LIST: u8 = 55;
    pub const MAX_MESSAGE_SIZE: u8 = 57;
    pub const RENEWAL_TIME: u8 = 58;
    pub const REBINDING_TIME: u8 = 59;
    pub const VENDOR_CLASS_ID: u8 = 60;
    pub const CLIENT_ID: u8 = 61;
    pub const CLIENT_FQDN: u8 = 81;
    pub const END: u8 = 0xff;
}

pub const CLIENT_PORT: u16 = 68;
pub const SERVER_PORT: u16 = 67;
pub const MAGIC: u32 = 0x63825363u32;

#[repr(C, packed(1))]
#[derive(Pod, Zeroable, Debug, Copy, Clone, Default)]
pub struct dhcp_opt {
    opt: u8,
    len: u8,
}

impl dhcp_opt {
    pub fn new(opt: u8, len: u8) -> Self {
        Self { opt, len }
    }

    pub fn from_buf<T: AsRef<[u8]>>(opt: u8, data: T) -> Self {
        Self::new(opt, data.as_ref().len() as u8)
    }

    pub fn create<T: AsRef<[u8]>>(opt: u8, data: T) -> Vec<u8> {
        let buf = data.as_ref();

        let hdr = Self::new(opt, buf.len() as u8);
        let mut ret = Vec::with_capacity(std::mem::size_of::<dhcp_opt>() + buf.len());

        ret.extend(bytes_of(&hdr));
        ret.extend(buf);

        ret
    }
}

#[repr(C, packed(1))]
#[derive(Pod, Zeroable, Debug, Copy, Clone)]
pub struct dhcp_hdr {
    pub op: u8,
    pub htype: u8,
    pub hlen: u8,
    pub hops: u8,
    pub xid: u32,
    pub secs: u16,
    pub flags: u16,
    pub ciaddr: u32,
    pub yiaddr: u32,
    pub siaddr: u32,
    pub giaddr: u32,
    pub chaddr: [u8; 16],
    pub sname: [u8; 64],
    pub file: [u8; 128],
    pub magic: u32,
}

impl dhcp_hdr {
    /// Set client hardware address, silently truncates
    pub fn set_chaddr<T: AsRef<[u8]>>(&mut self, chaddr: T) -> &mut Self {
        let buf = chaddr.as_ref();
        let cplen = std::cmp::min(buf.len(), self.chaddr.len());

        self.chaddr[..cplen].copy_from_slice(&buf[..cplen]);

        self
    }

    /// Set TFTP server name, silently truncates
    pub fn set_sname<T: AsRef<[u8]>>(&mut self, sname: T) -> &mut Self {
        let buf = sname.as_ref();
        let cplen = std::cmp::min(buf.len(), self.sname.len());

        self.sname[..cplen].copy_from_slice(&buf[..cplen]);

        self
    }

    /// Set TFTP file name, silently truncates
    pub fn set_file<T: AsRef<[u8]>>(&mut self, file: T) -> &mut Self {
        let buf = file.as_ref();
        let cplen = std::cmp::min(buf.len(), self.file.len());

        self.file[..cplen].copy_from_slice(&buf[..cplen]);

        self
    }
}
