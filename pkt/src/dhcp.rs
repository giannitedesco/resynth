use super::Serialize;
use crate::AsBytes;

pub mod opcode {
    pub const REQUEST: u8 = 1;
    pub const REPLY: u8 = 2;
}

pub mod message {
    pub const DISCOVER: u8 = 1;
    pub const OFFER: u8 = 2;
    pub const REQUEST: u8 = 3;
    pub const ACK: u8 = 5;
    pub const NACK: u8 = 6;
    pub const RELEASE: u8 = 7;
    pub const INFORM: u8 = 8;
}

pub mod opt {
    pub const PADDING: u8 = 0;
    pub const CLIENT_HOSTNAME: u8 = 12;
    pub const VENDOR_SPECIFIC: u8 = 43;
    pub const REQUESTED_ADDRESS: u8 = 50;
    pub const MESSAGE_TYPE: u8 = 53;
    pub const SERVER_ID: u8 = 54;
    pub const PARAM_REQUEST_LIST: u8 = 55;
    pub const MAX_MESSAGE_SIZE: u8 = 57;
    pub const VENDOR_CLASS_ID: u8 = 60;
    pub const CLIENT_ID: u8 = 61;
    pub const CLIENT_FQDN: u8 = 81;
}

pub const CLIENT_PORT: u8 = 68;
pub const SERVER_PORT: u8 = 67;
pub const MAGIC: u32 = 0x63825363u32;

#[repr(C, packed(1))]
#[derive(Debug, Copy, Clone, Default)]
pub struct dhcp_opt {
    opt: u8,
    len: u8,
}
impl Serialize for dhcp_opt {}

impl dhcp_opt {
    pub fn new(opt: u8, len: u8) -> Self {
        Self {
            opt,
            len,
        }
    }

    pub fn from_buf<T: AsRef<[u8]>>(opt: u8, data: &T) -> Self {
        Self::new(opt, data.as_ref().len() as u8)
    }

    pub fn create<T: AsRef<[u8]>>(opt: u8, data: &T) -> Vec<u8> {
        let buf = data.as_ref();

        let hdr = Self::new(opt, buf.len() as u8);
        let mut ret = Vec::with_capacity(std::mem::size_of::<dhcp_opt>() + buf.len());

        ret.extend(hdr.as_bytes());
        ret.extend(buf);

        ret
    }
}

#[repr(C, packed(1))]
#[derive(Debug, Copy, Clone)]
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
impl Serialize for dhcp_hdr {}
