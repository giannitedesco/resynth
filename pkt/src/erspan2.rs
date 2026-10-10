use bytemuck::{Pod, Zeroable};

/*
                    ERSPAN Type II header (8 octets [42:49])
      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |  Ver  |          VLAN         | COS | En|T|    Session ID     |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |      Reserved         |                  Index                |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

  Field         Position    Length          Definition
               [octet:bit]  (bits)

  Ver            [42:0]       4      ERSPAN Encapsulation version.
                                     This indicates the version of
                                     the ERSPAN encapsulation
                                     specification. Set to 0x1 for
                                     Type II. (Version 0x0 is
                                     obsoleted.)

  VLAN           [42:4]      12      Original VLAN of the frame,
                                     mirrored from the source.
                                     If the En field is set to 11,
                                     the value of VLAN is undefined.

  COS            [44:0]       3      Original class of service of the
                                     frame, mirrored from the source.

  En             [44:3]       2      The trunk encapsulation type
                                     associated with the ERSPAN source
                                     port for ingress ERSPAN traffic.

                                     The possible values are:
                                     00-originally without VLAN tag
                                     01-originally ISL encapsulated
                                     10-originally 802.1Q encapsulated
                                     11-VLAN tag preserved in frame.

  T              [44:5]       1      This bit indicates that the frame
                                     copy encapsulated in the ERSPAN
                                     packet has been truncated. This
                                     occurs if the ERSPAN encapsulated
                                     frame exceeds the configured MTU.

  Session ID     [44:6]      10      Identification associated with
  (ERSPAN ID)                        each ERSPAN session. Must be
                                     unique between the source and the
                                     receiver(s). (See section below.)

  Reserved       [46:0]      12      All bits are set to zero

  Index          [47:4]      20      A 20 bit index/port number
                                     associated with the ERSPAN
                                     traffic's source port and
                                     direction (ingress/egress). This
                                     field is platform dependent.
*/

pub mod mask {
    pub const VER: u32 = 0xf000_0000;
    pub const VLAN: u32 = 0x0fff_0000;
    pub const COS: u32 = 0x0000_e000;
    pub const EN: u32 = 0x0000_1800;
    pub const T: u32 = 0x0000_0400;
    pub const SESS: u32 = 0x0000_03ff;

    pub const RSVD: u32 = 0xfff0_0000;
    pub const INDX: u32 = 0x000f_ffff;
}

pub mod shift {
    pub const VER: u32 = 28;
    pub const VLAN: u32 = 16;
    pub const COS: u32 = 13;
    pub const EN: u32 = 11;
    pub const T: u32 = 10;

    pub const RSVD: u32 = 20;
}

pub mod version {
    pub const ERSPAN2: u8 = 1;
}

#[derive(Default, Debug, Copy, Clone)]
pub enum Encap {
    NoVlan = 0,
    IslStripped = 1,
    VlanStripped = 2,

    #[default]
    TagPreserved = 3,
}

#[repr(C, packed(1))]
#[derive(Debug, Copy, Clone)]
pub struct Erspan2 {
    ver: u8,
    vlan: u16,
    cos: u8,
    en: Encap,
    t: bool,
    sess_id: u16,

    rsvd: u16,
    index: u32,
}

impl Default for Erspan2 {
    fn default() -> Self {
        Self {
            ver: version::ERSPAN2,
            vlan: 0,
            cos: 0,
            en: Encap::default(),
            t: false,
            sess_id: 0,
            rsvd: 0,
            index: 0,
        }
    }
}

impl Erspan2 {
    #[must_use]
    pub fn ver(mut self, ver: u8) -> Self {
        self.ver = ver;
        self
    }

    #[must_use]
    pub fn session_id(mut self, sess_id: u16) -> Self {
        self.sess_id = sess_id;
        self
    }

    #[must_use]
    pub fn port_index(mut self, port_index: u32) -> Self {
        self.index = port_index;
        self
    }

    pub fn build(self) -> erspan2_hdr {
        self.into()
    }

    pub fn flags_word(&self) -> u32 {
        (self.sess_id as u32 & mask::SESS)
            | ((self.t as u32) << shift::T) & mask::T
            | ((self.en as u32) << shift::EN) & mask::EN
            | ((self.cos as u32) << shift::COS) & mask::COS
            | ((self.vlan as u32) << shift::VLAN) & mask::VLAN
            | ((self.ver as u32) << shift::VER) & mask::VER
    }

    pub fn index_word(&self) -> u32 {
        (self.index & mask::INDX) | ((self.rsvd as u32) << shift::RSVD) & mask::RSVD
    }
}

#[repr(C, packed(1))]
#[derive(Pod, Zeroable, Default, Debug, Copy, Clone)]
pub struct erspan2_hdr {
    pub flags: u32,
    pub index: u32,
}

impl From<Erspan2> for erspan2_hdr {
    fn from(s: Erspan2) -> Self {
        Self::new(s.flags_word(), s.index_word())
    }
}

impl erspan2_hdr {
    pub fn new(flags: u32, index: u32) -> Self {
        Self {
            flags: flags.to_be(),
            index: index.to_be(),
        }
    }

    pub fn init(&mut self) -> &mut Self {
        *self = Default::default();
        self
    }

    pub fn flags(&mut self, flags: u32) -> &mut Self {
        self.flags = flags.to_be();
        self
    }

    pub fn get_flags(&self) -> u32 {
        u32::from_be(self.flags)
    }

    pub fn index(&mut self, index: u32) -> &mut Self {
        self.index = index.to_be();
        self
    }

    pub fn get_index(&self) -> u32 {
        u32::from_be(self.index)
    }
}
