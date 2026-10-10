use bytemuck::{Pod, Zeroable};

/*
                    ERSPAN Type III header (12 octets [42:53])
      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |  Ver  |          VLAN         | COS | BSO |T|    Session ID    |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                          Timestamp                            |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |             SGT               |P|    FT   |   Hw ID  |D|Gra|O|
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

  Field         Position    Length          Definition
               [octet:bit]  (bits)

  Ver            [42:0]       4      ERSPAN Encapsulation version.
                                     Set to 0x2 for Type III.

  VLAN           [42:4]      12      Original VLAN of the frame,
                                     mirrored from the source.

  COS            [44:0]       3      Original class of service of the
                                     frame, mirrored from the source.

  BSO            [44:3]       2      Bad/Short/Oversized. Sobstitutes En
                                     field used in Type II.

  T              [44:5]       1      This bit indicates that the frame
                                     copy encapsulated in the ERSPAN
                                     packet has been truncated.

  Session ID     [44:6]      10      Identification associated with
  (ERSPAN ID)                        each ERSPAN session.

  Timestamp      [46:0]      32      Timestamp.

  SGT            [50:0]      16      Security Group Tag.

  P              [52:0]       1      Has optional Platform Specific
                                     subheader.

  FT             [52:1]       5      Frame Type.

  Hw ID          [52:6]       6      Unique identifier of an ERSPAN
                                     engine within a system.

  D              [53:4]       1      Direction. 0 = ingress, 1 = egress.

  Gra            [53:5]       2      Timestamp granularity.

  O              [53:7]       1      Optional subheader.
*/

pub mod mask {
    pub const VER: u32 = 0xf000_0000;
    pub const VLAN: u32 = 0x0fff_0000;
    pub const COS: u32 = 0x0000_e000;
    pub const BSO: u32 = 0x0000_1800;
    pub const T: u32 = 0x0000_0400;
    pub const SESS: u32 = 0x0000_03ff;

    pub const SGT: u32 = 0xffff_0000;
    pub const P: u32 = 0x0000_8000;
    pub const FT: u32 = 0x0000_7c00;
    pub const HWID: u32 = 0x0000_03f0;
    pub const D: u32 = 0x0000_0008;
    pub const GRA: u32 = 0x0000_0006;
    pub const O: u32 = 0x0000_0001;
}

pub mod shift {
    pub const VER: u32 = 28;
    pub const VLAN: u32 = 16;
    pub const COS: u32 = 13;
    pub const BSO: u32 = 11;
    pub const T: u32 = 10;

    pub const SGT: u32 = 16;
    pub const P: u32 = 15;
    pub const FT: u32 = 10;
    pub const HWID: u32 = 4;
    pub const D: u32 = 3;
    pub const GRA: u32 = 1;
}

pub mod version {
    pub const ERSPAN3: u8 = 2;
}

#[derive(Default, Debug, Copy, Clone)]
pub enum Bso {
    #[default]
    Good = 0,
    Short = 1,
    Oversized = 2,
    Bad = 3,
}

pub mod frametype {
    pub const ETHERNET: u8 = 0;
    pub const IP: u8 = 2;
}

pub mod granularity {
    pub const MICROSECONDS_100: u8 = 0;
    pub const NANOSECONDS_100: u8 = 1;
    pub const IEEE_1588: u8 = 2;
    pub const USER: u8 = 3;
}

#[repr(C, packed(1))]
#[derive(Debug, Copy, Clone)]
pub struct Erspan3 {
    ver: u8,
    vlan: u16,
    cos: u8,
    bso: Bso,
    t: bool,
    sess_id: u16,

    timestamp: u32,

    sgt: u16,
    p: bool,
    ft: u8,
    hwid: u8,
    d: bool,
    gra: u8,
    o: bool,
}

impl Default for Erspan3 {
    fn default() -> Self {
        Self {
            ver: version::ERSPAN3,
            vlan: 0,
            cos: 0,
            bso: Bso::default(),
            t: false,
            sess_id: 0,
            timestamp: 0,
            sgt: 0,
            p: false,
            ft: 0,
            hwid: 0,
            d: false,
            gra: 0,
            o: false,
        }
    }
}

impl Erspan3 {
    #[must_use]
    pub fn ver(mut self, ver: u8) -> Self {
        self.ver = ver;
        self
    }

    #[must_use]
    pub fn vlan(mut self, vlan: u16) -> Self {
        self.vlan = vlan;
        self
    }

    #[must_use]
    pub fn cos(mut self, cos: u8) -> Self {
        self.cos = cos;
        self
    }

    #[must_use]
    pub fn bso(mut self, bso: Bso) -> Self {
        self.bso = bso;
        self
    }

    #[must_use]
    pub fn truncated(mut self, t: bool) -> Self {
        self.t = t;
        self
    }

    #[must_use]
    pub fn session_id(mut self, sess_id: u16) -> Self {
        self.sess_id = sess_id;
        self
    }

    #[must_use]
    pub fn timestamp(mut self, timestamp: u32) -> Self {
        self.timestamp = timestamp;
        self
    }

    #[must_use]
    pub fn sgt(mut self, sgt: u16) -> Self {
        self.sgt = sgt;
        self
    }

    #[must_use]
    pub fn p(mut self, p: bool) -> Self {
        self.p = p;
        self
    }

    #[must_use]
    pub fn ft(mut self, ft: u8) -> Self {
        self.ft = ft;
        self
    }

    #[must_use]
    pub fn hwid(mut self, hwid: u8) -> Self {
        self.hwid = hwid;
        self
    }

    #[must_use]
    pub fn direction(mut self, d: bool) -> Self {
        self.d = d;
        self
    }

    #[must_use]
    pub fn gra(mut self, gra: u8) -> Self {
        self.gra = gra;
        self
    }

    #[must_use]
    pub fn optional(mut self, o: bool) -> Self {
        self.o = o;
        self
    }

    pub fn build(self) -> erspan3_hdr {
        self.into()
    }

    pub fn flags_word(&self) -> u32 {
        (self.sess_id as u32 & mask::SESS)
            | ((self.t as u32) << shift::T) & mask::T
            | ((self.bso as u32) << shift::BSO) & mask::BSO
            | ((self.cos as u32) << shift::COS) & mask::COS
            | ((self.vlan as u32) << shift::VLAN) & mask::VLAN
            | ((self.ver as u32) << shift::VER) & mask::VER
    }

    pub fn info_word(&self) -> u32 {
        (self.o as u32 & mask::O)
            | ((self.gra as u32) << shift::GRA) & mask::GRA
            | ((self.d as u32) << shift::D) & mask::D
            | ((self.hwid as u32) << shift::HWID) & mask::HWID
            | ((self.ft as u32) << shift::FT) & mask::FT
            | ((self.p as u32) << shift::P) & mask::P
            | ((self.sgt as u32) << shift::SGT) & mask::SGT
    }
}

#[repr(C, packed(1))]
#[derive(Pod, Zeroable, Default, Debug, Copy, Clone)]
pub struct erspan3_hdr {
    pub flags: u32,
    pub timestamp: u32,
    pub info: u32,
}

impl From<Erspan3> for erspan3_hdr {
    fn from(s: Erspan3) -> Self {
        Self::new(s.flags_word(), s.timestamp, s.info_word())
    }
}

impl erspan3_hdr {
    pub fn new(flags: u32, timestamp: u32, info: u32) -> Self {
        Self {
            flags: flags.to_be(),
            timestamp: timestamp.to_be(),
            info: info.to_be(),
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

    pub fn timestamp(&mut self, timestamp: u32) -> &mut Self {
        self.timestamp = timestamp.to_be();
        self
    }

    pub fn get_timestamp(&self) -> u32 {
        u32::from_be(self.timestamp)
    }

    pub fn info(&mut self, info: u32) -> &mut Self {
        self.info = info.to_be();
        self
    }

    pub fn get_info(&self) -> u32 {
        u32::from_be(self.info)
    }
}

/*
            Platform Specific SubHeader (8 octets, optional)
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |  Platf ID |               Platform Specific Info              |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                  Platform Specific Info                       |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

pub mod platform_id {
    pub const TYPE1: u8 = 1;
    pub const TYPE3: u8 = 3;
    pub const TYPE4: u8 = 4;
    pub const TYPE5: u8 = 5;
    pub const TYPE6: u8 = 6;
    pub const TYPE7: u8 = 7;
}

mod platf_mask {
    pub const PLATF_ID: u64 = 0xfc00_0000_0000_0000;

    // Type 1
    pub const VSM_DOMAIN: u64 = 0x0000_0fff_0000_0000;
    pub const T1_PORT_INDEX: u64 = 0x0000_0000_ffff_ffff;

    // Type 3
    pub const T3_PORT_INDEX: u64 = 0x0000_0fff_0000_0000;
    pub const T3_TIMESTAMP_HI: u64 = 0x0000_0000_ffff_ffff;

    // Type 5/6
    pub const SWITCH_ID: u64 = 0x03ff_0000_0000_0000;
    pub const T56_PORT_INDEX: u64 = 0x0000_ffff_0000_0000;
    pub const T56_TIMESTAMP_SEC: u64 = 0x0000_0000_ffff_ffff;

    // Type 7
    pub const SOURCE_INDEX: u64 = 0x000f_ffff_0000_0000;
    pub const T7_TIMESTAMP_HI: u64 = 0x0000_0000_ffff_ffff;
}

mod platf_shift {
    pub const PLATF_ID: u64 = 58;
    pub const VSM_DOMAIN: u64 = 32;
    pub const T3_PORT_INDEX: u64 = 32;
    pub const SWITCH_ID: u64 = 48;
    pub const T56_PORT_INDEX: u64 = 32;
    pub const SOURCE_INDEX: u64 = 32;
}

#[derive(Default, Debug, Copy, Clone, PartialEq, Eq)]
pub struct Erspan3Platform(u64);

impl Erspan3Platform {
    const fn platf_id(id: u8) -> u64 {
        ((id as u64) << platf_shift::PLATF_ID) & platf_mask::PLATF_ID
    }

    /// Type 1: Nexus VSM
    pub const fn type1(vsm_domain_id: u16, port_index: u32) -> Self {
        Self(
            Self::platf_id(platform_id::TYPE1)
                | ((vsm_domain_id as u64) << platf_shift::VSM_DOMAIN) & platf_mask::VSM_DOMAIN
                | (port_index as u64) & platf_mask::T1_PORT_INDEX,
        )
    }

    /// Type 3: Extended 64-bit timestamp
    pub const fn type3(port_index: u16, timestamp_hi: u32) -> Self {
        Self(
            Self::platf_id(platform_id::TYPE3)
                | ((port_index as u64) << platf_shift::T3_PORT_INDEX) & platf_mask::T3_PORT_INDEX
                | (timestamp_hi as u64) & platf_mask::T3_TIMESTAMP_HI,
        )
    }

    /// Type 4: 100 microsecond timestamp (all platform fields reserved)
    pub const fn type4() -> Self {
        Self(Self::platf_id(platform_id::TYPE4))
    }

    /// Type 5: IEEE 1588 with switch ID
    pub const fn type5(switch_id: u16, port_index: u16, timestamp_sec: u32) -> Self {
        Self(
            Self::platf_id(platform_id::TYPE5)
                | ((switch_id as u64) << platf_shift::SWITCH_ID) & platf_mask::SWITCH_ID
                | ((port_index as u64) << platf_shift::T56_PORT_INDEX) & platf_mask::T56_PORT_INDEX
                | (timestamp_sec as u64) & platf_mask::T56_TIMESTAMP_SEC,
        )
    }

    /// Type 6: IEEE 1588 with switch ID (alternate)
    pub const fn type6(switch_id: u16, port_index: u16, timestamp_sec: u32) -> Self {
        Self(
            Self::platf_id(platform_id::TYPE6)
                | ((switch_id as u64) << platf_shift::SWITCH_ID) & platf_mask::SWITCH_ID
                | ((port_index as u64) << platf_shift::T56_PORT_INDEX) & platf_mask::T56_PORT_INDEX
                | (timestamp_sec as u64) & platf_mask::T56_TIMESTAMP_SEC,
        )
    }

    /// Type 7: 64-bit nanosecond timestamp with source-index
    pub const fn type7(source_index: u32, timestamp_hi: u32) -> Self {
        Self(
            Self::platf_id(platform_id::TYPE7)
                | ((source_index as u64) << platf_shift::SOURCE_INDEX) & platf_mask::SOURCE_INDEX
                | (timestamp_hi as u64) & platf_mask::T7_TIMESTAMP_HI,
        )
    }

    pub const fn to_be_bytes(self) -> [u8; 8] {
        self.0.to_be_bytes()
    }
}
