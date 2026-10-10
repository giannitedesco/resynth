use bytemuck::{Pod, Zeroable};

pub mod version {
    pub const GRE: u8 = 0;
    pub const ENHANCED: u8 = 1;
}

pub mod flags {
    /// Checksum present
    pub const C: u16 = 0x8000;

    /// Routing present
    pub const R: u16 = 0x4000;

    /// Key present
    pub const K: u16 = 0x2000;

    /// Sequence present
    pub const S: u16 = 0x1000;

    /// Source-route present
    pub const SR: u16 = 0x0800;

    /// Recursion control
    pub const RECUR: u16 = 0x0700;

    /// ACK
    pub const A: u16 = 0x0080;

    /// Flags
    pub const FLAGS: u16 = 0x0078;

    /// Version (GRE or ENHANCED)
    pub const V: u16 = 0x0007;
}

#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
pub struct GreFlags {
    c: bool,
    r: bool,
    k: bool,
    s: bool,
    sr: bool,
    a: bool,
    recur: u8,
    flags: u8,
    v: u8,
}

impl GreFlags {
    #[must_use]
    pub fn csum(mut self, c: bool) -> Self {
        self.c = c;
        self
    }

    #[must_use]
    pub fn routing(mut self, r: bool) -> Self {
        self.r = r;
        self
    }

    #[must_use]
    pub fn key(mut self, k: bool) -> Self {
        self.k = k;
        self
    }

    #[must_use]
    pub fn seq(mut self, s: bool) -> Self {
        self.s = s;
        self
    }

    #[must_use]
    pub fn source_routing(mut self, sr: bool) -> Self {
        self.sr = sr;
        self
    }

    #[must_use]
    pub fn recursion(mut self, recur: u8) -> Self {
        self.recur = recur;
        self
    }

    #[must_use]
    pub fn ack(mut self, a: bool) -> Self {
        self.a = a;
        self
    }

    #[must_use]
    pub fn flags(mut self, flags: u8) -> Self {
        self.flags = flags;
        self
    }

    #[must_use]
    pub fn ver(mut self, v: u8) -> Self {
        self.v = v;
        self
    }
}

impl From<GreFlags> for u16 {
    fn from(s: GreFlags) -> Self {
        ((s.v as u16) & flags::V)
            | (((s.recur as u16) & 0x7) << 8)
            | (((s.flags as u16) & 0xf) << 3)
            | (if s.c { flags::C } else { 0 })
            | (if s.r { flags::R } else { 0 })
            | (if s.k { flags::K } else { 0 })
            | (if s.s { flags::S } else { 0 })
            | (if s.sr { flags::SR } else { 0 })
            | (if s.a { flags::A } else { 0 })
    }
}

#[repr(C, packed(1))]
#[derive(Pod, Zeroable, Default, Debug, Copy, Clone)]
pub struct gre_hdr {
    pub flags: u16,
    pub proto: u16,
}

impl gre_hdr {
    pub fn new(flags: GreFlags, proto: u16) -> Self {
        let f: u16 = flags.into();

        Self {
            flags: f.to_be(),
            proto: proto.to_be(),
        }
    }

    pub fn init(&mut self) -> &mut Self {
        *self = Self::default();
        self
    }

    pub fn flags<T>(&mut self, flags: T) -> &mut Self
    where
        u16: From<T>,
    {
        let f: u16 = flags.into();
        self.flags = f.to_be();
        self
    }

    pub fn proto(&mut self, proto: u16) -> &mut Self {
        self.proto = proto.to_be();
        self
    }

    pub fn get_flags(&self) -> u16 {
        u16::from_be(self.flags)
    }

    pub fn get_csum(&self) -> bool {
        (self.get_flags() & flags::C) != 0
    }

    pub fn get_key(&self) -> bool {
        (self.get_flags() & flags::K) != 0
    }

    pub fn get_seq(&self) -> bool {
        (self.get_flags() & flags::S) != 0
    }

    pub fn get_ver(&self) -> u8 {
        (self.get_flags() & flags::V) as u8
    }
}

#[repr(C, packed(1))]
#[derive(Pod, Zeroable, Debug, Copy, Clone)]
pub struct gre_hdr_sum {
    pub csum: u16,
    pub rsvd: u16,
}

impl gre_hdr_sum {
    #[must_use]
    pub fn csum(mut self, csum: u16) -> Self {
        self.csum = csum.to_be();
        self
    }

    #[must_use]
    pub fn rsvd(mut self, rsvd: u16) -> Self {
        self.rsvd = rsvd.to_be();
        self
    }

    pub fn get_csum(&self) -> u16 {
        u16::from_be(self.csum)
    }

    pub fn get_rsvd(&self) -> u16 {
        u16::from_be(self.rsvd)
    }
}

#[repr(C, packed(1))]
#[derive(Pod, Zeroable, Debug, Copy, Clone)]
pub struct gre_hdr_key {
    pub key: u32,
}

impl gre_hdr_key {
    #[must_use]
    pub fn key(mut self, key: u32) -> Self {
        self.key = key.to_be();
        self
    }

    pub fn get_key(&self) -> u32 {
        u32::from_be(self.key)
    }
}

#[repr(C, packed(1))]
#[derive(Pod, Zeroable, Debug, Copy, Clone)]
pub struct gre_hdr_seq {
    pub seq: u32,
}

impl gre_hdr_seq {
    #[must_use]
    pub const fn init(seq: u32) -> Self {
        Self { seq: seq.to_be() }
    }

    #[must_use]
    pub fn seq(mut self, seq: u32) -> Self {
        self.seq = seq.to_be();
        self
    }

    pub fn get_seq(&self) -> u32 {
        u32::from_be(self.seq)
    }
}
