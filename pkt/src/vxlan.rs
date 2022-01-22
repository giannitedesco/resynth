use super::Serialize;

#[repr(C, packed(1))]
#[derive(Debug, Copy, Clone, Default)]
pub struct vxlan_hdr {
    pub flags: u32,
    pub vni: u32,
}

impl Serialize for vxlan_hdr {}

impl vxlan_hdr {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            flags: 0,
            vni: 0,
        }
    }

    #[must_use]
    pub const fn with_vni(vni: u32) -> Self {
        Self::new().vni(vni)
    }

    #[must_use]
    pub const fn vni(mut self, vni: u32) -> Self {
        self.flags |= 1u32 << 27;
        self.vni = (vni << 8).to_be();
        self
    }
}
