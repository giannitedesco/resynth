use std::path::Path;
use std::fs::File;
use std::io;
use std::io::Write;

use super::{Hdr, Packet};
use super::util::{Serialize, AsBytes};

#[allow(unused)]
enum LinkType {
    Null = 0,
    Ethernet = 1,
}

#[allow(unused)]
#[derive(Debug)]
#[repr(C)]
struct pcap_hdr {
    magic: u32,
    ver_maj: u16,
    ver_min: u16,
    gmt_off: u32,
    sig_fig: u32,
    mtu: u32,
    linktype: u32,
}

impl Serialize for pcap_hdr {
}

#[derive(Debug)]
#[repr(C)]
struct pcap_pkt {
    sec: u32,
    nsec: u32,
    caplen: u32,
    len: u32,
}

impl Serialize for pcap_pkt {
}

impl pcap_hdr {
    pub fn new() -> Self {
        Self {
            magic: 0xa1b23c4d, // nanosecond pcap
            ver_maj: 2,
            ver_min: 4,
            gmt_off: 0,
            sig_fig: 0,
            mtu: 0,
            linktype: LinkType::Ethernet as u32,
        }
    }
}

#[derive(Debug)]
pub struct PcapWriter {
    wr: io::BufWriter<File>,
    cnt: usize,
    dbg: bool,
}

impl PcapWriter {
    pub fn create(p: &Path) -> Result<Self, io::Error> {
        let f = File::create(p)?;
        let mut ret = Self {
            wr: io::BufWriter::new(f),
            cnt: 0,
            dbg: false,
        };

        ret.write_header()?;

        Ok(ret)
    }

    pub fn debug(mut self) -> Self {
        self.dbg = true;
        self
    }

    fn write_header(&mut self) -> Result<(), io::Error> {
        let hdr = pcap_hdr::new();
        self.wr.write_all(hdr.as_bytes())
    }

    #[inline(always)]
    pub fn write_packet(&mut self, pkt: &mut Packet) -> Result<(), io::Error> {
        let len = pkt.len() as u32;

        if self.dbg {
            println!("pcap: writing {:#?}", pkt);
        }

        let hdr: Hdr<pcap_pkt> = pkt.lower_headroom();
        let mut pcap_hdr = pkt.get_mut_hdr(&hdr);

        pcap_hdr.sec = self.cnt as u32;
        pcap_hdr.len = len;
        pcap_hdr.caplen = len;

        self.cnt += 1;

        self.wr.write_all(pkt.as_bytes())?;
        pkt.return_headroom(hdr);

        Ok(())
    }
}
