use std::fs::File;
use std::io;
use std::io::Write;
use std::path::Path;

use bytemuck::{Pod, Zeroable, bytes_of};

use super::Packet;

pub enum LinkType {
    Null = 0,
    Ethernet = 1,
}

#[derive(Pod, Zeroable, Debug, Copy, Clone)]
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

#[derive(Pod, Zeroable, Debug, Copy, Clone)]
#[repr(C)]
struct pcap_pkt {
    sec: u32,
    nsec: u32,
    caplen: u32,
    len: u32,
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

/// A [buffered file writer](std::io::BufWriter) for pcap files.
#[derive(Debug)]
pub struct PcapWriter {
    wr: io::BufWriter<File>,
    dbg: bool,
}

impl PcapWriter {
    pub fn create(p: &Path) -> Result<Self, io::Error> {
        let f = File::create(p)?;
        let mut ret = Self {
            wr: io::BufWriter::new(f),
            dbg: false,
        };

        ret.write_header()?;

        Ok(ret)
    }

    #[inline(always)]
    fn ts_to_secs(time: u64) -> u32 {
        (time / 1_000_000_000) as u32
    }

    #[inline(always)]
    fn ts_to_nsecs(time: u64) -> u32 {
        (time % 1_000_000_000) as u32
    }

    #[must_use]
    pub fn debug(mut self) -> Self {
        self.dbg = true;
        self
    }

    fn write_header(&mut self) -> Result<(), io::Error> {
        let hdr = pcap_hdr::new();
        self.wr.write_all(bytes_of(&hdr))
    }

    #[inline(always)]
    pub fn write_packet(&mut self, time: u64, pkt: &mut Packet) -> Result<(), io::Error> {
        let len = pkt.len() as u32;

        if self.dbg {
            println!("pcap: writing {:#?}", pkt);
        }

        let pkt_hdr = pcap_pkt {
            sec: Self::ts_to_secs(time),
            nsec: Self::ts_to_nsecs(time),
            len,
            caplen: len,
        };
        let hdr = pkt.lower_headroom_for(pkt_hdr);

        {
            let pktbuf = pkt.as_slice().get(pkt);

            self.wr.write_all(&pktbuf)?;
        }

        pkt.return_headroom(hdr);

        Ok(())
    }
}
