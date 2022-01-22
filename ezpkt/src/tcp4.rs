use std::net::SocketAddrV4;

use pkt::eth::eth_hdr;
use pkt::ipv4::{ip_hdr, tcp_hdr};
use pkt::{Packet, Hdr};

#[derive(Debug, PartialEq, Eq)]
pub struct TcpFlow {
    cl: SocketAddrV4,
    sv: SocketAddrV4,
    cl_seq: u32,
    sv_seq: u32,
}

const TCPSEG_OVERHEAD: usize = 14 + 20 + 20;

/// Helper for creating TCP segments
pub struct TcpSeg {
    pkt: Packet,
    ip: Hdr<ip_hdr>,
    tcp: Hdr<tcp_hdr>,
    tot_len: usize,
}

impl TcpSeg {
    fn new(src: SocketAddrV4, dst: SocketAddrV4) -> Self {
        let mut pkt = Packet::with_capacity(TCPSEG_OVERHEAD);

        let eth: Hdr<eth_hdr> = pkt.push_hdr();
        pkt.get_mut_hdr(&eth)
            .dst_from_ip(*dst.ip())
            .src_from_ip(*src.ip())
            .proto(0x0800);

        let ip: Hdr<ip_hdr> = pkt.push_hdr();
        pkt.get_mut_hdr(&ip)
            .init()
            .protocol(6)
            .saddr(*src.ip())
            .daddr(*dst.ip());

        let tcp: Hdr<tcp_hdr> = pkt.push_hdr();
        pkt.get_mut_hdr(&tcp)
            .init()
            .sport(src.port())
            .dport(dst.port());

        let tot_len = ip.len() + tcp.len();

        let ret = Self {
            pkt,
            ip,
            tcp,
            tot_len,
        };

        ret.update_tot_len()
    }

    fn syn(mut self, seq: &mut u32) -> Self {
        self.pkt.get_mut_hdr(&self.tcp)
            .seq(*seq)
            .syn();
        *seq += 1;
        self
    }

    fn syn_ack(mut self, seq: &mut u32, ack: u32) -> Self {
        self.pkt.get_mut_hdr(&self.tcp)
            .seq(*seq)
            .syn()
            .ack(ack);
        *seq += 1;
        self
    }

    fn ack(mut self, seq: u32, ack: u32) -> Self {
        self.pkt.get_mut_hdr(&self.tcp)
            .seq(seq)
            .ack(ack);
        self
    }

    fn push(mut self, seq: &mut u32, ack: u32, bytes: &[u8]) -> Self {
        self.pkt.get_mut_hdr(&self.tcp)
            .seq(*seq)
            .ack(ack)
            .push();
        *seq += bytes.len() as u32;
        self.push_bytes(bytes)
    }

    fn push_bytes(mut self, bytes: &[u8]) -> Self {
        self.pkt.push_bytes(bytes);
        self.tot_len += bytes.len();
        self.update_tot_len()
    }

    fn fin(mut self, seq: &mut u32) -> Self {
        self.pkt.get_mut_hdr(&self.tcp)
            .seq(*seq)
            .fin();
        *seq += 1;
        self
    }

    fn fin_ack(mut self, seq: &mut u32, ack: u32) -> Self {
        self = self.fin(seq);
        self.pkt.get_mut_hdr(&self.tcp).ack(ack);
        self
    }

    fn update_tot_len(mut self) -> Self {
        self.pkt.get_mut_hdr(&self.ip)
            .tot_len(self.tot_len as u16);
        self
    }
}

impl From<TcpSeg> for Packet {
    fn from(seg: TcpSeg) -> Self{
        seg.pkt
    }
}

impl TcpFlow {
    pub fn new(cl: SocketAddrV4, sv: SocketAddrV4) -> Self {
        //println!("trace: tcp:flow({:?}, {:?})", cl, sv);
        Self {
            cl,
            sv,
            cl_seq: 1000,
            sv_seq: 2000,
        }
    }

    /* TODO: These could set sequence number automatically */
    fn clnt(&self) -> TcpSeg {
        TcpSeg::new(self.cl, self.sv)
    }

    fn srvr(&self) -> TcpSeg {
        TcpSeg::new(self.sv, self.cl)
    }

    pub fn open(&mut self) -> Vec<Packet> {
        let mut pkts: Vec<Packet> = Vec::with_capacity(3);

        //println!("trace: tcp:open()");

        /* XXX: We could have a method to update state rather than keep passing these borrows? */
        let pkt = self.clnt().syn(&mut self.cl_seq);
        pkts.push(pkt.into());

        let pkt = self.srvr().syn_ack(&mut self.sv_seq, self.cl_seq);
        pkts.push(pkt.into());

        let pkt = self.clnt().ack(self.cl_seq, self.sv_seq);
        pkts.push(pkt.into());

        pkts
    }

    pub fn client_close(&mut self) -> Vec<Packet> {
        let mut pkts: Vec<Packet> = Vec::with_capacity(3);

        //println!("trace: tcp:client_close()");

        let pkt = self.clnt().fin_ack(&mut self.cl_seq, self.sv_seq);
        pkts.push(pkt.into());

        let pkt = self.srvr().fin_ack(&mut self.sv_seq, self.cl_seq);
        pkts.push(pkt.into());

        let pkt = self.clnt().ack(self.cl_seq, self.sv_seq);
        pkts.push(pkt.into());

        pkts
    }

    pub fn server_close(&mut self) -> Vec<Packet> {
        let mut pkts: Vec<Packet> = Vec::with_capacity(3);

        //println!("trace: tcp:server_close()");

        let pkt = self.srvr().fin_ack(&mut self.sv_seq, self.cl_seq);
        pkts.push(pkt.into());

        let pkt = self.clnt().fin_ack(&mut self.cl_seq, self.sv_seq);
        pkts.push(pkt.into());

        let pkt = self.srvr().ack(self.sv_seq, self.cl_seq);
        pkts.push(pkt.into());

        pkts
    }

    pub fn client_segment(&mut self, bytes: &[u8]) -> Packet {
        //println!("trace: tcp:client({} bytes)", bytes.len());
        self.clnt().push(&mut self.cl_seq, self.sv_seq, bytes).into()
    }

    pub fn server_segment(&mut self, bytes: &[u8]) -> Packet {
        //println!("trace: tcp:server({} bytes)", bytes.len());
        self.srvr().push(&mut self.sv_seq, self.cl_seq, bytes).into()
    }

    pub fn client_message(&mut self, bytes: &[u8], send_ack: bool) -> Vec<Packet> {
        let mut pkts: Vec<Packet> = Vec::with_capacity(2);
        pkts.push(self.client_segment(bytes));

        if send_ack {
            let ack = self.srvr().ack(self.sv_seq, self.cl_seq);
            pkts.push(ack.into());
        }

        pkts
    }

    pub fn server_message(&mut self, bytes: &[u8], send_ack: bool) -> Vec<Packet> {
        let mut pkts: Vec<Packet> = Vec::with_capacity(2);
        pkts.push(self.server_segment(bytes));

        if send_ack {
            let ack = self.clnt().ack(self.cl_seq, self.sv_seq);
            pkts.push(ack.into());
        }

        pkts
    }
}
