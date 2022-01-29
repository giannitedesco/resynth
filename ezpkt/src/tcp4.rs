use std::net::SocketAddrV4;

use pkt::eth::eth_hdr;
use pkt::ipv4::{ip_hdr, tcp_hdr};
use pkt::{Packet, Hdr};

#[derive(Debug, PartialEq, Eq)]
struct TcpState {
    snd_nxt: u32,
    rcv_nxt: u32,
}

const TCPSEG_OVERHEAD: usize = 14 + 20 + 20;

/// Helper for creating TCP segments
pub struct TcpSeg {
    pkt: Packet,
    ip: Hdr<ip_hdr>,
    tcp: Hdr<tcp_hdr>,
    st: TcpState,
    tot_len: u32,
    seq: u32,
}

impl TcpSeg {
    fn new(src: SocketAddrV4, dst: SocketAddrV4, st: TcpState) -> Self {
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
            .seq(st.snd_nxt)
            .sport(src.port())
            .dport(dst.port());

        let tot_len = (ip.len() + tcp.len()) as u32;

        let ret = Self {
            pkt,
            ip,
            tcp,
            tot_len,
            st,
            seq: 0,
        };

        ret.update_tot_len()
    }

    fn syn(mut self) -> Self {
        self.pkt.get_mut_hdr(&self.tcp)
            .syn();
        self.seq += 1;
        self
    }

    fn syn_ack(mut self) -> Self {
        self.pkt.get_mut_hdr(&self.tcp)
            .syn()
            .ack(self.st.rcv_nxt);
        self.seq += 1;
        self
    }

    fn ack(mut self) -> Self {
        self.pkt.get_mut_hdr(&self.tcp)
            .ack(self.st.rcv_nxt);
        self
    }

    fn push(mut self, bytes: &[u8]) -> Self {
        self.pkt.get_mut_hdr(&self.tcp)
            .ack(self.st.rcv_nxt)
            .push();
        self.seq += bytes.len() as u32;
        self.push_bytes(bytes)
    }

    fn push_bytes(mut self, bytes: &[u8]) -> Self {
        self.pkt.push_bytes(bytes);
        self.tot_len += bytes.len() as u32;
        self.update_tot_len()
    }

    fn fin(mut self) -> Self {
        self.pkt.get_mut_hdr(&self.tcp)
            .fin();
        self.seq += 1;
        self
    }

    fn fin_ack(mut self) -> Self {
        self = self.fin();
        self = self.ack();
        self
    }

    fn update_tot_len(mut self) -> Self {
        self.pkt.get_mut_hdr(&self.ip)
            .tot_len(self.tot_len as u16);
        self
    }

    fn seq_consumed(&self) -> u32 {
        self.seq
    }
}

impl From<TcpSeg> for Packet {
    fn from(seg: TcpSeg) -> Self{
        seg.pkt
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct TcpFlow {
    cl: SocketAddrV4,
    sv: SocketAddrV4,
    cl_seq: u32,
    sv_seq: u32,
    pkts: Vec<Packet>,
}

impl TcpFlow {
    pub fn new(cl: SocketAddrV4,
               sv: SocketAddrV4,
               cl_seq: u32,
               sv_seq: u32,
               ) -> Self {
        Self {
            cl,
            sv,
            cl_seq,
            sv_seq,
            pkts: Vec::new(),
        }
    }

    fn cl_state(&self) -> TcpState {
        TcpState {
            snd_nxt: self.cl_seq,
            rcv_nxt: self.sv_seq,
        }
    }

    fn sv_state(&self) -> TcpState {
        TcpState {
            snd_nxt: self.sv_seq,
            rcv_nxt: self.cl_seq,
        }
    }

    fn clnt(&self) -> TcpSeg {
        TcpSeg::new(self.cl, self.sv, self.cl_state())
    }

    fn srvr(&self) -> TcpSeg {
        TcpSeg::new(self.sv, self.cl, self.sv_state())
    }
    
    fn cl_tx(&mut self, seg: TcpSeg) {
        self.cl_seq += seg.seq_consumed();
        self.pkts.push(seg.into());
    }
    
    fn sv_tx(&mut self, seg: TcpSeg) {
        self.sv_seq += seg.seq_consumed();
        self.pkts.push(seg.into());
    }

    pub fn open(&mut self) -> Vec<Packet> {
        self.cl_tx(self.clnt().syn());
        self.sv_tx(self.srvr().syn_ack());
        self.cl_tx(self.clnt().ack());

        std::mem::take(&mut self.pkts)
    }

    pub fn client_close(&mut self) -> Vec<Packet> {
        self.cl_tx(self.clnt().fin_ack());
        self.sv_tx(self.srvr().fin_ack());
        self.cl_tx(self.clnt().ack());

        std::mem::take(&mut self.pkts)
    }

    pub fn server_close(&mut self) -> Vec<Packet> {
        self.sv_tx(self.srvr().fin_ack());
        self.cl_tx(self.clnt().fin_ack());
        self.sv_tx(self.srvr().ack());

        std::mem::take(&mut self.pkts)
    }

    // Advance client seq by `bytes` bytes in order to simulate a hole
    pub fn client_hole(&mut self, bytes: u32) {
        self.cl_seq += bytes;
    }

    // Advance server seq by `bytes` bytes in order to simulate a hole
    pub fn server_hole(&mut self, bytes: u32) {
        self.sv_seq += bytes;
    }

    pub fn client_message(&mut self,
                          bytes: &[u8],
                          send_ack: bool,
                          //seq: Option<u32>,
                          //ack: Option<u32>,
                          ) -> Vec<Packet> {
        self.cl_tx(self.clnt().push(bytes));
        if send_ack {
            self.sv_tx(self.srvr().ack());
        }

        std::mem::take(&mut self.pkts)
    }

    pub fn server_message(&mut self,
                          bytes: &[u8],
                          send_ack: bool,
                          //seq: Option<u32>,
                          //ack: Option<u32>,
                          ) -> Vec<Packet> {
        self.sv_tx(self.srvr().push(bytes));
        if send_ack {
            self.cl_tx(self.clnt().ack());
        }

        std::mem::take(&mut self.pkts)
    }
}
