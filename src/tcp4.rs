use std::net::SocketAddrV4;
use std::rc::Rc;

use crate::err::Error;
use crate::val::Val;

use crate::net::eth::eth_hdr;
use crate::net::ipv4::{ip_hdr, tcp_hdr};
use crate::net::{Packet, Hdr};

#[derive(Debug)]
pub struct TcpFlow {
    cl: SocketAddrV4,
    sv: SocketAddrV4,
    cl_seq: u32,
    sv_seq: u32,
}

const TCPSEG_OVERHEAD: usize = 54;

/// Helper for creating TCP segments
struct TcpSeg {
    pkt: Packet,
    ip: Hdr<ip_hdr>,
    tcp: Hdr<tcp_hdr>,
    tot_len: usize,
}

impl TcpSeg {
    fn new(src: &SocketAddrV4, dst: &SocketAddrV4) -> Self {
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

impl From<TcpSeg> for Val {
    fn from(seg: TcpSeg) -> Self {
        Val::Pkt(Rc::new(seg.into()))
    }
}

impl TcpFlow {
    pub fn new(cl: SocketAddrV4, sv: SocketAddrV4) -> Self {
        println!("trace: tcp:flow({:?}, {:?})", cl, sv);
        Self {
            cl,
            sv,
            cl_seq: 1000,
            sv_seq: 2000,
        }
    }

    /* TODO: These could set sequence number automatically */
    fn clnt(&self) -> TcpSeg {
        TcpSeg::new(&self.cl, &self.sv)
    }

    fn srvr(&self) -> TcpSeg {
        TcpSeg::new(&self.sv, &self.cl)
    }

    pub fn open(&mut self) -> Result<Val, Error> {
        let mut ret: Rc<Vec<Packet>> = Rc::new(Vec::with_capacity(3));
        let pkts = Rc::get_mut(&mut ret).unwrap();

        println!("trace: tcp:open()");

        /* TODO: We could have a method to update state rather than keep passing these borrows? */
        let pkt = self.clnt().syn(&mut self.cl_seq);
        pkts.push(pkt.into());

        let pkt = self.srvr().syn_ack(&mut self.sv_seq, self.cl_seq - 1);
        pkts.push(pkt.into());

        let pkt = self.clnt().ack(self.cl_seq, self.sv_seq - 1);
        pkts.push(pkt.into());

        Ok(Val::PktGen(ret))
    }

    pub fn close(&mut self) -> Result<Val, Error> {
        let mut ret: Rc<Vec<Packet>> = Rc::new(Vec::with_capacity(3));
        let pkts = Rc::get_mut(&mut ret).unwrap();

        println!("trace: tcp:close()");

        let pkt = self.clnt().fin(&mut self.cl_seq);
        pkts.push(pkt.into());

        let pkt = self.srvr().ack(self.sv_seq, self.cl_seq - 1);
        pkts.push(pkt.into());

        let pkt = self.srvr().fin(&mut self.sv_seq);
        pkts.push(pkt.into());

        let pkt = self.clnt().ack(self.cl_seq, self.sv_seq - 1);
        pkts.push(pkt.into());

        Ok(Val::PktGen(ret))
    }

    pub fn client_message(&mut self, bytes: &[u8]) -> Result<Val, Error> {
        println!("trace: tcp:client({} bytes)", bytes.len());

        let pkt: Packet = self.clnt().push(&mut self.cl_seq, self.sv_seq - 1, bytes).into();

        Ok(Val::Pkt(Rc::new(pkt)))
    }

    pub fn server_message(&mut self, bytes: &[u8]) -> Result<Val, Error> {
        println!("trace: tcp:server({} bytes)", bytes.len());

        let pkt: Packet = self.srvr().push(&mut self.sv_seq, self.cl_seq - 1, bytes).into();

        Ok(Val::Pkt(Rc::new(pkt)))
    }
}
