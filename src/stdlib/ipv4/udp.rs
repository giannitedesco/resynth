use phf::phf_map;

use crate::err::Error;
use crate::val::{Symbol, ValType, FuncDef, Args, Val, BytesObj, ObjRef, ClassDef};
use crate::ezpkt::UdpFlow;

fn udp_client_message(mut args: Args) -> Result<Val, Error> {
    let mut obj: ObjRef = args.take().into();
    let bytes: BytesObj = args.take().into();
    let this = unsafe { ObjRef::get_mut_obj::<UdpFlow>(&mut obj) };
    Ok(this.client_message(bytes.as_ref()).into())
}

fn udp_server_message(mut args: Args) -> Result<Val, Error> {
    let mut obj: ObjRef = args.take().into();
    let bytes: BytesObj = args.take().into();
    let this = unsafe { ObjRef::get_mut_obj::<UdpFlow>(&mut obj) };
    Ok(this.server_message(bytes.as_ref()).into())
}

const UDP4_FLOW_CLASS: ClassDef = ClassDef {
    name: "ipv4::udp4.flow",
    methods: phf_map! {
        "client_message" => FuncDef {
            name: "ipv4::tcp::flow.client_message",
            return_type: ValType::Pkt,
            args: &[ ValType::Str ],
            collect_type: ValType::Void,
            exec: udp_client_message,
        },
        "server_message" => FuncDef {
            name: "ipv4::tcp::flow.server_message",
            return_type: ValType::Pkt,
            args: &[ ValType::Str ],
            collect_type: ValType::Void,
            exec: udp_server_message,
        },
    }
};

fn udp_flow(mut args: Args) -> Result<Val, Error> {
    let cl = args.take();
    let sv = args.take();
    let obj: ObjRef = ObjRef::new(
        &UDP4_FLOW_CLASS,
        UdpFlow::new(cl.into(), sv.into())
    );
    Ok(Val::Obj(obj))
}

pub const UDP4: phf::Map<&'static str, Symbol> = phf_map! {
    "flow" => Symbol::Func(FuncDef {
        name: "flow",
        return_type: ValType::Obj,
        args: &[ ValType::Sock4, ValType::Sock4 ],
        collect_type: ValType::Void,
        exec: udp_flow,
    }),
};

