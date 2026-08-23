// Required to allow DSL symbols to be all uppercase
#![allow(clippy::upper_case_acronyms)]

use crate::args::Args;
use crate::err::Error;
use crate::err::Error::LibTodo;
use crate::libapi::{ArgDecl, ClassDef, ClassMap, Documented, FuncDef, Module, SymDesc};
use crate::sym::Symbol;
use crate::val::{Typed, Val, ValDef, ValType};

use ::std::fs::{File, create_dir_all};
use ::std::io::BufWriter;
use ::std::path::{Path, PathBuf};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use serde_json::{Map, Value, json};

pub fn unimplemented(mut args: Args) -> Result<Val, Error> {
    args.void();
    Err(LibTodo)
}

mod arp;
mod dhcp;
mod dns;
mod erspan1;
mod erspan2;
mod erspan3;
mod eth;
mod gre;
mod io;
mod ipv4;
mod netbios;
mod std;
mod text;
mod time;
mod tls;
mod vxlan;

const STDLIB: Module = module! {
    /// # Resynth Standard Library
    ///
    /// Resynth is a packet synthesis language for building precise, readable network captures.
    /// Programs are compiled to `.pcap` files that can be used to test DPI engines, intrusion
    /// detection systems, protocol decoders, and other network analysis tools.
    ///
    /// A resynth program imports modules from this standard library, constructs flows and
    /// datagrams using typed functions, and emits packets by evaluating expressions. The language
    /// is small by design: there are exactly three statement forms, one binary operator, and a
    /// handful of literal types — but the stdlib covers a wide range of protocols.
    ///
    /// See the [language grammar and type system](grammar.md) for a full reference on syntax,
    /// types, calling conventions, and byte-encoding semantics. And the [style guide](style.md)
    /// for advice on writing clean, maintainable resynth.
    resynth mod stdlib {
        std => Symbol::Module(&std::MODULE),
        text => Symbol::Module(&text::MODULE),
        io => Symbol::Module(&io::MODULE),
        ipv4 => Symbol::Module(&ipv4::IPV4),
        dns => Symbol::Module(&dns::DNS),
        netbios => Symbol::Module(&netbios::NETBIOS),
        dhcp => Symbol::Module(&dhcp::MODULE),
        arp => Symbol::Module(&arp::MODULE),
        tls => Symbol::Module(&tls::TLS),
        vxlan => Symbol::Module(&vxlan::MODULE),
        gre => Symbol::Module(&gre::MODULE),
        eth => Symbol::Module(&eth::MODULE),
        erspan1 => Symbol::Module(&erspan1::MODULE),
        erspan2 => Symbol::Module(&erspan2::MODULE),
        erspan3 => Symbol::Module(&erspan3::MODULE),
        time => Symbol::Module(&time::MODULE),
    }
};

pub fn toplevel_module(name: &str) -> Option<&'static Module> {
    match STDLIB.get(name) {
        None => None,
        Some(Symbol::Module(module)) => Some(module),
        Some(Symbol::Func(_)) | Some(Symbol::Class(_)) | Some(Symbol::Val(_)) => {
            /* There shouldn't be any top level function or variable */
            unreachable!();
        }
    }
}

/// First pass: walk the module tree and collect all class → doc-root-relative path entries.
fn collect_classes(stk: &mut Vec<&'static str>, m: &'static Module, map: &mut ClassMap) {
    for SymDesc { name, sym } in m.symtab.iter() {
        stk.push(name);
        match sym {
            Symbol::Module(child) => collect_classes(stk, child, map),
            Symbol::Class(cls) => {
                let path = format!("{}/{}.md", stk[..stk.len() - 1].join("/"), name);
                map.insert(cls, path);
            }
            _ => {}
        }
        stk.pop();
    }
}

/// Compute the relative prefix needed to reach the docs root from a module at depth `depth`.
/// e.g. depth 1 → `"../"`, depth 2 → `"../../"`.
fn doc_root_prefix(depth: usize) -> String {
    "../".repeat(depth)
}

/// Generate documentation for a module.
pub fn recurse(
    out_dir: &Path,
    stk: &mut Vec<&'static str>,
    m: &'static Module,
    class_map: &ClassMap,
) {
    let mut mod_path = PathBuf::from(out_dir);

    for item in stk.iter() {
        mod_path.push(item);
    }

    create_dir_all(&mod_path).expect("mkdir");
    mod_path.push("README.md");

    println!("module -> {}", mod_path.display());

    let f = File::create(mod_path.clone()).expect("Unable to create file");
    let mut wr = BufWriter::new(f);

    mod_path.pop();

    let doc_root = doc_root_prefix(stk.len());
    m.write_docs(&mut wr, class_map, &doc_root)
        .expect("Write module docs");

    for SymDesc { name, sym } in m.symtab.iter() {
        stk.push(name);
        match sym {
            Symbol::Module(child) => recurse(out_dir, stk, child, class_map),
            Symbol::Class(cls) => {
                mod_path.push(format!("{}.md", name));
                println!("class -> {}", mod_path.display());

                let f = File::create(mod_path.clone()).expect("Unable to create file");
                let mut wr = BufWriter::new(f);

                let doc_root = doc_root_prefix(stk.len() - 1);
                cls.write_docs(&mut wr, class_map, &doc_root)
                    .expect("class doc");
            }
            _ => {}
        }
        stk.pop();
    }
}

pub fn write_docs(out_dir: &Path) {
    create_dir_all(out_dir).expect("mkdir");

    let mut stk: Vec<&'static str> = Vec::new();
    let mut class_map = ClassMap::new();
    collect_classes(&mut stk, &STDLIB, &mut class_map);

    recurse(out_dir, &mut stk, &STDLIB, &class_map)
}

// ── JSON stdlib export ────────────────────────────────────────────────────────

/// Maximum integer value that can be represented exactly in a JSON number (2⁵³ − 1).
const JSON_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

fn valdef_to_json_fields(val: &ValDef) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("type".into(), json!(val.val_type().to_string()));
    match val {
        ValDef::Nil => {}
        ValDef::Bool(b) => {
            m.insert("value".into(), json!(b));
        }
        ValDef::U8(n) => {
            m.insert("value".into(), json!(n));
        }
        ValDef::U16(n) => {
            m.insert("value".into(), json!(n));
        }
        ValDef::U32(n) => {
            m.insert("value".into(), json!(n));
        }
        ValDef::U64(n) => {
            if *n <= JSON_SAFE_INTEGER {
                m.insert("value".into(), json!(n));
            } else {
                m.insert("value_decimal".into(), json!(n.to_string()));
            }
        }
        ValDef::Ip4(addr) => {
            m.insert("value".into(), json!(addr.to_string()));
        }
        ValDef::Sock4(sock) => {
            m.insert("value".into(), json!(sock.to_string()));
        }
        ValDef::Str(bytes) => match ::std::str::from_utf8(bytes) {
            Ok(s) => {
                m.insert("value".into(), json!(s));
            }
            Err(_) => {
                m.insert("value_base64".into(), json!(BASE64.encode(bytes)));
            }
        },
        ValDef::Type(t) => {
            m.insert("value".into(), json!(t.to_string()));
        }
    }
    m
}

fn arg_to_json(arg: &crate::libapi::ArgDesc) -> Value {
    let mut m = Map::new();
    m.insert("name".into(), json!(arg.name));
    m.insert("doc".into(), json!(arg.doc.trim()));
    match &arg.typ {
        ArgDecl::Positional(t) => {
            m.insert("type".into(), json!(t.to_string()));
            m.insert("required".into(), json!(true));
        }
        ArgDecl::Optional(d) => {
            m.insert("type".into(), json!(d.val_type().to_string()));
            m.insert("required".into(), json!(false));
            m.insert("default".into(), json!(d.to_string()));
        }
    }
    Value::Object(m)
}

fn func_to_json(f: &'static FuncDef) -> Value {
    let args: Vec<Value> = f.args.iter().map(arg_to_json).collect();
    let collect_type = if f.collect_type == ValType::Void {
        Value::Null
    } else {
        json!(f.collect_type.to_string())
    };
    json!({
        "doc": f.doc.trim(),
        "signature": f.to_string(),
        "args": args,
        "collect_type": collect_type,
        "returns": f.return_type.to_string(),
    })
}

fn class_to_json(cls: &'static ClassDef) -> Value {
    let methods: Map<String, Value> = cls
        .symtab
        .iter()
        .filter_map(|SymDesc { name, sym }| {
            if let Symbol::Func(f) = sym {
                Some(((*name).to_string(), func_to_json(f)))
            } else {
                None
            }
        })
        .collect();
    json!({
        "doc": cls.doc.trim(),
        "methods": methods,
    })
}

fn collect_json(
    m: &'static Module,
    stk: &mut Vec<&'static str>,
    functions: &mut Map<String, Value>,
    classes: &mut Map<String, Value>,
    constants: &mut Map<String, Value>,
) {
    for SymDesc { name, sym } in m.symtab.iter() {
        stk.push(name);
        match sym {
            Symbol::Module(child) => {
                collect_json(child, stk, functions, classes, constants);
            }
            Symbol::Func(f) => {
                functions.insert(stk.join("::"), func_to_json(f));
            }
            Symbol::Class(cls) => {
                classes
                    .entry(cls.name.to_string())
                    .or_insert_with(|| class_to_json(cls));
            }
            Symbol::Val(val) => {
                constants.insert(stk.join("::"), Value::Object(valdef_to_json_fields(val)));
            }
        }
        stk.pop();
    }
}

/// Write the stdlib as structured JSON.
///
/// If `out_path` is `Some`, writes to that file; otherwise writes to stdout.
pub fn write_stdlib_json(out_path: Option<&Path>) {
    let mut functions: Map<String, Value> = Map::new();
    let mut classes: Map<String, Value> = Map::new();
    let mut constants: Map<String, Value> = Map::new();

    let mut stk: Vec<&'static str> = Vec::new();
    collect_json(
        &STDLIB,
        &mut stk,
        &mut functions,
        &mut classes,
        &mut constants,
    );

    let root = json!({
        "version": env!("CARGO_PKG_VERSION"),
        "functions": functions,
        "classes": classes,
        "constants": constants,
    });

    match out_path {
        Some(path) => {
            let f = File::create(path).expect("create json output file");
            serde_json::to_writer(f, &root).expect("write stdlib json");
        }
        None => {
            serde_json::to_writer(::std::io::stdout(), &root).expect("write stdlib json");
            println!();
        }
    }
}

#[cfg(test)]
mod test;
