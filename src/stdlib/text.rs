use phf::phf_map;

use crate::err::Error;
use crate::val::{Symbol, ValType, FuncDef, ValDef, Args, Val, BytesObj};

fn text_crlflines(mut args: Args) -> Result<Val, Error> {
    // We have to collect all the extra_args in to a vec so they can stay owning the bytes that
    // they reference
    let cargs: Vec<BytesObj> = args.collect_extra_args();

    // Then we construct a vec of all those references.
    //
    // XXX This is a good example of where rust imposes a performance penalty, this intermediate
    // vector is literally completely redundant. It servers no other purpose than not owning the
    // strings so that we can have a vec of unowned references for Vec::join to use.
    //
    // Itertools crate has a better "join" implementation from this use-case. And intersperse in
    // nightly also solves this reasonably well.
    let strs: Vec<&[u8]> = cargs.iter().map(|x| x.as_ref()).collect();

    // Finally we can do the join
    let ret = strs.join(b"\r\n" as &[u8]);

    Ok(Val::Str(BytesObj::new(ret)))
}

pub const TEXT: phf::Map<&'static str, Symbol> = phf_map! {
    "crlflines" => Symbol::Func(FuncDef {
        name: "crlflines",
        return_type: ValType::Str,
        args: &[],
        collect_type: ValType::Str,
        exec: text_crlflines,
    }),
    "CRLF" => Symbol::Val(ValDef::Str(b"\r\n")),
};
