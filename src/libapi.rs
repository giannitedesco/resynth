use std::cmp::Ordering;
use std::collections::HashMap;
use std::fmt::{Debug, Display, Formatter};
use std::hash::{Hash, Hasher};
use std::io::Write;

use derive_more::Display;

use crate::args::{ArgSpec, ArgVec, Args};
use crate::err::Error;
use crate::err::Error::{
    ArgMultiplySpecified, ArgTypeMismatch, CollectArgTypeMismatch, MissingArg, NoSuchArg,
    TooFewArgs, TooManyArgs, UnexpectedCollectArgs, UnexpectedNamedArg,
};
use crate::object::ObjRef;
use crate::sym::Symbol;
use crate::val::{Typed, Val, ValDef, ValType};

/// Map from `&'static ClassDef` to its path relative to the docs root (e.g.
/// `"ipv4/tcp/TcpFlow.md"`). Used to generate cross-module links in markdown docs.
pub type ClassMap = HashMap<&'static ClassDef, String>;

/// Argument declarator
#[derive(Debug, Clone, Copy, PartialEq, Eq, Display)]
pub enum ArgDecl {
    #[display("{}", _0)]
    Positional(ValType),
    #[display("{} = {}", _0.val_type(), _0)]
    Optional(ValDef),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Display)]
#[display("{}: {}", name, typ)]
pub struct ArgDesc {
    pub name: &'static str,
    pub typ: ArgDecl,
    pub doc: &'static str,
}

/// Defines a function or method for the resynth stdlib
#[derive(Debug)]
pub struct FuncDef {
    pub name: &'static str,
    pub return_type: ValType,
    /// Invariant: All Positionals must come first, then all Optional
    pub args: &'static [ArgDesc],
    pub arg_pos: fn(name: &str) -> Option<usize>,
    /// minimum number of args: ie. number of positionals
    pub min_args: usize,
    pub collect_type: ValType,
    pub exec: fn(args: Args) -> Result<Val, Error>,
    pub doc: &'static str,
}

impl Eq for FuncDef {}
impl PartialEq for FuncDef {
    fn eq(&self, other: &FuncDef) -> bool {
        std::ptr::eq(self as *const FuncDef, other as *const FuncDef)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SymDesc {
    pub name: &'static str,
    pub sym: Symbol,
}

/// Applies to anything with a symbol table which is documented into a documentation page
/// ie. classes and modules
pub trait Documented {
    fn symtab(&self) -> &'static [SymDesc];
    fn front_matter(&self) -> &'static str;

    fn symbol_set<F>(&self, flt: F) -> Vec<SymDesc>
    where
        F: FnMut(&SymDesc) -> bool,
    {
        let mut ret: Vec<SymDesc> = self.symtab().iter().cloned().filter(flt).collect();
        ret.sort();
        ret.shrink_to_fit();
        ret
    }

    fn modules(&self) -> Vec<SymDesc> {
        self.symbol_set(|&x| matches!(x.sym, Symbol::Module(_)))
    }

    fn functions(&self) -> Vec<SymDesc> {
        self.symbol_set(|&x| matches!(x.sym, Symbol::Func(_)))
    }

    fn classes(&self) -> Vec<SymDesc> {
        self.symbol_set(|&x| matches!(x.sym, Symbol::Class(_)))
    }

    fn constants(&self) -> Vec<SymDesc> {
        self.symbol_set(|&x| matches!(x.sym, Symbol::Val(_)))
    }

    fn write_docs<W: Write>(
        &self,
        wr: &mut W,
        class_map: &ClassMap,
        doc_root: &str,
    ) -> Result<(), std::io::Error> {
        wr.write_all(self.front_matter().as_bytes())?;

        let submods = self.modules();
        let funcs = self.functions();
        let classes = self.classes();
        let consts = self.constants();

        wr.write_all(b"\n## Index\n\n")?;

        if !submods.is_empty() {
            wr.write_all(b"\n### Modules\n\n")?;
            wr.write_all(b"| Module | Description |\n")?;
            wr.write_all(b"| ------ | ----------- |\n")?;
            for SymDesc { name, sym } in &submods {
                let desc = if let Symbol::Module(m) = sym {
                    table_cell(&doc_summary(m.doc))
                } else {
                    String::new()
                };
                wr.write_all(
                    format!("| [{}]({}/README.md) | {} |\n", name, name, desc).as_bytes(),
                )?;
            }
        }

        if !classes.is_empty() {
            wr.write_all(b"\n### Classes\n\n")?;
            wr.write_all(b"| Class | Description |\n")?;
            wr.write_all(b"| ----- | ----------- |\n")?;
            for SymDesc { name, sym } in &classes {
                let desc = if let Symbol::Class(cls) = sym {
                    table_cell(&doc_summary(cls.doc))
                } else {
                    String::new()
                };
                wr.write_all(format!("| [{}]({}.md) | {} |\n", name, name, desc).as_bytes())?;
            }
        }

        if !funcs.is_empty() {
            wr.write_all(b"\n### Functions\n\n")?;
            wr.write_all(b"| Function | Returns | Description |\n")?;
            wr.write_all(b"| -------- | ------- | ----------- |\n")?;
            for SymDesc { name, sym } in &funcs {
                let (ret, desc) = if let Symbol::Func(f) = sym {
                    (
                        fmt_type_link(&f.return_type, class_map, doc_root),
                        table_cell(&doc_summary(f.doc)),
                    )
                } else {
                    (String::new(), String::new())
                };
                wr.write_all(
                    format!("| [{}](#{}) | {} | {} |\n", name, name, ret, desc).as_bytes(),
                )?;
            }
        }

        if !consts.is_empty() {
            wr.write_all(b"\n### Constants\n\n")?;
            wr.write_all(b"| Name | Value |\n")?;
            wr.write_all(b"| ---- | ----- |\n")?;
            for SymDesc { name, sym } in &consts {
                if let Symbol::Val(val) = sym {
                    wr.write_all(
                        format!("| {} | `({}){}` |\n", name, val.val_type(), val,).as_bytes(),
                    )?;
                }
            }
        }

        if !funcs.is_empty() {
            wr.write_all(b"\n\n")?;
            for SymDesc { name, sym } in &funcs {
                if let Symbol::Func(func) = sym {
                    assert_eq!(*name, func.name);
                    func.write_docs(wr, class_map, doc_root)?;
                }
            }
        }

        Ok(())
    }
}

impl PartialOrd for SymDesc {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SymDesc {
    fn cmp(&self, other: &Self) -> Ordering {
        self.name.cmp(other.name)
    }
}

/// Defines a module for the resynth stdlib
#[derive(Debug)]
pub struct Module {
    pub name: &'static str,
    pub symtab: &'static [SymDesc],
    pub lookup: fn(name: &str) -> Option<usize>,
    pub doc: &'static str,
}

impl Documented for Module {
    fn symtab(&self) -> &'static [SymDesc] {
        self.symtab
    }

    fn front_matter(&self) -> &'static str {
        self.doc
    }
}

impl Module {
    pub fn get(&self, name: &str) -> Option<&'static Symbol> {
        match (self.lookup)(name) {
            Some(idx) => Some(&self.symtab[idx].sym),
            None => None,
        }
    }
}

/// Defines a module for the resynth stdlib
#[derive(Debug)]
pub struct ClassDef {
    pub name: &'static str,
    pub symtab: &'static [SymDesc],
    pub lookup: fn(name: &str) -> Option<usize>,
    pub doc: &'static str,
}

impl Eq for ClassDef {}
impl PartialEq for ClassDef {
    fn eq(&self, other: &ClassDef) -> bool {
        std::ptr::eq(self as *const ClassDef, other as *const ClassDef)
    }
}
impl Hash for ClassDef {
    fn hash<H: Hasher>(&self, state: &mut H) {
        std::ptr::hash(self as *const ClassDef, state);
    }
}

impl Documented for ClassDef {
    fn symtab(&self) -> &'static [SymDesc] {
        self.symtab
    }

    fn front_matter(&self) -> &'static str {
        self.doc
    }
}

impl ClassDef {
    pub fn get(&self, name: &str) -> Option<&'static Symbol> {
        match (self.lookup)(name) {
            Some(idx) => Some(&self.symtab[idx].sym),
            None => None,
        }
    }
}

pub trait Class {
    fn def(&self) -> &'static ClassDef;

    fn get(&self, name: &str) -> Option<&'static Symbol> {
        self.def().get(name)
    }

    fn symbols(&self) -> &'static [SymDesc] {
        self.def().symtab
    }

    fn class_name(&self) -> &'static str {
        self.def().name
    }

    fn doc(&self) -> &'static str {
        self.def().doc
    }
}

struct ArgPrep {
    positional: Vec<Val>,
    named: HashMap<String, Val>,
    extra: Vec<Val>,
}

/// Invariant: No argument may be supplied with a value more than once
/// Invariant: No argument can be ambiguous as to where it belongs
///
/// Rules:
///  P-FIRST Positonal args must be supplied first
///  P-NAME-OPTIONAL Positionals may be named or not
///  ANON-FIRST If one positional is named, all subsequent positionals + optionals must be named
///  COLLECT-NAME-OPTS if func has collect args, optionals MUST be named
///  NOCOLLECT-ANON-OPTS if func doesn't have collect args, optionals MAY be anonymous
///  COLLECT-AFTER-NAMED collect args must come after the last named arg
/// Extract a short summary from a doc string for use in index tables.
///
/// - If the first non-empty line is a heading (`# ...`), strip the leading `#` chars and
///   return that as the title.
/// - Otherwise collect the first contiguous paragraph (non-empty lines joined by spaces).
fn doc_summary(doc: &str) -> String {
    let mut lines = doc.lines().peekable();

    // Skip leading blank lines
    while matches!(lines.peek(), Some(l) if l.trim().is_empty()) {
        lines.next();
    }

    // If the first content line is a heading, return its text
    if let Some(&line) = lines.peek() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') {
            return trimmed.trim_start_matches('#').trim().to_string();
        }
    }

    // Otherwise collect the first paragraph
    let mut para: Vec<&str> = Vec::new();
    for line in lines {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            if !para.is_empty() {
                break;
            }
        } else {
            para.push(trimmed);
        }
    }
    para.join(" ")
}

/// Escape a string for safe use in a Markdown table cell.
fn table_cell(s: &str) -> String {
    s.replace('|', "\\|")
}

/// `doc_root` is the path from the current page's location to the docs root (e.g. `"../../"`).
fn fmt_type_link(typ: &ValType, class_map: &ClassMap, doc_root: &str) -> String {
    if let ValType::Class(cls) = typ {
        if let Some(path) = class_map.get(cls) {
            return format!("[{}]({}{})", cls.name, doc_root, path);
        }
        return format!("`{}`", cls.name);
    }
    format!("`{}`", typ)
}

impl FuncDef {
    pub fn is_collect(&self) -> bool {
        self.collect_type != ValType::Void
    }

    fn split_args(&self, args: Vec<ArgSpec>) -> Result<ArgPrep, Error> {
        enum State {
            Anon,
            Optional,
            CollectOnly,
        }
        let mut positional: Vec<Val> = Vec::new();
        let mut named: HashMap<String, Val> = HashMap::new();
        let mut extra: Vec<Val> = Vec::new();
        let mut state = State::Anon;

        for arg in args {
            loop {
                match state {
                    State::Anon => {
                        if !arg.is_anon() {
                            state = State::Optional;
                            continue;
                        } else if self.is_collect() && positional.len() >= self.min_args {
                            // If we have collect args, then any optionals must be named
                            state = State::CollectOnly;
                            continue;
                        } else if positional.len() >= self.args.len() {
                            if self.is_collect() {
                                state = State::CollectOnly;
                                continue;
                            }
                            return Err(TooManyArgs {
                                func: self.name.into(),
                                got: positional.len(),
                                want: self.args.len(),
                            });
                        } else {
                            positional.push(arg.val);
                            break;
                        }
                    }
                    State::Optional => {
                        if arg.is_anon() {
                            state = State::CollectOnly;
                            continue;
                        }

                        let name = arg.name.unwrap();

                        let arg_pos = (self.arg_pos)(&name);

                        if arg_pos.is_none() {
                            return Err(NoSuchArg {
                                func: self.name.into(),
                                arg: name.into(),
                            });
                        }

                        let arg_index = arg_pos.unwrap();

                        // Invariant: No argument may be supplied with a value more than once

                        // a) If the index of the arg is one of the positionals we've already got,
                        // then a positional has been specified by position, and is now attempting
                        // to be specified by name. So nope.
                        if arg_index < positional.len() {
                            return Err(ArgMultiplySpecified {
                                func: self.name.into(),
                                arg: name.into(),
                            });
                        }

                        // b) if we've named the same arg twice then that's also not allowed.
                        if named.contains_key(&name) {
                            return Err(ArgMultiplySpecified {
                                func: self.name.into(),
                                arg: name.into(),
                            });
                        }

                        named.insert(name, arg.val);
                        break;
                    }
                    State::CollectOnly => {
                        if !self.is_collect() {
                            return Err(UnexpectedCollectArgs {
                                func: self.name.into(),
                            });
                        }
                        if arg.is_named() {
                            return Err(UnexpectedNamedArg {
                                func: self.name.into(),
                                arg: arg.name.unwrap().into(),
                            });
                        }
                        extra.push(arg.val);
                        break;
                    }
                }
            }
        }

        positional.shrink_to_fit();
        named.shrink_to_fit();
        extra.shrink_to_fit();

        Ok(ArgPrep {
            positional,
            named,
            extra,
        })
    }

    pub fn argvec(&self, this: Option<ObjRef>, args: Vec<ArgSpec>) -> Result<ArgVec, Error> {
        let ArgPrep {
            positional,
            mut named,
            extra,
        } = self.split_args(args)?;
        let nr_positional = positional.len();
        let nr_named = named.len();
        let nr_specified = nr_positional + nr_named;

        // Now do some basic sanity checks to stup us shooting ourselves in the foot later
        if nr_specified < self.min_args {
            return Err(TooFewArgs {
                func: self.name.into(),
                got: nr_specified,
                want: self.min_args,
            });
        }

        let mut args: Vec<Val> = Vec::with_capacity(self.args.len());

        // 1. push anon vals to start with
        for a in positional {
            args.push(a);
        }

        // either all positional and optional args are supplied and then everything else is in
        // extra OR some positional/optional have been named, in which case all the collect args
        // are in extra assert!(args.len() <= self.args.len());

        // 2. Take named positionals and optionals
        for ArgDesc { name, typ, .. } in self.args.iter().skip(nr_positional) {
            if let Some(val) = named.remove(*name) {
                // positional or optional specified by name, push it
                args.push(val);
            } else if let ArgDecl::Optional(dfl) = typ {
                // not specified, but we're optional, so take the default
                args.push((*dfl).into());
            } else {
                // not specified, and we're mandatory, barf
                return Err(MissingArg {
                    func: self.name.into(),
                    arg: (*name).into(),
                });
            }
        }

        assert!(named.is_empty());

        // 3. Final type-check of all positional args
        for (ArgDesc { name, typ, .. }, arg) in self.args.iter().zip(args.iter()) {
            if !match typ {
                ArgDecl::Positional(typ) => typ.compatible_with(arg),
                ArgDecl::Optional(dfl) => dfl.arg_compatible(arg),
            } {
                return Err(ArgTypeMismatch {
                    func: self.name.into(),
                    arg: (*name).into(),
                });
            }
        }

        // 4. Type-check the collect-args
        if extra.iter().any(|x| !self.collect_type.compatible_with(x)) {
            return Err(CollectArgTypeMismatch {
                func: self.name.into(),
            });
        }

        Ok(ArgVec::new(this, args, extra))
    }

    pub fn args(&self, this: Option<ObjRef>, args: Vec<ArgSpec>) -> Result<Args, Error> {
        Ok(self.argvec(this, args)?.into())
    }

    pub fn write_docs<W: Write>(
        &self,
        wr: &mut W,
        class_map: &ClassMap,
        doc_root: &str,
    ) -> Result<(), std::io::Error> {
        wr.write_all(format!("\n## {}\n", self.name).as_bytes())?;
        wr.write_all(b"```resynth\n")?;
        wr.write_all(format!("{}\n", self).as_bytes())?;
        wr.write_all(b"```\n")?;
        wr.write_all(self.doc.trim().as_bytes())?;
        wr.write_all(b"\n")?;

        // Parameters table
        if !self.args.is_empty() || !self.collect_type.is_nil() {
            wr.write_all(b"\n### Parameters\n\n")?;
            wr.write_all(b"| Name | Type | Description |\n")?;
            wr.write_all(b"| ---- | ---- | ----------- |\n")?;
            for ArgDesc { name, typ, doc } in self.args.iter() {
                let (type_str, default) = match typ {
                    ArgDecl::Positional(t) => (fmt_type_link(t, class_map, doc_root), None),
                    ArgDecl::Optional(d) => (
                        fmt_type_link(&d.val_type(), class_map, doc_root),
                        Some(format!("{}", d)),
                    ),
                };
                let desc = if let Some(dfl) = default {
                    format!("{} _(default: `{}`)_", doc.trim(), dfl)
                } else {
                    doc.trim().to_string()
                };
                wr.write_all(format!("| `{}` | {} | {} |\n", name, type_str, desc).as_bytes())?;
            }
            if !self.collect_type.is_nil() {
                let type_str = fmt_type_link(&self.collect_type, class_map, doc_root);
                wr.write_all(
                    format!("| `…` | {} | Zero or more additional values |\n", type_str).as_bytes(),
                )?;
            }
        }

        // Returns table
        if !self.return_type.is_nil() {
            wr.write_all(b"\n### Returns\n\n")?;
            wr.write_all(b"| Type |\n")?;
            wr.write_all(b"| ---- |\n")?;
            let type_str = fmt_type_link(&self.return_type, class_map, doc_root);
            wr.write_all(format!("| {} |\n", type_str).as_bytes())?;
        }

        Ok(())
    }
}

impl Display for FuncDef {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        writeln!(f, "resynth fn {} (", self.name)?;

        for arg in self.args.iter() {
            writeln!(f, "    {},", arg)?;
        }

        if !self.collect_type.is_nil() {
            writeln!(f, "    =>\n    *collect_args: {},", self.collect_type)?;
        }

        write!(f, ") -> {};", self.return_type)
    }
}
