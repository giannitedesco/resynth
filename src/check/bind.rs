//! Binding a call's arguments to its callee's parameters, at check time, on types.
//!
//! The rules:
//! - Positional parameters come first. They may be given in order, or by name.
//! - Once one argument is named, every argument after it that fills a parameter must be named.
//! - If the function takes collect arguments, its optional parameters must be named, and the
//!   collect arguments come after the last named argument.
//! - If it doesn't, optional parameters may be given in order too.
//! - No parameter may be given twice.

use crate::ast::Ident;
use crate::hir::{Const, Expr, ExprKind};
use crate::libapi::{ArgDecl, FuncDef};
use crate::loc::Loc;

use super::SemanticError;
use super::SemanticErrorKind::{
    ArgType, CollectArgType, DuplicateArg, MissingArg, TooFewArgs, TooManyArgs,
    UnexpectedCollectArgs, UnexpectedNamedArg, UnknownArg,
};
use super::Ty;

/// A checked argument, as written in the source
pub(crate) struct ArgIn {
    /// Its name, if it was written `name: value`
    pub(crate) name: Option<Ident>,
    /// Where its value starts
    pub(crate) loc: Loc,
    pub(crate) hir: Expr,
    pub(crate) ty: Ty,
}

/// A call's arguments, bound to its callee's parameters
pub(crate) struct Bound {
    /// One argument per parameter, with its parameter's index. The arguments written in the
    /// source come first, in source order, then the defaults of the rest, in parameter order.
    pub(crate) args: Box<[(Expr, usize)]>,
    /// The collect arguments, in source order
    pub(crate) collect: Box<[Expr]>,
}

/// Where the binder is in the argument list
enum State {
    /// Filling parameters in order
    Anon,
    /// Filling parameters by name
    Named,
    /// Only collect arguments are left
    CollectOnly,
}

impl ArgIn {
    /// Where an error about this argument points: its name, if it has one
    fn err_loc(&self) -> Loc {
        self.name.as_ref().map_or(self.loc, |name| name.loc)
    }
}

impl Bound {
    /// Bind `args`, in source order, to `func`'s parameters. Errors about one argument point at
    /// it. Errors about a missing argument point at the call, `call_loc`.
    pub(crate) fn bind(
        func: &'static FuncDef,
        call_loc: Loc,
        args: Vec<ArgIn>,
    ) -> Result<Self, SemanticError> {
        // A named argument that isn't a parameter at all is reported before any rule about
        // where it was written. Each named argument is paired with its parameter's slot.
        let args = args
            .into_iter()
            .map(|arg| {
                let Some(name) = &arg.name else {
                    return Ok((arg, None));
                };
                match (func.arg_pos)(&name.name) {
                    Some(slot) => Ok((arg, Some(slot))),
                    None => Err(UnknownArg {
                        func: func.name,
                        arg: name.name.clone(),
                    }
                    .at(name.loc)),
                }
            })
            .collect::<Result<Vec<_>, _>>()?;

        let nparams = func.args.len();
        let leading_anon = args
            .iter()
            .take_while(|(arg, _)| arg.name.is_none())
            .count();
        let any_named = leading_anon < args.len();
        let mut filled = vec![false; nparams];
        let mut nanon = 0;
        let mut out = Vec::with_capacity(nparams);
        let mut collect = Vec::new();
        let mut state = State::Anon;

        for (arg, named_slot) in args {
            let slot = loop {
                match state {
                    State::Anon => {
                        if arg.name.is_some() {
                            state = State::Named;
                        } else if func.is_collect() && nanon >= func.min_args {
                            state = State::CollectOnly;
                        } else if nanon >= nparams {
                            // A collect function went to CollectOnly above, since it has no
                            // more than `nparams` positional parameters
                            return Err(TooManyArgs {
                                func: func.name,
                                got: leading_anon,
                                want: nparams,
                            }
                            .at(arg.loc));
                        } else {
                            nanon += 1;
                            break Some(nanon - 1);
                        }
                    }
                    State::Named => {
                        let (Some(name), Some(slot)) = (&arg.name, named_slot) else {
                            state = State::CollectOnly;
                            continue;
                        };
                        if filled[slot] {
                            return Err(DuplicateArg {
                                func: func.name,
                                arg: name.name.clone(),
                            }
                            .at(name.loc));
                        }
                        break Some(slot);
                    }
                    State::CollectOnly => {
                        if !func.is_collect() {
                            return Err(UnexpectedCollectArgs { func: func.name }.at(arg.err_loc()));
                        }
                        if let Some(name) = arg.name {
                            return Err(UnexpectedNamedArg {
                                func: func.name,
                                arg: name.name,
                            }
                            .at(name.loc));
                        }
                        break None;
                    }
                }
            };

            match slot {
                Some(slot) => {
                    let expected = func.args[slot].typ.param_type();
                    if !arg.ty.fits(expected) {
                        return Err(ArgType {
                            func: func.name,
                            arg: func.args[slot].name,
                            expected,
                            found: arg.ty,
                        }
                        .at(arg.err_loc()));
                    }
                    filled[slot] = true;
                    out.push((arg.hir, slot));
                }
                None => {
                    if !arg.ty.fits(func.collect_type) {
                        return Err(CollectArgType {
                            func: func.name,
                            expected: func.collect_type,
                            found: arg.ty,
                        }
                        .at(arg.loc));
                    }
                    collect.push(arg.hir);
                }
            }
        }

        // A call with only anonymous arguments is short of positionals by count. Once any
        // argument is named, the first missing positional is named instead, however many
        // optionals were also given.
        if !any_named && out.len() < func.min_args {
            return Err(TooFewArgs {
                func: func.name,
                got: out.len(),
                want: func.min_args,
            }
            .at(call_loc));
        }

        // Every parameter not given takes its default, or is absent if it's nullable
        for (slot, desc) in func.args.iter().enumerate() {
            if filled[slot] {
                continue;
            }
            let value = match desc.typ {
                ArgDecl::Optional(def) => Const::default_of(def),
                ArgDecl::Positional(_) => {
                    return Err(MissingArg {
                        func: func.name,
                        arg: desc.name,
                    }
                    .at(call_loc));
                }
            };
            out.push((Expr::new(call_loc, ExprKind::Const(value)), slot));
        }

        Ok(Self {
            args: out.into(),
            collect: collect.into(),
        })
    }
}
