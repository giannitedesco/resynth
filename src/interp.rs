//! The tree-walking interpreter, which runs a checked [Program].
//!
//! The checker has already resolved every name, bound every call and checked every type, so the
//! only errors left are the ones that depend on running: a stdlib function failing, and an effect
//! failing. Paths the checker rules out are `unreachable!`

use std::net::SocketAddrV4;

use pkt::Packet;

use crate::args::Args;
use crate::hir::{Call, Expr, ExprKind, Program, Stmt, StmtKind};
use crate::loc::Loc;
use crate::val::{Typed, Val};

use RuntimeErrorKind::PortOutOfRange;

pub use crate::program::{RuntimeError, RuntimeErrorKind};

type Result<T> = std::result::Result<T, RuntimeError>;

/// Something a running program does outside itself, or tells its caller about
#[derive(Debug)]
pub enum Effect<'a> {
    /// A statement's value was discarded, after the checker warned about it
    Discard(Val),

    /// Send a packet at `time`, in nanoseconds since the Unix epoch
    Packet { time: u64, pkt: &'a Packet },

    /// The clock moved forward by this many nanoseconds, for a wait
    TimeJump(u64),
}

/// A running [Program]: its statements, the values of its locals, and its clock
pub struct TreeInterp {
    stmts: Box<[Stmt]>,
    /// The value of each slot whose `let` has run, in slot order
    frame: Vec<Val>,
    /// Nanoseconds since the Unix epoch
    now: u64,
}

impl TreeInterp {
    /// Ready to run `prog`, with its clock at `start`, in nanoseconds since the Unix epoch
    pub fn new(prog: Program, start: u64) -> Self {
        let Program { stmts, slots } = prog;
        Self {
            stmts,
            frame: Vec::with_capacity(slots.len()),
            now: start,
        }
    }

    /// Run each statement in turn, stopping at the first error. Each effect goes to `effect`,
    /// with the statement's location, and an error from it is at the statement.
    pub fn run(
        mut self,
        mut effect: impl FnMut(Loc, Effect<'_>) -> std::result::Result<(), RuntimeErrorKind>,
    ) -> Result<()> {
        let stmts = std::mem::take(&mut self.stmts);
        for stmt in stmts {
            self.stmt(stmt, &mut effect)?;
        }
        Ok(())
    }

    fn stmt(
        &mut self,
        stmt: Stmt,
        effect: &mut impl FnMut(Loc, Effect<'_>) -> std::result::Result<(), RuntimeErrorKind>,
    ) -> Result<()> {
        let Stmt { loc, kind } = stmt;
        match kind {
            StmtKind::Let { slot, value } => {
                let val = self.eval(value)?;
                // Slots are numbered in the order their `let`s run, so the frame never holds an
                // unassigned slot
                assert_eq!(slot.index(), self.frame.len(), "slots are bound in order");
                self.frame.push(val);
            }
            StmtKind::Emit(expr) => match self.eval(expr)? {
                Val::Pkt(pkt) => self.send(loc, &pkt, effect)?,
                Val::PktGen(pkts) => {
                    for pkt in pkts.iter() {
                        self.send(loc, pkt, effect)?;
                    }
                }
                val => unreachable!("emit of {val:?}: return types are asserted"),
            },
            StmtKind::Wait(expr) => match self.eval(expr)? {
                Val::TimeJump(ns) => {
                    self.advance(ns);
                    effect(loc, Effect::TimeJump(ns)).map_err(|kind| kind.at(loc))?;
                }
                val => unreachable!("wait for {val:?}: return types are asserted"),
            },
            StmtKind::Eval(expr) => {
                self.eval(expr)?;
            }
            StmtKind::Discard(expr) => {
                let val = self.eval(expr)?;
                effect(loc, Effect::Discard(val)).map_err(|kind| kind.at(loc))?;
            }
        }
        Ok(())
    }

    fn advance(&mut self, ns: u64) {
        self.now = self.now.saturating_add(ns);
    }

    /// Send a packet once the time it takes to transmit has passed
    fn send(
        &mut self,
        loc: Loc,
        pkt: &Packet,
        effect: &mut impl FnMut(Loc, Effect<'_>) -> std::result::Result<(), RuntimeErrorKind>,
    ) -> Result<()> {
        self.advance(pkt.bit_time());
        effect(
            loc,
            Effect::Packet {
                time: self.now,
                pkt,
            },
        )
        .map_err(|kind| kind.at(loc))
    }

    fn eval(&mut self, expr: Expr) -> Result<Val> {
        let Expr { loc, kind } = expr;
        Ok(match kind {
            ExprKind::Const(c) => c.into_val(),
            ExprKind::Local(slot) => self
                .frame
                .get(slot.index())
                .expect("a local is read after its let")
                .clone(),
            ExprKind::Method { obj, func } => match self.eval(*obj)? {
                Val::Obj(obj) => Val::Method(obj, func),
                val => unreachable!("method {} of {val:?}: receivers are objects", func.name),
            },
            ExprKind::Seq { effects, value } => {
                for expr in effects {
                    self.eval(expr)?;
                }
                self.eval(*value)?
            }
            ExprKind::Call(call) => self.call(loc, *call)?,
            ExprKind::SockAddr { ip, port } => {
                let ip = match self.eval(*ip)? {
                    Val::Ip4(ip) => ip,
                    val => unreachable!("{val:?} / port: the left of / is an Ip4"),
                };
                let port_loc = port.loc;
                let port = u64::from(self.eval(*port)?);
                let port = u16::try_from(port).map_err(|_| PortOutOfRange(port).at(port_loc))?;
                Val::Sock4(SocketAddrV4::new(ip, port))
            }
        })
    }

    /// Evaluate the callee, then the arguments in the order the call holds them, scattering
    /// each into its parameter's place, then the collect arguments. Errors from the function
    /// are at the call's called name, `loc`.
    fn call(&mut self, loc: Loc, call: Call) -> Result<Val> {
        let Call {
            callee,
            func,
            args,
            collect,
        } = call;

        let this = match self.eval(callee)? {
            Val::Func(f) if f == func => None,
            Val::Method(obj, f) if f == func => Some(obj),
            val => unreachable!(
                "callee {val:?}: it is {}, which the call was bound to",
                func.name
            ),
        };

        assert_eq!(args.len(), func.args.len(), "one argument per parameter");
        let mut params: Vec<Option<Val>> = vec![None; args.len()];
        for (arg, slot) in args {
            let val = self.eval(arg)?;
            assert!(
                params[slot].replace(val).is_none(),
                "parameter {slot} bound twice"
            );
        }
        let params = params
            .into_iter()
            .map(|val| val.expect("every parameter is bound"))
            .collect();
        let extra = collect
            .into_iter()
            .map(|arg| self.eval(arg))
            .collect::<Result<_>>()?;

        let ret = (func.exec)(Args::new(this, params, extra)).map_err(|kind| kind.at(loc))?;

        // The checker typed this call by its declared return type, and a statement's effect
        // depends on it, so a stdlib function that lies about it is a bug
        assert!(
            ret.val_type() == func.return_type,
            "{} returned {}, but is declared to return {}",
            func.name,
            ret.val_type(),
            func.return_type
        );

        Ok(ret)
    }
}
