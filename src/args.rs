use crate::val::{Val, ValDef};
use crate::parse::Expr;
use crate::object::ObjRef;
use crate::str::Buf;

use std::ops::Drop;
use std::vec;

#[derive(Debug, PartialEq, Eq)]
pub struct ArgVec {
    this: Option<ObjRef>,
    args: Vec<Val>,
    extra: Vec<Val>,
}

impl ArgVec {
    pub fn new(this: Option<ObjRef>, args: Vec<Val>, extra: Vec<Val>) -> Self {
        Self {
            this,
            args,
            extra,
        }
    }
}

#[derive(Debug)]
pub struct Args {
    this: Option<ObjRef>,
    it: vec::IntoIter<Val>,
    extra_args: Vec<Val>,
}

impl From<ArgVec> for Args {
    fn from(v: ArgVec) -> Self {
        let ArgVec { this, args, extra } = v;
        Self::new(this, args, extra)
    }
}

impl Args {
    pub fn new(this: Option<ObjRef>, args: Vec<Val>, extra_args: Vec<Val>) -> Self {
        Self {
            this,
            it: args.into_iter(),
            extra_args,
        }
    }

    pub fn take_this(&mut self) -> ObjRef {
        self.this.take().unwrap()
    }

    pub fn next(&mut self) -> Val {
        self.it.next().unwrap()
    }

    pub fn extra_args(&mut self) -> Vec<Val> {
        std::mem::take(&mut self.extra_args)
    }
    
    pub fn extra_len(&self) -> usize {
        self.extra_args.len()
    }

    // Collect all extra args into a vec of the given type
    pub fn collect_extra_args<T>(&mut self) -> Vec<T> where T: From<Val> {
        self.extra_args().into_iter().map(|x| -> T { x.into() } ).collect()
    }

    pub fn join_extra(&mut self, j: &[u8]) -> Val {
        // We have to collect all the extra_args in to a vec so they can stay owning the bytes that
        // they reference
        let cargs: Vec<Buf> = self.collect_extra_args();

        // Then we construct a vec of all those references.
        //
        // XXX This is a good example of where rust imposes a performance penalty, this
        // intermediate vector is literally completely redundant. It serves no other purpose than
        // not owning the strings so that we can have a vec of unowned references for Vec::join to
        // use.
        //
        // Itertools crate has a better "join" implementation from this use-case. And intersperse
        // in nightly also solves this reasonably well.
        let strs: Vec<&[u8]> = cargs.iter().map(|x| x.as_ref()).collect();

        // Finally we can do the join in to a byte vector
        let ret = strs.join(j);

        // Which we can then convert into a buf
        Val::Str(Buf::from(ret))
    }

    /// Dumps all remaining, untaken args
    pub fn void(&mut self) {
        loop {
            if self.it.next().is_none() {
                break;
            }
        }
        self.extra_args = vec!();
    }
}

impl Drop for Args {
    fn drop(&mut self) {
        assert!(self.this.is_none(), "Method didn't take ownership of this");
        assert!(self.it.next().is_none(), "Function didn't consume all args");
        assert!(self.extra_args.is_empty(), "Function didn't consume extra args");
    }
}

#[derive(Debug)]
pub struct ArgExpr {
    pub name: Option<String>,
    pub expr: Expr,
}

impl ArgExpr {
    pub fn new(name: Option<String>, expr: Expr) -> Self {
        Self {
            name,
            expr,
        }
    }
}

#[derive(Debug)]
pub struct ArgSpec {
    pub name: Option<String>,
    pub val: Val,
}

impl ArgSpec {
    pub fn new(name: Option<String>, val: Val) -> Self {
        Self {
            name,
            val,
        }
    }

    pub fn is_anon(&self) -> bool {
        self.name.is_none()
    }
}

impl From<ValDef> for ArgSpec {
    fn from(val: ValDef) -> Self {
        Self {
            name: None,
            val: Val::from(val),
        }
    }
}

impl From<bool> for ArgSpec {
    fn from(val: bool) -> Self {
        Self {
            name: None,
            val: Val::Bool(val),
        }
    }
}

impl From<u64> for ArgSpec {
    fn from(val: u64) -> Self {
        Self {
            name: None,
            val: Val::U64(val),
        }
    }
}

impl<T> From<&T> for ArgSpec where T: AsRef<[u8]> + ? Sized {
    fn from(s: &T) -> Self {
        Self {
            name: None,
            val: Val::Str(Buf::from(s)),
        }
    }
}

impl From<(&str, ValDef)> for ArgSpec {
    fn from((name, val): (&str, ValDef)) -> Self {
        Self {
            name: Some(name.to_owned()),
            val: Val::from(val),
        }
    }
}

impl From<(&str, bool)> for ArgSpec {
    fn from((name, val): (&str, bool)) -> Self {
        Self {
            name: Some(name.to_owned()),
            val: Val::from(val),
        }
    }
}
