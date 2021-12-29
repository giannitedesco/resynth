use crate::val::Val;
use crate::parse::Expr;
use crate::object::ObjRef;
use crate::str::BytesObj;

use std::iter::FromIterator;
use std::ops::Drop;
use std::vec;

#[derive(Debug)]
pub struct Args {
    this: Option<ObjRef>,
    it: vec::IntoIter<Val>,
    extra_args: vec::IntoIter<Val>,
}

impl Args {
    pub fn from(this: Option<ObjRef>, args: Vec<Val>, extra_args: Vec<Val>) -> Self {
        Self {
            this,
            it: args.into_iter(),
            extra_args: extra_args.into_iter(),
        }
    }

    pub fn take_this(&mut self) -> ObjRef {
        return self.this.take().unwrap();
    }

    pub fn take(&mut self) -> Val {
        self.it.next().unwrap()
    }

    pub fn extra_args(&mut self) -> vec::IntoIter<Val> {
        std::mem::replace(&mut self.extra_args, vec!().into_iter())
    }

    // Collect all extra args into a vec of the given type
    pub fn collect_extra_args<T>(&mut self) -> Vec<T> where T: From<Val> {
        Vec::from_iter(self.extra_args().map(|x| -> T { x.into() } ))
    }

    pub fn join_extra(&mut self, j: &[u8]) -> Val {
        // We have to collect all the extra_args in to a vec so they can stay owning the bytes that
        // they reference
        let cargs: Vec<BytesObj> = self.collect_extra_args();

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

        // Which we can then convert in to a :1
        Val::Str(BytesObj::new(ret))
    }

    /// Dumps all remaining, untaken args
    pub fn void(&mut self) {
        loop {
            if self.it.next().is_none() {
                break;
            }
        }
        loop {
            if self.extra_args.next().is_none() {
                break;
            }
        }
    }
}

impl Drop for Args {
    fn drop(&mut self) {
        assert!(self.this.is_none());
        assert!(self.it.next().is_none());
        assert!(self.extra_args.next().is_none());
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

    pub fn take_name(&mut self) -> Option<String> {
        return self.name.take();
    }

    pub fn take_expr(&mut self) -> Expr {
        return std::mem::take(&mut self.expr);
    }
}

#[derive(Debug)]
pub struct ArgSpec {
    name: Option<String>,
    val: Val,
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

    pub fn is_named(&self) -> bool {
        self.name.is_some()
    }

    pub fn take_name(&mut self) -> Option<String> {
        self.name.take()
    }

    pub fn take_val(&mut self) -> Val {
        std::mem::take(&mut self.val)
    }

    pub fn destructure(self) -> (Option<String>, Val) {
        (self.name, self.val)
    }

    pub fn named_destructure(self) -> (String, Val) {
        (self.name.unwrap(), self.val)
    }
}
