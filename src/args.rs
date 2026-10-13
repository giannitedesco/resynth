use crate::object::ObjRef;
use crate::str::Buf;
use crate::val::Val;

use std::ops::Drop;
use std::vec;

#[derive(Debug)]
pub struct Args {
    this: Option<ObjRef>,
    it: vec::IntoIter<Val>,
    extra_args: Vec<Val>,
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

    pub fn extra_len(&self) -> usize {
        self.extra_args.len()
    }

    /// Extra args can be of any type which is coercible into the specified type so it may be
    /// dangerous to use this function because you're going to have to remember to coerce
    /// everything into the right type yourself.
    pub fn raw_extra_args(&mut self) -> Vec<Val> {
        std::mem::take(&mut self.extra_args)
    }

    /// Collect all extra args into a vec of the given type
    pub fn collect_extra_args<T>(&mut self) -> Vec<T>
    where
        T: From<Val>,
    {
        let source_vec = std::mem::take(&mut self.extra_args);

        source_vec.into_iter().map(|x| -> T { x.into() }).collect()
    }

    /// Assume extra args are strings and join them up
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
        // Itertools crate has a better "join" implementation for this use-case. And intersperse
        // in nightly also solves this reasonably well.
        let strs: Vec<&[u8]> = cargs.iter().map(|x| x.as_ref()).collect();

        // Finally we can do the join in to a byte vector
        let ret = strs.join(j);

        // Which we can then convert into a buf
        Val::str(ret)
    }

    /// Dumps all remaining, untaken args
    pub fn void(&mut self) {
        loop {
            if self.it.next().is_none() {
                break;
            }
        }
        self.extra_args = vec![];
    }
}

impl Drop for Args {
    fn drop(&mut self) {
        assert!(self.this.is_none(), "Method didn't take ownership of this");
        assert!(self.it.next().is_none(), "Function didn't consume all args");
        assert!(
            self.extra_args.is_empty(),
            "Function didn't consume extra args"
        );
    }
}
