use std::any::Any;
use std::cell::{Ref, RefCell, RefMut};
use std::fmt::Debug;
use std::ops::Deref;
use std::rc::Rc;

use crate::libapi::Class;

pub trait Obj: Class + Debug {
    fn as_any(&self) -> &dyn Any;
    fn as_mut_any(&mut self) -> &mut dyn Any;
    fn equals_obj(&self, _: &dyn Obj) -> bool;
}

impl<T: 'static + PartialEq + Eq + Class + Debug> Obj for T {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_mut_any(&mut self) -> &mut dyn Any {
        self
    }

    fn equals_obj(&self, other: &dyn Obj) -> bool {
        other.as_any().downcast_ref::<T>() == Some(self)
    }
}

#[derive(Debug, Clone)]
pub struct ObjRef {
    inner: Rc<RefCell<dyn Obj>>,
}

impl From<Rc<RefCell<dyn Obj>>> for ObjRef {
    fn from(obj: Rc<RefCell<dyn Obj>>) -> Self {
        Self { inner: obj }
    }
}

impl<T: 'static + Obj> From<T> for ObjRef {
    fn from(obj: T) -> Self {
        Self {
            inner: Rc::new(RefCell::new(obj)),
        }
    }
}

impl Eq for ObjRef {}
impl PartialEq for ObjRef {
    fn eq(&self, other: &ObjRef) -> bool {
        self.inner.borrow().equals_obj(other.inner.borrow().deref())
    }
}

impl ObjRef {
    pub fn borrow(&self) -> Ref<'_, dyn Obj> {
        self.inner.borrow()
    }

    pub fn borrow_mut(&self) -> RefMut<'_, dyn Obj> {
        self.inner.borrow_mut()
    }
}
