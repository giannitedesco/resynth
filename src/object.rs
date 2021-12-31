use crate::libapi::ClassDef;
use crate::val::Val;

use std::rc::Rc;
use std::cell::UnsafeCell;
use std::fmt;

#[cfg(debug_assertions)]
use std::alloc::Layout;

struct Opaque {
}

#[derive(Clone)]
pub(crate) struct ObjRef {
    pub cls: &'static ClassDef,
    rc: Rc<UnsafeCell<Opaque>>,

    /* This is very wasteful because it should really be part of the actual allocation but it's
     * just a sanity check
     */
    #[cfg(debug_assertions)]
    layout: Layout,
}

impl ObjRef {
    pub fn new<T>(cls: &'static ClassDef, inner: T) -> ObjRef {
        let x = Rc::new(UnsafeCell::new(inner));
        ObjRef {
            cls,
            rc: unsafe { Rc::from_raw(Rc::into_raw(x) as *const UnsafeCell<Opaque>) },
            #[cfg(debug_assertions)]
            layout: unsafe {
                Layout::from_size_align_unchecked(
                    ::std::mem::size_of::<T>(),
                    ::std::mem::align_of::<T>(),
                )
            },
        }
    }

    #[allow(unused)]
    pub unsafe fn get_obj<T>(obj: &Self) -> &T {
        #[cfg(debug_assertions)]
        debug_assert_eq!(
                Layout::from_size_align_unchecked(
                    ::std::mem::size_of::<T>(),
                    ::std::mem::align_of::<T>(),
                ),
                obj.layout
        );

        unsafe {
            let ptr = obj.rc.get();
            &*(ptr as *const T)
        }
    }

    #[allow(unused)]
    pub unsafe fn get_mut_obj<T>(obj: &mut Self) -> &mut T {
        #[cfg(debug_assertions)]
        debug_assert_eq!(
                Layout::from_size_align_unchecked(
                    ::std::mem::size_of::<T>(),
                    ::std::mem::align_of::<T>(),
                ),
                obj.layout
        );

        unsafe {
            let ptr: *mut Opaque = obj.rc.get();
            &mut *(ptr as *mut T)
        }
    }
}

impl From<Val> for ObjRef {
    fn from(val: Val) -> Self {
        match val {
            Val::Obj(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl fmt::Debug for ObjRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!("Class<{}>", self.cls.name))
    }
}
