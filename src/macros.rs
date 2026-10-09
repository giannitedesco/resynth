extern crate concat_with;

#[macro_export]
macro_rules! func {
    (@as_expr $e:expr) => {$e};
    (@replace $_t:tt $sub:expr) => {$sub};
    (@len $($tt:tt)*) => {{<[()]>::len(&[$(func!(@replace $tt ())),*])}};

    (
        @pdecl $type:ident
    ) => {
        ArgDecl::Positional(ValType::$type)
    };

    (
        @odecl $type:ident $init:expr
    ) => {
        ArgDecl::Optional(func!(@as_expr ValDef::$type($init)))
    };

    (
        @pos $(#[doc = $arg_doc:literal])+ $name:ident $type:ident
    ) => {
        ArgDesc {
            name: stringify!($name),
            typ: func!(@pdecl $type),
            doc: concat_with::concat_line!($($arg_doc),+),
        }
    };

    (
        @opt $(#[doc = $dfl_doc:literal])+ $name:ident $type:ident $init:expr
    ) => {
        ArgDesc {
            name: stringify!($name),
            typ: func!(@odecl $type $init),
            doc: concat_with::concat_line!($($dfl_doc),+),
        }
    };

    (
        $(#[doc = $doc:literal])+
        resynth fn $name:ident
        (
            $($(#[doc = $arg_doc:literal])+ $arg_name:ident : $arg_type:ident),* $(,)*
            =>
            $($(#[doc = $dfl_doc:literal])+ $dfl_name:ident : $dfl_type:ident = $dfl_init:expr),* $(,)*
            =>
            $collect_type:ident
        ) -> Class($cls:expr)
        $exec:expr
    ) => {
        {
            #[allow(unused)]
            use $crate::libapi::{FuncDef, ArgDesc, ArgDecl};
            #[allow(unused)]
            use $crate::val::ValType;

            #[allow(non_camel_case_types,unused)]
            enum ArgName {
               $($arg_name,)*
               $($dfl_name,)*
            }

            fn arg_pos(name: &str) -> Option<usize> {
                match name {
                    $(stringify!($arg_name) => Some(ArgName::$arg_name as usize),)*
                    $(stringify!($dfl_name) => Some(ArgName::$dfl_name as usize),)*
                    _ => None,
                }
            }

            FuncDef {
                name: stringify!($name),
                return_type: ValType::Class($cls),
                args: &[
                    $(func!(@pos $(#[doc = $arg_doc])+ $arg_name $arg_type),)*
                    $(func!(@opt $(#[doc = $dfl_doc])+ $dfl_name $dfl_type $dfl_init),)*
                ],
                arg_pos,
                min_args: func!(@len $($arg_name)*),
                collect_type: ValType::$collect_type,
                exec: $exec,
                doc: concat_with::concat_line!($($doc),+),
            }
        }
    };

    (
        $(#[doc = $doc:literal])+
        resynth fn $name:ident
        (
            $($(#[doc = $arg_doc:literal])+ $arg_name:ident : $arg_type:ident),* $(,)*
            =>
            $($(#[doc = $dfl_doc:literal])+ $dfl_name:ident : $dfl_type:ident = $dfl_init:expr),* $(,)*
            =>
            $collect_type:ident
        ) -> $return_type:ident
        $exec:expr
    ) => {
        {
            #[allow(unused)]
            use $crate::libapi::{FuncDef, ArgDesc, ArgDecl};
            #[allow(unused)]
            use $crate::val::ValType;

            #[allow(non_camel_case_types,unused)]
            enum ArgName {
               $($arg_name,)*
               $($dfl_name,)*
            }

            fn arg_pos(name: &str) -> Option<usize> {
                match name {
                    $(stringify!($arg_name) => Some(ArgName::$arg_name as usize),)*
                    $(stringify!($dfl_name) => Some(ArgName::$dfl_name as usize),)*
                    _ => None,
                }
            }

            FuncDef {
                name: stringify!($name),
                return_type: ValType::$return_type,
                args: &[
                    $(func!(@pos $(#[doc = $arg_doc])+ $arg_name $arg_type),)*
                    $(func!(@opt $(#[doc = $dfl_doc])+ $dfl_name $dfl_type $dfl_init),)*
                ],
                arg_pos,
                min_args: func!(@len $($arg_name)*),
                collect_type: ValType::$collect_type,
                exec: $exec,
                doc: concat_with::concat_line!($($doc),+),
            }
        }
    };
}

#[macro_export]
macro_rules! module {
    (
        @sym $name:ident $sym:expr
    ) => {
        SymDesc {
            name: stringify!($name),
            sym: $sym,
        }
    };

    (
        $(#[doc = $doc:literal])+
        resynth mod $modname:ident {$(
            $name:ident => $sym:expr,
        )*}
    ) => {
        {
            #[allow(unused)]
            use $crate::libapi::{Module, SymDesc};

            #[allow(non_camel_case_types,unused)]
            enum SymName {
               $($name,)*
            }

            fn lookup(name: &str) -> Option<usize> {
                match name {
                    $(stringify!($name) => Some(SymName::$name as usize),)*
                    _ => None,
                }
            }

            Module {
                name: stringify!($modname),
                symtab: &[
                    $(module!(@sym $name $sym),)*
                ],
                lookup,
                doc: concat_with::concat_line!($($doc),+),
            }
        }
    };
}

#[macro_export]
macro_rules! class {
    (
        @sym $name:ident $sym:expr
    ) => {
        SymDesc {
            name: stringify!($name),
            sym: $sym,
        }
    };

    (
        $(#[doc = $doc:literal])+
        resynth class $modname:ident {$(
            $name:ident => $sym:expr,
        )*}
    ) => {
        {
            #[allow(unused)]
            use $crate::libapi::{ClassDef, SymDesc};

            #[allow(non_camel_case_types,unused)]
            enum MethodName {
               $($name,)*
            }

            fn lookup(name: &str) -> Option<usize> {
                match name {
                    $(stringify!($name) => Some(MethodName::$name as usize),)*
                    _ => None,
                }
            }

            ClassDef {
                name: stringify!($modname),
                symtab: &[
                    $(class!(@sym $name $sym),)*
                ],
                lookup,
                doc: concat_with::concat_line!($($doc),+),
            }
        }
    };
}

#[macro_export]
macro_rules! ok {
    ($st:expr, $($args:tt)*) => {{
        $st.set_color(ColorSpec::new()
            .set_fg(Some(Color::Green))
            .set_bold(true)
            .set_intense(true)
        ).unwrap();
        let ret = print!($($args)*);
        $st.set_color(&ColorSpec::default()).unwrap();
        ret
    }
}}

#[macro_export]
macro_rules! warn {
    ($st:expr, $($args:tt)*) => {{
        $st.set_color(ColorSpec::new()
            .set_fg(Some(Color::Yellow))
            .set_bold(true)
            .set_intense(true)
        ).unwrap();
        let ret = print!($($args)*);
        $st.set_color(&ColorSpec::default()).unwrap();
        ret
    }
}}

#[macro_export]
macro_rules! error {
    ($st:expr, $($args:tt)*) => {{
        $st.set_color(ColorSpec::new()
            .set_fg(Some(Color::Red))
            .set_bold(true)
            .set_intense(true)
        ).unwrap();
        let ret = print!($($args)*);
        $st.set_color(&ColorSpec::default()).unwrap();
        ret
    }
}}

#[macro_export]
macro_rules! notice {
    ($st:expr, $($args:tt)*) => {{
        $st.set_color(ColorSpec::new()
            .set_bold(true)
            .set_intense(true)
        ).unwrap();
        let ret = print!($($args)*);
        $st.set_color(&ColorSpec::default()).unwrap();
        ret
    }}
}
