macro_rules! replace_expr {
    ($_t:tt $sub:expr) => {$sub};
}

#[macro_export]
macro_rules! func_def {
    (
        $name:expr
        ;
        $return_type:expr
        ;
        $($arg_name:expr => $arg_val:expr),+ $(,)*
        =>
        $($dfl_name:expr => $dfl_val:expr),* $(,)*
        =>
        $collect_type:expr
        ;
        $exec:expr
    ) => {
        FuncDef {
            name: $name,
            return_type: $return_type,
            args: phf_ordered_map!(
                $($arg_name => ArgDecl::Positional($arg_val)),*
                ,
                $($dfl_name => ArgDecl::Named($dfl_val)),*
            ),
            min_args: {<[()]>::len(&[$(replace_expr!($arg_name ())),*])},
            collect_type: $collect_type,
            exec: $exec,
        }
    };
    (
        $name:expr
        ;
        $return_type:expr
        ;
        =>
        $($dfl_name:expr => $dfl_val:expr),* $(,)*
        =>
        $collect_type:expr
        ;
        $exec:expr
    ) => {
        FuncDef {
            name: $name,
            return_type: $return_type,
            args: phf_ordered_map!(
                $($dfl_name => ArgDecl::Named($dfl_val)),*
            ),
            min_args: 0,
            collect_type: $collect_type,
            exec: $exec,
        }
    };
}

#[macro_export]
macro_rules! ok {
    ($st:expr, $fmt:expr $(, $($arg:expr),*)*) => {{
        $st.set_color(ColorSpec::new()
            .set_fg(Some(Color::Green))
            .set_bold(true)
            .set_intense(true)
        ).unwrap();
        let ret = print!($fmt, $($arg),*);
        $st.set_color(&ColorSpec::default()).unwrap();
        ret
    }
}}

#[macro_export]
macro_rules! warn {
    ($st:expr, $fmt:expr $(, $($arg:expr),*)*) => {{
        $st.set_color(ColorSpec::new()
            .set_fg(Some(Color::Yellow))
            .set_bold(true)
            .set_intense(true)
        ).unwrap();
        let ret = print!($fmt, $($arg),*);
        $st.set_color(&ColorSpec::default()).unwrap();
        ret
    }
}}

#[macro_export]
macro_rules! error {
    ($st:expr, $fmt:expr $(, $($arg:expr),*)*) => {{
        $st.set_color(ColorSpec::new()
            .set_fg(Some(Color::Red))
            .set_bold(true)
            .set_intense(true)
        ).unwrap();
        let ret = print!($fmt, $($arg),*);
        $st.set_color(&ColorSpec::default()).unwrap();
        ret
    }
}}

#[macro_export]
macro_rules! notice {
    ($st:expr, $fmt:expr $(, $($arg:expr),*)*) => {{
        $st.set_color(ColorSpec::new()
            .set_bold(true)
            .set_intense(true)
        ).unwrap();
        let ret = print!($fmt, $($arg),*);
        $st.set_color(&ColorSpec::default()).unwrap();
        ret
    }}
}
