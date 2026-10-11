use crate::val::Val;

use super::eval;

/// Every suffix in the doc table exists, with the value the table gives. The table used to list
/// a DOMAIN_NAME constant that didn't exist.
#[test]
fn suffix_doc_table() {
    for (name, want) in [
        ("WORKSTATION", 0x00),
        ("MESSENGER", 0x03),
        ("RAS_SERVER", 0x06),
        ("DOMAIN_MASTER", 0x1b),
        ("DOMAIN_CONTROLLER", 0x1c),
        ("MASTER_BROWSER", 0x1d),
        ("FILE_SERVER", 0x20),
        ("RAS_CLIENT", 0x21),
        ("BROWSER_ELECTIONS", 0x1e),
    ] {
        let val = eval(&format!("import netbios;\nnetbios::name::suffix::{name};")).unwrap();
        assert!(
            matches!(val, Val::U8(got) if got == want),
            "{name}: {val:?}"
        );
    }
}
