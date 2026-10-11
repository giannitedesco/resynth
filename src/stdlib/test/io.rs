use crate::program::RuntimeErrorKind::TooManyArgs;

use super::eval;

/// io::file takes one filename, and passing more used to abort the process
#[test]
fn file_rejects_extra_args() {
    let err = eval("import io;\nio::file(\"a\", \"b\");").unwrap_err();
    assert!(matches!(err.kind, TooManyArgs { .. }), "{err}");
}
