use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

/// Runs resynth with `args`, piping `program` to its stdin
fn resynth_with_stdin(args: &[&str], program: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_resynth"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn resynth");

    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(program.as_bytes())
        .expect("write program");

    child.wait_with_output().expect("wait for resynth")
}

/// A path for `name` in a directory of its own, so tests running in parallel don't collide
fn out_path(test: &str, name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(test);
    fs::create_dir_all(&dir).expect("create test dir");
    let path = dir.join(name);
    let _ = fs::remove_file(&path);
    path
}

/// `resynth -o out.pcap < prog.rsyn`
#[test]
fn stdin_is_written_to_output() {
    let out = out_path("stdin_is_written_to_output", "out.pcap");

    let result = resynth_with_stdin(&["-o", out.to_str().unwrap()], "import ipv4;\n");

    assert!(result.status.success(), "{result:?}");
    assert!(out.exists());
}

#[test]
fn stdin_error_deletes_output() {
    let out = out_path("stdin_error_deletes_output", "out.pcap");

    let result = resynth_with_stdin(&["-o", out.to_str().unwrap()], "nope();\n");

    assert!(!result.status.success(), "{result:?}");
    assert!(
        String::from_utf8_lossy(&result.stdout).starts_with("<stdin>:1:1: "),
        "{result:?}",
    );
    assert!(!out.exists());
}

#[test]
fn stdin_error_keeps_output_with_keep() {
    let out = out_path("stdin_error_keeps_output_with_keep", "out.pcap");

    let result = resynth_with_stdin(&["-k", "-o", out.to_str().unwrap()], "nope();\n");

    assert!(!result.status.success(), "{result:?}");
    assert!(out.exists());
}
