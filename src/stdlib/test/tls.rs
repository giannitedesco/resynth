use crate::stdlib::tls::TLS;

use super::frames;

/// The code in each ```resynth block of a doc comment, joined into one program
fn doc_program(doc: &str) -> String {
    let mut prog = String::new();
    let mut in_block = false;

    for line in doc.lines().map(str::trim_start) {
        match line {
            "```resynth" => in_block = true,
            "```" => in_block = false,
            code if in_block => {
                prog.push_str(code);
                prog.push('\n');
            }
            _ => {}
        }
    }

    prog
}

/// The module's handshake example runs. It used to load a file that didn't exist.
#[test]
fn module_doc_example() {
    let frames = frames(&doc_program(TLS.doc));

    // The server flight holds the Server Key Exchange record: handshake, TLS 1.2, 556 bytes,
    // then a server_key_exchange message of 552 bytes
    let ske: &[u8] = &[0x16, 0x03, 0x03, 0x02, 0x2c, 0x0c, 0x00, 0x02, 0x28];
    let flight = frames[0].ip_payload();
    assert!(flight.windows(ske.len()).any(|w| w == ske));
}
