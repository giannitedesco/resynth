use bytemuck::{bytes_of, pod_read_unaligned};

use crate::erspan2::{Erspan2, erspan2_hdr};

/// The header bytes an Erspan2 builder produces
fn build(erspan: Erspan2) -> Vec<u8> {
    bytes_of(&erspan.build()).to_vec()
}

/// The default bytes with `bits` ORed in
fn dfl_with(bits: [u8; 8]) -> Vec<u8> {
    build(Erspan2::default())
        .iter()
        .zip(bits)
        .map(|(b, bits)| b | bits)
        .collect()
}

#[test]
fn test_new() {
    let hdr = erspan2_hdr::new(0x0102_0304, 0x0506_0708);
    assert_eq!(bytes_of(&hdr), [1, 2, 3, 4, 5, 6, 7, 8]);
}

#[test]
fn test_set_flags() {
    let mut hdr = erspan2_hdr::default();
    hdr.flags(0x0102_0304);
    assert_eq!(bytes_of(&hdr), [1, 2, 3, 4, 0, 0, 0, 0]);
}

/// Setting the index used to overwrite the flags word instead
#[test]
fn test_set_index() {
    let mut hdr = erspan2_hdr::default();
    hdr.index(0x0506_0708);
    assert_eq!(bytes_of(&hdr), [0, 0, 0, 0, 5, 6, 7, 8]);
}

#[test]
fn test_getters() {
    let hdr: erspan2_hdr = pod_read_unaligned(&[1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(hdr.get_flags(), 0x0102_0304);
    assert_eq!(hdr.get_index(), 0x0506_0708);
}

/// Version 1 is Type II. The trunk encapsulation defaults to 11, VLAN tag preserved.
#[test]
fn test_builder_default() {
    assert_eq!(build(Erspan2::default()), [0x10, 0, 0x18, 0, 0, 0, 0, 0]);
}

/// Version is the top 4 bits, session ID the low 10 bits of the first word, and the index the
/// low 20 bits of the second, draft-foschiano-erspan section 4.1
#[test]
fn test_builder_fields() {
    assert_eq!(
        build(Erspan2::default().ver(0xa)),
        [0xa0, 0, 0x18, 0, 0, 0, 0, 0]
    );
    assert_eq!(
        build(Erspan2::default().session_id(0x2a5)),
        dfl_with([0, 0, 0x02, 0xa5, 0, 0, 0, 0])
    );
    assert_eq!(
        build(Erspan2::default().port_index(0xa_bcde)),
        dfl_with([0, 0, 0, 0, 0, 0x0a, 0xbc, 0xde])
    );
}

/// Values too wide for a field don't spill into the next one
#[test]
fn test_builder_field_widths() {
    assert_eq!(
        build(Erspan2::default().ver(0xff)),
        dfl_with([0xf0, 0, 0, 0, 0, 0, 0, 0])
    );
    assert_eq!(
        build(Erspan2::default().session_id(0xffff)),
        dfl_with([0, 0, 0x03, 0xff, 0, 0, 0, 0])
    );
    assert_eq!(
        build(Erspan2::default().port_index(0xffff_ffff)),
        dfl_with([0, 0, 0, 0, 0, 0x0f, 0xff, 0xff])
    );
}
