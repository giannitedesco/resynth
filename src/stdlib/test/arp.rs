use super::bytes;

/// The ARP hardware type is 16 bits, but used to encode as 8 bytes
#[test]
fn hrd_ether_is_be16() {
    assert_eq!(
        bytes("import arp;\nimport text;\ntext::concat(arp::hrd::ETHER);"),
        [0, 1]
    );
}
