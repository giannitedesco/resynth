use super::{Call, constant};

/// The ARP hardware type is 16 bits, but used to encode as 8 bytes
#[test]
fn hrd_ether_is_be16() {
    assert_eq!(
        Call::func("text::concat")
            .extra(constant("arp::hrd::ETHER"))
            .bytes(),
        [0, 1]
    );
}
