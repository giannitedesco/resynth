use std::net::Ipv4Addr;

use crate::eth::eth_addr;

/// The documented example. The address used to be 00:02:..., which isn't locally administered.
#[test]
fn test_addr_from_ip() {
    let addr = eth_addr::from(Ipv4Addr::new(192, 0, 2, 1));
    assert_eq!((&addr).as_ref(), [0x02, 0x00, 0xc0, 0x00, 0x02, 0x01]);
}
