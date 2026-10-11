use super::bytes;

/// END and PADDING are a lone code byte, but used to get a zero length byte too
#[test]
fn option_end_and_padding_have_no_length() {
    assert_eq!(bytes("import dhcp;\ndhcp::option(dhcp::opt::END);"), [0xff]);
    assert_eq!(
        bytes("import dhcp;\ndhcp::option(dhcp::opt::PADDING);"),
        [0x00]
    );
}

/// With data, END gets a length like any other option, for malformed tests
#[test]
fn option_end_with_data() {
    assert_eq!(
        bytes("import dhcp;\ndhcp::option(dhcp::opt::END, \"|01|\");"),
        [0xff, 1, 1]
    );
}

/// Other options with no data still get a zero length byte
#[test]
fn option_empty() {
    assert_eq!(
        bytes("import dhcp;\ndhcp::option(dhcp::opt::CLIENT_ID);"),
        [61, 0]
    );
}
