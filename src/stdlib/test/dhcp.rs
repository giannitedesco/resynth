use super::{Call, constant, s};

/// END and PADDING are a lone code byte, but used to get a zero length byte too
#[test]
fn option_end_and_padding_have_no_length() {
    assert_eq!(
        Call::func("dhcp::option")
            .arg(constant("dhcp::opt::END"))
            .bytes(),
        [0xff]
    );
    assert_eq!(
        Call::func("dhcp::option")
            .arg(constant("dhcp::opt::PADDING"))
            .bytes(),
        [0x00]
    );
}

/// With data, END gets a length like any other option, for malformed tests
#[test]
fn option_end_with_data() {
    assert_eq!(
        Call::func("dhcp::option")
            .arg(constant("dhcp::opt::END"))
            .extra(s([1u8]))
            .bytes(),
        [0xff, 1, 1]
    );
}

/// Other options with no data still get a zero length byte
#[test]
fn option_empty() {
    assert_eq!(
        Call::func("dhcp::option")
            .arg(constant("dhcp::opt::CLIENT_ID"))
            .bytes(),
        [61, 0]
    );
}
