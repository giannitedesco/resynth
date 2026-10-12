use super::{Call, constant, s};

/// tls::sni is a whole extension, type and length included
#[test]
fn sni_is_a_whole_extension() {
    assert_eq!(
        Call::func("tls::sni").extra(s("a.io")).bytes(),
        [
            0x00, 0x00, // extension type: server_name
            0x00, 0x09, // extension length
            0x00, 0x07, // server name list length
            0x00, // name type: host_name
            0x00, 0x04, b'a', b'.', b'i', b'o',
        ]
    );
}

/// tls::ciphers is a length-prefixed list for client_hello
#[test]
fn ciphers_list() {
    assert_eq!(
        Call::func("tls::ciphers")
            .extra(constant("tls::cipher::AES_128_GCM_SHA256"))
            .extra(constant("tls::cipher::AES_256_GCM_SHA384"))
            .bytes(),
        [0x00, 0x04, 0x13, 0x01, 0x13, 0x02]
    );
}
