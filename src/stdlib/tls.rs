use pkt::tls::{ciphers, content, ext, handshake, version};

use crate::libapi::{FuncDef, Module};
use crate::str::Buf;
use crate::sym::Symbol;
use crate::val::{Val, ValDef};

const VERSION: Module = module!(
    /// # TLS Versions
    resynth mod version {
        SSL_1 => Symbol::u16(version::SSL_1),
        SSL_2 => Symbol::u16(version::SSL_2),
        SSL_3 => Symbol::u16(version::SSL_3),
        TLS_1_0 => Symbol::u16(version::TLS_1_0),
        TLS_1_1 => Symbol::u16(version::TLS_1_1),
        TLS_1_2 => Symbol::u16(version::TLS_1_2),
        TLS_1_3 => Symbol::u16(version::TLS_1_3),
    }
);

const CONTENT: Module = module! {
    /// # TLS Record Content Types
    resynth mod content {
        INVALID => Symbol::u8(content::INVALID),
        CHANGE_CIPHER_SPEC => Symbol::u8(content::CHANGE_CIPHER_SPEC),
        ALERT => Symbol::u8(content::ALERT),
        HANDSHAKE => Symbol::u8(content::HANDSHAKE),
        APP_DATA => Symbol::u8(content::APP_DATA),
        HEARTBEAT => Symbol::u8(content::HEARTBEAT),
        TLS12_CID => Symbol::u8(content::TLS12_CID),
        ACK => Symbol::u8(content::ACK),
    }
};

const HANDSHAKE: Module = module! {
    /// # TLS Handshake types
    resynth mod handshake {
        HELLO_REQUEST => Symbol::u8(handshake::HELLO_REQUEST),
        CLIENT_HELLO => Symbol::u8(handshake::CLIENT_HELLO),
        SERVER_HELLO => Symbol::u8(handshake::SERVER_HELLO),
        HELLO_VERIFY_REQUEST => Symbol::u8(handshake::HELLO_VERIFY_REQUEST),
        NEW_SESSION_TICKET => Symbol::u8(handshake::NEW_SESSION_TICKET),
        END_OF_EARLY_DATA => Symbol::u8(handshake::END_OF_EARLY_DATA),
        HELLO_RETRY_REQUEST => Symbol::u8(handshake::HELLO_RETRY_REQUEST),
        ENCRYPTED_EXTENSIONS => Symbol::u8(handshake::ENCRYPTED_EXTENSIONS),
        REQUESTCONNECTIONID => Symbol::u8(handshake::REQUESTCONNECTIONID),
        NEWCONNECTIONID => Symbol::u8(handshake::NEWCONNECTIONID),
        CERTIFICATE => Symbol::u8(handshake::CERTIFICATE),
        SERVER_KEY_EXCHANGE => Symbol::u8(handshake::SERVER_KEY_EXCHANGE),
        CERTIFICATE_REQUEST => Symbol::u8(handshake::CERTIFICATE_REQUEST),
        SERVER_HELLO_DONE => Symbol::u8(handshake::SERVER_HELLO_DONE),
        CERTIFICATE_VERIFY => Symbol::u8(handshake::CERTIFICATE_VERIFY),
        CLIENT_KEY_EXCHANGE => Symbol::u8(handshake::CLIENT_KEY_EXCHANGE),
        FINISHED => Symbol::u8(handshake::FINISHED),
        CERTIFICATE_URL => Symbol::u8(handshake::CERTIFICATE_URL),
        CERTIFICATE_STATUS => Symbol::u8(handshake::CERTIFICATE_STATUS),
        SUPPLEMENTAL_DATA => Symbol::u8(handshake::SUPPLEMENTAL_DATA),
        KEY_UPDATE => Symbol::u8(handshake::KEY_UPDATE),
        COMPRESSED_CERTIFICATE => Symbol::u8(handshake::COMPRESSED_CERTIFICATE),
        EKT_KEY => Symbol::u8(handshake::EKT_KEY),
        MESSAGE_HASH => Symbol::u8(handshake::MESSAGE_HASH),
    }
};

const EXT: Module = module! {
    /// # TLS Extensions
    resynth mod ext {
        SERVER_NAME => Symbol::u16(ext::SERVER_NAME),
        MAX_FRAGMENT_LENGTH => Symbol::u16(ext::MAX_FRAGMENT_LENGTH),
        CLIENT_CERTIFICATE_URL => Symbol::u16(ext::CLIENT_CERTIFICATE_URL),
        TRUSTED_CA_KEYS => Symbol::u16(ext::TRUSTED_CA_KEYS),
        TRUNCATED_HMAC => Symbol::u16(ext::TRUNCATED_HMAC),
        STATUS_REQUEST => Symbol::u16(ext::STATUS_REQUEST),
        USER_MAPPING => Symbol::u16(ext::USER_MAPPING),
        CLIENT_AUTHZ => Symbol::u16(ext::CLIENT_AUTHZ),
        SERVER_AUTHZ => Symbol::u16(ext::SERVER_AUTHZ),
        CERT_TYPE => Symbol::u16(ext::CERT_TYPE),
        SUPPORTED_GROUPS => Symbol::u16(ext::SUPPORTED_GROUPS),
        EC_POINT_FORMATS => Symbol::u16(ext::EC_POINT_FORMATS),
        SRP => Symbol::u16(ext::SRP),
        SIGNATURE_ALGORITHMS => Symbol::u16(ext::SIGNATURE_ALGORITHMS),
        USE_SRTP => Symbol::u16(ext::USE_SRTP),
        HEARTBEAT => Symbol::u16(ext::HEARTBEAT),
        APPLICATION_LAYER_PROTOCOL_NEGOTIATION
            => Symbol::u16(ext::APPLICATION_LAYER_PROTOCOL_NEGOTIATION),
        ALPN
            => Symbol::u16(ext::APPLICATION_LAYER_PROTOCOL_NEGOTIATION),
        STATUS_REQUEST_V2 => Symbol::u16(ext::STATUS_REQUEST_V2),
        SIGNED_CERTIFICATE_TIMESTAMP => Symbol::u16(ext::SIGNED_CERTIFICATE_TIMESTAMP),
        CLIENT_CERTIFICATE_TYPE => Symbol::u16(ext::CLIENT_CERTIFICATE_TYPE),
        SERVER_CERTIFICATE_TYPE => Symbol::u16(ext::SERVER_CERTIFICATE_TYPE),
        PADDING => Symbol::u16(ext::PADDING),
        ENCRYPT_THEN_MAC => Symbol::u16(ext::ENCRYPT_THEN_MAC),
        EXTENDED_MASTER_SECRET => Symbol::u16(ext::EXTENDED_MASTER_SECRET),
        TOKEN_BINDING => Symbol::u16(ext::TOKEN_BINDING),
        CACHED_INFO => Symbol::u16(ext::CACHED_INFO),
        TLS_LTS => Symbol::u16(ext::TLS_LTS),
        COMPRESS_CERTIFICATE => Symbol::u16(ext::COMPRESS_CERTIFICATE),
        RECORD_SIZE_LIMIT => Symbol::u16(ext::RECORD_SIZE_LIMIT),
        PWD_PROTECT => Symbol::u16(ext::PWD_PROTECT),
        PWD_CLEAR => Symbol::u16(ext::PWD_CLEAR),
        PASSWORD_SALT => Symbol::u16(ext::PASSWORD_SALT),
        TICKET_PINNING => Symbol::u16(ext::TICKET_PINNING),
        TLS_CERT_WITH_EXTERN_PSK => Symbol::u16(ext::TLS_CERT_WITH_EXTERN_PSK),
        DELEGATED_CREDENTIALS => Symbol::u16(ext::DELEGATED_CREDENTIALS),
        SESSION_TICKET => Symbol::u16(ext::SESSION_TICKET),
        TLMSP => Symbol::u16(ext::TLMSP),
        TLMSP_PROXYING => Symbol::u16(ext::TLMSP_PROXYING),
        TLMSP_DELEGATE => Symbol::u16(ext::TLMSP_DELEGATE),
        SUPPORTED_EKT_CIPHERS => Symbol::u16(ext::SUPPORTED_EKT_CIPHERS),
        PRE_SHARED_KEY => Symbol::u16(ext::PRE_SHARED_KEY),
        EARLY_DATA => Symbol::u16(ext::EARLY_DATA),
        SUPPORTED_VERSIONS => Symbol::u16(ext::SUPPORTED_VERSIONS),
        COOKIE => Symbol::u16(ext::COOKIE),
        PSK_KEY_EXCHANGE_MODES => Symbol::u16(ext::PSK_KEY_EXCHANGE_MODES),
        CERTIFICATE_AUTHORITIES => Symbol::u16(ext::CERTIFICATE_AUTHORITIES),
        OID_FILTERS => Symbol::u16(ext::OID_FILTERS),
        POST_HANDSHAKE_AUTH => Symbol::u16(ext::POST_HANDSHAKE_AUTH),
        SIGNATURE_ALGORITHMS_CERT => Symbol::u16(ext::SIGNATURE_ALGORITHMS_CERT),
        KEY_SHARE => Symbol::u16(ext::KEY_SHARE),
        TRANSPARENCY_INFO => Symbol::u16(ext::TRANSPARENCY_INFO),
        CONNECTION_ID_DEPRECATED => Symbol::u16(ext::CONNECTION_ID_DEPRECATED),
        CONNECTION_ID => Symbol::u16(ext::CONNECTION_ID),
        EXTERNAL_ID_HASH => Symbol::u16(ext::EXTERNAL_ID_HASH),
        EXTERNAL_SESSION_ID => Symbol::u16(ext::EXTERNAL_SESSION_ID),
        QUIC_TRANSPORT_PARAMETERS => Symbol::u16(ext::QUIC_TRANSPORT_PARAMETERS),
        TICKET_REQUEST => Symbol::u16(ext::TICKET_REQUEST),
        DNSSEC_CHAIN => Symbol::u16(ext::DNSSEC_CHAIN),
        RENEGOTIATION_INFO => Symbol::u16(ext::RENEGOTIATION_INFO),
    }
};

const CIPHER: Module = module! {
    /// # TLS Cipher Suites
    resynth mod cipher {
        NULL_WITH_NULL_NULL =>
            Symbol::u16(ciphers::NULL_WITH_NULL_NULL),
        RSA_WITH_NULL_MD5 =>
            Symbol::u16(ciphers::RSA_WITH_NULL_MD5),
        RSA_WITH_NULL_SHA =>
            Symbol::u16(ciphers::RSA_WITH_NULL_SHA),
        RSA_EXPORT_WITH_RC4_40_MD5 =>
            Symbol::u16(ciphers::RSA_EXPORT_WITH_RC4_40_MD5),
        RSA_WITH_RC4_128_MD5 =>
            Symbol::u16(ciphers::RSA_WITH_RC4_128_MD5),
        RSA_WITH_RC4_128_SHA =>
            Symbol::u16(ciphers::RSA_WITH_RC4_128_SHA),
        RSA_EXPORT_WITH_RC2_CBC_40_MD5 =>
            Symbol::u16(ciphers::RSA_EXPORT_WITH_RC2_CBC_40_MD5),
        RSA_WITH_IDEA_CBC_SHA =>
            Symbol::u16(ciphers::RSA_WITH_IDEA_CBC_SHA),
        RSA_EXPORT_WITH_DES40_CBC_SHA =>
            Symbol::u16(ciphers::RSA_EXPORT_WITH_DES40_CBC_SHA),
        RSA_WITH_DES_CBC_SHA =>
            Symbol::u16(ciphers::RSA_WITH_DES_CBC_SHA),
        RSA_WITH_3DES_EDE_CBC_SHA =>
            Symbol::u16(ciphers::RSA_WITH_3DES_EDE_CBC_SHA),
        DH_DSS_EXPORT_WITH_DES40_CBC_SHA =>
            Symbol::u16(ciphers::DH_DSS_EXPORT_WITH_DES40_CBC_SHA),
        DH_DSS_WITH_DES_CBC_SHA =>
            Symbol::u16(ciphers::DH_DSS_WITH_DES_CBC_SHA),
        DH_DSS_WITH_3DES_EDE_CBC_SHA =>
            Symbol::u16(ciphers::DH_DSS_WITH_3DES_EDE_CBC_SHA),
        DH_RSA_EXPORT_WITH_DES40_CBC_SHA =>
            Symbol::u16(ciphers::DH_RSA_EXPORT_WITH_DES40_CBC_SHA),
        DH_RSA_WITH_DES_CBC_SHA =>
            Symbol::u16(ciphers::DH_RSA_WITH_DES_CBC_SHA),
        DH_RSA_WITH_3DES_EDE_CBC_SHA =>
            Symbol::u16(ciphers::DH_RSA_WITH_3DES_EDE_CBC_SHA),
        DHE_DSS_EXPORT_WITH_DES40_CBC_SHA =>
            Symbol::u16(ciphers::DHE_DSS_EXPORT_WITH_DES40_CBC_SHA),
        DHE_DSS_WITH_DES_CBC_SHA =>
            Symbol::u16(ciphers::DHE_DSS_WITH_DES_CBC_SHA),
        DHE_DSS_WITH_3DES_EDE_CBC_SHA =>
            Symbol::u16(ciphers::DHE_DSS_WITH_3DES_EDE_CBC_SHA),
        DHE_RSA_EXPORT_WITH_DES40_CBC_SHA =>
            Symbol::u16(ciphers::DHE_RSA_EXPORT_WITH_DES40_CBC_SHA),
        DHE_RSA_WITH_DES_CBC_SHA =>
            Symbol::u16(ciphers::DHE_RSA_WITH_DES_CBC_SHA),
        DHE_RSA_WITH_3DES_EDE_CBC_SHA =>
            Symbol::u16(ciphers::DHE_RSA_WITH_3DES_EDE_CBC_SHA),
        DH_ANON_EXPORT_WITH_RC4_40_MD5 =>
            Symbol::u16(ciphers::DH_ANON_EXPORT_WITH_RC4_40_MD5),
        DH_ANON_WITH_RC4_128_MD5 =>
            Symbol::u16(ciphers::DH_ANON_WITH_RC4_128_MD5),
        DH_ANON_EXPORT_WITH_DES40_CBC_SHA =>
            Symbol::u16(ciphers::DH_ANON_EXPORT_WITH_DES40_CBC_SHA),
        DH_ANON_WITH_DES_CBC_SHA =>
            Symbol::u16(ciphers::DH_ANON_WITH_DES_CBC_SHA),
        DH_ANON_WITH_3DES_EDE_CBC_SHA =>
            Symbol::u16(ciphers::DH_ANON_WITH_3DES_EDE_CBC_SHA),
        KRB5_WITH_DES_CBC_SHA =>
            Symbol::u16(ciphers::KRB5_WITH_DES_CBC_SHA),
        KRB5_WITH_3DES_EDE_CBC_SHA =>
            Symbol::u16(ciphers::KRB5_WITH_3DES_EDE_CBC_SHA),
        KRB5_WITH_RC4_128_SHA =>
            Symbol::u16(ciphers::KRB5_WITH_RC4_128_SHA),
        KRB5_WITH_IDEA_CBC_SHA =>
            Symbol::u16(ciphers::KRB5_WITH_IDEA_CBC_SHA),
        KRB5_WITH_DES_CBC_MD5 =>
            Symbol::u16(ciphers::KRB5_WITH_DES_CBC_MD5),
        KRB5_WITH_3DES_EDE_CBC_MD5 =>
            Symbol::u16(ciphers::KRB5_WITH_3DES_EDE_CBC_MD5),
        KRB5_WITH_RC4_128_MD5 =>
            Symbol::u16(ciphers::KRB5_WITH_RC4_128_MD5),
        KRB5_WITH_IDEA_CBC_MD5 =>
            Symbol::u16(ciphers::KRB5_WITH_IDEA_CBC_MD5),
        KRB5_EXPORT_WITH_DES_CBC_40_SHA =>
            Symbol::u16(ciphers::KRB5_EXPORT_WITH_DES_CBC_40_SHA),
        KRB5_EXPORT_WITH_RC2_CBC_40_SHA =>
            Symbol::u16(ciphers::KRB5_EXPORT_WITH_RC2_CBC_40_SHA),
        KRB5_EXPORT_WITH_RC4_40_SHA =>
            Symbol::u16(ciphers::KRB5_EXPORT_WITH_RC4_40_SHA),
        KRB5_EXPORT_WITH_DES_CBC_40_MD5 =>
            Symbol::u16(ciphers::KRB5_EXPORT_WITH_DES_CBC_40_MD5),
        KRB5_EXPORT_WITH_RC2_CBC_40_MD5 =>
            Symbol::u16(ciphers::KRB5_EXPORT_WITH_RC2_CBC_40_MD5),
        KRB5_EXPORT_WITH_RC4_40_MD5 =>
            Symbol::u16(ciphers::KRB5_EXPORT_WITH_RC4_40_MD5),
        PSK_WITH_NULL_SHA =>
            Symbol::u16(ciphers::PSK_WITH_NULL_SHA),
        DHE_PSK_WITH_NULL_SHA =>
            Symbol::u16(ciphers::DHE_PSK_WITH_NULL_SHA),
        RSA_PSK_WITH_NULL_SHA =>
            Symbol::u16(ciphers::RSA_PSK_WITH_NULL_SHA),
        RSA_WITH_AES_128_CBC_SHA =>
            Symbol::u16(ciphers::RSA_WITH_AES_128_CBC_SHA),
        DH_DSS_WITH_AES_128_CBC_SHA =>
            Symbol::u16(ciphers::DH_DSS_WITH_AES_128_CBC_SHA),
        DH_RSA_WITH_AES_128_CBC_SHA =>
            Symbol::u16(ciphers::DH_RSA_WITH_AES_128_CBC_SHA),
        DHE_DSS_WITH_AES_128_CBC_SHA =>
            Symbol::u16(ciphers::DHE_DSS_WITH_AES_128_CBC_SHA),
        DHE_RSA_WITH_AES_128_CBC_SHA =>
            Symbol::u16(ciphers::DHE_RSA_WITH_AES_128_CBC_SHA),
        DH_ANON_WITH_AES_128_CBC_SHA =>
            Symbol::u16(ciphers::DH_ANON_WITH_AES_128_CBC_SHA),
        RSA_WITH_AES_256_CBC_SHA =>
            Symbol::u16(ciphers::RSA_WITH_AES_256_CBC_SHA),
        DH_DSS_WITH_AES_256_CBC_SHA =>
            Symbol::u16(ciphers::DH_DSS_WITH_AES_256_CBC_SHA),
        DH_RSA_WITH_AES_256_CBC_SHA =>
            Symbol::u16(ciphers::DH_RSA_WITH_AES_256_CBC_SHA),
        DHE_DSS_WITH_AES_256_CBC_SHA =>
            Symbol::u16(ciphers::DHE_DSS_WITH_AES_256_CBC_SHA),
        DHE_RSA_WITH_AES_256_CBC_SHA =>
            Symbol::u16(ciphers::DHE_RSA_WITH_AES_256_CBC_SHA),
        DH_ANON_WITH_AES_256_CBC_SHA =>
            Symbol::u16(ciphers::DH_ANON_WITH_AES_256_CBC_SHA),
        RSA_WITH_NULL_SHA256 =>
            Symbol::u16(ciphers::RSA_WITH_NULL_SHA256),
        RSA_WITH_AES_128_CBC_SHA256 =>
            Symbol::u16(ciphers::RSA_WITH_AES_128_CBC_SHA256),
        RSA_WITH_AES_256_CBC_SHA256 =>
            Symbol::u16(ciphers::RSA_WITH_AES_256_CBC_SHA256),
        DH_DSS_WITH_AES_128_CBC_SHA256 =>
            Symbol::u16(ciphers::DH_DSS_WITH_AES_128_CBC_SHA256),
        DH_RSA_WITH_AES_128_CBC_SHA256 =>
            Symbol::u16(ciphers::DH_RSA_WITH_AES_128_CBC_SHA256),
        DHE_DSS_WITH_AES_128_CBC_SHA256 =>
            Symbol::u16(ciphers::DHE_DSS_WITH_AES_128_CBC_SHA256),
        RSA_WITH_CAMELLIA_128_CBC_SHA =>
            Symbol::u16(ciphers::RSA_WITH_CAMELLIA_128_CBC_SHA),
        DH_DSS_WITH_CAMELLIA_128_CBC_SHA =>
            Symbol::u16(ciphers::DH_DSS_WITH_CAMELLIA_128_CBC_SHA),
        DH_RSA_WITH_CAMELLIA_128_CBC_SHA =>
            Symbol::u16(ciphers::DH_RSA_WITH_CAMELLIA_128_CBC_SHA),
        DHE_DSS_WITH_CAMELLIA_128_CBC_SHA =>
            Symbol::u16(ciphers::DHE_DSS_WITH_CAMELLIA_128_CBC_SHA),
        DHE_RSA_WITH_CAMELLIA_128_CBC_SHA =>
            Symbol::u16(ciphers::DHE_RSA_WITH_CAMELLIA_128_CBC_SHA),
        DH_ANON_WITH_CAMELLIA_128_CBC_SHA =>
            Symbol::u16(ciphers::DH_ANON_WITH_CAMELLIA_128_CBC_SHA),
        DHE_RSA_WITH_AES_128_CBC_SHA256 =>
            Symbol::u16(ciphers::DHE_RSA_WITH_AES_128_CBC_SHA256),
        DH_DSS_WITH_AES_256_CBC_SHA256 =>
            Symbol::u16(ciphers::DH_DSS_WITH_AES_256_CBC_SHA256),
        DH_RSA_WITH_AES_256_CBC_SHA256 =>
            Symbol::u16(ciphers::DH_RSA_WITH_AES_256_CBC_SHA256),
        DHE_DSS_WITH_AES_256_CBC_SHA256 =>
            Symbol::u16(ciphers::DHE_DSS_WITH_AES_256_CBC_SHA256),
        DHE_RSA_WITH_AES_256_CBC_SHA256 =>
            Symbol::u16(ciphers::DHE_RSA_WITH_AES_256_CBC_SHA256),
        DH_ANON_WITH_AES_128_CBC_SHA256 =>
            Symbol::u16(ciphers::DH_ANON_WITH_AES_128_CBC_SHA256),
        DH_ANON_WITH_AES_256_CBC_SHA256 =>
            Symbol::u16(ciphers::DH_ANON_WITH_AES_256_CBC_SHA256),
        RSA_WITH_CAMELLIA_256_CBC_SHA =>
            Symbol::u16(ciphers::RSA_WITH_CAMELLIA_256_CBC_SHA),
        DH_DSS_WITH_CAMELLIA_256_CBC_SHA =>
            Symbol::u16(ciphers::DH_DSS_WITH_CAMELLIA_256_CBC_SHA),
        DH_RSA_WITH_CAMELLIA_256_CBC_SHA =>
            Symbol::u16(ciphers::DH_RSA_WITH_CAMELLIA_256_CBC_SHA),
        DHE_DSS_WITH_CAMELLIA_256_CBC_SHA =>
            Symbol::u16(ciphers::DHE_DSS_WITH_CAMELLIA_256_CBC_SHA),
        DHE_RSA_WITH_CAMELLIA_256_CBC_SHA =>
            Symbol::u16(ciphers::DHE_RSA_WITH_CAMELLIA_256_CBC_SHA),
        DH_ANON_WITH_CAMELLIA_256_CBC_SHA =>
            Symbol::u16(ciphers::DH_ANON_WITH_CAMELLIA_256_CBC_SHA),
        PSK_WITH_RC4_128_SHA =>
            Symbol::u16(ciphers::PSK_WITH_RC4_128_SHA),
        PSK_WITH_3DES_EDE_CBC_SHA =>
            Symbol::u16(ciphers::PSK_WITH_3DES_EDE_CBC_SHA),
        PSK_WITH_AES_128_CBC_SHA =>
            Symbol::u16(ciphers::PSK_WITH_AES_128_CBC_SHA),
        PSK_WITH_AES_256_CBC_SHA =>
            Symbol::u16(ciphers::PSK_WITH_AES_256_CBC_SHA),
        DHE_PSK_WITH_RC4_128_SHA =>
            Symbol::u16(ciphers::DHE_PSK_WITH_RC4_128_SHA),
        DHE_PSK_WITH_3DES_EDE_CBC_SHA =>
            Symbol::u16(ciphers::DHE_PSK_WITH_3DES_EDE_CBC_SHA),
        DHE_PSK_WITH_AES_128_CBC_SHA =>
            Symbol::u16(ciphers::DHE_PSK_WITH_AES_128_CBC_SHA),
        DHE_PSK_WITH_AES_256_CBC_SHA =>
            Symbol::u16(ciphers::DHE_PSK_WITH_AES_256_CBC_SHA),
        RSA_PSK_WITH_RC4_128_SHA =>
            Symbol::u16(ciphers::RSA_PSK_WITH_RC4_128_SHA),
        RSA_PSK_WITH_3DES_EDE_CBC_SHA =>
            Symbol::u16(ciphers::RSA_PSK_WITH_3DES_EDE_CBC_SHA),
        RSA_PSK_WITH_AES_128_CBC_SHA =>
            Symbol::u16(ciphers::RSA_PSK_WITH_AES_128_CBC_SHA),
        RSA_PSK_WITH_AES_256_CBC_SHA =>
            Symbol::u16(ciphers::RSA_PSK_WITH_AES_256_CBC_SHA),
        RSA_WITH_SEED_CBC_SHA =>
            Symbol::u16(ciphers::RSA_WITH_SEED_CBC_SHA),
        DH_DSS_WITH_SEED_CBC_SHA =>
            Symbol::u16(ciphers::DH_DSS_WITH_SEED_CBC_SHA),
        DH_RSA_WITH_SEED_CBC_SHA =>
            Symbol::u16(ciphers::DH_RSA_WITH_SEED_CBC_SHA),
        DHE_DSS_WITH_SEED_CBC_SHA =>
            Symbol::u16(ciphers::DHE_DSS_WITH_SEED_CBC_SHA),
        DHE_RSA_WITH_SEED_CBC_SHA =>
            Symbol::u16(ciphers::DHE_RSA_WITH_SEED_CBC_SHA),
        DH_ANON_WITH_SEED_CBC_SHA =>
            Symbol::u16(ciphers::DH_ANON_WITH_SEED_CBC_SHA),
        RSA_WITH_AES_128_GCM_SHA256 =>
            Symbol::u16(ciphers::RSA_WITH_AES_128_GCM_SHA256),
        RSA_WITH_AES_256_GCM_SHA384 =>
            Symbol::u16(ciphers::RSA_WITH_AES_256_GCM_SHA384),
        DHE_RSA_WITH_AES_128_GCM_SHA256 =>
            Symbol::u16(ciphers::DHE_RSA_WITH_AES_128_GCM_SHA256),
        DHE_RSA_WITH_AES_256_GCM_SHA384 =>
            Symbol::u16(ciphers::DHE_RSA_WITH_AES_256_GCM_SHA384),
        DH_RSA_WITH_AES_128_GCM_SHA256 =>
            Symbol::u16(ciphers::DH_RSA_WITH_AES_128_GCM_SHA256),
        DH_RSA_WITH_AES_256_GCM_SHA384 =>
            Symbol::u16(ciphers::DH_RSA_WITH_AES_256_GCM_SHA384),
        DHE_DSS_WITH_AES_128_GCM_SHA256 =>
            Symbol::u16(ciphers::DHE_DSS_WITH_AES_128_GCM_SHA256),
        DHE_DSS_WITH_AES_256_GCM_SHA384 =>
            Symbol::u16(ciphers::DHE_DSS_WITH_AES_256_GCM_SHA384),
        DH_DSS_WITH_AES_128_GCM_SHA256 =>
            Symbol::u16(ciphers::DH_DSS_WITH_AES_128_GCM_SHA256),
        DH_DSS_WITH_AES_256_GCM_SHA384 =>
            Symbol::u16(ciphers::DH_DSS_WITH_AES_256_GCM_SHA384),
        DH_ANON_WITH_AES_128_GCM_SHA256 =>
            Symbol::u16(ciphers::DH_ANON_WITH_AES_128_GCM_SHA256),
        DH_ANON_WITH_AES_256_GCM_SHA384 =>
            Symbol::u16(ciphers::DH_ANON_WITH_AES_256_GCM_SHA384),
        PSK_WITH_AES_128_GCM_SHA256 =>
            Symbol::u16(ciphers::PSK_WITH_AES_128_GCM_SHA256),
        PSK_WITH_AES_256_GCM_SHA384 =>
            Symbol::u16(ciphers::PSK_WITH_AES_256_GCM_SHA384),
        DHE_PSK_WITH_AES_128_GCM_SHA256 =>
            Symbol::u16(ciphers::DHE_PSK_WITH_AES_128_GCM_SHA256),
        DHE_PSK_WITH_AES_256_GCM_SHA384 =>
            Symbol::u16(ciphers::DHE_PSK_WITH_AES_256_GCM_SHA384),
        RSA_PSK_WITH_AES_128_GCM_SHA256 =>
            Symbol::u16(ciphers::RSA_PSK_WITH_AES_128_GCM_SHA256),
        RSA_PSK_WITH_AES_256_GCM_SHA384 =>
            Symbol::u16(ciphers::RSA_PSK_WITH_AES_256_GCM_SHA384),
        PSK_WITH_AES_128_CBC_SHA256 =>
            Symbol::u16(ciphers::PSK_WITH_AES_128_CBC_SHA256),
        PSK_WITH_AES_256_CBC_SHA384 =>
            Symbol::u16(ciphers::PSK_WITH_AES_256_CBC_SHA384),
        PSK_WITH_NULL_SHA256 =>
            Symbol::u16(ciphers::PSK_WITH_NULL_SHA256),
        PSK_WITH_NULL_SHA384 =>
            Symbol::u16(ciphers::PSK_WITH_NULL_SHA384),
        DHE_PSK_WITH_AES_128_CBC_SHA256 =>
            Symbol::u16(ciphers::DHE_PSK_WITH_AES_128_CBC_SHA256),
        DHE_PSK_WITH_AES_256_CBC_SHA384 =>
            Symbol::u16(ciphers::DHE_PSK_WITH_AES_256_CBC_SHA384),
        DHE_PSK_WITH_NULL_SHA256 =>
            Symbol::u16(ciphers::DHE_PSK_WITH_NULL_SHA256),
        DHE_PSK_WITH_NULL_SHA384 =>
            Symbol::u16(ciphers::DHE_PSK_WITH_NULL_SHA384),
        RSA_PSK_WITH_AES_128_CBC_SHA256 =>
            Symbol::u16(ciphers::RSA_PSK_WITH_AES_128_CBC_SHA256),
        RSA_PSK_WITH_AES_256_CBC_SHA384 =>
            Symbol::u16(ciphers::RSA_PSK_WITH_AES_256_CBC_SHA384),
        RSA_PSK_WITH_NULL_SHA256 =>
            Symbol::u16(ciphers::RSA_PSK_WITH_NULL_SHA256),
        RSA_PSK_WITH_NULL_SHA384 =>
            Symbol::u16(ciphers::RSA_PSK_WITH_NULL_SHA384),
        RSA_WITH_CAMELLIA_128_CBC_SHA256 =>
            Symbol::u16(ciphers::RSA_WITH_CAMELLIA_128_CBC_SHA256),
        DH_DSS_WITH_CAMELLIA_128_CBC_SHA256 =>
            Symbol::u16(ciphers::DH_DSS_WITH_CAMELLIA_128_CBC_SHA256),
        DH_RSA_WITH_CAMELLIA_128_CBC_SHA256 =>
            Symbol::u16(ciphers::DH_RSA_WITH_CAMELLIA_128_CBC_SHA256),
        DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256 =>
            Symbol::u16(ciphers::DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256),
        DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 =>
            Symbol::u16(ciphers::DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256),
        DH_ANON_WITH_CAMELLIA_128_CBC_SHA256 =>
            Symbol::u16(ciphers::DH_ANON_WITH_CAMELLIA_128_CBC_SHA256),
        RSA_WITH_CAMELLIA_256_CBC_SHA256 =>
            Symbol::u16(ciphers::RSA_WITH_CAMELLIA_256_CBC_SHA256),
        DH_DSS_WITH_CAMELLIA_256_CBC_SHA256 =>
            Symbol::u16(ciphers::DH_DSS_WITH_CAMELLIA_256_CBC_SHA256),
        DH_RSA_WITH_CAMELLIA_256_CBC_SHA256 =>
            Symbol::u16(ciphers::DH_RSA_WITH_CAMELLIA_256_CBC_SHA256),
        DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256 =>
            Symbol::u16(ciphers::DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256),
        DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256 =>
            Symbol::u16(ciphers::DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256),
        DH_ANON_WITH_CAMELLIA_256_CBC_SHA256 =>
            Symbol::u16(ciphers::DH_ANON_WITH_CAMELLIA_256_CBC_SHA256),
        SM4_GCM_SM3 =>
            Symbol::u16(ciphers::SM4_GCM_SM3),
        SM4_CCM_SM3 =>
            Symbol::u16(ciphers::SM4_CCM_SM3),
        EMPTY_RENEGOTIATION_INFO_SCSV =>
            Symbol::u16(ciphers::EMPTY_RENEGOTIATION_INFO_SCSV),
        AES_128_GCM_SHA256 =>
            Symbol::u16(ciphers::AES_128_GCM_SHA256),
        AES_256_GCM_SHA384 =>
            Symbol::u16(ciphers::AES_256_GCM_SHA384),
        CHACHA20_POLY1305_SHA256 =>
            Symbol::u16(ciphers::CHACHA20_POLY1305_SHA256),
        AES_128_CCM_SHA256 =>
            Symbol::u16(ciphers::AES_128_CCM_SHA256),
        AES_128_CCM_8_SHA256 =>
            Symbol::u16(ciphers::AES_128_CCM_8_SHA256),
        FALLBACK_SCSV =>
            Symbol::u16(ciphers::FALLBACK_SCSV),
        ECDH_ECDSA_WITH_NULL_SHA =>
            Symbol::u16(ciphers::ECDH_ECDSA_WITH_NULL_SHA),
        ECDH_ECDSA_WITH_RC4_128_SHA =>
            Symbol::u16(ciphers::ECDH_ECDSA_WITH_RC4_128_SHA),
        ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA =>
            Symbol::u16(ciphers::ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA),
        ECDH_ECDSA_WITH_AES_128_CBC_SHA =>
            Symbol::u16(ciphers::ECDH_ECDSA_WITH_AES_128_CBC_SHA),
        ECDH_ECDSA_WITH_AES_256_CBC_SHA =>
            Symbol::u16(ciphers::ECDH_ECDSA_WITH_AES_256_CBC_SHA),
        ECDHE_ECDSA_WITH_NULL_SHA =>
            Symbol::u16(ciphers::ECDHE_ECDSA_WITH_NULL_SHA),
        ECDHE_ECDSA_WITH_RC4_128_SHA =>
            Symbol::u16(ciphers::ECDHE_ECDSA_WITH_RC4_128_SHA),
        ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA =>
            Symbol::u16(ciphers::ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA),
        ECDHE_ECDSA_WITH_AES_128_CBC_SHA =>
            Symbol::u16(ciphers::ECDHE_ECDSA_WITH_AES_128_CBC_SHA),
        ECDHE_ECDSA_WITH_AES_256_CBC_SHA =>
            Symbol::u16(ciphers::ECDHE_ECDSA_WITH_AES_256_CBC_SHA),
        ECDH_RSA_WITH_NULL_SHA =>
            Symbol::u16(ciphers::ECDH_RSA_WITH_NULL_SHA),
        ECDH_RSA_WITH_RC4_128_SHA =>
            Symbol::u16(ciphers::ECDH_RSA_WITH_RC4_128_SHA),
        ECDH_RSA_WITH_3DES_EDE_CBC_SHA =>
            Symbol::u16(ciphers::ECDH_RSA_WITH_3DES_EDE_CBC_SHA),
        ECDH_RSA_WITH_AES_128_CBC_SHA =>
            Symbol::u16(ciphers::ECDH_RSA_WITH_AES_128_CBC_SHA),
        ECDH_RSA_WITH_AES_256_CBC_SHA =>
            Symbol::u16(ciphers::ECDH_RSA_WITH_AES_256_CBC_SHA),
        ECDHE_RSA_WITH_NULL_SHA =>
            Symbol::u16(ciphers::ECDHE_RSA_WITH_NULL_SHA),
        ECDHE_RSA_WITH_RC4_128_SHA =>
            Symbol::u16(ciphers::ECDHE_RSA_WITH_RC4_128_SHA),
        ECDHE_RSA_WITH_3DES_EDE_CBC_SHA =>
            Symbol::u16(ciphers::ECDHE_RSA_WITH_3DES_EDE_CBC_SHA),
        ECDHE_RSA_WITH_AES_128_CBC_SHA =>
            Symbol::u16(ciphers::ECDHE_RSA_WITH_AES_128_CBC_SHA),
        ECDHE_RSA_WITH_AES_256_CBC_SHA =>
            Symbol::u16(ciphers::ECDHE_RSA_WITH_AES_256_CBC_SHA),
        ECDH_ANON_WITH_NULL_SHA =>
            Symbol::u16(ciphers::ECDH_ANON_WITH_NULL_SHA),
        ECDH_ANON_WITH_RC4_128_SHA =>
            Symbol::u16(ciphers::ECDH_ANON_WITH_RC4_128_SHA),
        ECDH_ANON_WITH_3DES_EDE_CBC_SHA =>
            Symbol::u16(ciphers::ECDH_ANON_WITH_3DES_EDE_CBC_SHA),
        ECDH_ANON_WITH_AES_128_CBC_SHA =>
            Symbol::u16(ciphers::ECDH_ANON_WITH_AES_128_CBC_SHA),
        ECDH_ANON_WITH_AES_256_CBC_SHA =>
            Symbol::u16(ciphers::ECDH_ANON_WITH_AES_256_CBC_SHA),
        SRP_SHA_WITH_3DES_EDE_CBC_SHA =>
            Symbol::u16(ciphers::SRP_SHA_WITH_3DES_EDE_CBC_SHA),
        SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA =>
            Symbol::u16(ciphers::SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA),
        SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA =>
            Symbol::u16(ciphers::SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA),
        SRP_SHA_WITH_AES_128_CBC_SHA =>
            Symbol::u16(ciphers::SRP_SHA_WITH_AES_128_CBC_SHA),
        SRP_SHA_RSA_WITH_AES_128_CBC_SHA =>
            Symbol::u16(ciphers::SRP_SHA_RSA_WITH_AES_128_CBC_SHA),
        SRP_SHA_DSS_WITH_AES_128_CBC_SHA =>
            Symbol::u16(ciphers::SRP_SHA_DSS_WITH_AES_128_CBC_SHA),
        SRP_SHA_WITH_AES_256_CBC_SHA =>
            Symbol::u16(ciphers::SRP_SHA_WITH_AES_256_CBC_SHA),
        SRP_SHA_RSA_WITH_AES_256_CBC_SHA =>
            Symbol::u16(ciphers::SRP_SHA_RSA_WITH_AES_256_CBC_SHA),
        SRP_SHA_DSS_WITH_AES_256_CBC_SHA =>
            Symbol::u16(ciphers::SRP_SHA_DSS_WITH_AES_256_CBC_SHA),
        ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 =>
            Symbol::u16(ciphers::ECDHE_ECDSA_WITH_AES_128_CBC_SHA256),
        ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 =>
            Symbol::u16(ciphers::ECDHE_ECDSA_WITH_AES_256_CBC_SHA384),
        ECDH_ECDSA_WITH_AES_128_CBC_SHA256 =>
            Symbol::u16(ciphers::ECDH_ECDSA_WITH_AES_128_CBC_SHA256),
        ECDH_ECDSA_WITH_AES_256_CBC_SHA384 =>
            Symbol::u16(ciphers::ECDH_ECDSA_WITH_AES_256_CBC_SHA384),
        ECDHE_RSA_WITH_AES_128_CBC_SHA256 =>
            Symbol::u16(ciphers::ECDHE_RSA_WITH_AES_128_CBC_SHA256),
        ECDHE_RSA_WITH_AES_256_CBC_SHA384 =>
            Symbol::u16(ciphers::ECDHE_RSA_WITH_AES_256_CBC_SHA384),
        ECDH_RSA_WITH_AES_128_CBC_SHA256 =>
            Symbol::u16(ciphers::ECDH_RSA_WITH_AES_128_CBC_SHA256),
        ECDH_RSA_WITH_AES_256_CBC_SHA384 =>
            Symbol::u16(ciphers::ECDH_RSA_WITH_AES_256_CBC_SHA384),
        ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 =>
            Symbol::u16(ciphers::ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
        ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 =>
            Symbol::u16(ciphers::ECDHE_ECDSA_WITH_AES_256_GCM_SHA384),
        ECDH_ECDSA_WITH_AES_128_GCM_SHA256 =>
            Symbol::u16(ciphers::ECDH_ECDSA_WITH_AES_128_GCM_SHA256),
        ECDH_ECDSA_WITH_AES_256_GCM_SHA384 =>
            Symbol::u16(ciphers::ECDH_ECDSA_WITH_AES_256_GCM_SHA384),
        ECDHE_RSA_WITH_AES_128_GCM_SHA256 =>
            Symbol::u16(ciphers::ECDHE_RSA_WITH_AES_128_GCM_SHA256),
        ECDHE_RSA_WITH_AES_256_GCM_SHA384 =>
            Symbol::u16(ciphers::ECDHE_RSA_WITH_AES_256_GCM_SHA384),
        ECDH_RSA_WITH_AES_128_GCM_SHA256 =>
            Symbol::u16(ciphers::ECDH_RSA_WITH_AES_128_GCM_SHA256),
        ECDH_RSA_WITH_AES_256_GCM_SHA384 =>
            Symbol::u16(ciphers::ECDH_RSA_WITH_AES_256_GCM_SHA384),
        ECDHE_PSK_WITH_RC4_128_SHA =>
            Symbol::u16(ciphers::ECDHE_PSK_WITH_RC4_128_SHA),
        ECDHE_PSK_WITH_3DES_EDE_CBC_SHA =>
            Symbol::u16(ciphers::ECDHE_PSK_WITH_3DES_EDE_CBC_SHA),
        ECDHE_PSK_WITH_AES_128_CBC_SHA =>
            Symbol::u16(ciphers::ECDHE_PSK_WITH_AES_128_CBC_SHA),
        ECDHE_PSK_WITH_AES_256_CBC_SHA =>
            Symbol::u16(ciphers::ECDHE_PSK_WITH_AES_256_CBC_SHA),
        ECDHE_PSK_WITH_AES_128_CBC_SHA256 =>
            Symbol::u16(ciphers::ECDHE_PSK_WITH_AES_128_CBC_SHA256),
        ECDHE_PSK_WITH_AES_256_CBC_SHA384 =>
            Symbol::u16(ciphers::ECDHE_PSK_WITH_AES_256_CBC_SHA384),
        ECDHE_PSK_WITH_NULL_SHA =>
            Symbol::u16(ciphers::ECDHE_PSK_WITH_NULL_SHA),
        ECDHE_PSK_WITH_NULL_SHA256 =>
            Symbol::u16(ciphers::ECDHE_PSK_WITH_NULL_SHA256),
        ECDHE_PSK_WITH_NULL_SHA384 =>
            Symbol::u16(ciphers::ECDHE_PSK_WITH_NULL_SHA384),
        RSA_WITH_ARIA_128_CBC_SHA256 =>
            Symbol::u16(ciphers::RSA_WITH_ARIA_128_CBC_SHA256),
        RSA_WITH_ARIA_256_CBC_SHA384 =>
            Symbol::u16(ciphers::RSA_WITH_ARIA_256_CBC_SHA384),
        DH_DSS_WITH_ARIA_128_CBC_SHA256 =>
            Symbol::u16(ciphers::DH_DSS_WITH_ARIA_128_CBC_SHA256),
        DH_DSS_WITH_ARIA_256_CBC_SHA384 =>
            Symbol::u16(ciphers::DH_DSS_WITH_ARIA_256_CBC_SHA384),
        DH_RSA_WITH_ARIA_128_CBC_SHA256 =>
            Symbol::u16(ciphers::DH_RSA_WITH_ARIA_128_CBC_SHA256),
        DH_RSA_WITH_ARIA_256_CBC_SHA384 =>
            Symbol::u16(ciphers::DH_RSA_WITH_ARIA_256_CBC_SHA384),
        DHE_DSS_WITH_ARIA_128_CBC_SHA256 =>
            Symbol::u16(ciphers::DHE_DSS_WITH_ARIA_128_CBC_SHA256),
        DHE_DSS_WITH_ARIA_256_CBC_SHA384 =>
            Symbol::u16(ciphers::DHE_DSS_WITH_ARIA_256_CBC_SHA384),
        DHE_RSA_WITH_ARIA_128_CBC_SHA256 =>
            Symbol::u16(ciphers::DHE_RSA_WITH_ARIA_128_CBC_SHA256),
        DHE_RSA_WITH_ARIA_256_CBC_SHA384 =>
            Symbol::u16(ciphers::DHE_RSA_WITH_ARIA_256_CBC_SHA384),
        DH_ANON_WITH_ARIA_128_CBC_SHA256 =>
            Symbol::u16(ciphers::DH_ANON_WITH_ARIA_128_CBC_SHA256),
        DH_ANON_WITH_ARIA_256_CBC_SHA384 =>
            Symbol::u16(ciphers::DH_ANON_WITH_ARIA_256_CBC_SHA384),
        ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256 =>
            Symbol::u16(ciphers::ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256),
        ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384 =>
            Symbol::u16(ciphers::ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384),
        ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256 =>
            Symbol::u16(ciphers::ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256),
        ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384 =>
            Symbol::u16(ciphers::ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384),
        ECDHE_RSA_WITH_ARIA_128_CBC_SHA256 =>
            Symbol::u16(ciphers::ECDHE_RSA_WITH_ARIA_128_CBC_SHA256),
        ECDHE_RSA_WITH_ARIA_256_CBC_SHA384 =>
            Symbol::u16(ciphers::ECDHE_RSA_WITH_ARIA_256_CBC_SHA384),
        ECDH_RSA_WITH_ARIA_128_CBC_SHA256 =>
            Symbol::u16(ciphers::ECDH_RSA_WITH_ARIA_128_CBC_SHA256),
        ECDH_RSA_WITH_ARIA_256_CBC_SHA384 =>
            Symbol::u16(ciphers::ECDH_RSA_WITH_ARIA_256_CBC_SHA384),
        RSA_WITH_ARIA_128_GCM_SHA256 =>
            Symbol::u16(ciphers::RSA_WITH_ARIA_128_GCM_SHA256),
        RSA_WITH_ARIA_256_GCM_SHA384 =>
            Symbol::u16(ciphers::RSA_WITH_ARIA_256_GCM_SHA384),
        DHE_RSA_WITH_ARIA_128_GCM_SHA256 =>
            Symbol::u16(ciphers::DHE_RSA_WITH_ARIA_128_GCM_SHA256),
        DHE_RSA_WITH_ARIA_256_GCM_SHA384 =>
            Symbol::u16(ciphers::DHE_RSA_WITH_ARIA_256_GCM_SHA384),
        DH_RSA_WITH_ARIA_128_GCM_SHA256 =>
            Symbol::u16(ciphers::DH_RSA_WITH_ARIA_128_GCM_SHA256),
        DH_RSA_WITH_ARIA_256_GCM_SHA384 =>
            Symbol::u16(ciphers::DH_RSA_WITH_ARIA_256_GCM_SHA384),
        DHE_DSS_WITH_ARIA_128_GCM_SHA256 =>
            Symbol::u16(ciphers::DHE_DSS_WITH_ARIA_128_GCM_SHA256),
        DHE_DSS_WITH_ARIA_256_GCM_SHA384 =>
            Symbol::u16(ciphers::DHE_DSS_WITH_ARIA_256_GCM_SHA384),
        DH_DSS_WITH_ARIA_128_GCM_SHA256 =>
            Symbol::u16(ciphers::DH_DSS_WITH_ARIA_128_GCM_SHA256),
        DH_DSS_WITH_ARIA_256_GCM_SHA384 =>
            Symbol::u16(ciphers::DH_DSS_WITH_ARIA_256_GCM_SHA384),
        DH_ANON_WITH_ARIA_128_GCM_SHA256 =>
            Symbol::u16(ciphers::DH_ANON_WITH_ARIA_128_GCM_SHA256),
        DH_ANON_WITH_ARIA_256_GCM_SHA384 =>
            Symbol::u16(ciphers::DH_ANON_WITH_ARIA_256_GCM_SHA384),
        ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256 =>
            Symbol::u16(ciphers::ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256),
        ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384 =>
            Symbol::u16(ciphers::ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384),
        ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256 =>
            Symbol::u16(ciphers::ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256),
        ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384 =>
            Symbol::u16(ciphers::ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384),
        ECDHE_RSA_WITH_ARIA_128_GCM_SHA256 =>
            Symbol::u16(ciphers::ECDHE_RSA_WITH_ARIA_128_GCM_SHA256),
        ECDHE_RSA_WITH_ARIA_256_GCM_SHA384 =>
            Symbol::u16(ciphers::ECDHE_RSA_WITH_ARIA_256_GCM_SHA384),
        ECDH_RSA_WITH_ARIA_128_GCM_SHA256 =>
            Symbol::u16(ciphers::ECDH_RSA_WITH_ARIA_128_GCM_SHA256),
        ECDH_RSA_WITH_ARIA_256_GCM_SHA384 =>
            Symbol::u16(ciphers::ECDH_RSA_WITH_ARIA_256_GCM_SHA384),
        PSK_WITH_ARIA_128_CBC_SHA256 =>
            Symbol::u16(ciphers::PSK_WITH_ARIA_128_CBC_SHA256),
        PSK_WITH_ARIA_256_CBC_SHA384 =>
            Symbol::u16(ciphers::PSK_WITH_ARIA_256_CBC_SHA384),
        DHE_PSK_WITH_ARIA_128_CBC_SHA256 =>
            Symbol::u16(ciphers::DHE_PSK_WITH_ARIA_128_CBC_SHA256),
        DHE_PSK_WITH_ARIA_256_CBC_SHA384 =>
            Symbol::u16(ciphers::DHE_PSK_WITH_ARIA_256_CBC_SHA384),
        RSA_PSK_WITH_ARIA_128_CBC_SHA256 =>
            Symbol::u16(ciphers::RSA_PSK_WITH_ARIA_128_CBC_SHA256),
        RSA_PSK_WITH_ARIA_256_CBC_SHA384 =>
            Symbol::u16(ciphers::RSA_PSK_WITH_ARIA_256_CBC_SHA384),
        PSK_WITH_ARIA_128_GCM_SHA256 =>
            Symbol::u16(ciphers::PSK_WITH_ARIA_128_GCM_SHA256),
        PSK_WITH_ARIA_256_GCM_SHA384 =>
            Symbol::u16(ciphers::PSK_WITH_ARIA_256_GCM_SHA384),
        DHE_PSK_WITH_ARIA_128_GCM_SHA256 =>
            Symbol::u16(ciphers::DHE_PSK_WITH_ARIA_128_GCM_SHA256),
        DHE_PSK_WITH_ARIA_256_GCM_SHA384 =>
            Symbol::u16(ciphers::DHE_PSK_WITH_ARIA_256_GCM_SHA384),
        RSA_PSK_WITH_ARIA_128_GCM_SHA256 =>
            Symbol::u16(ciphers::RSA_PSK_WITH_ARIA_128_GCM_SHA256),
        RSA_PSK_WITH_ARIA_256_GCM_SHA384 =>
            Symbol::u16(ciphers::RSA_PSK_WITH_ARIA_256_GCM_SHA384),
        ECDHE_PSK_WITH_ARIA_128_CBC_SHA256 =>
            Symbol::u16(ciphers::ECDHE_PSK_WITH_ARIA_128_CBC_SHA256),
        ECDHE_PSK_WITH_ARIA_256_CBC_SHA384 =>
            Symbol::u16(ciphers::ECDHE_PSK_WITH_ARIA_256_CBC_SHA384),
        ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 =>
            Symbol::u16(ciphers::ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256),
        ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 =>
            Symbol::u16(ciphers::ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384),
        ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 =>
            Symbol::u16(ciphers::ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256),
        ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 =>
            Symbol::u16(ciphers::ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384),
        ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 =>
            Symbol::u16(ciphers::ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256),
        ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384 =>
            Symbol::u16(ciphers::ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384),
        ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256 =>
            Symbol::u16(ciphers::ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256),
        ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384 =>
            Symbol::u16(ciphers::ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384),
        RSA_WITH_CAMELLIA_128_GCM_SHA256 =>
            Symbol::u16(ciphers::RSA_WITH_CAMELLIA_128_GCM_SHA256),
        RSA_WITH_CAMELLIA_256_GCM_SHA384 =>
            Symbol::u16(ciphers::RSA_WITH_CAMELLIA_256_GCM_SHA384),
        DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 =>
            Symbol::u16(ciphers::DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256),
        DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 =>
            Symbol::u16(ciphers::DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384),
        DH_RSA_WITH_CAMELLIA_128_GCM_SHA256 =>
            Symbol::u16(ciphers::DH_RSA_WITH_CAMELLIA_128_GCM_SHA256),
        DH_RSA_WITH_CAMELLIA_256_GCM_SHA384 =>
            Symbol::u16(ciphers::DH_RSA_WITH_CAMELLIA_256_GCM_SHA384),
        DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256 =>
            Symbol::u16(ciphers::DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256),
        DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384 =>
            Symbol::u16(ciphers::DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384),
        DH_DSS_WITH_CAMELLIA_128_GCM_SHA256 =>
            Symbol::u16(ciphers::DH_DSS_WITH_CAMELLIA_128_GCM_SHA256),
        DH_DSS_WITH_CAMELLIA_256_GCM_SHA384 =>
            Symbol::u16(ciphers::DH_DSS_WITH_CAMELLIA_256_GCM_SHA384),
        DH_ANON_WITH_CAMELLIA_128_GCM_SHA256 =>
            Symbol::u16(ciphers::DH_ANON_WITH_CAMELLIA_128_GCM_SHA256),
        DH_ANON_WITH_CAMELLIA_256_GCM_SHA384 =>
            Symbol::u16(ciphers::DH_ANON_WITH_CAMELLIA_256_GCM_SHA384),
        ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 =>
            Symbol::u16(ciphers::ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256),
        ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 =>
            Symbol::u16(ciphers::ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384),
        ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 =>
            Symbol::u16(ciphers::ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256),
        ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 =>
            Symbol::u16(ciphers::ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384),
        ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 =>
            Symbol::u16(ciphers::ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256),
        ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 =>
            Symbol::u16(ciphers::ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384),
        ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256 =>
            Symbol::u16(ciphers::ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256),
        ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384 =>
            Symbol::u16(ciphers::ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384),
        PSK_WITH_CAMELLIA_128_GCM_SHA256 =>
            Symbol::u16(ciphers::PSK_WITH_CAMELLIA_128_GCM_SHA256),
        PSK_WITH_CAMELLIA_256_GCM_SHA384 =>
            Symbol::u16(ciphers::PSK_WITH_CAMELLIA_256_GCM_SHA384),
        DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256 =>
            Symbol::u16(ciphers::DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256),
        DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384 =>
            Symbol::u16(ciphers::DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384),
        RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256 =>
            Symbol::u16(ciphers::RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256),
        RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384 =>
            Symbol::u16(ciphers::RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384),
        PSK_WITH_CAMELLIA_128_CBC_SHA256 =>
            Symbol::u16(ciphers::PSK_WITH_CAMELLIA_128_CBC_SHA256),
        PSK_WITH_CAMELLIA_256_CBC_SHA384 =>
            Symbol::u16(ciphers::PSK_WITH_CAMELLIA_256_CBC_SHA384),
        DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 =>
            Symbol::u16(ciphers::DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256),
        DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 =>
            Symbol::u16(ciphers::DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384),
        RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256 =>
            Symbol::u16(ciphers::RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256),
        RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384 =>
            Symbol::u16(ciphers::RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384),
        ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 =>
            Symbol::u16(ciphers::ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256),
        ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 =>
            Symbol::u16(ciphers::ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384),
        RSA_WITH_AES_128_CCM =>
            Symbol::u16(ciphers::RSA_WITH_AES_128_CCM),
        RSA_WITH_AES_256_CCM =>
            Symbol::u16(ciphers::RSA_WITH_AES_256_CCM),
        DHE_RSA_WITH_AES_128_CCM =>
            Symbol::u16(ciphers::DHE_RSA_WITH_AES_128_CCM),
        DHE_RSA_WITH_AES_256_CCM =>
            Symbol::u16(ciphers::DHE_RSA_WITH_AES_256_CCM),
        RSA_WITH_AES_128_CCM_8 =>
            Symbol::u16(ciphers::RSA_WITH_AES_128_CCM_8),
        RSA_WITH_AES_256_CCM_8 =>
            Symbol::u16(ciphers::RSA_WITH_AES_256_CCM_8),
        DHE_RSA_WITH_AES_128_CCM_8 =>
            Symbol::u16(ciphers::DHE_RSA_WITH_AES_128_CCM_8),
        DHE_RSA_WITH_AES_256_CCM_8 =>
            Symbol::u16(ciphers::DHE_RSA_WITH_AES_256_CCM_8),
        PSK_WITH_AES_128_CCM =>
            Symbol::u16(ciphers::PSK_WITH_AES_128_CCM),
        PSK_WITH_AES_256_CCM =>
            Symbol::u16(ciphers::PSK_WITH_AES_256_CCM),
        DHE_PSK_WITH_AES_128_CCM =>
            Symbol::u16(ciphers::DHE_PSK_WITH_AES_128_CCM),
        DHE_PSK_WITH_AES_256_CCM =>
            Symbol::u16(ciphers::DHE_PSK_WITH_AES_256_CCM),
        PSK_WITH_AES_128_CCM_8 =>
            Symbol::u16(ciphers::PSK_WITH_AES_128_CCM_8),
        PSK_WITH_AES_256_CCM_8 =>
            Symbol::u16(ciphers::PSK_WITH_AES_256_CCM_8),
        PSK_DHE_WITH_AES_128_CCM_8 =>
            Symbol::u16(ciphers::PSK_DHE_WITH_AES_128_CCM_8),
        PSK_DHE_WITH_AES_256_CCM_8 =>
            Symbol::u16(ciphers::PSK_DHE_WITH_AES_256_CCM_8),
        ECDHE_ECDSA_WITH_AES_128_CCM =>
            Symbol::u16(ciphers::ECDHE_ECDSA_WITH_AES_128_CCM),
        ECDHE_ECDSA_WITH_AES_256_CCM =>
            Symbol::u16(ciphers::ECDHE_ECDSA_WITH_AES_256_CCM),
        ECDHE_ECDSA_WITH_AES_128_CCM_8 =>
            Symbol::u16(ciphers::ECDHE_ECDSA_WITH_AES_128_CCM_8),
        ECDHE_ECDSA_WITH_AES_256_CCM_8 =>
            Symbol::u16(ciphers::ECDHE_ECDSA_WITH_AES_256_CCM_8),
        ECCPWD_WITH_AES_128_GCM_SHA256 =>
            Symbol::u16(ciphers::ECCPWD_WITH_AES_128_GCM_SHA256),
        ECCPWD_WITH_AES_256_GCM_SHA384 =>
            Symbol::u16(ciphers::ECCPWD_WITH_AES_256_GCM_SHA384),
        ECCPWD_WITH_AES_128_CCM_SHA256 =>
            Symbol::u16(ciphers::ECCPWD_WITH_AES_128_CCM_SHA256),
        ECCPWD_WITH_AES_256_CCM_SHA384 =>
            Symbol::u16(ciphers::ECCPWD_WITH_AES_256_CCM_SHA384),
        SHA256_SHA256 =>
            Symbol::u16(ciphers::SHA256_SHA256),
        SHA384_SHA384 =>
            Symbol::u16(ciphers::SHA384_SHA384),
        GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC =>
            Symbol::u16(ciphers::GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC),
        GOSTR341112_256_WITH_MAGMA_CTR_OMAC =>
            Symbol::u16(ciphers::GOSTR341112_256_WITH_MAGMA_CTR_OMAC),
        GOSTR341112_256_WITH_28147_CNT_IMIT =>
            Symbol::u16(ciphers::GOSTR341112_256_WITH_28147_CNT_IMIT),
        GOSTR341112_256_WITH_KUZNYECHIK_MGM_L =>
            Symbol::u16(ciphers::GOSTR341112_256_WITH_KUZNYECHIK_MGM_L),
        GOSTR341112_256_WITH_MAGMA_MGM_L =>
            Symbol::u16(ciphers::GOSTR341112_256_WITH_MAGMA_MGM_L),
        GOSTR341112_256_WITH_KUZNYECHIK_MGM_S =>
            Symbol::u16(ciphers::GOSTR341112_256_WITH_KUZNYECHIK_MGM_S),
        GOSTR341112_256_WITH_MAGMA_MGM_S =>
            Symbol::u16(ciphers::GOSTR341112_256_WITH_MAGMA_MGM_S),
        ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 =>
            Symbol::u16(ciphers::ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256),
        ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 =>
            Symbol::u16(ciphers::ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256),
        DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 =>
            Symbol::u16(ciphers::DHE_RSA_WITH_CHACHA20_POLY1305_SHA256),
        PSK_WITH_CHACHA20_POLY1305_SHA256 =>
            Symbol::u16(ciphers::PSK_WITH_CHACHA20_POLY1305_SHA256),
        ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256 =>
            Symbol::u16(ciphers::ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256),
        DHE_PSK_WITH_CHACHA20_POLY1305_SHA256 =>
            Symbol::u16(ciphers::DHE_PSK_WITH_CHACHA20_POLY1305_SHA256),
        RSA_PSK_WITH_CHACHA20_POLY1305_SHA256 =>
            Symbol::u16(ciphers::RSA_PSK_WITH_CHACHA20_POLY1305_SHA256),
        ECDHE_PSK_WITH_AES_128_GCM_SHA256 =>
            Symbol::u16(ciphers::ECDHE_PSK_WITH_AES_128_GCM_SHA256),
        ECDHE_PSK_WITH_AES_256_GCM_SHA384 =>
            Symbol::u16(ciphers::ECDHE_PSK_WITH_AES_256_GCM_SHA384),
        ECDHE_PSK_WITH_AES_128_CCM_8_SHA256 =>
            Symbol::u16(ciphers::ECDHE_PSK_WITH_AES_128_CCM_8_SHA256),
        ECDHE_PSK_WITH_AES_128_CCM_SHA256 =>
            Symbol::u16(ciphers::ECDHE_PSK_WITH_AES_128_CCM_SHA256),
    }
};

const TLS_MESSAGE: FuncDef = func! (
    /// Construct a TLS record
    ///
    /// Wraps payload bytes in the TLS record framing:
    ///
    /// ```c
    /// struct tls_hdr {
    ///     uint8_t content;
    ///     uint16_t version;
    ///     uint16_t len;
    ///     uint8_t payload[0];
    /// } _packed;
    /// ```
    resynth fn message(
        =>
        /// [TLS version](version/README.md) for the record header (e.g. [tls::version::TLS_1_2](version/README.md))
        version: U16 = version::TLS_1_2,
        /// [TLS content type](content/README.md) (e.g. [tls::content::HANDSHAKE](content/README.md))
        content: U8 = content::HANDSHAKE,
        =>
        Str
    ) -> Str
    |mut args| {
        let version: u16 = args.next().into();
        let content: u8 = args.next().into();
        let bytes: Buf = args.join_extra(b"").into();
        let mut msg: Vec<u8> = Vec::with_capacity(bytes.len() + 5);

        msg.extend(content.to_be_bytes());
        msg.extend(version.to_be_bytes());
        msg.extend((bytes.len() as u16).to_be_bytes());

        /* extensions I guess? */
        msg.extend(bytes.as_ref());

        Ok(Val::str(msg))
    }
);

const TLS_EXTENSION: FuncDef = func! (
    /// Construct a TLS extension
    ///
    /// Wraps payload bytes in the TLS extension framing:
    ///
    /// ```c
    /// struct tls_ext {
    ///     uint16_t ext;
    ///     uint16_t len;
    ///     uint8_t payload[0];
    /// } _packed;
    /// ```
    resynth fn extension(
        /// [TLS extension type](ext/README.md) (e.g. [tls::ext::SERVER_NAME](ext/README.md))
        ext: U16,
        =>
        =>
        Str
    ) -> Str
    |mut args| {
        let ext: u16 = args.next().into();
        let bytes: Buf = args.join_extra(b"").into();
        let mut msg: Vec<u8> = Vec::with_capacity(bytes.len() + 5);

        msg.extend(ext.to_be_bytes());
        msg.extend((bytes.len() as u16).to_be_bytes());

        msg.extend(bytes.as_ref());

        Ok(Val::str(msg))
    }
);

fn len24(len: usize) -> [u8; 3] {
    let b = (len as u32).to_be_bytes();
    [b[1], b[2], b[3]]
}

const TLS_CIPHERS: FuncDef = func! (
    /// Build a TLS cipher suites list
    ///
    /// Encodes the supplied [cipher suite](cipher/README.md) constants as a
    /// 16-bit length-prefixed list, ready to embed in a [client_hello](#client_hello)
    /// or [server_hello](#server_hello).
    resynth fn ciphers(
        =>
        =>
        U16
    ) -> Str
    |mut args| {
        let extra: Vec<u16> = args.collect_extra_args();
        let list_len = extra.len() * 2;

        let mut msg: Vec<u8> = Vec::with_capacity(2 + list_len);

        msg.extend((list_len as u16).to_be_bytes());
        for id in extra {
            msg.extend(id.to_be_bytes());
        }

        Ok(Val::str(msg))
    }
);

const TLS_CLIENT_HELLO: FuncDef = func! (
    /// Construct a TLS ClientHello handshake message
    ///
    /// Must be framed inside a [tls::content::HANDSHAKE](content/README.md)
    /// [message](#message). The random field is fixed to a placeholder value.
    resynth fn client_hello(
        =>
        /// Requested [TLS version](version/README.md)
        version: U16 = version::TLS_1_2,
        /// Session ID bytes (u8 length-prefixed; `"|00|"` means no session resumption)
        sessionid: Str = b"\x00",
        /// Supported cipher suites list — use [tls::ciphers()](#ciphers) to construct
        ciphers: Str = b"\x00\x02\x00\x00", // null cipher
        /// Supported compression methods list (essentially defunct; null compression = `"|01 00|"`)
        compression: Str = b"\x01\x00", // null compression
        =>
        Str
    ) -> Str
    |mut args| {
        let version: u16 = args.next().into();
        let sessionid: Buf = args.next().into();
        let ciphers: Buf = args.next().into();
        let compression: Buf = args.next().into();
        let extensions: Buf = args.join_extra(b"").into();

        let hlen = 34
            + sessionid.len()
            + ciphers.len()
            + compression.len()
            + if extensions.len() > 0 { 2 } else { 0 }
            + extensions.len();

        let mut msg: Vec<u8> = Vec::with_capacity(4 + hlen);

        /* 4 bytes handshake header */
        msg.push(handshake::CLIENT_HELLO);
        msg.extend(len24(hlen));

        /* 34 bytes version + random */
        msg.extend(version.to_be_bytes());
        msg.extend(b"_client__random__client__random_");

        msg.extend(sessionid.as_ref());
        msg.extend(ciphers.as_ref());
        msg.extend(compression.as_ref());

        if extensions.len() > 0 {
            msg.extend((extensions.len() as u16).to_be_bytes());
            msg.extend(extensions.as_ref());
        }

        Ok(Val::str(msg))
    }
);

const TLS_SERVER_HELLO: FuncDef = func! (
    /// Construct a TLS ServerHello handshake message
    ///
    /// Must be framed inside a [tls::content::HANDSHAKE](content/README.md)
    /// [message](#message). The random field is fixed to a placeholder value.
    resynth fn server_hello(
        =>
        /// Negotiated [TLS version](version/README.md)
        version: U16 = version::TLS_1_2,
        /// Session ID bytes (u8 length-prefixed; `"|00|"` means no session resumption)
        sessionid: Str = b"\x00",
        /// Negotiated [cipher suite](cipher/README.md)
        cipher: U16 = ciphers::NULL_WITH_NULL_NULL,
        /// Negotiated compression method (essentially defunct; 0 = null compression)
        compression: U8 = 0,
        =>
        Str
    ) -> Str
    |mut args| {
        let version: u16 = args.next().into();
        let sessionid: Buf = args.next().into();
        let cipher: u16 = args.next().into();
        let compression: u8 = args.next().into();
        let extensions: Buf = args.join_extra(b"").into();

        let hlen = 34
            + sessionid.len()
            + 2
            + 1
            + if extensions.len() > 0 { 2 } else { 0 }
            + extensions.len();

        let mut msg: Vec<u8> = Vec::with_capacity(4 + hlen);

        /* 4 bytes handshake header */
        msg.push(handshake::SERVER_HELLO);
        msg.extend(len24(hlen));

        /* 34 bytes version + random */
        msg.extend(version.to_be_bytes());
        msg.extend(b"_server__random__server__random_");

        msg.extend(sessionid.as_ref());

        msg.extend(cipher.to_be_bytes());
        msg.push(compression);

        if extensions.len() > 0 {
            msg.extend((extensions.len() as u16).to_be_bytes());
            msg.extend(extensions.as_ref());
        }

        Ok(Val::str(msg))
    }
);

const TLS_SNI: FuncDef = func! (
    /// Construct a TLS Server Name Indication (SNI) extension
    ///
    /// Encodes one or more server names as a [tls::ext::SERVER_NAME](ext/README.md)
    /// extension, ready to pass to [extension](#extension) or embed directly in
    /// [client_hello](#client_hello).
    resynth fn sni(
        =>
        =>
        Str
    ) -> Str
    |mut args| {
        let names: Vec<Buf> = args.collect_extra_args();
        let names_len: usize = names.iter().map(|x| -> Buf { x.into() }).map(|x| x.len()).sum();
        let name_list_len = 3 * names.len() + names_len;
        let tot_len = 2 + name_list_len;

        let mut msg: Vec<u8> = Vec::with_capacity(tot_len + 4);

        msg.extend(ext::SERVER_NAME.to_be_bytes());
        msg.extend((tot_len as u16).to_be_bytes());

        msg.extend((name_list_len as u16).to_be_bytes());
        for name in names {
            msg.push(0);
            msg.extend((name.len() as u16).to_be_bytes());
            msg.extend(name.as_ref());
        }

        Ok(Val::str(msg))
    }
);

const TLS_CERTIFICATES: FuncDef = func! (
    /// Returns a chain of X.509 certificates
    resynth fn certificates(
        =>
        =>
        Str
    ) -> Str
    |mut args| {
        let certs: Vec<Buf> = args.collect_extra_args();
        let certs_len: usize = certs.iter().map(|x| -> Buf { x.into() }).map(|x| x.len()).sum();
        let cert_list_len = 3 * certs.len() + certs_len;
        let tot_len = 3 + cert_list_len;

        let mut msg: Vec<u8> = Vec::with_capacity(tot_len + 4);

        msg.push(handshake::CERTIFICATE);
        msg.extend(len24(tot_len));

        msg.extend(len24(cert_list_len));
        for cert in certs {
            msg.extend(len24(cert.len()));
            msg.extend(cert.as_ref());
        }

        Ok(Val::str(msg))
    }
);

pub const TLS: Module = module! {
    /// # Transport Layer Security (TLS)
    ///
    /// Construct TLS handshake traffic over a TCP flow. The module provides record framing
    /// ([message](#message)), handshake message builders ([client_hello](#client_hello),
    /// [server_hello](#server_hello), [certificates](#certificates)), and extension helpers
    /// ([extension](#extension), [sni](#sni), [ciphers](#ciphers)).
    ///
    /// ## Full handshake example
    ///
    /// ### Setup — open a TCP connection
    ///
    /// ```resynth
    /// import io;
    /// import ipv4;
    /// import std;
    /// import tls;
    ///
    /// let tls = ipv4::tcp::flow(
    ///   192.168.106.72:40015,
    ///   172.16.14.121:443,
    /// );
    ///
    /// tls.open();
    /// ```
    ///
    /// ### Client Hello
    ///
    /// The client advertises a minimal modern cipher suite list and a handful of extensions.
    /// The outer record uses [tls::version::TLS_1_0](version/README.md) for broad
    /// compatibility; the inner `client_hello` requests
    /// [tls::version::TLS_1_2](version/README.md).
    ///
    /// ```resynth
    /// tls.client_message(
    ///   tls::message(
    ///     content: tls::content::HANDSHAKE,
    ///     version: tls::version::TLS_1_0,
    ///     tls::client_hello(
    ///       version: tls::version::TLS_1_2,
    ///       ciphers: tls::ciphers(
    ///         tls::cipher::ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    ///         tls::cipher::ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    ///         tls::cipher::ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    ///         tls::cipher::EMPTY_RENEGOTIATION_INFO_SCSV,
    ///       ),
    ///       tls::sni("test.local"),
    ///       tls::extension(tls::ext::SESSION_TICKET),
    ///       tls::extension(tls::ext::EXTENDED_MASTER_SECRET),
    ///       tls::extension(
    ///         tls::ext::EC_POINT_FORMATS,
    ///         std::len_u8("|00 01 02|"),
    ///       ),
    ///       tls::extension(
    ///         tls::ext::ALPN,
    ///         std::len_be16(
    ///           std::len_u8("http/0.9"),
    ///           std::len_u8("pop3"),
    ///         ),
    ///       ),
    ///     )
    ///   ),
    /// );
    /// ```
    ///
    /// ### Server Hello, Certificate, and Server Hello Done
    ///
    /// The server responds with its chosen cipher suite and extensions, followed by its
    /// certificate chain, and a Server Hello Done to signal it is ready for key exchange.
    /// All three messages are bundled into a single `server_message` call so they arrive
    /// in the same TCP segment.
    ///
    /// ```resynth
    /// tls.server_message(
    ///   // Server Hello — negotiate cipher and extensions
    ///   tls::message(
    ///     content: tls::content::HANDSHAKE,
    ///     version: tls::version::TLS_1_2,
    ///     tls::server_hello(
    ///       version: tls::version::TLS_1_2,
    ///       cipher: tls::cipher::ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    ///       tls::extension(tls::ext::RENEGOTIATION_INFO, std::u8(0)),
    ///       tls::extension(
    ///         tls::ext::EC_POINT_FORMATS,
    ///         std::len_u8("|00 01 02|"),
    ///       ),
    ///       tls::extension(tls::ext::SESSION_TICKET),
    ///       tls::extension(tls::ext::EXTENDED_MASTER_SECRET),
    ///       tls::extension(
    ///         tls::ext::ALPN,
    ///         std::len_be16(std::len_u8("http/0.9")),
    ///       ),
    ///     ),
    ///   ),
    ///
    ///   // Certificate — DER-encoded X.509 certificate chain
    ///   tls::message(
    ///     content: tls::content::HANDSHAKE,
    ///     version: tls::version::TLS_1_2,
    ///     tls::certificates(io::file("./example-data/rsa4096.x509.cert.der")),
    ///   ),
    ///
    ///   // Server Key Exchange — ECDH parameters (load from file or embed as hex bytes)
    ///   tls::message(
    ///     content: tls::content::HANDSHAKE,
    ///     version: tls::version::TLS_1_2,
    ///     tls::handshake::SERVER_KEY_EXCHANGE,
    ///     io::file("./example-data/server_key_exchange.bin"),
    ///   ),
    ///
    ///   // Server Hello Done — signals end of server's handshake flight
    ///   tls::message(
    ///     content: tls::content::HANDSHAKE,
    ///     version: tls::version::TLS_1_2,
    ///     tls::handshake::SERVER_HELLO_DONE,
    ///     "|00 00 00|"
    ///   ),
    /// );
    /// ```
    resynth mod tls {
        version => Symbol::Module(&VERSION),
        content => Symbol::Module(&CONTENT),
        handshake => Symbol::Module(&HANDSHAKE),
        ext => Symbol::Module(&EXT),
        cipher => Symbol::Module(&CIPHER),

        message => Symbol::Func(&TLS_MESSAGE),
        extension => Symbol::Func(&TLS_EXTENSION),
        client_hello => Symbol::Func(&TLS_CLIENT_HELLO),
        server_hello => Symbol::Func(&TLS_SERVER_HELLO),
        ciphers => Symbol::Func(&TLS_CIPHERS),
        certificates => Symbol::Func(&TLS_CERTIFICATES),
        sni => Symbol::Func(&TLS_SNI),
    }
};
