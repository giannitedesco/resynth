use phf::{phf_map, phf_ordered_map};

use pkt::tls::{version, content, handshake, ext, ciphers};

use crate::val::{ValType, Val, ValDef};
use crate::libapi::{FuncDef, ArgDecl};
use crate::sym::Symbol;
use crate::str::Buf;
use crate::func_def;

const VERSION: phf::Map<&'static str, Symbol> = phf_map! {
    "SSL_1" => Symbol::int_val(version::SSL_1 as u64),
    "SSL_2" => Symbol::int_val(version::SSL_2 as u64),
    "SSL_3" => Symbol::int_val(version::SSL_3 as u64),
    "TLS_1_0" => Symbol::int_val(version::TLS_1_0 as u64),
    "TLS_1_1" => Symbol::int_val(version::TLS_1_1 as u64),
    "TLS_1_2" => Symbol::int_val(version::TLS_1_2 as u64),
    "TLS_1_3" => Symbol::int_val(version::TLS_1_3 as u64),
};

const CONTENT: phf::Map<&'static str, Symbol> = phf_map! {
    "INVALID" => Symbol::int_val(content::INVALID as u64),
    "CHANGE_CIPHER_SPEC" => Symbol::int_val(content::CHANGE_CIPHER_SPEC as u64),
    "ALERT" => Symbol::int_val(content::ALERT as u64),
    "HANDSHAKE" => Symbol::int_val(content::HANDSHAKE as u64),
    "APP_DATA" => Symbol::int_val(content::APP_DATA as u64),
    "HEARTBEAT" => Symbol::int_val(content::HEARTBEAT as u64),
    "TLS12_CID" => Symbol::int_val(content::TLS12_CID as u64),
    "ACK" => Symbol::int_val(content::ACK as u64),
};

const HANDSHAKE: phf::Map<&'static str, Symbol> = phf_map! {
    "HELLO_REQUEST" => Symbol::int_val(handshake::HELLO_REQUEST as u64),
    "CLIENT_HELLO" => Symbol::int_val(handshake::CLIENT_HELLO as u64),
    "SERVER_HELLO" => Symbol::int_val(handshake::SERVER_HELLO as u64),
    "HELLO_VERIFY_REQUEST" => Symbol::int_val(handshake::HELLO_VERIFY_REQUEST as u64),
    "NEW_SESSION_TICKET" => Symbol::int_val(handshake::NEW_SESSION_TICKET as u64),
    "END_OF_EARLY_DATA" => Symbol::int_val(handshake::END_OF_EARLY_DATA as u64),
    "HELLO_RETRY_REQUEST" => Symbol::int_val(handshake::HELLO_RETRY_REQUEST as u64),
    "ENCRYPTED_EXTENSIONS" => Symbol::int_val(handshake::ENCRYPTED_EXTENSIONS as u64),
    "REQUESTCONNECTIONID" => Symbol::int_val(handshake::REQUESTCONNECTIONID as u64),
    "NEWCONNECTIONID" => Symbol::int_val(handshake::NEWCONNECTIONID as u64),
    "CERTIFICATE" => Symbol::int_val(handshake::CERTIFICATE as u64),
    "SERVER_KEY_EXCHANGE" => Symbol::int_val(handshake::SERVER_KEY_EXCHANGE as u64),
    "CERTIFICATE_REQUEST" => Symbol::int_val(handshake::CERTIFICATE_REQUEST as u64),
    "SERVER_HELLO_DONE" => Symbol::int_val(handshake::SERVER_HELLO_DONE as u64),
    "CERTIFICATE_VERIFY" => Symbol::int_val(handshake::CERTIFICATE_VERIFY as u64),
    "CLIENT_KEY_EXCHANGE" => Symbol::int_val(handshake::CLIENT_KEY_EXCHANGE as u64),
    "FINISHED" => Symbol::int_val(handshake::FINISHED as u64),
    "CERTIFICATE_URL" => Symbol::int_val(handshake::CERTIFICATE_URL as u64),
    "CERTIFICATE_STATUS" => Symbol::int_val(handshake::CERTIFICATE_STATUS as u64),
    "SUPPLEMENTAL_DATA" => Symbol::int_val(handshake::SUPPLEMENTAL_DATA as u64),
    "KEY_UPDATE" => Symbol::int_val(handshake::KEY_UPDATE as u64),
    "COMPRESSED_CERTIFICATE" => Symbol::int_val(handshake::COMPRESSED_CERTIFICATE as u64),
    "EKT_KEY" => Symbol::int_val(handshake::EKT_KEY as u64),
    "MESSAGE_HASH" => Symbol::int_val(handshake::MESSAGE_HASH as u64),
};

const EXT: phf::Map<&'static str, Symbol> = phf_map! {
    "SERVER_NAME" => Symbol::int_val(ext::SERVER_NAME as u64),
    "MAX_FRAGMENT_LENGTH" => Symbol::int_val(ext::MAX_FRAGMENT_LENGTH as u64),
    "CLIENT_CERTIFICATE_URL" => Symbol::int_val(ext::CLIENT_CERTIFICATE_URL as u64),
    "TRUSTED_CA_KEYS" => Symbol::int_val(ext::TRUSTED_CA_KEYS as u64),
    "TRUNCATED_HMAC" => Symbol::int_val(ext::TRUNCATED_HMAC as u64),
    "STATUS_REQUEST" => Symbol::int_val(ext::STATUS_REQUEST as u64),
    "USER_MAPPING" => Symbol::int_val(ext::USER_MAPPING as u64),
    "CLIENT_AUTHZ" => Symbol::int_val(ext::CLIENT_AUTHZ as u64),
    "SERVER_AUTHZ" => Symbol::int_val(ext::SERVER_AUTHZ as u64),
    "CERT_TYPE" => Symbol::int_val(ext::CERT_TYPE as u64),
    "SUPPORTED_GROUPS" => Symbol::int_val(ext::SUPPORTED_GROUPS as u64),
    "EC_POINT_FORMATS" => Symbol::int_val(ext::EC_POINT_FORMATS as u64),
    "SRP" => Symbol::int_val(ext::SRP as u64),
    "SIGNATURE_ALGORITHMS" => Symbol::int_val(ext::SIGNATURE_ALGORITHMS as u64),
    "USE_SRTP" => Symbol::int_val(ext::USE_SRTP as u64),
    "HEARTBEAT" => Symbol::int_val(ext::HEARTBEAT as u64),
    "APPLICATION_LAYER_PROTOCOL_NEGOTIATION"
        => Symbol::int_val(ext::APPLICATION_LAYER_PROTOCOL_NEGOTIATION as u64),
    "ALPN"
        => Symbol::int_val(ext::APPLICATION_LAYER_PROTOCOL_NEGOTIATION as u64),
    "STATUS_REQUEST_V2" => Symbol::int_val(ext::STATUS_REQUEST_V2 as u64),
    "SIGNED_CERTIFICATE_TIMESTAMP" => Symbol::int_val(ext::SIGNED_CERTIFICATE_TIMESTAMP as u64),
    "CLIENT_CERTIFICATE_TYPE" => Symbol::int_val(ext::CLIENT_CERTIFICATE_TYPE as u64),
    "SERVER_CERTIFICATE_TYPE" => Symbol::int_val(ext::SERVER_CERTIFICATE_TYPE as u64),
    "PADDING" => Symbol::int_val(ext::PADDING as u64),
    "ENCRYPT_THEN_MAC" => Symbol::int_val(ext::ENCRYPT_THEN_MAC as u64),
    "EXTENDED_MASTER_SECRET" => Symbol::int_val(ext::EXTENDED_MASTER_SECRET as u64),
    "TOKEN_BINDING" => Symbol::int_val(ext::TOKEN_BINDING as u64),
    "CACHED_INFO" => Symbol::int_val(ext::CACHED_INFO as u64),
    "TLS_LTS" => Symbol::int_val(ext::TLS_LTS as u64),
    "COMPRESS_CERTIFICATE" => Symbol::int_val(ext::COMPRESS_CERTIFICATE as u64),
    "RECORD_SIZE_LIMIT" => Symbol::int_val(ext::RECORD_SIZE_LIMIT as u64),
    "PWD_PROTECT" => Symbol::int_val(ext::PWD_PROTECT as u64),
    "PWD_CLEAR" => Symbol::int_val(ext::PWD_CLEAR as u64),
    "PASSWORD_SALT" => Symbol::int_val(ext::PASSWORD_SALT as u64),
    "TICKET_PINNING" => Symbol::int_val(ext::TICKET_PINNING as u64),
    "TLS_CERT_WITH_EXTERN_PSK" => Symbol::int_val(ext::TLS_CERT_WITH_EXTERN_PSK as u64),
    "DELEGATED_CREDENTIALS" => Symbol::int_val(ext::DELEGATED_CREDENTIALS as u64),
    "SESSION_TICKET" => Symbol::int_val(ext::SESSION_TICKET as u64),
    "TLMSP" => Symbol::int_val(ext::TLMSP as u64),
    "TLMSP_PROXYING" => Symbol::int_val(ext::TLMSP_PROXYING as u64),
    "TLMSP_DELEGATE" => Symbol::int_val(ext::TLMSP_DELEGATE as u64),
    "SUPPORTED_EKT_CIPHERS" => Symbol::int_val(ext::SUPPORTED_EKT_CIPHERS as u64),
    "PRE_SHARED_KEY" => Symbol::int_val(ext::PRE_SHARED_KEY as u64),
    "EARLY_DATA" => Symbol::int_val(ext::EARLY_DATA as u64),
    "SUPPORTED_VERSIONS" => Symbol::int_val(ext::SUPPORTED_VERSIONS as u64),
    "COOKIE" => Symbol::int_val(ext::COOKIE as u64),
    "PSK_KEY_EXCHANGE_MODES" => Symbol::int_val(ext::PSK_KEY_EXCHANGE_MODES as u64),
    "CERTIFICATE_AUTHORITIES" => Symbol::int_val(ext::CERTIFICATE_AUTHORITIES as u64),
    "OID_FILTERS" => Symbol::int_val(ext::OID_FILTERS as u64),
    "POST_HANDSHAKE_AUTH" => Symbol::int_val(ext::POST_HANDSHAKE_AUTH as u64),
    "SIGNATURE_ALGORITHMS_CERT" => Symbol::int_val(ext::SIGNATURE_ALGORITHMS_CERT as u64),
    "KEY_SHARE" => Symbol::int_val(ext::KEY_SHARE as u64),
    "TRANSPARENCY_INFO" => Symbol::int_val(ext::TRANSPARENCY_INFO as u64),
    "CONNECTION_ID_DEPRECATED" => Symbol::int_val(ext::CONNECTION_ID_DEPRECATED as u64),
    "CONNECTION_ID" => Symbol::int_val(ext::CONNECTION_ID as u64),
    "EXTERNAL_ID_HASH" => Symbol::int_val(ext::EXTERNAL_ID_HASH as u64),
    "EXTERNAL_SESSION_ID" => Symbol::int_val(ext::EXTERNAL_SESSION_ID as u64),
    "QUIC_TRANSPORT_PARAMETERS" => Symbol::int_val(ext::QUIC_TRANSPORT_PARAMETERS as u64),
    "TICKET_REQUEST" => Symbol::int_val(ext::TICKET_REQUEST as u64),
    "DNSSEC_CHAIN" => Symbol::int_val(ext::DNSSEC_CHAIN as u64),
    "RENEGOTIATION_INFO" => Symbol::int_val(ext::RENEGOTIATION_INFO as u64),
};

const CIPHER: phf::Map<&'static str, Symbol> = phf_map! {
    "NULL_WITH_NULL_NULL" => 
        Symbol::int_val(ciphers::NULL_WITH_NULL_NULL as u64),
    "RSA_WITH_NULL_MD5" => 
        Symbol::int_val(ciphers::RSA_WITH_NULL_MD5 as u64),
    "RSA_WITH_NULL_SHA" => 
        Symbol::int_val(ciphers::RSA_WITH_NULL_SHA as u64),
    "RSA_EXPORT_WITH_RC4_40_MD5" => 
        Symbol::int_val(ciphers::RSA_EXPORT_WITH_RC4_40_MD5 as u64),
    "RSA_WITH_RC4_128_MD5" => 
        Symbol::int_val(ciphers::RSA_WITH_RC4_128_MD5 as u64),
    "RSA_WITH_RC4_128_SHA" => 
        Symbol::int_val(ciphers::RSA_WITH_RC4_128_SHA as u64),
    "RSA_EXPORT_WITH_RC2_CBC_40_MD5" => 
        Symbol::int_val(ciphers::RSA_EXPORT_WITH_RC2_CBC_40_MD5 as u64),
    "RSA_WITH_IDEA_CBC_SHA" => 
        Symbol::int_val(ciphers::RSA_WITH_IDEA_CBC_SHA as u64),
    "RSA_EXPORT_WITH_DES40_CBC_SHA" => 
        Symbol::int_val(ciphers::RSA_EXPORT_WITH_DES40_CBC_SHA as u64),
    "RSA_WITH_DES_CBC_SHA" => 
        Symbol::int_val(ciphers::RSA_WITH_DES_CBC_SHA as u64),
    "RSA_WITH_3DES_EDE_CBC_SHA" => 
        Symbol::int_val(ciphers::RSA_WITH_3DES_EDE_CBC_SHA as u64),
    "DH_DSS_EXPORT_WITH_DES40_CBC_SHA" => 
        Symbol::int_val(ciphers::DH_DSS_EXPORT_WITH_DES40_CBC_SHA as u64),
    "DH_DSS_WITH_DES_CBC_SHA" => 
        Symbol::int_val(ciphers::DH_DSS_WITH_DES_CBC_SHA as u64),
    "DH_DSS_WITH_3DES_EDE_CBC_SHA" => 
        Symbol::int_val(ciphers::DH_DSS_WITH_3DES_EDE_CBC_SHA as u64),
    "DH_RSA_EXPORT_WITH_DES40_CBC_SHA" => 
        Symbol::int_val(ciphers::DH_RSA_EXPORT_WITH_DES40_CBC_SHA as u64),
    "DH_RSA_WITH_DES_CBC_SHA" => 
        Symbol::int_val(ciphers::DH_RSA_WITH_DES_CBC_SHA as u64),
    "DH_RSA_WITH_3DES_EDE_CBC_SHA" => 
        Symbol::int_val(ciphers::DH_RSA_WITH_3DES_EDE_CBC_SHA as u64),
    "DHE_DSS_EXPORT_WITH_DES40_CBC_SHA" => 
        Symbol::int_val(ciphers::DHE_DSS_EXPORT_WITH_DES40_CBC_SHA as u64),
    "DHE_DSS_WITH_DES_CBC_SHA" => 
        Symbol::int_val(ciphers::DHE_DSS_WITH_DES_CBC_SHA as u64),
    "DHE_DSS_WITH_3DES_EDE_CBC_SHA" => 
        Symbol::int_val(ciphers::DHE_DSS_WITH_3DES_EDE_CBC_SHA as u64),
    "DHE_RSA_EXPORT_WITH_DES40_CBC_SHA" => 
        Symbol::int_val(ciphers::DHE_RSA_EXPORT_WITH_DES40_CBC_SHA as u64),
    "DHE_RSA_WITH_DES_CBC_SHA" => 
        Symbol::int_val(ciphers::DHE_RSA_WITH_DES_CBC_SHA as u64),
    "DHE_RSA_WITH_3DES_EDE_CBC_SHA" => 
        Symbol::int_val(ciphers::DHE_RSA_WITH_3DES_EDE_CBC_SHA as u64),
    "DH_ANON_EXPORT_WITH_RC4_40_MD5" => 
        Symbol::int_val(ciphers::DH_ANON_EXPORT_WITH_RC4_40_MD5 as u64),
    "DH_ANON_WITH_RC4_128_MD5" => 
        Symbol::int_val(ciphers::DH_ANON_WITH_RC4_128_MD5 as u64),
    "DH_ANON_EXPORT_WITH_DES40_CBC_SHA" => 
        Symbol::int_val(ciphers::DH_ANON_EXPORT_WITH_DES40_CBC_SHA as u64),
    "DH_ANON_WITH_DES_CBC_SHA" => 
        Symbol::int_val(ciphers::DH_ANON_WITH_DES_CBC_SHA as u64),
    "DH_ANON_WITH_3DES_EDE_CBC_SHA" => 
        Symbol::int_val(ciphers::DH_ANON_WITH_3DES_EDE_CBC_SHA as u64),
    "KRB5_WITH_DES_CBC_SHA" => 
        Symbol::int_val(ciphers::KRB5_WITH_DES_CBC_SHA as u64),
    "KRB5_WITH_3DES_EDE_CBC_SHA" => 
        Symbol::int_val(ciphers::KRB5_WITH_3DES_EDE_CBC_SHA as u64),
    "KRB5_WITH_RC4_128_SHA" => 
        Symbol::int_val(ciphers::KRB5_WITH_RC4_128_SHA as u64),
    "KRB5_WITH_IDEA_CBC_SHA" => 
        Symbol::int_val(ciphers::KRB5_WITH_IDEA_CBC_SHA as u64),
    "KRB5_WITH_DES_CBC_MD5" => 
        Symbol::int_val(ciphers::KRB5_WITH_DES_CBC_MD5 as u64),
    "KRB5_WITH_3DES_EDE_CBC_MD5" => 
        Symbol::int_val(ciphers::KRB5_WITH_3DES_EDE_CBC_MD5 as u64),
    "KRB5_WITH_RC4_128_MD5" => 
        Symbol::int_val(ciphers::KRB5_WITH_RC4_128_MD5 as u64),
    "KRB5_WITH_IDEA_CBC_MD5" => 
        Symbol::int_val(ciphers::KRB5_WITH_IDEA_CBC_MD5 as u64),
    "KRB5_EXPORT_WITH_DES_CBC_40_SHA" => 
        Symbol::int_val(ciphers::KRB5_EXPORT_WITH_DES_CBC_40_SHA as u64),
    "KRB5_EXPORT_WITH_RC2_CBC_40_SHA" => 
        Symbol::int_val(ciphers::KRB5_EXPORT_WITH_RC2_CBC_40_SHA as u64),
    "KRB5_EXPORT_WITH_RC4_40_SHA" => 
        Symbol::int_val(ciphers::KRB5_EXPORT_WITH_RC4_40_SHA as u64),
    "KRB5_EXPORT_WITH_DES_CBC_40_MD5" => 
        Symbol::int_val(ciphers::KRB5_EXPORT_WITH_DES_CBC_40_MD5 as u64),
    "KRB5_EXPORT_WITH_RC2_CBC_40_MD5" => 
        Symbol::int_val(ciphers::KRB5_EXPORT_WITH_RC2_CBC_40_MD5 as u64),
    "KRB5_EXPORT_WITH_RC4_40_MD5" => 
        Symbol::int_val(ciphers::KRB5_EXPORT_WITH_RC4_40_MD5 as u64),
    "PSK_WITH_NULL_SHA" => 
        Symbol::int_val(ciphers::PSK_WITH_NULL_SHA as u64),
    "DHE_PSK_WITH_NULL_SHA" => 
        Symbol::int_val(ciphers::DHE_PSK_WITH_NULL_SHA as u64),
    "RSA_PSK_WITH_NULL_SHA" => 
        Symbol::int_val(ciphers::RSA_PSK_WITH_NULL_SHA as u64),
    "RSA_WITH_AES_128_CBC_SHA" => 
        Symbol::int_val(ciphers::RSA_WITH_AES_128_CBC_SHA as u64),
    "DH_DSS_WITH_AES_128_CBC_SHA" => 
        Symbol::int_val(ciphers::DH_DSS_WITH_AES_128_CBC_SHA as u64),
    "DH_RSA_WITH_AES_128_CBC_SHA" => 
        Symbol::int_val(ciphers::DH_RSA_WITH_AES_128_CBC_SHA as u64),
    "DHE_DSS_WITH_AES_128_CBC_SHA" => 
        Symbol::int_val(ciphers::DHE_DSS_WITH_AES_128_CBC_SHA as u64),
    "DHE_RSA_WITH_AES_128_CBC_SHA" => 
        Symbol::int_val(ciphers::DHE_RSA_WITH_AES_128_CBC_SHA as u64),
    "DH_ANON_WITH_AES_128_CBC_SHA" => 
        Symbol::int_val(ciphers::DH_ANON_WITH_AES_128_CBC_SHA as u64),
    "RSA_WITH_AES_256_CBC_SHA" => 
        Symbol::int_val(ciphers::RSA_WITH_AES_256_CBC_SHA as u64),
    "DH_DSS_WITH_AES_256_CBC_SHA" => 
        Symbol::int_val(ciphers::DH_DSS_WITH_AES_256_CBC_SHA as u64),
    "DH_RSA_WITH_AES_256_CBC_SHA" => 
        Symbol::int_val(ciphers::DH_RSA_WITH_AES_256_CBC_SHA as u64),
    "DHE_DSS_WITH_AES_256_CBC_SHA" => 
        Symbol::int_val(ciphers::DHE_DSS_WITH_AES_256_CBC_SHA as u64),
    "DHE_RSA_WITH_AES_256_CBC_SHA" => 
        Symbol::int_val(ciphers::DHE_RSA_WITH_AES_256_CBC_SHA as u64),
    "DH_ANON_WITH_AES_256_CBC_SHA" => 
        Symbol::int_val(ciphers::DH_ANON_WITH_AES_256_CBC_SHA as u64),
    "RSA_WITH_NULL_SHA256" => 
        Symbol::int_val(ciphers::RSA_WITH_NULL_SHA256 as u64),
    "RSA_WITH_AES_128_CBC_SHA256" => 
        Symbol::int_val(ciphers::RSA_WITH_AES_128_CBC_SHA256 as u64),
    "RSA_WITH_AES_256_CBC_SHA256" => 
        Symbol::int_val(ciphers::RSA_WITH_AES_256_CBC_SHA256 as u64),
    "DH_DSS_WITH_AES_128_CBC_SHA256" => 
        Symbol::int_val(ciphers::DH_DSS_WITH_AES_128_CBC_SHA256 as u64),
    "DH_RSA_WITH_AES_128_CBC_SHA256" => 
        Symbol::int_val(ciphers::DH_RSA_WITH_AES_128_CBC_SHA256 as u64),
    "DHE_DSS_WITH_AES_128_CBC_SHA256" => 
        Symbol::int_val(ciphers::DHE_DSS_WITH_AES_128_CBC_SHA256 as u64),
    "RSA_WITH_CAMELLIA_128_CBC_SHA" => 
        Symbol::int_val(ciphers::RSA_WITH_CAMELLIA_128_CBC_SHA as u64),
    "DH_DSS_WITH_CAMELLIA_128_CBC_SHA" => 
        Symbol::int_val(ciphers::DH_DSS_WITH_CAMELLIA_128_CBC_SHA as u64),
    "DH_RSA_WITH_CAMELLIA_128_CBC_SHA" => 
        Symbol::int_val(ciphers::DH_RSA_WITH_CAMELLIA_128_CBC_SHA as u64),
    "DHE_DSS_WITH_CAMELLIA_128_CBC_SHA" => 
        Symbol::int_val(ciphers::DHE_DSS_WITH_CAMELLIA_128_CBC_SHA as u64),
    "DHE_RSA_WITH_CAMELLIA_128_CBC_SHA" => 
        Symbol::int_val(ciphers::DHE_RSA_WITH_CAMELLIA_128_CBC_SHA as u64),
    "DH_ANON_WITH_CAMELLIA_128_CBC_SHA" => 
        Symbol::int_val(ciphers::DH_ANON_WITH_CAMELLIA_128_CBC_SHA as u64),
    "DHE_RSA_WITH_AES_128_CBC_SHA256" => 
        Symbol::int_val(ciphers::DHE_RSA_WITH_AES_128_CBC_SHA256 as u64),
    "DH_DSS_WITH_AES_256_CBC_SHA256" => 
        Symbol::int_val(ciphers::DH_DSS_WITH_AES_256_CBC_SHA256 as u64),
    "DH_RSA_WITH_AES_256_CBC_SHA256" => 
        Symbol::int_val(ciphers::DH_RSA_WITH_AES_256_CBC_SHA256 as u64),
    "DHE_DSS_WITH_AES_256_CBC_SHA256" => 
        Symbol::int_val(ciphers::DHE_DSS_WITH_AES_256_CBC_SHA256 as u64),
    "DHE_RSA_WITH_AES_256_CBC_SHA256" => 
        Symbol::int_val(ciphers::DHE_RSA_WITH_AES_256_CBC_SHA256 as u64),
    "DH_ANON_WITH_AES_128_CBC_SHA256" => 
        Symbol::int_val(ciphers::DH_ANON_WITH_AES_128_CBC_SHA256 as u64),
    "DH_ANON_WITH_AES_256_CBC_SHA256" => 
        Symbol::int_val(ciphers::DH_ANON_WITH_AES_256_CBC_SHA256 as u64),
    "RSA_WITH_CAMELLIA_256_CBC_SHA" => 
        Symbol::int_val(ciphers::RSA_WITH_CAMELLIA_256_CBC_SHA as u64),
    "DH_DSS_WITH_CAMELLIA_256_CBC_SHA" => 
        Symbol::int_val(ciphers::DH_DSS_WITH_CAMELLIA_256_CBC_SHA as u64),
    "DH_RSA_WITH_CAMELLIA_256_CBC_SHA" => 
        Symbol::int_val(ciphers::DH_RSA_WITH_CAMELLIA_256_CBC_SHA as u64),
    "DHE_DSS_WITH_CAMELLIA_256_CBC_SHA" => 
        Symbol::int_val(ciphers::DHE_DSS_WITH_CAMELLIA_256_CBC_SHA as u64),
    "DHE_RSA_WITH_CAMELLIA_256_CBC_SHA" => 
        Symbol::int_val(ciphers::DHE_RSA_WITH_CAMELLIA_256_CBC_SHA as u64),
    "DH_ANON_WITH_CAMELLIA_256_CBC_SHA" => 
        Symbol::int_val(ciphers::DH_ANON_WITH_CAMELLIA_256_CBC_SHA as u64),
    "PSK_WITH_RC4_128_SHA" => 
        Symbol::int_val(ciphers::PSK_WITH_RC4_128_SHA as u64),
    "PSK_WITH_3DES_EDE_CBC_SHA" => 
        Symbol::int_val(ciphers::PSK_WITH_3DES_EDE_CBC_SHA as u64),
    "PSK_WITH_AES_128_CBC_SHA" => 
        Symbol::int_val(ciphers::PSK_WITH_AES_128_CBC_SHA as u64),
    "PSK_WITH_AES_256_CBC_SHA" => 
        Symbol::int_val(ciphers::PSK_WITH_AES_256_CBC_SHA as u64),
    "DHE_PSK_WITH_RC4_128_SHA" => 
        Symbol::int_val(ciphers::DHE_PSK_WITH_RC4_128_SHA as u64),
    "DHE_PSK_WITH_3DES_EDE_CBC_SHA" => 
        Symbol::int_val(ciphers::DHE_PSK_WITH_3DES_EDE_CBC_SHA as u64),
    "DHE_PSK_WITH_AES_128_CBC_SHA" => 
        Symbol::int_val(ciphers::DHE_PSK_WITH_AES_128_CBC_SHA as u64),
    "DHE_PSK_WITH_AES_256_CBC_SHA" => 
        Symbol::int_val(ciphers::DHE_PSK_WITH_AES_256_CBC_SHA as u64),
    "RSA_PSK_WITH_RC4_128_SHA" => 
        Symbol::int_val(ciphers::RSA_PSK_WITH_RC4_128_SHA as u64),
    "RSA_PSK_WITH_3DES_EDE_CBC_SHA" => 
        Symbol::int_val(ciphers::RSA_PSK_WITH_3DES_EDE_CBC_SHA as u64),
    "RSA_PSK_WITH_AES_128_CBC_SHA" => 
        Symbol::int_val(ciphers::RSA_PSK_WITH_AES_128_CBC_SHA as u64),
    "RSA_PSK_WITH_AES_256_CBC_SHA" => 
        Symbol::int_val(ciphers::RSA_PSK_WITH_AES_256_CBC_SHA as u64),
    "RSA_WITH_SEED_CBC_SHA" => 
        Symbol::int_val(ciphers::RSA_WITH_SEED_CBC_SHA as u64),
    "DH_DSS_WITH_SEED_CBC_SHA" => 
        Symbol::int_val(ciphers::DH_DSS_WITH_SEED_CBC_SHA as u64),
    "DH_RSA_WITH_SEED_CBC_SHA" => 
        Symbol::int_val(ciphers::DH_RSA_WITH_SEED_CBC_SHA as u64),
    "DHE_DSS_WITH_SEED_CBC_SHA" => 
        Symbol::int_val(ciphers::DHE_DSS_WITH_SEED_CBC_SHA as u64),
    "DHE_RSA_WITH_SEED_CBC_SHA" => 
        Symbol::int_val(ciphers::DHE_RSA_WITH_SEED_CBC_SHA as u64),
    "DH_ANON_WITH_SEED_CBC_SHA" => 
        Symbol::int_val(ciphers::DH_ANON_WITH_SEED_CBC_SHA as u64),
    "RSA_WITH_AES_128_GCM_SHA256" => 
        Symbol::int_val(ciphers::RSA_WITH_AES_128_GCM_SHA256 as u64),
    "RSA_WITH_AES_256_GCM_SHA384" => 
        Symbol::int_val(ciphers::RSA_WITH_AES_256_GCM_SHA384 as u64),
    "DHE_RSA_WITH_AES_128_GCM_SHA256" => 
        Symbol::int_val(ciphers::DHE_RSA_WITH_AES_128_GCM_SHA256 as u64),
    "DHE_RSA_WITH_AES_256_GCM_SHA384" => 
        Symbol::int_val(ciphers::DHE_RSA_WITH_AES_256_GCM_SHA384 as u64),
    "DH_RSA_WITH_AES_128_GCM_SHA256" => 
        Symbol::int_val(ciphers::DH_RSA_WITH_AES_128_GCM_SHA256 as u64),
    "DH_RSA_WITH_AES_256_GCM_SHA384" => 
        Symbol::int_val(ciphers::DH_RSA_WITH_AES_256_GCM_SHA384 as u64),
    "DHE_DSS_WITH_AES_128_GCM_SHA256" => 
        Symbol::int_val(ciphers::DHE_DSS_WITH_AES_128_GCM_SHA256 as u64),
    "DHE_DSS_WITH_AES_256_GCM_SHA384" => 
        Symbol::int_val(ciphers::DHE_DSS_WITH_AES_256_GCM_SHA384 as u64),
    "DH_DSS_WITH_AES_128_GCM_SHA256" => 
        Symbol::int_val(ciphers::DH_DSS_WITH_AES_128_GCM_SHA256 as u64),
    "DH_DSS_WITH_AES_256_GCM_SHA384" => 
        Symbol::int_val(ciphers::DH_DSS_WITH_AES_256_GCM_SHA384 as u64),
    "DH_ANON_WITH_AES_128_GCM_SHA256" => 
        Symbol::int_val(ciphers::DH_ANON_WITH_AES_128_GCM_SHA256 as u64),
    "DH_ANON_WITH_AES_256_GCM_SHA384" => 
        Symbol::int_val(ciphers::DH_ANON_WITH_AES_256_GCM_SHA384 as u64),
    "PSK_WITH_AES_128_GCM_SHA256" => 
        Symbol::int_val(ciphers::PSK_WITH_AES_128_GCM_SHA256 as u64),
    "PSK_WITH_AES_256_GCM_SHA384" => 
        Symbol::int_val(ciphers::PSK_WITH_AES_256_GCM_SHA384 as u64),
    "DHE_PSK_WITH_AES_128_GCM_SHA256" => 
        Symbol::int_val(ciphers::DHE_PSK_WITH_AES_128_GCM_SHA256 as u64),
    "DHE_PSK_WITH_AES_256_GCM_SHA384" => 
        Symbol::int_val(ciphers::DHE_PSK_WITH_AES_256_GCM_SHA384 as u64),
    "RSA_PSK_WITH_AES_128_GCM_SHA256" => 
        Symbol::int_val(ciphers::RSA_PSK_WITH_AES_128_GCM_SHA256 as u64),
    "RSA_PSK_WITH_AES_256_GCM_SHA384" => 
        Symbol::int_val(ciphers::RSA_PSK_WITH_AES_256_GCM_SHA384 as u64),
    "PSK_WITH_AES_128_CBC_SHA256" => 
        Symbol::int_val(ciphers::PSK_WITH_AES_128_CBC_SHA256 as u64),
    "PSK_WITH_AES_256_CBC_SHA384" => 
        Symbol::int_val(ciphers::PSK_WITH_AES_256_CBC_SHA384 as u64),
    "PSK_WITH_NULL_SHA256" => 
        Symbol::int_val(ciphers::PSK_WITH_NULL_SHA256 as u64),
    "PSK_WITH_NULL_SHA384" => 
        Symbol::int_val(ciphers::PSK_WITH_NULL_SHA384 as u64),
    "DHE_PSK_WITH_AES_128_CBC_SHA256" => 
        Symbol::int_val(ciphers::DHE_PSK_WITH_AES_128_CBC_SHA256 as u64),
    "DHE_PSK_WITH_AES_256_CBC_SHA384" => 
        Symbol::int_val(ciphers::DHE_PSK_WITH_AES_256_CBC_SHA384 as u64),
    "DHE_PSK_WITH_NULL_SHA256" => 
        Symbol::int_val(ciphers::DHE_PSK_WITH_NULL_SHA256 as u64),
    "DHE_PSK_WITH_NULL_SHA384" => 
        Symbol::int_val(ciphers::DHE_PSK_WITH_NULL_SHA384 as u64),
    "RSA_PSK_WITH_AES_128_CBC_SHA256" => 
        Symbol::int_val(ciphers::RSA_PSK_WITH_AES_128_CBC_SHA256 as u64),
    "RSA_PSK_WITH_AES_256_CBC_SHA384" => 
        Symbol::int_val(ciphers::RSA_PSK_WITH_AES_256_CBC_SHA384 as u64),
    "RSA_PSK_WITH_NULL_SHA256" => 
        Symbol::int_val(ciphers::RSA_PSK_WITH_NULL_SHA256 as u64),
    "RSA_PSK_WITH_NULL_SHA384" => 
        Symbol::int_val(ciphers::RSA_PSK_WITH_NULL_SHA384 as u64),
    "RSA_WITH_CAMELLIA_128_CBC_SHA256" => 
        Symbol::int_val(ciphers::RSA_WITH_CAMELLIA_128_CBC_SHA256 as u64),
    "DH_DSS_WITH_CAMELLIA_128_CBC_SHA256" => 
        Symbol::int_val(ciphers::DH_DSS_WITH_CAMELLIA_128_CBC_SHA256 as u64),
    "DH_RSA_WITH_CAMELLIA_128_CBC_SHA256" => 
        Symbol::int_val(ciphers::DH_RSA_WITH_CAMELLIA_128_CBC_SHA256 as u64),
    "DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256" => 
        Symbol::int_val(ciphers::DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256 as u64),
    "DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256" => 
        Symbol::int_val(ciphers::DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 as u64),
    "DH_ANON_WITH_CAMELLIA_128_CBC_SHA256" => 
        Symbol::int_val(ciphers::DH_ANON_WITH_CAMELLIA_128_CBC_SHA256 as u64),
    "RSA_WITH_CAMELLIA_256_CBC_SHA256" => 
        Symbol::int_val(ciphers::RSA_WITH_CAMELLIA_256_CBC_SHA256 as u64),
    "DH_DSS_WITH_CAMELLIA_256_CBC_SHA256" => 
        Symbol::int_val(ciphers::DH_DSS_WITH_CAMELLIA_256_CBC_SHA256 as u64),
    "DH_RSA_WITH_CAMELLIA_256_CBC_SHA256" => 
        Symbol::int_val(ciphers::DH_RSA_WITH_CAMELLIA_256_CBC_SHA256 as u64),
    "DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256" => 
        Symbol::int_val(ciphers::DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256 as u64),
    "DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256" => 
        Symbol::int_val(ciphers::DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256 as u64),
    "DH_ANON_WITH_CAMELLIA_256_CBC_SHA256" => 
        Symbol::int_val(ciphers::DH_ANON_WITH_CAMELLIA_256_CBC_SHA256 as u64),
    "SM4_GCM_SM3" => 
        Symbol::int_val(ciphers::SM4_GCM_SM3 as u64),
    "SM4_CCM_SM3" => 
        Symbol::int_val(ciphers::SM4_CCM_SM3 as u64),
    "EMPTY_RENEGOTIATION_INFO_SCSV" => 
        Symbol::int_val(ciphers::EMPTY_RENEGOTIATION_INFO_SCSV as u64),
    "AES_128_GCM_SHA256" => 
        Symbol::int_val(ciphers::AES_128_GCM_SHA256 as u64),
    "AES_256_GCM_SHA384" => 
        Symbol::int_val(ciphers::AES_256_GCM_SHA384 as u64),
    "CHACHA20_POLY1305_SHA256" => 
        Symbol::int_val(ciphers::CHACHA20_POLY1305_SHA256 as u64),
    "AES_128_CCM_SHA256" => 
        Symbol::int_val(ciphers::AES_128_CCM_SHA256 as u64),
    "AES_128_CCM_8_SHA256" => 
        Symbol::int_val(ciphers::AES_128_CCM_8_SHA256 as u64),
    "FALLBACK_SCSV" => 
        Symbol::int_val(ciphers::FALLBACK_SCSV as u64),
    "ECDH_ECDSA_WITH_NULL_SHA" => 
        Symbol::int_val(ciphers::ECDH_ECDSA_WITH_NULL_SHA as u64),
    "ECDH_ECDSA_WITH_RC4_128_SHA" => 
        Symbol::int_val(ciphers::ECDH_ECDSA_WITH_RC4_128_SHA as u64),
    "ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA" => 
        Symbol::int_val(ciphers::ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA as u64),
    "ECDH_ECDSA_WITH_AES_128_CBC_SHA" => 
        Symbol::int_val(ciphers::ECDH_ECDSA_WITH_AES_128_CBC_SHA as u64),
    "ECDH_ECDSA_WITH_AES_256_CBC_SHA" => 
        Symbol::int_val(ciphers::ECDH_ECDSA_WITH_AES_256_CBC_SHA as u64),
    "ECDHE_ECDSA_WITH_NULL_SHA" => 
        Symbol::int_val(ciphers::ECDHE_ECDSA_WITH_NULL_SHA as u64),
    "ECDHE_ECDSA_WITH_RC4_128_SHA" => 
        Symbol::int_val(ciphers::ECDHE_ECDSA_WITH_RC4_128_SHA as u64),
    "ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA" => 
        Symbol::int_val(ciphers::ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA as u64),
    "ECDHE_ECDSA_WITH_AES_128_CBC_SHA" => 
        Symbol::int_val(ciphers::ECDHE_ECDSA_WITH_AES_128_CBC_SHA as u64),
    "ECDHE_ECDSA_WITH_AES_256_CBC_SHA" => 
        Symbol::int_val(ciphers::ECDHE_ECDSA_WITH_AES_256_CBC_SHA as u64),
    "ECDH_RSA_WITH_NULL_SHA" => 
        Symbol::int_val(ciphers::ECDH_RSA_WITH_NULL_SHA as u64),
    "ECDH_RSA_WITH_RC4_128_SHA" => 
        Symbol::int_val(ciphers::ECDH_RSA_WITH_RC4_128_SHA as u64),
    "ECDH_RSA_WITH_3DES_EDE_CBC_SHA" => 
        Symbol::int_val(ciphers::ECDH_RSA_WITH_3DES_EDE_CBC_SHA as u64),
    "ECDH_RSA_WITH_AES_128_CBC_SHA" => 
        Symbol::int_val(ciphers::ECDH_RSA_WITH_AES_128_CBC_SHA as u64),
    "ECDH_RSA_WITH_AES_256_CBC_SHA" => 
        Symbol::int_val(ciphers::ECDH_RSA_WITH_AES_256_CBC_SHA as u64),
    "ECDHE_RSA_WITH_NULL_SHA" => 
        Symbol::int_val(ciphers::ECDHE_RSA_WITH_NULL_SHA as u64),
    "ECDHE_RSA_WITH_RC4_128_SHA" => 
        Symbol::int_val(ciphers::ECDHE_RSA_WITH_RC4_128_SHA as u64),
    "ECDHE_RSA_WITH_3DES_EDE_CBC_SHA" => 
        Symbol::int_val(ciphers::ECDHE_RSA_WITH_3DES_EDE_CBC_SHA as u64),
    "ECDHE_RSA_WITH_AES_128_CBC_SHA" => 
        Symbol::int_val(ciphers::ECDHE_RSA_WITH_AES_128_CBC_SHA as u64),
    "ECDHE_RSA_WITH_AES_256_CBC_SHA" => 
        Symbol::int_val(ciphers::ECDHE_RSA_WITH_AES_256_CBC_SHA as u64),
    "ECDH_ANON_WITH_NULL_SHA" => 
        Symbol::int_val(ciphers::ECDH_ANON_WITH_NULL_SHA as u64),
    "ECDH_ANON_WITH_RC4_128_SHA" => 
        Symbol::int_val(ciphers::ECDH_ANON_WITH_RC4_128_SHA as u64),
    "ECDH_ANON_WITH_3DES_EDE_CBC_SHA" => 
        Symbol::int_val(ciphers::ECDH_ANON_WITH_3DES_EDE_CBC_SHA as u64),
    "ECDH_ANON_WITH_AES_128_CBC_SHA" => 
        Symbol::int_val(ciphers::ECDH_ANON_WITH_AES_128_CBC_SHA as u64),
    "ECDH_ANON_WITH_AES_256_CBC_SHA" => 
        Symbol::int_val(ciphers::ECDH_ANON_WITH_AES_256_CBC_SHA as u64),
    "SRP_SHA_WITH_3DES_EDE_CBC_SHA" => 
        Symbol::int_val(ciphers::SRP_SHA_WITH_3DES_EDE_CBC_SHA as u64),
    "SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA" => 
        Symbol::int_val(ciphers::SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA as u64),
    "SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA" => 
        Symbol::int_val(ciphers::SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA as u64),
    "SRP_SHA_WITH_AES_128_CBC_SHA" => 
        Symbol::int_val(ciphers::SRP_SHA_WITH_AES_128_CBC_SHA as u64),
    "SRP_SHA_RSA_WITH_AES_128_CBC_SHA" => 
        Symbol::int_val(ciphers::SRP_SHA_RSA_WITH_AES_128_CBC_SHA as u64),
    "SRP_SHA_DSS_WITH_AES_128_CBC_SHA" => 
        Symbol::int_val(ciphers::SRP_SHA_DSS_WITH_AES_128_CBC_SHA as u64),
    "SRP_SHA_WITH_AES_256_CBC_SHA" => 
        Symbol::int_val(ciphers::SRP_SHA_WITH_AES_256_CBC_SHA as u64),
    "SRP_SHA_RSA_WITH_AES_256_CBC_SHA" => 
        Symbol::int_val(ciphers::SRP_SHA_RSA_WITH_AES_256_CBC_SHA as u64),
    "SRP_SHA_DSS_WITH_AES_256_CBC_SHA" => 
        Symbol::int_val(ciphers::SRP_SHA_DSS_WITH_AES_256_CBC_SHA as u64),
    "ECDHE_ECDSA_WITH_AES_128_CBC_SHA256" => 
        Symbol::int_val(ciphers::ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 as u64),
    "ECDHE_ECDSA_WITH_AES_256_CBC_SHA384" => 
        Symbol::int_val(ciphers::ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 as u64),
    "ECDH_ECDSA_WITH_AES_128_CBC_SHA256" => 
        Symbol::int_val(ciphers::ECDH_ECDSA_WITH_AES_128_CBC_SHA256 as u64),
    "ECDH_ECDSA_WITH_AES_256_CBC_SHA384" => 
        Symbol::int_val(ciphers::ECDH_ECDSA_WITH_AES_256_CBC_SHA384 as u64),
    "ECDHE_RSA_WITH_AES_128_CBC_SHA256" => 
        Symbol::int_val(ciphers::ECDHE_RSA_WITH_AES_128_CBC_SHA256 as u64),
    "ECDHE_RSA_WITH_AES_256_CBC_SHA384" => 
        Symbol::int_val(ciphers::ECDHE_RSA_WITH_AES_256_CBC_SHA384 as u64),
    "ECDH_RSA_WITH_AES_128_CBC_SHA256" => 
        Symbol::int_val(ciphers::ECDH_RSA_WITH_AES_128_CBC_SHA256 as u64),
    "ECDH_RSA_WITH_AES_256_CBC_SHA384" => 
        Symbol::int_val(ciphers::ECDH_RSA_WITH_AES_256_CBC_SHA384 as u64),
    "ECDHE_ECDSA_WITH_AES_128_GCM_SHA256" => 
        Symbol::int_val(ciphers::ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 as u64),
    "ECDHE_ECDSA_WITH_AES_256_GCM_SHA384" => 
        Symbol::int_val(ciphers::ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 as u64),
    "ECDH_ECDSA_WITH_AES_128_GCM_SHA256" => 
        Symbol::int_val(ciphers::ECDH_ECDSA_WITH_AES_128_GCM_SHA256 as u64),
    "ECDH_ECDSA_WITH_AES_256_GCM_SHA384" => 
        Symbol::int_val(ciphers::ECDH_ECDSA_WITH_AES_256_GCM_SHA384 as u64),
    "ECDHE_RSA_WITH_AES_128_GCM_SHA256" => 
        Symbol::int_val(ciphers::ECDHE_RSA_WITH_AES_128_GCM_SHA256 as u64),
    "ECDHE_RSA_WITH_AES_256_GCM_SHA384" => 
        Symbol::int_val(ciphers::ECDHE_RSA_WITH_AES_256_GCM_SHA384 as u64),
    "ECDH_RSA_WITH_AES_128_GCM_SHA256" => 
        Symbol::int_val(ciphers::ECDH_RSA_WITH_AES_128_GCM_SHA256 as u64),
    "ECDH_RSA_WITH_AES_256_GCM_SHA384" => 
        Symbol::int_val(ciphers::ECDH_RSA_WITH_AES_256_GCM_SHA384 as u64),
    "ECDHE_PSK_WITH_RC4_128_SHA" => 
        Symbol::int_val(ciphers::ECDHE_PSK_WITH_RC4_128_SHA as u64),
    "ECDHE_PSK_WITH_3DES_EDE_CBC_SHA" => 
        Symbol::int_val(ciphers::ECDHE_PSK_WITH_3DES_EDE_CBC_SHA as u64),
    "ECDHE_PSK_WITH_AES_128_CBC_SHA" => 
        Symbol::int_val(ciphers::ECDHE_PSK_WITH_AES_128_CBC_SHA as u64),
    "ECDHE_PSK_WITH_AES_256_CBC_SHA" => 
        Symbol::int_val(ciphers::ECDHE_PSK_WITH_AES_256_CBC_SHA as u64),
    "ECDHE_PSK_WITH_AES_128_CBC_SHA256" => 
        Symbol::int_val(ciphers::ECDHE_PSK_WITH_AES_128_CBC_SHA256 as u64),
    "ECDHE_PSK_WITH_AES_256_CBC_SHA384" => 
        Symbol::int_val(ciphers::ECDHE_PSK_WITH_AES_256_CBC_SHA384 as u64),
    "ECDHE_PSK_WITH_NULL_SHA" => 
        Symbol::int_val(ciphers::ECDHE_PSK_WITH_NULL_SHA as u64),
    "ECDHE_PSK_WITH_NULL_SHA256" => 
        Symbol::int_val(ciphers::ECDHE_PSK_WITH_NULL_SHA256 as u64),
    "ECDHE_PSK_WITH_NULL_SHA384" => 
        Symbol::int_val(ciphers::ECDHE_PSK_WITH_NULL_SHA384 as u64),
    "RSA_WITH_ARIA_128_CBC_SHA256" => 
        Symbol::int_val(ciphers::RSA_WITH_ARIA_128_CBC_SHA256 as u64),
    "RSA_WITH_ARIA_256_CBC_SHA384" => 
        Symbol::int_val(ciphers::RSA_WITH_ARIA_256_CBC_SHA384 as u64),
    "DH_DSS_WITH_ARIA_128_CBC_SHA256" => 
        Symbol::int_val(ciphers::DH_DSS_WITH_ARIA_128_CBC_SHA256 as u64),
    "DH_DSS_WITH_ARIA_256_CBC_SHA384" => 
        Symbol::int_val(ciphers::DH_DSS_WITH_ARIA_256_CBC_SHA384 as u64),
    "DH_RSA_WITH_ARIA_128_CBC_SHA256" => 
        Symbol::int_val(ciphers::DH_RSA_WITH_ARIA_128_CBC_SHA256 as u64),
    "DH_RSA_WITH_ARIA_256_CBC_SHA384" => 
        Symbol::int_val(ciphers::DH_RSA_WITH_ARIA_256_CBC_SHA384 as u64),
    "DHE_DSS_WITH_ARIA_128_CBC_SHA256" => 
        Symbol::int_val(ciphers::DHE_DSS_WITH_ARIA_128_CBC_SHA256 as u64),
    "DHE_DSS_WITH_ARIA_256_CBC_SHA384" => 
        Symbol::int_val(ciphers::DHE_DSS_WITH_ARIA_256_CBC_SHA384 as u64),
    "DHE_RSA_WITH_ARIA_128_CBC_SHA256" => 
        Symbol::int_val(ciphers::DHE_RSA_WITH_ARIA_128_CBC_SHA256 as u64),
    "DHE_RSA_WITH_ARIA_256_CBC_SHA384" => 
        Symbol::int_val(ciphers::DHE_RSA_WITH_ARIA_256_CBC_SHA384 as u64),
    "DH_ANON_WITH_ARIA_128_CBC_SHA256" => 
        Symbol::int_val(ciphers::DH_ANON_WITH_ARIA_128_CBC_SHA256 as u64),
    "DH_ANON_WITH_ARIA_256_CBC_SHA384" => 
        Symbol::int_val(ciphers::DH_ANON_WITH_ARIA_256_CBC_SHA384 as u64),
    "ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256" => 
        Symbol::int_val(ciphers::ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256 as u64),
    "ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384" => 
        Symbol::int_val(ciphers::ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384 as u64),
    "ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256" => 
        Symbol::int_val(ciphers::ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256 as u64),
    "ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384" => 
        Symbol::int_val(ciphers::ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384 as u64),
    "ECDHE_RSA_WITH_ARIA_128_CBC_SHA256" => 
        Symbol::int_val(ciphers::ECDHE_RSA_WITH_ARIA_128_CBC_SHA256 as u64),
    "ECDHE_RSA_WITH_ARIA_256_CBC_SHA384" => 
        Symbol::int_val(ciphers::ECDHE_RSA_WITH_ARIA_256_CBC_SHA384 as u64),
    "ECDH_RSA_WITH_ARIA_128_CBC_SHA256" => 
        Symbol::int_val(ciphers::ECDH_RSA_WITH_ARIA_128_CBC_SHA256 as u64),
    "ECDH_RSA_WITH_ARIA_256_CBC_SHA384" => 
        Symbol::int_val(ciphers::ECDH_RSA_WITH_ARIA_256_CBC_SHA384 as u64),
    "RSA_WITH_ARIA_128_GCM_SHA256" => 
        Symbol::int_val(ciphers::RSA_WITH_ARIA_128_GCM_SHA256 as u64),
    "RSA_WITH_ARIA_256_GCM_SHA384" => 
        Symbol::int_val(ciphers::RSA_WITH_ARIA_256_GCM_SHA384 as u64),
    "DHE_RSA_WITH_ARIA_128_GCM_SHA256" => 
        Symbol::int_val(ciphers::DHE_RSA_WITH_ARIA_128_GCM_SHA256 as u64),
    "DHE_RSA_WITH_ARIA_256_GCM_SHA384" => 
        Symbol::int_val(ciphers::DHE_RSA_WITH_ARIA_256_GCM_SHA384 as u64),
    "DH_RSA_WITH_ARIA_128_GCM_SHA256" => 
        Symbol::int_val(ciphers::DH_RSA_WITH_ARIA_128_GCM_SHA256 as u64),
    "DH_RSA_WITH_ARIA_256_GCM_SHA384" => 
        Symbol::int_val(ciphers::DH_RSA_WITH_ARIA_256_GCM_SHA384 as u64),
    "DHE_DSS_WITH_ARIA_128_GCM_SHA256" => 
        Symbol::int_val(ciphers::DHE_DSS_WITH_ARIA_128_GCM_SHA256 as u64),
    "DHE_DSS_WITH_ARIA_256_GCM_SHA384" => 
        Symbol::int_val(ciphers::DHE_DSS_WITH_ARIA_256_GCM_SHA384 as u64),
    "DH_DSS_WITH_ARIA_128_GCM_SHA256" => 
        Symbol::int_val(ciphers::DH_DSS_WITH_ARIA_128_GCM_SHA256 as u64),
    "DH_DSS_WITH_ARIA_256_GCM_SHA384" => 
        Symbol::int_val(ciphers::DH_DSS_WITH_ARIA_256_GCM_SHA384 as u64),
    "DH_ANON_WITH_ARIA_128_GCM_SHA256" => 
        Symbol::int_val(ciphers::DH_ANON_WITH_ARIA_128_GCM_SHA256 as u64),
    "DH_ANON_WITH_ARIA_256_GCM_SHA384" => 
        Symbol::int_val(ciphers::DH_ANON_WITH_ARIA_256_GCM_SHA384 as u64),
    "ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256" => 
        Symbol::int_val(ciphers::ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256 as u64),
    "ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384" => 
        Symbol::int_val(ciphers::ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384 as u64),
    "ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256" => 
        Symbol::int_val(ciphers::ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256 as u64),
    "ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384" => 
        Symbol::int_val(ciphers::ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384 as u64),
    "ECDHE_RSA_WITH_ARIA_128_GCM_SHA256" => 
        Symbol::int_val(ciphers::ECDHE_RSA_WITH_ARIA_128_GCM_SHA256 as u64),
    "ECDHE_RSA_WITH_ARIA_256_GCM_SHA384" => 
        Symbol::int_val(ciphers::ECDHE_RSA_WITH_ARIA_256_GCM_SHA384 as u64),
    "ECDH_RSA_WITH_ARIA_128_GCM_SHA256" => 
        Symbol::int_val(ciphers::ECDH_RSA_WITH_ARIA_128_GCM_SHA256 as u64),
    "ECDH_RSA_WITH_ARIA_256_GCM_SHA384" => 
        Symbol::int_val(ciphers::ECDH_RSA_WITH_ARIA_256_GCM_SHA384 as u64),
    "PSK_WITH_ARIA_128_CBC_SHA256" => 
        Symbol::int_val(ciphers::PSK_WITH_ARIA_128_CBC_SHA256 as u64),
    "PSK_WITH_ARIA_256_CBC_SHA384" => 
        Symbol::int_val(ciphers::PSK_WITH_ARIA_256_CBC_SHA384 as u64),
    "DHE_PSK_WITH_ARIA_128_CBC_SHA256" => 
        Symbol::int_val(ciphers::DHE_PSK_WITH_ARIA_128_CBC_SHA256 as u64),
    "DHE_PSK_WITH_ARIA_256_CBC_SHA384" => 
        Symbol::int_val(ciphers::DHE_PSK_WITH_ARIA_256_CBC_SHA384 as u64),
    "RSA_PSK_WITH_ARIA_128_CBC_SHA256" => 
        Symbol::int_val(ciphers::RSA_PSK_WITH_ARIA_128_CBC_SHA256 as u64),
    "RSA_PSK_WITH_ARIA_256_CBC_SHA384" => 
        Symbol::int_val(ciphers::RSA_PSK_WITH_ARIA_256_CBC_SHA384 as u64),
    "PSK_WITH_ARIA_128_GCM_SHA256" => 
        Symbol::int_val(ciphers::PSK_WITH_ARIA_128_GCM_SHA256 as u64),
    "PSK_WITH_ARIA_256_GCM_SHA384" => 
        Symbol::int_val(ciphers::PSK_WITH_ARIA_256_GCM_SHA384 as u64),
    "DHE_PSK_WITH_ARIA_128_GCM_SHA256" => 
        Symbol::int_val(ciphers::DHE_PSK_WITH_ARIA_128_GCM_SHA256 as u64),
    "DHE_PSK_WITH_ARIA_256_GCM_SHA384" => 
        Symbol::int_val(ciphers::DHE_PSK_WITH_ARIA_256_GCM_SHA384 as u64),
    "RSA_PSK_WITH_ARIA_128_GCM_SHA256" => 
        Symbol::int_val(ciphers::RSA_PSK_WITH_ARIA_128_GCM_SHA256 as u64),
    "RSA_PSK_WITH_ARIA_256_GCM_SHA384" => 
        Symbol::int_val(ciphers::RSA_PSK_WITH_ARIA_256_GCM_SHA384 as u64),
    "ECDHE_PSK_WITH_ARIA_128_CBC_SHA256" => 
        Symbol::int_val(ciphers::ECDHE_PSK_WITH_ARIA_128_CBC_SHA256 as u64),
    "ECDHE_PSK_WITH_ARIA_256_CBC_SHA384" => 
        Symbol::int_val(ciphers::ECDHE_PSK_WITH_ARIA_256_CBC_SHA384 as u64),
    "ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256" => 
        Symbol::int_val(ciphers::ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 as u64),
    "ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384" => 
        Symbol::int_val(ciphers::ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 as u64),
    "ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256" => 
        Symbol::int_val(ciphers::ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 as u64),
    "ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384" => 
        Symbol::int_val(ciphers::ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 as u64),
    "ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256" => 
        Symbol::int_val(ciphers::ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 as u64),
    "ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384" => 
        Symbol::int_val(ciphers::ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384 as u64),
    "ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256" => 
        Symbol::int_val(ciphers::ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256 as u64),
    "ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384" => 
        Symbol::int_val(ciphers::ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384 as u64),
    "RSA_WITH_CAMELLIA_128_GCM_SHA256" => 
        Symbol::int_val(ciphers::RSA_WITH_CAMELLIA_128_GCM_SHA256 as u64),
    "RSA_WITH_CAMELLIA_256_GCM_SHA384" => 
        Symbol::int_val(ciphers::RSA_WITH_CAMELLIA_256_GCM_SHA384 as u64),
    "DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256" => 
        Symbol::int_val(ciphers::DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 as u64),
    "DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384" => 
        Symbol::int_val(ciphers::DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 as u64),
    "DH_RSA_WITH_CAMELLIA_128_GCM_SHA256" => 
        Symbol::int_val(ciphers::DH_RSA_WITH_CAMELLIA_128_GCM_SHA256 as u64),
    "DH_RSA_WITH_CAMELLIA_256_GCM_SHA384" => 
        Symbol::int_val(ciphers::DH_RSA_WITH_CAMELLIA_256_GCM_SHA384 as u64),
    "DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256" => 
        Symbol::int_val(ciphers::DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256 as u64),
    "DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384" => 
        Symbol::int_val(ciphers::DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384 as u64),
    "DH_DSS_WITH_CAMELLIA_128_GCM_SHA256" => 
        Symbol::int_val(ciphers::DH_DSS_WITH_CAMELLIA_128_GCM_SHA256 as u64),
    "DH_DSS_WITH_CAMELLIA_256_GCM_SHA384" => 
        Symbol::int_val(ciphers::DH_DSS_WITH_CAMELLIA_256_GCM_SHA384 as u64),
    "DH_ANON_WITH_CAMELLIA_128_GCM_SHA256" => 
        Symbol::int_val(ciphers::DH_ANON_WITH_CAMELLIA_128_GCM_SHA256 as u64),
    "DH_ANON_WITH_CAMELLIA_256_GCM_SHA384" => 
        Symbol::int_val(ciphers::DH_ANON_WITH_CAMELLIA_256_GCM_SHA384 as u64),
    "ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256" => 
        Symbol::int_val(ciphers::ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 as u64),
    "ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384" => 
        Symbol::int_val(ciphers::ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 as u64),
    "ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256" => 
        Symbol::int_val(ciphers::ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 as u64),
    "ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384" => 
        Symbol::int_val(ciphers::ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 as u64),
    "ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256" => 
        Symbol::int_val(ciphers::ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 as u64),
    "ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384" => 
        Symbol::int_val(ciphers::ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 as u64),
    "ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256" => 
        Symbol::int_val(ciphers::ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256 as u64),
    "ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384" => 
        Symbol::int_val(ciphers::ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384 as u64),
    "PSK_WITH_CAMELLIA_128_GCM_SHA256" => 
        Symbol::int_val(ciphers::PSK_WITH_CAMELLIA_128_GCM_SHA256 as u64),
    "PSK_WITH_CAMELLIA_256_GCM_SHA384" => 
        Symbol::int_val(ciphers::PSK_WITH_CAMELLIA_256_GCM_SHA384 as u64),
    "DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256" => 
        Symbol::int_val(ciphers::DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256 as u64),
    "DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384" => 
        Symbol::int_val(ciphers::DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384 as u64),
    "RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256" => 
        Symbol::int_val(ciphers::RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256 as u64),
    "RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384" => 
        Symbol::int_val(ciphers::RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384 as u64),
    "PSK_WITH_CAMELLIA_128_CBC_SHA256" => 
        Symbol::int_val(ciphers::PSK_WITH_CAMELLIA_128_CBC_SHA256 as u64),
    "PSK_WITH_CAMELLIA_256_CBC_SHA384" => 
        Symbol::int_val(ciphers::PSK_WITH_CAMELLIA_256_CBC_SHA384 as u64),
    "DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256" => 
        Symbol::int_val(ciphers::DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 as u64),
    "DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384" => 
        Symbol::int_val(ciphers::DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 as u64),
    "RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256" => 
        Symbol::int_val(ciphers::RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256 as u64),
    "RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384" => 
        Symbol::int_val(ciphers::RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384 as u64),
    "ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256" => 
        Symbol::int_val(ciphers::ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 as u64),
    "ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384" => 
        Symbol::int_val(ciphers::ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 as u64),
    "RSA_WITH_AES_128_CCM" => 
        Symbol::int_val(ciphers::RSA_WITH_AES_128_CCM as u64),
    "RSA_WITH_AES_256_CCM" => 
        Symbol::int_val(ciphers::RSA_WITH_AES_256_CCM as u64),
    "DHE_RSA_WITH_AES_128_CCM" => 
        Symbol::int_val(ciphers::DHE_RSA_WITH_AES_128_CCM as u64),
    "DHE_RSA_WITH_AES_256_CCM" => 
        Symbol::int_val(ciphers::DHE_RSA_WITH_AES_256_CCM as u64),
    "RSA_WITH_AES_128_CCM_8" => 
        Symbol::int_val(ciphers::RSA_WITH_AES_128_CCM_8 as u64),
    "RSA_WITH_AES_256_CCM_8" => 
        Symbol::int_val(ciphers::RSA_WITH_AES_256_CCM_8 as u64),
    "DHE_RSA_WITH_AES_128_CCM_8" => 
        Symbol::int_val(ciphers::DHE_RSA_WITH_AES_128_CCM_8 as u64),
    "DHE_RSA_WITH_AES_256_CCM_8" => 
        Symbol::int_val(ciphers::DHE_RSA_WITH_AES_256_CCM_8 as u64),
    "PSK_WITH_AES_128_CCM" => 
        Symbol::int_val(ciphers::PSK_WITH_AES_128_CCM as u64),
    "PSK_WITH_AES_256_CCM" => 
        Symbol::int_val(ciphers::PSK_WITH_AES_256_CCM as u64),
    "DHE_PSK_WITH_AES_128_CCM" => 
        Symbol::int_val(ciphers::DHE_PSK_WITH_AES_128_CCM as u64),
    "DHE_PSK_WITH_AES_256_CCM" => 
        Symbol::int_val(ciphers::DHE_PSK_WITH_AES_256_CCM as u64),
    "PSK_WITH_AES_128_CCM_8" => 
        Symbol::int_val(ciphers::PSK_WITH_AES_128_CCM_8 as u64),
    "PSK_WITH_AES_256_CCM_8" => 
        Symbol::int_val(ciphers::PSK_WITH_AES_256_CCM_8 as u64),
    "PSK_DHE_WITH_AES_128_CCM_8" => 
        Symbol::int_val(ciphers::PSK_DHE_WITH_AES_128_CCM_8 as u64),
    "PSK_DHE_WITH_AES_256_CCM_8" => 
        Symbol::int_val(ciphers::PSK_DHE_WITH_AES_256_CCM_8 as u64),
    "ECDHE_ECDSA_WITH_AES_128_CCM" => 
        Symbol::int_val(ciphers::ECDHE_ECDSA_WITH_AES_128_CCM as u64),
    "ECDHE_ECDSA_WITH_AES_256_CCM" => 
        Symbol::int_val(ciphers::ECDHE_ECDSA_WITH_AES_256_CCM as u64),
    "ECDHE_ECDSA_WITH_AES_128_CCM_8" => 
        Symbol::int_val(ciphers::ECDHE_ECDSA_WITH_AES_128_CCM_8 as u64),
    "ECDHE_ECDSA_WITH_AES_256_CCM_8" => 
        Symbol::int_val(ciphers::ECDHE_ECDSA_WITH_AES_256_CCM_8 as u64),
    "ECCPWD_WITH_AES_128_GCM_SHA256" => 
        Symbol::int_val(ciphers::ECCPWD_WITH_AES_128_GCM_SHA256 as u64),
    "ECCPWD_WITH_AES_256_GCM_SHA384" => 
        Symbol::int_val(ciphers::ECCPWD_WITH_AES_256_GCM_SHA384 as u64),
    "ECCPWD_WITH_AES_128_CCM_SHA256" => 
        Symbol::int_val(ciphers::ECCPWD_WITH_AES_128_CCM_SHA256 as u64),
    "ECCPWD_WITH_AES_256_CCM_SHA384" => 
        Symbol::int_val(ciphers::ECCPWD_WITH_AES_256_CCM_SHA384 as u64),
    "SHA256_SHA256" => 
        Symbol::int_val(ciphers::SHA256_SHA256 as u64),
    "SHA384_SHA384" => 
        Symbol::int_val(ciphers::SHA384_SHA384 as u64),
    "GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC" => 
        Symbol::int_val(ciphers::GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC as u64),
    "GOSTR341112_256_WITH_MAGMA_CTR_OMAC" => 
        Symbol::int_val(ciphers::GOSTR341112_256_WITH_MAGMA_CTR_OMAC as u64),
    "GOSTR341112_256_WITH_28147_CNT_IMIT" => 
        Symbol::int_val(ciphers::GOSTR341112_256_WITH_28147_CNT_IMIT as u64),
    "GOSTR341112_256_WITH_KUZNYECHIK_MGM_L" => 
        Symbol::int_val(ciphers::GOSTR341112_256_WITH_KUZNYECHIK_MGM_L as u64),
    "GOSTR341112_256_WITH_MAGMA_MGM_L" => 
        Symbol::int_val(ciphers::GOSTR341112_256_WITH_MAGMA_MGM_L as u64),
    "GOSTR341112_256_WITH_KUZNYECHIK_MGM_S" => 
        Symbol::int_val(ciphers::GOSTR341112_256_WITH_KUZNYECHIK_MGM_S as u64),
    "GOSTR341112_256_WITH_MAGMA_MGM_S" => 
        Symbol::int_val(ciphers::GOSTR341112_256_WITH_MAGMA_MGM_S as u64),
    "ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256" => 
        Symbol::int_val(ciphers::ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 as u64),
    "ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256" => 
        Symbol::int_val(ciphers::ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 as u64),
    "DHE_RSA_WITH_CHACHA20_POLY1305_SHA256" => 
        Symbol::int_val(ciphers::DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 as u64),
    "PSK_WITH_CHACHA20_POLY1305_SHA256" => 
        Symbol::int_val(ciphers::PSK_WITH_CHACHA20_POLY1305_SHA256 as u64),
    "ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256" => 
        Symbol::int_val(ciphers::ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256 as u64),
    "DHE_PSK_WITH_CHACHA20_POLY1305_SHA256" => 
        Symbol::int_val(ciphers::DHE_PSK_WITH_CHACHA20_POLY1305_SHA256 as u64),
    "RSA_PSK_WITH_CHACHA20_POLY1305_SHA256" => 
        Symbol::int_val(ciphers::RSA_PSK_WITH_CHACHA20_POLY1305_SHA256 as u64),
    "ECDHE_PSK_WITH_AES_128_GCM_SHA256" => 
        Symbol::int_val(ciphers::ECDHE_PSK_WITH_AES_128_GCM_SHA256 as u64),
    "ECDHE_PSK_WITH_AES_256_GCM_SHA384" => 
        Symbol::int_val(ciphers::ECDHE_PSK_WITH_AES_256_GCM_SHA384 as u64),
    "ECDHE_PSK_WITH_AES_128_CCM_8_SHA256" => 
        Symbol::int_val(ciphers::ECDHE_PSK_WITH_AES_128_CCM_8_SHA256 as u64),
    "ECDHE_PSK_WITH_AES_128_CCM_SHA256" => 
        Symbol::int_val(ciphers::ECDHE_PSK_WITH_AES_128_CCM_SHA256 as u64),
};

const TLS_MESSAGE: FuncDef = func_def! (
    "tls::message";
    ValType::Str;

    =>
    "version" => ValDef::U64(version::TLS_1_2 as u64),
    "content" => ValDef::U64(content::HANDSHAKE as u64),
    =>
    ValType::Str;

    |mut args| {
        let version: u64 = args.next().into();
        let content: u64 = args.next().into();
        let bytes: Buf = args.join_extra(b"").into();
        let mut msg: Vec<u8> = Vec::with_capacity(bytes.len() + 5);

        msg.extend((content as u8).to_be_bytes());
        msg.extend((version as u16).to_be_bytes());
        msg.extend((bytes.len() as u16).to_be_bytes());

		/* extensions I guess? */
        msg.extend(bytes.as_ref());

        Ok(Val::Str(Buf::from(msg)))
    }
);

fn len24(len: usize) -> [u8; 3] {
    let b = (len as u32).to_be_bytes();
    [b[1], b[2], b[3]]
}

const TLS_CIPHERS: FuncDef = func_def! (
    "tls::ciphers";
    ValType::Str;

    =>
    =>
    ValType::U64;

    |mut args| {
        let extra = args.extra_args();
        let list_len = extra.len() * 2;

        let mut msg: Vec<u8> = Vec::with_capacity(2 + list_len);


        msg.extend((list_len as u16).to_be_bytes());
        for cipher in extra {
            let id: u64 = cipher.into();
            msg.extend((id as u16).to_be_bytes());
        }

        Ok(Val::Str(Buf::from(msg)))
    }
);

const TLS_CLIENT_HELLO: FuncDef = func_def! (
    "tls::client_hello";
    ValType::Str;

    =>
    "version" => ValDef::U64(version::TLS_1_2 as u64),
    "sessionid" => ValDef::Str(b"\x00"),
    "ciphers" => ValDef::Str(b"\x00\x02\x00\x00"), // null cipher
    "compression" => ValDef::Str(b"\x01\x00"), // null compression
    =>
    ValType::Str;

    |mut args| {
        let version: u64 = args.next().into();
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

        let mut msg: Vec<u8> = Vec::with_capacity(4 + hlen as usize);

        /* 4 bytes handshake header */
        msg.push(handshake::CLIENT_HELLO);
        msg.extend(len24(hlen));

        /* 34 bytes version + random */
        msg.extend((version as u16).to_be_bytes());
        msg.extend(b"_client__random__client__random_");

        msg.extend(sessionid.as_ref());
        msg.extend(ciphers.as_ref());
        msg.extend(compression.as_ref());

        if extensions.len() > 0 {
            msg.extend((extensions.len() as u16).to_be_bytes());
            msg.extend(extensions.as_ref());
        }

        Ok(Val::Str(Buf::from(msg)))
    }
);

const TLS_SERVER_HELLO: FuncDef = func_def! (
    "tls::server_hello";
    ValType::Str;

    =>
    "version" => ValDef::U64(version::TLS_1_2 as u64),
    "sessionid" => ValDef::Str(b"\x00"),
    "cipher" => ValDef::U64(ciphers::NULL_WITH_NULL_NULL as u64),
    "compression" => ValDef::U64(0),
    =>
    ValType::Str;

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

        let mut msg: Vec<u8> = Vec::with_capacity(4 + hlen as usize);

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

        Ok(Val::Str(Buf::from(msg)))
    }
);

const TLS_SNI: FuncDef = func_def! (
    "tls::sni";
    ValType::Str;

    =>
    =>
    ValType::Str;

    |mut args| {
        let names = args.extra_args();
        let names_len: usize = names.iter().map(|x| -> Buf { x.into() }).map(|x| x.len()).sum();
        let name_list_len = 3 * names.len() + names_len;
        let tot_len = 2 + name_list_len;

        let mut msg: Vec<u8> = Vec::with_capacity(tot_len + 4);

        msg.extend(ext::SERVER_NAME.to_be_bytes());
        msg.extend((tot_len as u16).to_be_bytes());

        msg.extend((name_list_len as u16).to_be_bytes());
        for val in names {
            let name: Buf = val.into();
            msg.push(0);
            msg.extend((name.len() as u16).to_be_bytes());
            msg.extend(name.as_ref());
        }

        Ok(Val::Str(Buf::from(msg)))
    }
);

const TLS_CERTIFICATES: FuncDef = func_def! (
    "tls::certificates";
    ValType::Str;

    =>
    =>
    ValType::Str;

    |mut args| {
        let certs = args.extra_args();
        let certs_len: usize = certs.iter().map(|x| -> Buf { x.into() }).map(|x| x.len()).sum();
        let cert_list_len = 3 * certs.len() + certs_len;
        let tot_len = 3 + cert_list_len;

        let mut msg: Vec<u8> = Vec::with_capacity(tot_len + 4);

        msg.push(handshake::CERTIFICATE);
        msg.extend(len24(tot_len));

        msg.extend(len24(cert_list_len));
        for val in certs {
            let cert: Buf = val.into();
            msg.extend(len24(cert.len()));
            msg.extend(cert.as_ref());
        }

        Ok(Val::Str(Buf::from(msg)))
    }
);

pub const TLS: phf::Map<&'static str, Symbol> = phf_map! {
    "version" => Symbol::Module(&VERSION),
    "content" => Symbol::Module(&CONTENT),
    "handshake" => Symbol::Module(&HANDSHAKE),
    "ext" => Symbol::Module(&EXT),
    "cipher" => Symbol::Module(&CIPHER),

    "message" => Symbol::Func(&TLS_MESSAGE),
    "client_hello" => Symbol::Func(&TLS_CLIENT_HELLO),
    "server_hello" => Symbol::Func(&TLS_SERVER_HELLO),
    "ciphers" => Symbol::Func(&TLS_CIPHERS),
    "certificates" => Symbol::Func(&TLS_CERTIFICATES),
    "sni" => Symbol::Func(&TLS_SNI),
};
