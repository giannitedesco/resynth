pub mod version {
    pub const SSL_1: u16 = 0x0001;
    pub const SSL_2: u16 = 0x0002;
    pub const SSL_3: u16 = 0x0300;
    pub const TLS_1_0: u16 = 0x0301;
    pub const TLS_1_1: u16 = 0x0302;
    pub const TLS_1_2: u16 = 0x0303;
    pub const TLS_1_3: u16 = 0x0304;
}

pub mod content {
    pub const INVALID: u8 = 0;
    pub const CHANGE_CIPHER_SPEC: u8 = 20;
    pub const ALERT: u8 = 21;
    pub const HANDSHAKE: u8 = 22;
    pub const APP_DATA: u8 = 23;
    pub const HEARTBEAT: u8 = 24;
    pub const TLS12_CID: u8 = 25;
    pub const ACK: u8 = 26;
}

pub mod handshake {
    pub const HELLO_REQUEST: u8 = 0x00;
    pub const CLIENT_HELLO: u8 = 0x01;
    pub const SERVER_HELLO: u8 = 0x02;
    pub const HELLO_VERIFY_REQUEST: u8 = 0x03;
    pub const NEW_SESSION_TICKET: u8 = 0x04;
    pub const END_OF_EARLY_DATA: u8 = 0x05;
    pub const HELLO_RETRY_REQUEST: u8 = 0x06;
    pub const ENCRYPTED_EXTENSIONS: u8 = 0x08;
    pub const REQUESTCONNECTIONID: u8 = 0x09;
    pub const NEWCONNECTIONID: u8 = 0x0a;
    pub const CERTIFICATE: u8 = 0x0b;
    pub const SERVER_KEY_EXCHANGE: u8 = 0x0c;
    pub const CERTIFICATE_REQUEST: u8 = 0x0d;
    pub const SERVER_HELLO_DONE: u8 = 0x0e;
    pub const CERTIFICATE_VERIFY: u8 = 0x0f;
    pub const CLIENT_KEY_EXCHANGE: u8 = 0x10;
    pub const FINISHED: u8 = 0x14;
    pub const CERTIFICATE_URL: u8 = 0x15;
    pub const CERTIFICATE_STATUS: u8 = 0x16;
    pub const SUPPLEMENTAL_DATA: u8 = 0x17;
    pub const KEY_UPDATE: u8 = 0x18;
    pub const COMPRESSED_CERTIFICATE: u8 = 0x19;
    pub const EKT_KEY: u8 = 0x1a;
    pub const MESSAGE_HASH: u8 = 0xfe;
}

pub mod ext {
    pub const SERVER_NAME: u16 = 0x0000;
    pub const MAX_FRAGMENT_LENGTH: u16 = 0x0001;
    pub const CLIENT_CERTIFICATE_URL: u16 = 0x0002;
    pub const TRUSTED_CA_KEYS: u16 = 0x0003;
    pub const TRUNCATED_HMAC: u16 = 0x0004;
    pub const STATUS_REQUEST: u16 = 0x0005;
    pub const USER_MAPPING: u16 = 0x0006;
    pub const CLIENT_AUTHZ: u16 = 0x0007;
    pub const SERVER_AUTHZ: u16 = 0x0008;
    pub const CERT_TYPE: u16 = 0x0009;
    pub const SUPPORTED_GROUPS: u16 = 0x000a;
    pub const EC_POINT_FORMATS: u16 = 0x000b;
    pub const SRP: u16 = 0x000c;
    pub const SIGNATURE_ALGORITHMS: u16 = 0x000d;
    pub const USE_SRTP: u16 = 0x000e;
    pub const HEARTBEAT: u16 = 0x000f;
    pub const APPLICATION_LAYER_PROTOCOL_NEGOTIATION: u16 = 0x0010;
    pub const ALPN: u16 = APPLICATION_LAYER_PROTOCOL_NEGOTIATION;
    pub const STATUS_REQUEST_V2: u16 = 0x0011;
    pub const SIGNED_CERTIFICATE_TIMESTAMP: u16 = 0x0012;
    pub const CLIENT_CERTIFICATE_TYPE: u16 = 0x0013;
    pub const SERVER_CERTIFICATE_TYPE: u16 = 0x0014;
    pub const PADDING: u16 = 0x0015;
    pub const ENCRYPT_THEN_MAC: u16 = 0x0016;
    pub const EXTENDED_MASTER_SECRET: u16 = 0x0017;
    pub const TOKEN_BINDING: u16 = 0x0018;
    pub const CACHED_INFO: u16 = 0x0019;
    pub const TLS_LTS: u16 = 0x001a;
    pub const COMPRESS_CERTIFICATE: u16 = 0x001b;
    pub const RECORD_SIZE_LIMIT: u16 = 0x001c;
    pub const PWD_PROTECT: u16 = 0x001d;
    pub const PWD_CLEAR: u16 = 0x001e;
    pub const PASSWORD_SALT: u16 = 0x001f;
    pub const TICKET_PINNING: u16 = 0x0020;
    pub const TLS_CERT_WITH_EXTERN_PSK: u16 = 0x0021;
    pub const DELEGATED_CREDENTIALS: u16 = 0x0022;
    pub const SESSION_TICKET: u16 = 0x0023;
    pub const TLMSP: u16 = 0x0024;
    pub const TLMSP_PROXYING: u16 = 0x0025;
    pub const TLMSP_DELEGATE: u16 = 0x0026;
    pub const SUPPORTED_EKT_CIPHERS: u16 = 0x0027;
    pub const PRE_SHARED_KEY: u16 = 0x0029;
    pub const EARLY_DATA: u16 = 0x002a;
    pub const SUPPORTED_VERSIONS: u16 = 0x002b;
    pub const COOKIE: u16 = 0x002c;
    pub const PSK_KEY_EXCHANGE_MODES: u16 = 0x002d;
    pub const CERTIFICATE_AUTHORITIES: u16 = 0x002f;
    pub const OID_FILTERS: u16 = 0x0030;
    pub const POST_HANDSHAKE_AUTH: u16 = 0x0031;
    pub const SIGNATURE_ALGORITHMS_CERT: u16 = 0x0032;
    pub const KEY_SHARE: u16 = 0x0033;
    pub const TRANSPARENCY_INFO: u16 = 0x0034;
    pub const CONNECTION_ID_DEPRECATED: u16 = 0x0035;
    pub const CONNECTION_ID: u16 = 0x0036;
    pub const EXTERNAL_ID_HASH: u16 = 0x0037;
    pub const EXTERNAL_SESSION_ID: u16 = 0x0038;
    pub const QUIC_TRANSPORT_PARAMETERS: u16 = 0x0039;
    pub const TICKET_REQUEST: u16 = 0x003a;
    pub const DNSSEC_CHAIN: u16 = 0x003b;
    pub const RENEGOTIATION_INFO: u16 = 0xff01;
}

pub mod ciphers {
    pub const NULL_WITH_NULL_NULL: u16 = 0x0000;
    pub const RSA_WITH_NULL_MD5: u16 = 0x0001;
    pub const RSA_WITH_NULL_SHA: u16 = 0x0002;
    pub const RSA_EXPORT_WITH_RC4_40_MD5: u16 = 0x0003;
    pub const RSA_WITH_RC4_128_MD5: u16 = 0x0004;
    pub const RSA_WITH_RC4_128_SHA: u16 = 0x0005;
    pub const RSA_EXPORT_WITH_RC2_CBC_40_MD5: u16 = 0x0006;
    pub const RSA_WITH_IDEA_CBC_SHA: u16 = 0x0007;
    pub const RSA_EXPORT_WITH_DES40_CBC_SHA: u16 = 0x0008;
    pub const RSA_WITH_DES_CBC_SHA: u16 = 0x0009;
    pub const RSA_WITH_3DES_EDE_CBC_SHA: u16 = 0x000a;
    pub const DH_DSS_EXPORT_WITH_DES40_CBC_SHA: u16 = 0x000b;
    pub const DH_DSS_WITH_DES_CBC_SHA: u16 = 0x000c;
    pub const DH_DSS_WITH_3DES_EDE_CBC_SHA: u16 = 0x000d;
    pub const DH_RSA_EXPORT_WITH_DES40_CBC_SHA: u16 = 0x000e;
    pub const DH_RSA_WITH_DES_CBC_SHA: u16 = 0x000f;
    pub const DH_RSA_WITH_3DES_EDE_CBC_SHA: u16 = 0x0010;
    pub const DHE_DSS_EXPORT_WITH_DES40_CBC_SHA: u16 = 0x0011;
    pub const DHE_DSS_WITH_DES_CBC_SHA: u16 = 0x0012;
    pub const DHE_DSS_WITH_3DES_EDE_CBC_SHA: u16 = 0x0013;
    pub const DHE_RSA_EXPORT_WITH_DES40_CBC_SHA: u16 = 0x0014;
    pub const DHE_RSA_WITH_DES_CBC_SHA: u16 = 0x0015;
    pub const DHE_RSA_WITH_3DES_EDE_CBC_SHA: u16 = 0x0016;
    pub const DH_ANON_EXPORT_WITH_RC4_40_MD5: u16 = 0x0017;
    pub const DH_ANON_WITH_RC4_128_MD5: u16 = 0x0018;
    pub const DH_ANON_EXPORT_WITH_DES40_CBC_SHA: u16 = 0x0019;
    pub const DH_ANON_WITH_DES_CBC_SHA: u16 = 0x001a;
    pub const DH_ANON_WITH_3DES_EDE_CBC_SHA: u16 = 0x001b;
    pub const KRB5_WITH_DES_CBC_SHA: u16 = 0x001e;
    pub const KRB5_WITH_3DES_EDE_CBC_SHA: u16 = 0x001f;
    pub const KRB5_WITH_RC4_128_SHA: u16 = 0x0020;
    pub const KRB5_WITH_IDEA_CBC_SHA: u16 = 0x0021;
    pub const KRB5_WITH_DES_CBC_MD5: u16 = 0x0022;
    pub const KRB5_WITH_3DES_EDE_CBC_MD5: u16 = 0x0023;
    pub const KRB5_WITH_RC4_128_MD5: u16 = 0x0024;
    pub const KRB5_WITH_IDEA_CBC_MD5: u16 = 0x0025;
    pub const KRB5_EXPORT_WITH_DES_CBC_40_SHA: u16 = 0x0026;
    pub const KRB5_EXPORT_WITH_RC2_CBC_40_SHA: u16 = 0x0027;
    pub const KRB5_EXPORT_WITH_RC4_40_SHA: u16 = 0x0028;
    pub const KRB5_EXPORT_WITH_DES_CBC_40_MD5: u16 = 0x0029;
    pub const KRB5_EXPORT_WITH_RC2_CBC_40_MD5: u16 = 0x002a;
    pub const KRB5_EXPORT_WITH_RC4_40_MD5: u16 = 0x002b;
    pub const PSK_WITH_NULL_SHA: u16 = 0x002c;
    pub const DHE_PSK_WITH_NULL_SHA: u16 = 0x002d;
    pub const RSA_PSK_WITH_NULL_SHA: u16 = 0x002e;
    pub const RSA_WITH_AES_128_CBC_SHA: u16 = 0x002f;
    pub const DH_DSS_WITH_AES_128_CBC_SHA: u16 = 0x0030;
    pub const DH_RSA_WITH_AES_128_CBC_SHA: u16 = 0x0031;
    pub const DHE_DSS_WITH_AES_128_CBC_SHA: u16 = 0x0032;
    pub const DHE_RSA_WITH_AES_128_CBC_SHA: u16 = 0x0033;
    pub const DH_ANON_WITH_AES_128_CBC_SHA: u16 = 0x0034;
    pub const RSA_WITH_AES_256_CBC_SHA: u16 = 0x0035;
    pub const DH_DSS_WITH_AES_256_CBC_SHA: u16 = 0x0036;
    pub const DH_RSA_WITH_AES_256_CBC_SHA: u16 = 0x0037;
    pub const DHE_DSS_WITH_AES_256_CBC_SHA: u16 = 0x0038;
    pub const DHE_RSA_WITH_AES_256_CBC_SHA: u16 = 0x0039;
    pub const DH_ANON_WITH_AES_256_CBC_SHA: u16 = 0x003a;
    pub const RSA_WITH_NULL_SHA256: u16 = 0x003b;
    pub const RSA_WITH_AES_128_CBC_SHA256: u16 = 0x003c;
    pub const RSA_WITH_AES_256_CBC_SHA256: u16 = 0x003d;
    pub const DH_DSS_WITH_AES_128_CBC_SHA256: u16 = 0x003e;
    pub const DH_RSA_WITH_AES_128_CBC_SHA256: u16 = 0x003f;
    pub const DHE_DSS_WITH_AES_128_CBC_SHA256: u16 = 0x0040;
    pub const RSA_WITH_CAMELLIA_128_CBC_SHA: u16 = 0x0041;
    pub const DH_DSS_WITH_CAMELLIA_128_CBC_SHA: u16 = 0x0042;
    pub const DH_RSA_WITH_CAMELLIA_128_CBC_SHA: u16 = 0x0043;
    pub const DHE_DSS_WITH_CAMELLIA_128_CBC_SHA: u16 = 0x0044;
    pub const DHE_RSA_WITH_CAMELLIA_128_CBC_SHA: u16 = 0x0045;
    pub const DH_ANON_WITH_CAMELLIA_128_CBC_SHA: u16 = 0x0046;
    pub const DHE_RSA_WITH_AES_128_CBC_SHA256: u16 = 0x0067;
    pub const DH_DSS_WITH_AES_256_CBC_SHA256: u16 = 0x0068;
    pub const DH_RSA_WITH_AES_256_CBC_SHA256: u16 = 0x0069;
    pub const DHE_DSS_WITH_AES_256_CBC_SHA256: u16 = 0x006a;
    pub const DHE_RSA_WITH_AES_256_CBC_SHA256: u16 = 0x006b;
    pub const DH_ANON_WITH_AES_128_CBC_SHA256: u16 = 0x006c;
    pub const DH_ANON_WITH_AES_256_CBC_SHA256: u16 = 0x006d;
    pub const RSA_WITH_CAMELLIA_256_CBC_SHA: u16 = 0x0084;
    pub const DH_DSS_WITH_CAMELLIA_256_CBC_SHA: u16 = 0x0085;
    pub const DH_RSA_WITH_CAMELLIA_256_CBC_SHA: u16 = 0x0086;
    pub const DHE_DSS_WITH_CAMELLIA_256_CBC_SHA: u16 = 0x0087;
    pub const DHE_RSA_WITH_CAMELLIA_256_CBC_SHA: u16 = 0x0088;
    pub const DH_ANON_WITH_CAMELLIA_256_CBC_SHA: u16 = 0x0089;
    pub const PSK_WITH_RC4_128_SHA: u16 = 0x008a;
    pub const PSK_WITH_3DES_EDE_CBC_SHA: u16 = 0x008b;
    pub const PSK_WITH_AES_128_CBC_SHA: u16 = 0x008c;
    pub const PSK_WITH_AES_256_CBC_SHA: u16 = 0x008d;
    pub const DHE_PSK_WITH_RC4_128_SHA: u16 = 0x008e;
    pub const DHE_PSK_WITH_3DES_EDE_CBC_SHA: u16 = 0x008f;
    pub const DHE_PSK_WITH_AES_128_CBC_SHA: u16 = 0x0090;
    pub const DHE_PSK_WITH_AES_256_CBC_SHA: u16 = 0x0091;
    pub const RSA_PSK_WITH_RC4_128_SHA: u16 = 0x0092;
    pub const RSA_PSK_WITH_3DES_EDE_CBC_SHA: u16 = 0x0093;
    pub const RSA_PSK_WITH_AES_128_CBC_SHA: u16 = 0x0094;
    pub const RSA_PSK_WITH_AES_256_CBC_SHA: u16 = 0x0095;
    pub const RSA_WITH_SEED_CBC_SHA: u16 = 0x0096;
    pub const DH_DSS_WITH_SEED_CBC_SHA: u16 = 0x0097;
    pub const DH_RSA_WITH_SEED_CBC_SHA: u16 = 0x0098;
    pub const DHE_DSS_WITH_SEED_CBC_SHA: u16 = 0x0099;
    pub const DHE_RSA_WITH_SEED_CBC_SHA: u16 = 0x009a;
    pub const DH_ANON_WITH_SEED_CBC_SHA: u16 = 0x009b;
    pub const RSA_WITH_AES_128_GCM_SHA256: u16 = 0x009c;
    pub const RSA_WITH_AES_256_GCM_SHA384: u16 = 0x009d;
    pub const DHE_RSA_WITH_AES_128_GCM_SHA256: u16 = 0x009e;
    pub const DHE_RSA_WITH_AES_256_GCM_SHA384: u16 = 0x009f;
    pub const DH_RSA_WITH_AES_128_GCM_SHA256: u16 = 0x00a0;
    pub const DH_RSA_WITH_AES_256_GCM_SHA384: u16 = 0x00a1;
    pub const DHE_DSS_WITH_AES_128_GCM_SHA256: u16 = 0x00a2;
    pub const DHE_DSS_WITH_AES_256_GCM_SHA384: u16 = 0x00a3;
    pub const DH_DSS_WITH_AES_128_GCM_SHA256: u16 = 0x00a4;
    pub const DH_DSS_WITH_AES_256_GCM_SHA384: u16 = 0x00a5;
    pub const DH_ANON_WITH_AES_128_GCM_SHA256: u16 = 0x00a6;
    pub const DH_ANON_WITH_AES_256_GCM_SHA384: u16 = 0x00a7;
    pub const PSK_WITH_AES_128_GCM_SHA256: u16 = 0x00a8;
    pub const PSK_WITH_AES_256_GCM_SHA384: u16 = 0x00a9;
    pub const DHE_PSK_WITH_AES_128_GCM_SHA256: u16 = 0x00aa;
    pub const DHE_PSK_WITH_AES_256_GCM_SHA384: u16 = 0x00ab;
    pub const RSA_PSK_WITH_AES_128_GCM_SHA256: u16 = 0x00ac;
    pub const RSA_PSK_WITH_AES_256_GCM_SHA384: u16 = 0x00ad;
    pub const PSK_WITH_AES_128_CBC_SHA256: u16 = 0x00ae;
    pub const PSK_WITH_AES_256_CBC_SHA384: u16 = 0x00af;
    pub const PSK_WITH_NULL_SHA256: u16 = 0x00b0;
    pub const PSK_WITH_NULL_SHA384: u16 = 0x00b1;
    pub const DHE_PSK_WITH_AES_128_CBC_SHA256: u16 = 0x00b2;
    pub const DHE_PSK_WITH_AES_256_CBC_SHA384: u16 = 0x00b3;
    pub const DHE_PSK_WITH_NULL_SHA256: u16 = 0x00b4;
    pub const DHE_PSK_WITH_NULL_SHA384: u16 = 0x00b5;
    pub const RSA_PSK_WITH_AES_128_CBC_SHA256: u16 = 0x00b6;
    pub const RSA_PSK_WITH_AES_256_CBC_SHA384: u16 = 0x00b7;
    pub const RSA_PSK_WITH_NULL_SHA256: u16 = 0x00b8;
    pub const RSA_PSK_WITH_NULL_SHA384: u16 = 0x00b9;
    pub const RSA_WITH_CAMELLIA_128_CBC_SHA256: u16 = 0x00ba;
    pub const DH_DSS_WITH_CAMELLIA_128_CBC_SHA256: u16 = 0x00bb;
    pub const DH_RSA_WITH_CAMELLIA_128_CBC_SHA256: u16 = 0x00bc;
    pub const DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256: u16 = 0x00bd;
    pub const DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256: u16 = 0x00be;
    pub const DH_ANON_WITH_CAMELLIA_128_CBC_SHA256: u16 = 0x00bf;
    pub const RSA_WITH_CAMELLIA_256_CBC_SHA256: u16 = 0x00c0;
    pub const DH_DSS_WITH_CAMELLIA_256_CBC_SHA256: u16 = 0x00c1;
    pub const DH_RSA_WITH_CAMELLIA_256_CBC_SHA256: u16 = 0x00c2;
    pub const DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256: u16 = 0x00c3;
    pub const DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256: u16 = 0x00c4;
    pub const DH_ANON_WITH_CAMELLIA_256_CBC_SHA256: u16 = 0x00c5;
    pub const SM4_GCM_SM3: u16 = 0x00c6;
    pub const SM4_CCM_SM3: u16 = 0x00c7;
    pub const EMPTY_RENEGOTIATION_INFO_SCSV: u16 = 0x00ff;
    pub const AES_128_GCM_SHA256: u16 = 0x1301;
    pub const AES_256_GCM_SHA384: u16 = 0x1302;
    pub const CHACHA20_POLY1305_SHA256: u16 = 0x1303;
    pub const AES_128_CCM_SHA256: u16 = 0x1304;
    pub const AES_128_CCM_8_SHA256: u16 = 0x1305;
    pub const FALLBACK_SCSV: u16 = 0x5600;
    pub const ECDH_ECDSA_WITH_NULL_SHA: u16 = 0xc001;
    pub const ECDH_ECDSA_WITH_RC4_128_SHA: u16 = 0xc002;
    pub const ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA: u16 = 0xc003;
    pub const ECDH_ECDSA_WITH_AES_128_CBC_SHA: u16 = 0xc004;
    pub const ECDH_ECDSA_WITH_AES_256_CBC_SHA: u16 = 0xc005;
    pub const ECDHE_ECDSA_WITH_NULL_SHA: u16 = 0xc006;
    pub const ECDHE_ECDSA_WITH_RC4_128_SHA: u16 = 0xc007;
    pub const ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA: u16 = 0xc008;
    pub const ECDHE_ECDSA_WITH_AES_128_CBC_SHA: u16 = 0xc009;
    pub const ECDHE_ECDSA_WITH_AES_256_CBC_SHA: u16 = 0xc00a;
    pub const ECDH_RSA_WITH_NULL_SHA: u16 = 0xc00b;
    pub const ECDH_RSA_WITH_RC4_128_SHA: u16 = 0xc00c;
    pub const ECDH_RSA_WITH_3DES_EDE_CBC_SHA: u16 = 0xc00d;
    pub const ECDH_RSA_WITH_AES_128_CBC_SHA: u16 = 0xc00e;
    pub const ECDH_RSA_WITH_AES_256_CBC_SHA: u16 = 0xc00f;
    pub const ECDHE_RSA_WITH_NULL_SHA: u16 = 0xc010;
    pub const ECDHE_RSA_WITH_RC4_128_SHA: u16 = 0xc011;
    pub const ECDHE_RSA_WITH_3DES_EDE_CBC_SHA: u16 = 0xc012;
    pub const ECDHE_RSA_WITH_AES_128_CBC_SHA: u16 = 0xc013;
    pub const ECDHE_RSA_WITH_AES_256_CBC_SHA: u16 = 0xc014;
    pub const ECDH_ANON_WITH_NULL_SHA: u16 = 0xc015;
    pub const ECDH_ANON_WITH_RC4_128_SHA: u16 = 0xc016;
    pub const ECDH_ANON_WITH_3DES_EDE_CBC_SHA: u16 = 0xc017;
    pub const ECDH_ANON_WITH_AES_128_CBC_SHA: u16 = 0xc018;
    pub const ECDH_ANON_WITH_AES_256_CBC_SHA: u16 = 0xc019;
    pub const SRP_SHA_WITH_3DES_EDE_CBC_SHA: u16 = 0xc01a;
    pub const SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA: u16 = 0xc01b;
    pub const SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA: u16 = 0xc01c;
    pub const SRP_SHA_WITH_AES_128_CBC_SHA: u16 = 0xc01d;
    pub const SRP_SHA_RSA_WITH_AES_128_CBC_SHA: u16 = 0xc01e;
    pub const SRP_SHA_DSS_WITH_AES_128_CBC_SHA: u16 = 0xc01f;
    pub const SRP_SHA_WITH_AES_256_CBC_SHA: u16 = 0xc020;
    pub const SRP_SHA_RSA_WITH_AES_256_CBC_SHA: u16 = 0xc021;
    pub const SRP_SHA_DSS_WITH_AES_256_CBC_SHA: u16 = 0xc022;
    pub const ECDHE_ECDSA_WITH_AES_128_CBC_SHA256: u16 = 0xc023;
    pub const ECDHE_ECDSA_WITH_AES_256_CBC_SHA384: u16 = 0xc024;
    pub const ECDH_ECDSA_WITH_AES_128_CBC_SHA256: u16 = 0xc025;
    pub const ECDH_ECDSA_WITH_AES_256_CBC_SHA384: u16 = 0xc026;
    pub const ECDHE_RSA_WITH_AES_128_CBC_SHA256: u16 = 0xc027;
    pub const ECDHE_RSA_WITH_AES_256_CBC_SHA384: u16 = 0xc028;
    pub const ECDH_RSA_WITH_AES_128_CBC_SHA256: u16 = 0xc029;
    pub const ECDH_RSA_WITH_AES_256_CBC_SHA384: u16 = 0xc02a;
    pub const ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: u16 = 0xc02b;
    pub const ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: u16 = 0xc02c;
    pub const ECDH_ECDSA_WITH_AES_128_GCM_SHA256: u16 = 0xc02d;
    pub const ECDH_ECDSA_WITH_AES_256_GCM_SHA384: u16 = 0xc02e;
    pub const ECDHE_RSA_WITH_AES_128_GCM_SHA256: u16 = 0xc02f;
    pub const ECDHE_RSA_WITH_AES_256_GCM_SHA384: u16 = 0xc030;
    pub const ECDH_RSA_WITH_AES_128_GCM_SHA256: u16 = 0xc031;
    pub const ECDH_RSA_WITH_AES_256_GCM_SHA384: u16 = 0xc032;
    pub const ECDHE_PSK_WITH_RC4_128_SHA: u16 = 0xc033;
    pub const ECDHE_PSK_WITH_3DES_EDE_CBC_SHA: u16 = 0xc034;
    pub const ECDHE_PSK_WITH_AES_128_CBC_SHA: u16 = 0xc035;
    pub const ECDHE_PSK_WITH_AES_256_CBC_SHA: u16 = 0xc036;
    pub const ECDHE_PSK_WITH_AES_128_CBC_SHA256: u16 = 0xc037;
    pub const ECDHE_PSK_WITH_AES_256_CBC_SHA384: u16 = 0xc038;
    pub const ECDHE_PSK_WITH_NULL_SHA: u16 = 0xc039;
    pub const ECDHE_PSK_WITH_NULL_SHA256: u16 = 0xc03a;
    pub const ECDHE_PSK_WITH_NULL_SHA384: u16 = 0xc03b;
    pub const RSA_WITH_ARIA_128_CBC_SHA256: u16 = 0xc03c;
    pub const RSA_WITH_ARIA_256_CBC_SHA384: u16 = 0xc03d;
    pub const DH_DSS_WITH_ARIA_128_CBC_SHA256: u16 = 0xc03e;
    pub const DH_DSS_WITH_ARIA_256_CBC_SHA384: u16 = 0xc03f;
    pub const DH_RSA_WITH_ARIA_128_CBC_SHA256: u16 = 0xc040;
    pub const DH_RSA_WITH_ARIA_256_CBC_SHA384: u16 = 0xc041;
    pub const DHE_DSS_WITH_ARIA_128_CBC_SHA256: u16 = 0xc042;
    pub const DHE_DSS_WITH_ARIA_256_CBC_SHA384: u16 = 0xc043;
    pub const DHE_RSA_WITH_ARIA_128_CBC_SHA256: u16 = 0xc044;
    pub const DHE_RSA_WITH_ARIA_256_CBC_SHA384: u16 = 0xc045;
    pub const DH_ANON_WITH_ARIA_128_CBC_SHA256: u16 = 0xc046;
    pub const DH_ANON_WITH_ARIA_256_CBC_SHA384: u16 = 0xc047;
    pub const ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256: u16 = 0xc048;
    pub const ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384: u16 = 0xc049;
    pub const ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256: u16 = 0xc04a;
    pub const ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384: u16 = 0xc04b;
    pub const ECDHE_RSA_WITH_ARIA_128_CBC_SHA256: u16 = 0xc04c;
    pub const ECDHE_RSA_WITH_ARIA_256_CBC_SHA384: u16 = 0xc04d;
    pub const ECDH_RSA_WITH_ARIA_128_CBC_SHA256: u16 = 0xc04e;
    pub const ECDH_RSA_WITH_ARIA_256_CBC_SHA384: u16 = 0xc04f;
    pub const RSA_WITH_ARIA_128_GCM_SHA256: u16 = 0xc050;
    pub const RSA_WITH_ARIA_256_GCM_SHA384: u16 = 0xc051;
    pub const DHE_RSA_WITH_ARIA_128_GCM_SHA256: u16 = 0xc052;
    pub const DHE_RSA_WITH_ARIA_256_GCM_SHA384: u16 = 0xc053;
    pub const DH_RSA_WITH_ARIA_128_GCM_SHA256: u16 = 0xc054;
    pub const DH_RSA_WITH_ARIA_256_GCM_SHA384: u16 = 0xc055;
    pub const DHE_DSS_WITH_ARIA_128_GCM_SHA256: u16 = 0xc056;
    pub const DHE_DSS_WITH_ARIA_256_GCM_SHA384: u16 = 0xc057;
    pub const DH_DSS_WITH_ARIA_128_GCM_SHA256: u16 = 0xc058;
    pub const DH_DSS_WITH_ARIA_256_GCM_SHA384: u16 = 0xc059;
    pub const DH_ANON_WITH_ARIA_128_GCM_SHA256: u16 = 0xc05a;
    pub const DH_ANON_WITH_ARIA_256_GCM_SHA384: u16 = 0xc05b;
    pub const ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256: u16 = 0xc05c;
    pub const ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384: u16 = 0xc05d;
    pub const ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256: u16 = 0xc05e;
    pub const ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384: u16 = 0xc05f;
    pub const ECDHE_RSA_WITH_ARIA_128_GCM_SHA256: u16 = 0xc060;
    pub const ECDHE_RSA_WITH_ARIA_256_GCM_SHA384: u16 = 0xc061;
    pub const ECDH_RSA_WITH_ARIA_128_GCM_SHA256: u16 = 0xc062;
    pub const ECDH_RSA_WITH_ARIA_256_GCM_SHA384: u16 = 0xc063;
    pub const PSK_WITH_ARIA_128_CBC_SHA256: u16 = 0xc064;
    pub const PSK_WITH_ARIA_256_CBC_SHA384: u16 = 0xc065;
    pub const DHE_PSK_WITH_ARIA_128_CBC_SHA256: u16 = 0xc066;
    pub const DHE_PSK_WITH_ARIA_256_CBC_SHA384: u16 = 0xc067;
    pub const RSA_PSK_WITH_ARIA_128_CBC_SHA256: u16 = 0xc068;
    pub const RSA_PSK_WITH_ARIA_256_CBC_SHA384: u16 = 0xc069;
    pub const PSK_WITH_ARIA_128_GCM_SHA256: u16 = 0xc06a;
    pub const PSK_WITH_ARIA_256_GCM_SHA384: u16 = 0xc06b;
    pub const DHE_PSK_WITH_ARIA_128_GCM_SHA256: u16 = 0xc06c;
    pub const DHE_PSK_WITH_ARIA_256_GCM_SHA384: u16 = 0xc06d;
    pub const RSA_PSK_WITH_ARIA_128_GCM_SHA256: u16 = 0xc06e;
    pub const RSA_PSK_WITH_ARIA_256_GCM_SHA384: u16 = 0xc06f;
    pub const ECDHE_PSK_WITH_ARIA_128_CBC_SHA256: u16 = 0xc070;
    pub const ECDHE_PSK_WITH_ARIA_256_CBC_SHA384: u16 = 0xc071;
    pub const ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256: u16 = 0xc072;
    pub const ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384: u16 = 0xc073;
    pub const ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256: u16 = 0xc074;
    pub const ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384: u16 = 0xc075;
    pub const ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256: u16 = 0xc076;
    pub const ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384: u16 = 0xc077;
    pub const ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256: u16 = 0xc078;
    pub const ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384: u16 = 0xc079;
    pub const RSA_WITH_CAMELLIA_128_GCM_SHA256: u16 = 0xc07a;
    pub const RSA_WITH_CAMELLIA_256_GCM_SHA384: u16 = 0xc07b;
    pub const DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256: u16 = 0xc07c;
    pub const DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384: u16 = 0xc07d;
    pub const DH_RSA_WITH_CAMELLIA_128_GCM_SHA256: u16 = 0xc07e;
    pub const DH_RSA_WITH_CAMELLIA_256_GCM_SHA384: u16 = 0xc07f;
    pub const DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256: u16 = 0xc080;
    pub const DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384: u16 = 0xc081;
    pub const DH_DSS_WITH_CAMELLIA_128_GCM_SHA256: u16 = 0xc082;
    pub const DH_DSS_WITH_CAMELLIA_256_GCM_SHA384: u16 = 0xc083;
    pub const DH_ANON_WITH_CAMELLIA_128_GCM_SHA256: u16 = 0xc084;
    pub const DH_ANON_WITH_CAMELLIA_256_GCM_SHA384: u16 = 0xc085;
    pub const ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256: u16 = 0xc086;
    pub const ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384: u16 = 0xc087;
    pub const ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256: u16 = 0xc088;
    pub const ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384: u16 = 0xc089;
    pub const ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256: u16 = 0xc08a;
    pub const ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384: u16 = 0xc08b;
    pub const ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256: u16 = 0xc08c;
    pub const ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384: u16 = 0xc08d;
    pub const PSK_WITH_CAMELLIA_128_GCM_SHA256: u16 = 0xc08e;
    pub const PSK_WITH_CAMELLIA_256_GCM_SHA384: u16 = 0xc08f;
    pub const DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256: u16 = 0xc090;
    pub const DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384: u16 = 0xc091;
    pub const RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256: u16 = 0xc092;
    pub const RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384: u16 = 0xc093;
    pub const PSK_WITH_CAMELLIA_128_CBC_SHA256: u16 = 0xc094;
    pub const PSK_WITH_CAMELLIA_256_CBC_SHA384: u16 = 0xc095;
    pub const DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256: u16 = 0xc096;
    pub const DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384: u16 = 0xc097;
    pub const RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256: u16 = 0xc098;
    pub const RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384: u16 = 0xc099;
    pub const ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256: u16 = 0xc09a;
    pub const ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384: u16 = 0xc09b;
    pub const RSA_WITH_AES_128_CCM: u16 = 0xc09c;
    pub const RSA_WITH_AES_256_CCM: u16 = 0xc09d;
    pub const DHE_RSA_WITH_AES_128_CCM: u16 = 0xc09e;
    pub const DHE_RSA_WITH_AES_256_CCM: u16 = 0xc09f;
    pub const RSA_WITH_AES_128_CCM_8: u16 = 0xc0a0;
    pub const RSA_WITH_AES_256_CCM_8: u16 = 0xc0a1;
    pub const DHE_RSA_WITH_AES_128_CCM_8: u16 = 0xc0a2;
    pub const DHE_RSA_WITH_AES_256_CCM_8: u16 = 0xc0a3;
    pub const PSK_WITH_AES_128_CCM: u16 = 0xc0a4;
    pub const PSK_WITH_AES_256_CCM: u16 = 0xc0a5;
    pub const DHE_PSK_WITH_AES_128_CCM: u16 = 0xc0a6;
    pub const DHE_PSK_WITH_AES_256_CCM: u16 = 0xc0a7;
    pub const PSK_WITH_AES_128_CCM_8: u16 = 0xc0a8;
    pub const PSK_WITH_AES_256_CCM_8: u16 = 0xc0a9;
    pub const PSK_DHE_WITH_AES_128_CCM_8: u16 = 0xc0aa;
    pub const PSK_DHE_WITH_AES_256_CCM_8: u16 = 0xc0ab;
    pub const ECDHE_ECDSA_WITH_AES_128_CCM: u16 = 0xc0ac;
    pub const ECDHE_ECDSA_WITH_AES_256_CCM: u16 = 0xc0ad;
    pub const ECDHE_ECDSA_WITH_AES_128_CCM_8: u16 = 0xc0ae;
    pub const ECDHE_ECDSA_WITH_AES_256_CCM_8: u16 = 0xc0af;
    pub const ECCPWD_WITH_AES_128_GCM_SHA256: u16 = 0xc0b0;
    pub const ECCPWD_WITH_AES_256_GCM_SHA384: u16 = 0xc0b1;
    pub const ECCPWD_WITH_AES_128_CCM_SHA256: u16 = 0xc0b2;
    pub const ECCPWD_WITH_AES_256_CCM_SHA384: u16 = 0xc0b3;
    pub const SHA256_SHA256: u16 = 0xc0b4;
    pub const SHA384_SHA384: u16 = 0xc0b5;
    pub const GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC: u16 = 0xc100;
    pub const GOSTR341112_256_WITH_MAGMA_CTR_OMAC: u16 = 0xc101;
    pub const GOSTR341112_256_WITH_28147_CNT_IMIT: u16 = 0xc102;
    pub const GOSTR341112_256_WITH_KUZNYECHIK_MGM_L: u16 = 0xc103;
    pub const GOSTR341112_256_WITH_MAGMA_MGM_L: u16 = 0xc104;
    pub const GOSTR341112_256_WITH_KUZNYECHIK_MGM_S: u16 = 0xc105;
    pub const GOSTR341112_256_WITH_MAGMA_MGM_S: u16 = 0xc106;
    pub const ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: u16 = 0xcca8;
    pub const ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: u16 = 0xcca9;
    pub const DHE_RSA_WITH_CHACHA20_POLY1305_SHA256: u16 = 0xccaa;
    pub const PSK_WITH_CHACHA20_POLY1305_SHA256: u16 = 0xccab;
    pub const ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256: u16 = 0xccac;
    pub const DHE_PSK_WITH_CHACHA20_POLY1305_SHA256: u16 = 0xccad;
    pub const RSA_PSK_WITH_CHACHA20_POLY1305_SHA256: u16 = 0xccae;
    pub const ECDHE_PSK_WITH_AES_128_GCM_SHA256: u16 = 0xd001;
    pub const ECDHE_PSK_WITH_AES_256_GCM_SHA384: u16 = 0xd002;
    pub const ECDHE_PSK_WITH_AES_128_CCM_8_SHA256: u16 = 0xd003;
    pub const ECDHE_PSK_WITH_AES_128_CCM_SHA256: u16 = 0xd005;
}
