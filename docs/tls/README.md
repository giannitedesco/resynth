 # Transport Layer Security (TLS)

 Construct TLS handshake traffic over a TCP flow. The module provides record framing
 ([message](#message)), handshake message builders ([client_hello](#client_hello),
 [server_hello](#server_hello), [certificates](#certificates)), and extension helpers
 ([extension](#extension), [sni](#sni), [ciphers](#ciphers)).

 ## Full handshake example

 ### Setup — open a TCP connection

 ```resynth
 import io;
 import ipv4;
 import std;
 import tls;

 let tls = ipv4::tcp::flow(
   192.168.106.72:40015,
   172.16.14.121:443,
 );

 tls.open();
 ```

 ### Client Hello

 The client advertises a minimal modern cipher suite list and a handful of extensions.
 The outer record uses [tls::version::TLS_1_0](version/README.md) for broad
 compatibility; the inner `client_hello` requests
 [tls::version::TLS_1_2](version/README.md).

 ```resynth
 tls.client_message(
   tls::message(
     content: tls::content::HANDSHAKE,
     version: tls::version::TLS_1_0,
     tls::client_hello(
       version: tls::version::TLS_1_2,
       ciphers: tls::ciphers(
         tls::cipher::ECDHE_RSA_WITH_AES_256_GCM_SHA384,
         tls::cipher::ECDHE_RSA_WITH_AES_128_GCM_SHA256,
         tls::cipher::ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
         tls::cipher::EMPTY_RENEGOTIATION_INFO_SCSV,
       ),
       tls::sni("test.local"),
       tls::extension(tls::ext::SESSION_TICKET),
       tls::extension(tls::ext::EXTENDED_MASTER_SECRET),
       tls::extension(
         tls::ext::EC_POINT_FORMATS,
         std::len_u8("|00 01 02|"),
       ),
       tls::extension(
         tls::ext::ALPN,
         std::len_be16(
           std::len_u8("http/0.9"),
           std::len_u8("pop3"),
         ),
       ),
     )
   ),
 );
 ```

 ### Server Hello, Certificate, and Server Hello Done

 The server responds with its chosen cipher suite and extensions, followed by its
 certificate chain, and a Server Hello Done to signal it is ready for key exchange.
 All three messages are bundled into a single `server_message` call so they arrive
 in the same TCP segment.

 ```resynth
 tls.server_message(
   // Server Hello — negotiate cipher and extensions
   tls::message(
     content: tls::content::HANDSHAKE,
     version: tls::version::TLS_1_2,
     tls::server_hello(
       version: tls::version::TLS_1_2,
       cipher: tls::cipher::ECDHE_RSA_WITH_AES_256_GCM_SHA384,
       tls::extension(tls::ext::RENEGOTIATION_INFO, std::u8(0)),
       tls::extension(
         tls::ext::EC_POINT_FORMATS,
         std::len_u8("|00 01 02|"),
       ),
       tls::extension(tls::ext::SESSION_TICKET),
       tls::extension(tls::ext::EXTENDED_MASTER_SECRET),
       tls::extension(
         tls::ext::ALPN,
         std::len_be16(std::len_u8("http/0.9")),
       ),
     ),
   ),

   // Certificate — DER-encoded X.509 certificate chain
   tls::message(
     content: tls::content::HANDSHAKE,
     version: tls::version::TLS_1_2,
     tls::certificates(io::file("./example-data/rsa4096.x509.cert.der")),
   ),

   // Server Key Exchange — ECDH parameters (load from file or embed as hex bytes)
   tls::message(
     content: tls::content::HANDSHAKE,
     version: tls::version::TLS_1_2,
     tls::handshake::SERVER_KEY_EXCHANGE,
     io::file("./example-data/server_key_exchange.bin"),
   ),

   // Server Hello Done — signals end of server's handshake flight
   tls::message(
     content: tls::content::HANDSHAKE,
     version: tls::version::TLS_1_2,
     tls::handshake::SERVER_HELLO_DONE,
     "|00 00 00|"
   ),
 );
 ```
## Index


### Modules

| Module | Description |
| ------ | ----------- |
| [cipher](cipher/README.md) | TLS Cipher Suites |
| [content](content/README.md) | TLS Record Content Types |
| [ext](ext/README.md) | TLS Extensions |
| [handshake](handshake/README.md) | TLS Handshake types |
| [version](version/README.md) | TLS Versions |

### Functions

| Function | Returns | Description |
| -------- | ------- | ----------- |
| [certificates](#certificates) | `bytes` | Returns a chain of X.509 certificates |
| [ciphers](#ciphers) | `bytes` | Build a TLS cipher suites list |
| [client_hello](#client_hello) | `bytes` | Construct a TLS ClientHello handshake message |
| [extension](#extension) | `bytes` | Construct a TLS extension |
| [message](#message) | `bytes` | Construct a TLS record |
| [server_hello](#server_hello) | `bytes` | Construct a TLS ServerHello handshake message |
| [sni](#sni) | `bytes` | Construct a TLS Server Name Indication (SNI) extension |



## certificates
```resynth
resynth fn certificates (
    =>
    *collect_args: bytes,
) -> bytes;
```
Returns a chain of X.509 certificates

### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| `…` | `bytes` | Zero or more additional values |

### Returns

| Type |
| ---- |
| `bytes` |

## ciphers
```resynth
resynth fn ciphers (
    =>
    *collect_args: u16,
) -> bytes;
```
Build a TLS cipher suites list

 Encodes the supplied [cipher suite](cipher/README.md) constants as a
 16-bit length-prefixed list, ready to embed in a [client_hello](#client_hello)
 or [server_hello](#server_hello).

### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| `…` | `u16` | Zero or more additional values |

### Returns

| Type |
| ---- |
| `bytes` |

## client_hello
```resynth
resynth fn client_hello (
    version: u16 = 0x0303,
    sessionid: bytes = "|00|",
    ciphers: bytes = "|00 02 00 00|",
    compression: bytes = "|01 00|",
    =>
    *collect_args: bytes,
) -> bytes;
```
Construct a TLS ClientHello handshake message

 Must be framed inside a [tls::content::HANDSHAKE](content/README.md)
 [message](#message). The random field is fixed to a placeholder value.

### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| `version` | `u16` | Requested [TLS version](version/README.md) _(default: `0x0303`)_ |
| `sessionid` | `bytes` | Session ID bytes (u8 length-prefixed; `"\|00\|"` means no session resumption) _(default: `"\|00\|"`)_ |
| `ciphers` | `bytes` | Supported cipher suites list — use [tls::ciphers()](#ciphers) to construct _(default: `"\|00 02 00 00\|"`)_ |
| `compression` | `bytes` | Supported compression methods list (essentially defunct; null compression = `"\|01 00\|"`) _(default: `"\|01 00\|"`)_ |
| `…` | `bytes` | Zero or more additional values |

### Returns

| Type |
| ---- |
| `bytes` |

## extension
```resynth
resynth fn extension (
    ext: u16,
    =>
    *collect_args: bytes,
) -> bytes;
```
Construct a TLS extension

 Wraps payload bytes in the TLS extension framing:

 ```c
 struct tls_ext {
     uint16_t ext;
     uint16_t len;
     uint8_t payload[0];
 } _packed;
 ```

### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| `ext` | `u16` | [TLS extension type](ext/README.md) (e.g. [tls::ext::SERVER_NAME](ext/README.md)) |
| `…` | `bytes` | Zero or more additional values |

### Returns

| Type |
| ---- |
| `bytes` |

## message
```resynth
resynth fn message (
    version: u16 = 0x0303,
    content: u8 = 0x16,
    =>
    *collect_args: bytes,
) -> bytes;
```
Construct a TLS record

 Wraps payload bytes in the TLS record framing:

 ```c
 struct tls_hdr {
     uint8_t content;
     uint16_t version;
     uint16_t len;
     uint8_t payload[0];
 } _packed;
 ```

### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| `version` | `u16` | [TLS version](version/README.md) for the record header (e.g. [tls::version::TLS_1_2](version/README.md)) _(default: `0x0303`)_ |
| `content` | `u8` | [TLS content type](content/README.md) (e.g. [tls::content::HANDSHAKE](content/README.md)) _(default: `0x16`)_ |
| `…` | `bytes` | Zero or more additional values |

### Returns

| Type |
| ---- |
| `bytes` |

## server_hello
```resynth
resynth fn server_hello (
    version: u16 = 0x0303,
    sessionid: bytes = "|00|",
    cipher: u16 = 0x0000,
    compression: u8 = 0x00,
    =>
    *collect_args: bytes,
) -> bytes;
```
Construct a TLS ServerHello handshake message

 Must be framed inside a [tls::content::HANDSHAKE](content/README.md)
 [message](#message). The random field is fixed to a placeholder value.

### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| `version` | `u16` | Negotiated [TLS version](version/README.md) _(default: `0x0303`)_ |
| `sessionid` | `bytes` | Session ID bytes (u8 length-prefixed; `"\|00\|"` means no session resumption) _(default: `"\|00\|"`)_ |
| `cipher` | `u16` | Negotiated [cipher suite](cipher/README.md) _(default: `0x0000`)_ |
| `compression` | `u8` | Negotiated compression method (essentially defunct; 0 = null compression) _(default: `0x00`)_ |
| `…` | `bytes` | Zero or more additional values |

### Returns

| Type |
| ---- |
| `bytes` |

## sni
```resynth
resynth fn sni (
    =>
    *collect_args: bytes,
) -> bytes;
```
Construct a TLS Server Name Indication (SNI) extension

 Encodes one or more server names as a [tls::ext::SERVER_NAME](ext/README.md)
 extension, ready to pass to [extension](#extension) or embed directly in
 [client_hello](#client_hello).

### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| `…` | `bytes` | Zero or more additional values |

### Returns

| Type |
| ---- |
| `bytes` |
