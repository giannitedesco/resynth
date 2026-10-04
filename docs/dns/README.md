 # Domain Name System

 You can use [host](#host) to do simple DNS requests

 Or you can use the other functions to build custom DNS messages
## Index


### Modules

| Module | Description |
| ------ | ----------- |
| [class](class/README.md) | DNS Record Class |
| [opcode](opcode/README.md) | DNS Opcode |
| [qtype](qtype/README.md) | DNS Record Type |
| [rcode](rcode/README.md) | DNS Response Codes (Errors) |
| [rtype](rtype/README.md) | DNS Record Type |

### Functions

| Function | Returns | Description |
| -------- | ------- | ----------- |
| [answer](#answer) | `bytes` | A DNS answer (RR) |
| [flags](#flags) | `u16` | a DNS flags field |
| [hdr](#hdr) | `bytes` | A DNS header |
| [host](#host) | `PktGen` | Perform a DNS lookup, with response |
| [name](#name) | `bytes` | A DNS name encoded with DNS label format (length-prefixed labels, null-terminated). |
| [pointer](#pointer) | `bytes` | A DNS compression pointer |
| [question](#question) | `bytes` | A DNS question |



## answer
```resynth
resynth fn answer (
    aname: bytes,
    atype: u16 = 0x0001,
    aclass: u16 = 0x0001,
    ttl: u32 = 0x000000e5,
    =>
    *collect_args: bytes,
) -> bytes;
```
A DNS answer (RR)

### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| `aname` | `bytes` | Encoded DNS name this record applies to |
| `atype` | `u16` | DNS record type (e.g. dns::rtype::A) _(default: `0x0001`)_ |
| `aclass` | `u16` | DNS record class (e.g. dns::class::IN) _(default: `0x0001`)_ |
| `ttl` | `u32` | Time-to-live for this record in seconds _(default: `0x000000e5`)_ |
| `…` | `bytes` | Zero or more additional values |

### Returns

| Type |
| ---- |
| `bytes` |

## flags
```resynth
resynth fn flags (
    opcode: u8,
    response: bool = false,
    aa: bool = false,
    tc: bool = false,
    rd: bool = false,
    ra: bool = false,
    z: bool = false,
    ad: bool = false,
    cd: bool = false,
    rcode: u8 = 0x00,
) -> u16;
```
a DNS flags field

### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| `opcode` | `u8` | DNS opcode for this message |
| `response` | `bool` | If true, this is a response; if false, a query _(default: `false`)_ |
| `aa` | `bool` | Authoritative Answer flag _(default: `false`)_ |
| `tc` | `bool` | Truncation flag _(default: `false`)_ |
| `rd` | `bool` | Recursion Desired flag _(default: `false`)_ |
| `ra` | `bool` | Recursion Available flag _(default: `false`)_ |
| `z` | `bool` | Reserved (Z) bit _(default: `false`)_ |
| `ad` | `bool` | Authentic Data flag (DNSSEC) _(default: `false`)_ |
| `cd` | `bool` | Checking Disabled flag (DNSSEC) _(default: `false`)_ |
| `rcode` | `u8` | Response code _(default: `0x00`)_ |

### Returns

| Type |
| ---- |
| `u16` |

## hdr
```resynth
resynth fn hdr (
    id: u16,
    flags: u16,
    qdcount: u16 = 0x0000,
    ancount: u16 = 0x0000,
    nscount: u16 = 0x0000,
    arcount: u16 = 0x0000,
) -> bytes;
```
A DNS header

### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| `id` | `u16` | DNS message transaction ID |
| `flags` | `u16` | DNS flags field (use dns::flags() to construct) |
| `qdcount` | `u16` | Number of entries in the question section _(default: `0x0000`)_ |
| `ancount` | `u16` | Number of resource records in the answer section _(default: `0x0000`)_ |
| `nscount` | `u16` | Number of name server resource records in the authority section _(default: `0x0000`)_ |
| `arcount` | `u16` | Number of resource records in the additional records section _(default: `0x0000`)_ |

### Returns

| Type |
| ---- |
| `bytes` |

## host
```resynth
resynth fn host (
    client: Ip4,
    qname: bytes,
    ttl: u32 = 0x000000e5,
    ns: Ip4 = 1.1.1.1,
    raw: bool = false,
    =>
    *collect_args: Ip4,
) -> PktGen;
```
Perform a DNS lookup, with response

### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| `client` | `Ip4` | Client IP address sending the DNS query |
| `qname` | `bytes` | DNS name to look up |
| `ttl` | `u32` | Time-to-live for the answer records in seconds _(default: `0x000000e5`)_ |
| `ns` | `Ip4` | IP address of the DNS name server _(default: `1.1.1.1`)_ |
| `raw` | `bool` | Enable raw mode; omits ethernet framing _(default: `false`)_ |
| `…` | `Ip4` | Zero or more additional values |

### Returns

| Type |
| ---- |
| `PktGen` |

## name
```resynth
resynth fn name (
    complete: bool = true,
    =>
    *collect_args: bytes,
) -> bytes;
```
A DNS name encoded with DNS label format (length-prefixed labels, null-terminated).

 Also used to wrap a `netbios::name::encode()` result into a complete NBNS
 name label for use in NBNS packets (which share the DNS wire format).

### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| `complete` | `bool` | If true, append a root label to terminate the name; if false, leave it open _(default: `true`)_ |
| `…` | `bytes` | Zero or more additional values |

### Returns

| Type |
| ---- |
| `bytes` |

## pointer
```resynth
resynth fn pointer (
    offset: u16 = 0x000c,
) -> bytes;
```
A DNS compression pointer

### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| `offset` | `u16` | Byte offset within the DNS message to point to _(default: `0x000c`)_ |

### Returns

| Type |
| ---- |
| `bytes` |

## question
```resynth
resynth fn question (
    qname: bytes,
    qtype: u16 = 0x0001,
    qclass: u16 = 0x0001,
) -> bytes;
```
A DNS question

### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| `qname` | `bytes` | Encoded DNS name being queried |
| `qtype` | `u16` | DNS record type to query (e.g. dns::rtype::A) _(default: `0x0001`)_ |
| `qclass` | `u16` | DNS record class (e.g. dns::class::IN) _(default: `0x0001`)_ |

### Returns

| Type |
| ---- |
| `bytes` |
