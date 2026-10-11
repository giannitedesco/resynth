 # Internet Protocol Version 4

 IPv4 packet construction — TCP, UDP, ICMP flows and IP-level fragmentation.
## Index


### Modules

| Module | Description |
| ------ | ----------- |
| [icmp](icmp/README.md) | Internet Control Message Protocol (ICMP) |
| [proto](proto/README.md) | IP Protocols |
| [tcp](tcp/README.md) | Transmission Control Protocol (TCP) |
| [udp](udp/README.md) | User Datagram Protocol (UDP) |

### Classes

| Class | Description |
| ----- | ----------- |
| [IpFrag](IpFrag.md) | IP Packet Fragment Builder |

### Functions

| Function | Returns | Description |
| -------- | ------- | ----------- |
| [datagram](#datagram) | `Pkt` | Create a raw IPv4 header or datagram |
| [frag](#frag) | [IpFrag](../ipv4/IpFrag.md) | Create a context for a packet which can be arbitrarily fragmented |



## datagram
```resynth
resynth fn datagram (
    src: Ip4,
    dst: Ip4,
    id: u16 = 0x0000,
    evil: bool = false,
    df: bool = false,
    mf: bool = false,
    ttl: u8 = 0x40,
    frag_off: u16 = 0x0000,
    proto: u8 = 0x11,
    =>
    *collect_args: bytes,
) -> Pkt;
```
Create a raw IPv4 header or datagram

 The IP total length wraps around if the payload is too long for it.

### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| `src` | `Ip4` | Source IPv4 address |
| `dst` | `Ip4` | Destination IPv4 address |
| `id` | `u16` | IP identification field _(default: `0x0000`)_ |
| `evil` | `bool` | Set the evil bit (RFC 3514) _(default: `false`)_ |
| `df` | `bool` | Set the Don't Fragment (DF) flag _(default: `false`)_ |
| `mf` | `bool` | Set the More Fragments (MF) flag _(default: `false`)_ |
| `ttl` | `u8` | IP Time-To-Live value _(default: `0x40`)_ |
| `frag_off` | `u16` | Fragment offset field (in 8-byte units) _(default: `0x0000`)_ |
| `proto` | `u8` | IP protocol number _(default: `0x11`)_ |
| `…` | `bytes` | Zero or more additional values |

### Returns

| Type |
| ---- |
| `Pkt` |

## frag
```resynth
resynth fn frag (
    src: Ip4,
    dst: Ip4,
    id: u16 = 0x0000,
    evil: bool = false,
    df: bool = false,
    ttl: u8 = 0x40,
    proto: u8 = 0x11,
    =>
    *collect_args: bytes,
) -> IpFrag;
```
Create a context for a packet which can be arbitrarily fragmented

### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| `src` | `Ip4` | Source IPv4 address |
| `dst` | `Ip4` | Destination IPv4 address |
| `id` | `u16` | IP identification field _(default: `0x0000`)_ |
| `evil` | `bool` | Set the evil bit (RFC 3514) _(default: `false`)_ |
| `df` | `bool` | Set the Don't Fragment (DF) flag _(default: `false`)_ |
| `ttl` | `u8` | IP Time-To-Live value _(default: `0x40`)_ |
| `proto` | `u8` | IP protocol number _(default: `0x11`)_ |
| `…` | `bytes` | Zero or more additional values |

### Returns

| Type |
| ---- |
| [IpFrag](../ipv4/IpFrag.md) |
