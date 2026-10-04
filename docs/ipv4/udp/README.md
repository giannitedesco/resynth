 # User Datagram Protocol (UDP)

 UDP flow construction — send and receive datagrams over IPv4.
## Index


### Classes

| Class | Description |
| ----- | ----------- |
| [UdpFlow](UdpFlow.md) | UDP Flow |

### Functions

| Function | Returns | Description |
| -------- | ------- | ----------- |
| [broadcast](#broadcast) | `Pkt` | Send a broadcast datagram |
| [flow](#flow) | [UdpFlow](../../ipv4/udp/UdpFlow.md) | Create a UDP flow context, from which other packets can be created |
| [hdr](#hdr) | `bytes` | Returns a UDP header (with no IP header) |
| [unicast](#unicast) | `Pkt` | Send a unicast datagram |



## broadcast
```resynth
resynth fn broadcast (
    src: Sock4,
    dst: Sock4,
    srcip: type = Ip4,
    raw: bool = false,
    =>
    *collect_args: bytes,
) -> Pkt;
```
Send a broadcast datagram

### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| `src` | `Sock4` | Source socket address |
| `dst` | `Sock4` | Destination socket address |
| `srcip` | `type` | Override source IP address (useful for spoofed/crafted packets) _(default: `Ip4`)_ |
| `raw` | `bool` | Enable raw mode; omits ethernet framing _(default: `false`)_ |
| `…` | `bytes` | Zero or more additional values |

### Returns

| Type |
| ---- |
| `Pkt` |

## flow
```resynth
resynth fn flow (
    cl: Sock4,
    sv: Sock4,
    raw: bool = false,
) -> UdpFlow;
```
Create a UDP flow context, from which other packets can be created

### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| `cl` | `Sock4` | Client socket address |
| `sv` | `Sock4` | Server socket address |
| `raw` | `bool` | Enable raw mode; omits ethernet framing _(default: `false`)_ |

### Returns

| Type |
| ---- |
| [UdpFlow](../../ipv4/udp/UdpFlow.md) |

## hdr
```resynth
resynth fn hdr (
    src: u16,
    dst: u16,
    len: u16 = 0x0000,
    csum: u16 = 0x0000,
) -> bytes;
```
Returns a UDP header (with no IP header)

### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| `src` | `u16` | Source UDP port |
| `dst` | `u16` | Destination UDP port |
| `len` | `u16` | Payload length in bytes (added to UDP header size automatically) _(default: `0x0000`)_ |
| `csum` | `u16` | UDP checksum value _(default: `0x0000`)_ |

### Returns

| Type |
| ---- |
| `bytes` |

## unicast
```resynth
resynth fn unicast (
    src: Sock4,
    dst: Sock4,
    raw: bool = false,
    =>
    *collect_args: bytes,
) -> Pkt;
```
Send a unicast datagram

### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| `src` | `Sock4` | Source socket address |
| `dst` | `Sock4` | Destination socket address |
| `raw` | `bool` | Enable raw mode; omits ethernet framing _(default: `false`)_ |
| `…` | `bytes` | Zero or more additional values |

### Returns

| Type |
| ---- |
| `Pkt` |
