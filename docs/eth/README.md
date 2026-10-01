 # Ethernet

 Ethernet frame construction and ethertype constants.
## Index


### Modules

| Module | Description |
| ------ | ----------- |
| [ethertype](ethertype/README.md) | Ethernet Ethertypes |

### Functions

| Function | Returns | Description |
| -------- | ------- | ----------- |
| [frame](#frame) | `Pkt` | Construct an Ethernet frame |
| [from_ip](#from_ip) | `bytes` | Map an IPv4 address to a locally-administered Ethernet address |

### Constants

| Name | Value |
| ---- | ----- |
| BROADCAST | `(bytes)"\|ff ff ff ff ff ff\|"` |



## frame
```resynth
resynth fn frame (
    src: bytes,
    dst: bytes,
    ethertype: u16 = 0x0800,
    =>
    *collect_args: bytes,
) -> Pkt;
```
Construct an Ethernet frame

 Wraps the payload bytes in an Ethernet II frame header.

### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| `src` | `bytes` | Source ethernet address as 6 bytes |
| `dst` | `bytes` | Destination ethernet address as 6 bytes |
| `ethertype` | `u16` | [EtherType](ethertype/README.md) identifying the encapsulated protocol _(default: `0x0800`)_ |
| `…` | `bytes` | Zero or more additional values |

### Returns

| Type |
| ---- |
| `Pkt` |

## from_ip
```resynth
resynth fn from_ip (
    ip: Ip4,
) -> bytes;
```
Map an IPv4 address to a locally-administered Ethernet address

 Produces a locally-administered unicast MAC address with the IPv4 address
 encoded in the last four octets (e.g. `192.0.2.1` → `02:00:c0:00:02:01`).

### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| `ip` | `Ip4` | IPv4 address to map to an ethernet address |

### Returns

| Type |
| ---- |
| `bytes` |
