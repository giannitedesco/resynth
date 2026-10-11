 # DHCP / BOOTP

 Dynamic Host Configuration Protocol — packet construction and protocol constants
 for DHCP and its predecessor BOOTP.
## Index


### Modules

| Module | Description |
| ------ | ----------- |
| [msgtype](msgtype/README.md) | DHCP Message Type |
| [opcode](opcode/README.md) | DHCP Opcodes |
| [opt](opt/README.md) | DHCP Options |

### Functions

| Function | Returns | Description |
| -------- | ------- | ----------- |
| [hdr](#hdr) | `bytes` | DHCP header |
| [option](#option) | `bytes` | DHCP Option |

### Constants

| Name | Value |
| ---- | ----- |
| CLIENT_PORT | `(u16)0x0044` |
| SERVER_PORT | `(u16)0x0043` |



## hdr
```resynth
resynth fn hdr (
    opcode: u8 = 0x01,
    htype: u8 = 0x01,
    hlen: u8 = 0x06,
    hops: u8 = 0x00,
    xid: u32 = 0x00000000,
    ciaddr: Ip4 = 0.0.0.0,
    yiaddr: Ip4 = 0.0.0.0,
    siaddr: Ip4 = 0.0.0.0,
    giaddr: Ip4 = 0.0.0.0,
    chaddr: type = Str,
    sname: type = Str,
    file: type = Str,
    magic: u32 = 0x63825363,
) -> bytes;
```
DHCP header

### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| `opcode` | `u8` | DHCP opcode (REQUEST or REPLY) _(default: `0x01`)_ |
| `htype` | `u8` | Hardware address type (e.g. ETHER) _(default: `0x01`)_ |
| `hlen` | `u8` | Hardware address length in bytes _(default: `0x06`)_ |
| `hops` | `u8` | Number of relay agent hops _(default: `0x00`)_ |
| `xid` | `u32` | Transaction ID to correlate request and reply _(default: `0x00000000`)_ |
| `ciaddr` | `Ip4` | Client IP address (filled in if client has one) _(default: `0.0.0.0`)_ |
| `yiaddr` | `Ip4` | Your (client) IP address as assigned by the server _(default: `0.0.0.0`)_ |
| `siaddr` | `Ip4` | Next server IP address _(default: `0.0.0.0`)_ |
| `giaddr` | `Ip4` | Relay agent IP address _(default: `0.0.0.0`)_ |
| `chaddr` | `type` | Client hardware address (MAC address bytes) _(default: `Str`)_ |
| `sname` | `type` | Server host name (optional, null-terminated string) _(default: `Str`)_ |
| `file` | `type` | Boot file name (optional, null-terminated string) _(default: `Str`)_ |
| `magic` | `u32` | DHCP magic cookie value _(default: `0x63825363`)_ |

### Returns

| Type |
| ---- |
| `bytes` |

## option
```resynth
resynth fn option (
    opt: u8,
    =>
    *collect_args: bytes,
) -> bytes;
```
DHCP Option

 Length fields wrap around if the content is too long for them.

### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| `opt` | `u8` | DHCP option code |
| `…` | `bytes` | Zero or more additional values |

### Returns

| Type |
| ---- |
| `bytes` |
