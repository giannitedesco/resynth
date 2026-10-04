 # VXLAN Encapsulation

 Encapsulates ethernet frames in [UDP](../ipv4/udp/README.md) datagrams.
## Index


### Classes

| Class | Description |
| ----- | ----------- |
| [Vxlan](Vxlan.md) | VXLAN Session |

### Functions

| Function | Returns | Description |
| -------- | ------- | ----------- |
| [session](#session) | [Vxlan](../vxlan/Vxlan.md) | Create a VXLAN session |

### Constants

| Name | Value |
| ---- | ----- |
| DEFAULT_PORT | `(u16)0x12b5` |



## session
```resynth
resynth fn session (
    cl: Sock4,
    sv: Sock4,
    sessionid: u32 = 0x00000000,
    raw: bool = false,
) -> Vxlan;
```
Create a VXLAN session

### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| `cl` | `Sock4` | Client (sender) socket address |
| `sv` | `Sock4` | Server (receiver) socket address |
| `sessionid` | `u32` | VXLAN Network Identifier (VNI) _(default: `0x00000000`)_ |
| `raw` | `bool` | Enable raw mode; omits ethernet framing _(default: `false`)_ |

### Returns

| Type |
| ---- |
| [Vxlan](../vxlan/Vxlan.md) |
