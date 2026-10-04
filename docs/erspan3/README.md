 # ERSPAN Version 3

 ERSPAN Type III — extends version 2 with timestamps, SGT, hardware ID, and directional metadata.
## Index


### Classes

| Class | Description |
| ----- | ----------- |
| [Erspan3](Erspan3.md) | ERSPAN3 Session |

### Functions

| Function | Returns | Description |
| -------- | ------- | ----------- |
| [session](#session) | [Erspan3](../erspan3/Erspan3.md) | Create an erspan3 session |



## session
```resynth
resynth fn session (
    cl: Ip4,
    sv: Ip4,
    raw: bool = false,
    hwid: u32 = 0x00000000,
    sgt: u32 = 0x00000000,
    granularity: u32 = 0x00000000,
    direction: u32 = 0x00000000,
) -> Erspan3;
```
Create an erspan3 session

### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| `cl` | `Ip4` | Source (collector) IP address |
| `sv` | `Ip4` | Destination (monitor) IP address |
| `raw` | `bool` | Enable raw mode; omits ethernet framing _(default: `false`)_ |
| `hwid` | `u32` | Hardware ID field in the ERSPAN3 header _(default: `0x00000000`)_ |
| `sgt` | `u32` | Security Group Tag (SGT) field _(default: `0x00000000`)_ |
| `granularity` | `u32` | Timestamp granularity field _(default: `0x00000000`)_ |
| `direction` | `u32` | Direction bit (0 = ingress, non-zero = egress) _(default: `0x00000000`)_ |

### Returns

| Type |
| ---- |
| [Erspan3](../erspan3/Erspan3.md) |
