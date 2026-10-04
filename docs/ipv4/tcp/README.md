 # Transmission Control Protocol (TCP)

 TCP flow construction — open connections, send data, and close sessions over IPv4.
## Index


### Classes

| Class | Description |
| ----- | ----------- |
| [TcpFlow](TcpFlow.md) | TCP Connection |

### Functions

| Function | Returns | Description |
| -------- | ------- | ----------- |
| [flow](#flow) | [TcpFlow](../../ipv4/tcp/TcpFlow.md) | Create a [TCP flow context](TcpFlow.md), from which packets can be created |



## flow
```resynth
resynth fn flow (
    cl: Sock4,
    sv: Sock4,
    cl_seq: u32 = 0x00000001,
    sv_seq: u32 = 0x00000001,
    raw: bool = false,
) -> TcpFlow;
```
Create a [TCP flow context](TcpFlow.md), from which packets can be created

### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| `cl` | `Sock4` | Client socket address |
| `sv` | `Sock4` | Server socket address |
| `cl_seq` | `u32` | Initial client TCP sequence number _(default: `0x00000001`)_ |
| `sv_seq` | `u32` | Initial server TCP sequence number _(default: `0x00000001`)_ |
| `raw` | `bool` | Enable raw mode; omits ethernet framing _(default: `false`)_ |

### Returns

| Type |
| ---- |
| [TcpFlow](../../ipv4/tcp/TcpFlow.md) |
