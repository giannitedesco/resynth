 # Internet Control Message Protocol (ICMP)

 ICMP flow construction — echo requests, replies, and other control messages over IPv4.
## Index


### Classes

| Class | Description |
| ----- | ----------- |
| [Icmp](Icmp.md) | ICMP Session |

### Functions

| Function | Returns | Description |
| -------- | ------- | ----------- |
| [flow](#flow) | [Icmp](../../ipv4/icmp/Icmp.md) | Create an ICMP flow |



## flow
```resynth
resynth fn flow (
    cl: Ip4,
    sv: Ip4,
    raw: bool = false,
) -> Icmp;
```
Create an ICMP flow

### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| `cl` | `Ip4` | Client (sender) IP address |
| `sv` | `Ip4` | Server (responder) IP address |
| `raw` | `bool` | Enable raw mode; omits ethernet framing _(default: `false`)_ |

### Returns

| Type |
| ---- |
| [Icmp](../../ipv4/icmp/Icmp.md) |
