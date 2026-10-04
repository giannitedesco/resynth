 # ERSPAN Version 1

 ERSPAN Type I — encapsulates mirrored traffic in a GRE tunnel (version 1, no sequence numbers).
## Index


### Classes

| Class | Description |
| ----- | ----------- |
| [Erspan1](Erspan1.md) | ERSPAN1 Session |

### Functions

| Function | Returns | Description |
| -------- | ------- | ----------- |
| [session](#session) | [Erspan1](../erspan1/Erspan1.md) | Create an ERSPAN session |



## session
```resynth
resynth fn session (
    cl: Ip4,
    sv: Ip4,
    raw: bool = false,
) -> Erspan1;
```
Create an ERSPAN session

### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| `cl` | `Ip4` | Source (collector) IP address |
| `sv` | `Ip4` | Destination (monitor) IP address |
| `raw` | `bool` | Enable raw mode; omits ethernet framing _(default: `false`)_ |

### Returns

| Type |
| ---- |
| [Erspan1](../erspan1/Erspan1.md) |
