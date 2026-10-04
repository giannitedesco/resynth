 # ERSPAN Version 2

 ERSPAN Type II — encapsulates mirrored traffic in a GRE tunnel with sequence numbers and port IDs.
## Index


### Classes

| Class | Description |
| ----- | ----------- |
| [Erspan2](Erspan2.md) | ERSPAN2 Session |

### Functions

| Function | Returns | Description |
| -------- | ------- | ----------- |
| [session](#session) | [Erspan2](../erspan2/Erspan2.md) | Create an erspan2 session |



## session
```resynth
resynth fn session (
    cl: Ip4,
    sv: Ip4,
    raw: bool = false,
) -> Erspan2;
```
Create an erspan2 session

### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| `cl` | `Ip4` | Source (collector) IP address |
| `sv` | `Ip4` | Destination (monitor) IP address |
| `raw` | `bool` | Enable raw mode; omits ethernet framing _(default: `false`)_ |

### Returns

| Type |
| ---- |
| [Erspan2](../erspan2/Erspan2.md) |
