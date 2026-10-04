 # Generic Routing Encapsulation (GRE)

 Right now this exists only for GRETAP [sessions](#session)
## Index


### Classes

| Class | Description |
| ----- | ----------- |
| [Gre](Gre.md) | GRE Session |

### Functions

| Function | Returns | Description |
| -------- | ------- | ----------- |
| [session](#session) | [Gre](../gre/Gre.md) | Create a GRETAP session |



## session
```resynth
resynth fn session (
    cl: Ip4,
    sv: Ip4,
    ethertype: u16,
    raw: bool = false,
) -> Gre;
```
Create a GRETAP session

### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| `cl` | `Ip4` | Source IP address |
| `sv` | `Ip4` | Destination IP address |
| `ethertype` | `u16` | EtherType of the encapsulated payload |
| `raw` | `bool` | Enable raw mode; omits ethernet framing _(default: `false`)_ |

### Returns

| Type |
| ---- |
| [Gre](../gre/Gre.md) |
