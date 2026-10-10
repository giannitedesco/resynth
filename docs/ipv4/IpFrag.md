 # IP Packet Fragment Builder

 Represents a single IP datagram that can be emitted either whole or split
 into multiple fragments. Create one with `ipv4::frag(src, dst, ..., payload)`,
 then emit fragments in the desired order:

 - `fragment(frag_off, len)` — emits a fragment with the MF (more-fragments) bit set,
   unless it reaches the end of the payload
 - `tail(frag_off)` — emits the final fragment (MF clear), inferring the length
 - `datagram()` — emits the whole datagram unfragmented

 `frag_off` and `len` are in 8-byte units as per the IP specification. Fragments can be
 emitted out of order and with time gaps (using `time::jump_*`) to test
 reassembly timeout handling.
## Index


### Functions

| Function | Returns | Description |
| -------- | ------- | ----------- |
| [datagram](#datagram) | `Pkt` | Return the entire datagram as a single unfragmented packet |
| [fragment](#fragment) | `Pkt` | Return an IPv4 packet fragment |
| [tail](#tail) | `Pkt` | Return the final IPv4 fragment with MF=0 |



## datagram
```resynth
resynth fn datagram (
    raw: bool = false,
    =>
    *collect_args: bytes,
) -> Pkt;
```
Return the entire datagram as a single unfragmented packet

 Emits the full payload as one IPv4 packet with no fragmentation headers.

### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| `raw` | `bool` | If true, omit the ethernet header _(default: `false`)_ |
| `…` | `bytes` | Zero or more additional values |

### Returns

| Type |
| ---- |
| `Pkt` |

## fragment
```resynth
resynth fn fragment (
    frag_off: u16,
    len: u16,
    raw: bool = false,
    =>
    *collect_args: bytes,
) -> Pkt;
```
Return an IPv4 packet fragment

 Slices the stored datagram at the given offset and length and wraps it in
 an IPv4 header. Both are in units of 8 bytes, as the fragment offset is in RFC 791,
 so `fragment(1, 2)` is bytes 8 to 23 of the payload. A fragment that would run past
 the end of the payload stops there, and one that starts past the end is empty. The
 MF (more-fragments) bit is set unless the fragment reaches the end of the payload.

### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| `frag_off` | `u16` | Fragment offset in 8-byte blocks |
| `len` | `u16` | Length of this fragment in 8-byte blocks |
| `raw` | `bool` | If true, omit the ethernet header _(default: `false`)_ |
| `…` | `bytes` | Zero or more additional values |

### Returns

| Type |
| ---- |
| `Pkt` |

## tail
```resynth
resynth fn tail (
    frag_off: u16,
    raw: bool = false,
    =>
    *collect_args: bytes,
) -> Pkt;
```
Return the final IPv4 fragment with MF=0

 Convenience wrapper around [fragment](#fragment) for the last fragment in a
 series — the MF bit is cleared automatically so no `len` is required.

### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| `frag_off` | `u16` | Fragment offset in 8-byte blocks |
| `raw` | `bool` | If true, omit the ethernet header _(default: `false`)_ |
| `…` | `bytes` | Zero or more additional values |

### Returns

| Type |
| ---- |
| `Pkt` |
