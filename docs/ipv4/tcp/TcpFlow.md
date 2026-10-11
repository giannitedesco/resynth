 # TCP Connection

 Represents a TCP flow between a client and server socket address. The
 flow tracks sequence and acknowledgement numbers automatically.

 Use [open](#open) to perform the 3-way handshake and [client_close](#client_close) /
 [server_close](#server_close) for the FIN/ACK teardown.

 For data transfer there are three levels of abstraction:

 - [client_message](#client_message) / [server_message](#server_message) — emit a data
   segment and automatically follow it with an ACK from the other side. This is the
   highest-level option and covers most use cases.
 - [client_segment](#client_segment) / [server_segment](#server_segment) — emit a single
   data segment with no auto-ACK. Use when you need fine-grained control over ACK timing
   or want to interleave segments from both sides manually.
 - [client_raw_segment](#client_raw_segment) / [server_raw_segment](#server_raw_segment) —
   return TCP header + payload as raw bytes (no IP or Ethernet framing). Use with
   [`ipv4::frag`](../README.md#frag) to build IP-fragmented TCP segments.

 [client_hdr](#client_hdr) / [server_hdr](#server_hdr) go one step further and return
 only the TCP header bytes, for cases where the header and payload must land in separate
 IP fragments. [client_hole](#client_hole) / [server_hole](#server_hole) advance the
 sequence number without emitting any packet, simulating a missing segment for
 reassembly test cases.
## Index


### Functions

| Function | Returns | Description |
| -------- | ------- | ----------- |
| [client_ack](#client_ack) | `Pkt` | Sends an ACK from the client |
| [client_close](#client_close) | `PktGen` | Shutdown both sides of the TCP connection, with the client sending the first FIN |
| [client_hdr](#client_hdr) | `bytes` | Returns a TCP header only (no payload, no IP header) for a client-to-server segment, as `bytes`. The optional `bytes` argument declares how many payload bytes the header should account for in the sequence number, without actually emitting them. Use with `ipv4::frag` to craft fragmented packets where the TCP header lands in one fragment and the payload in another. |
| [client_hole](#client_hole) | `void` | Creates a hole in the client's Tx sequence space, making it look like we missed a packet from the client |
| [client_message](#client_message) | `PktGen` | Sends a message from client to server, advancing the sequence number. By default also emits an ACK from the server in response (`send_ack: true`). Use `send_ack: false` to suppress the ACK, for example when building out-of-order or reassembly test cases. |
| [client_raw_segment](#client_raw_segment) | `bytes` | Returns TCP header + payload bytes only (no Ethernet or IP header) for a client-to-server segment, advancing the sequence number. Returns `bytes` rather than `Pkt`. Use this with `ipv4::frag` to build IP-fragmented TCP segments. |
| [client_reset](#client_reset) | `Pkt` | Send a RST packet from the client |
| [client_segment](#client_segment) | `Pkt` | Returns a single data segment from client to server, advancing the sequence number. Does not emit an ACK. Returns a `Pkt` (complete Ethernet+IP+TCP packet) rather than a `PktGen`. |
| [open](#open) | `PktGen` | Performs a TCP 3-way handshake |
| [server_ack](#server_ack) | `Pkt` | Sends an ACK from the server |
| [server_close](#server_close) | `PktGen` | Shutdown both sides of the TCP connection, with the server sending the first FIN |
| [server_hdr](#server_hdr) | `bytes` | Returns a TCP header only (no payload, no IP header) for a server-to-client segment, as `bytes`. The optional `bytes` argument declares how many payload bytes the header should account for in the sequence number, without actually emitting them. Use with `ipv4::frag` to craft fragmented packets where the TCP header lands in one fragment and the payload in another. |
| [server_hole](#server_hole) | `void` | Creates a hole in the server's Tx sequence space, making it look like we missed a packet from the server |
| [server_message](#server_message) | `PktGen` | Sends a message from server to client, advancing the sequence number. By default also emits an ACK from the client in response (`send_ack: true`). Use `send_ack: false` to suppress the ACK, for example when building out-of-order or reassembly test cases. |
| [server_raw_segment](#server_raw_segment) | `bytes` | Returns TCP header + payload bytes only (no Ethernet or IP header) for a server-to-client segment, advancing the sequence number. Returns `bytes` rather than `Pkt`. Use this with `ipv4::frag` to build IP-fragmented TCP segments. |
| [server_reset](#server_reset) | `Pkt` | Send a RST packet from the server |
| [server_segment](#server_segment) | `Pkt` | Returns a single data segment from server to client, advancing the sequence number. Does not emit an ACK. Returns a `Pkt` (complete Ethernet+IP+TCP packet) rather than a `PktGen`. |



## client_ack
```resynth
resynth fn client_ack (
    seq: type = U32,
    ack: type = U32,
) -> Pkt;
```
Sends an ACK from the client

### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| `seq` | `type` | Override the TCP sequence number for this ACK _(default: `U32`)_ |
| `ack` | `type` | Override the TCP acknowledgement number for this ACK _(default: `U32`)_ |

### Returns

| Type |
| ---- |
| `Pkt` |

## client_close
```resynth
resynth fn client_close (
) -> PktGen;
```
Shutdown both sides of the TCP connection, with the client sending the first FIN

### Returns

| Type |
| ---- |
| `PktGen` |

## client_hdr
```resynth
resynth fn client_hdr (
    bytes: u32 = 0x00000000,
    csum: u16 = 0x0000,
) -> bytes;
```
Returns a TCP header only (no payload, no IP header) for a
 client-to-server segment, as `bytes`. The optional `bytes` argument
 declares how many payload bytes the header should account for in the
 sequence number, without actually emitting them. Use with `ipv4::frag`
 to craft fragmented packets where the TCP header lands in one fragment
 and the payload in another.

 The payload isn't known here, so the TCP checksum can't be computed. It is zero
 unless you pass the right value as `csum`, so a receiver that checks it will
 discard the reassembled segment.

### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| `bytes` | `u32` | Number of payload bytes to advance the sequence number by, without emitting them _(default: `0x00000000`)_ |
| `csum` | `u16` | Value for the TCP checksum field _(default: `0x0000`)_ |

### Returns

| Type |
| ---- |
| `bytes` |

## client_hole
```resynth
resynth fn client_hole (
    bytes: u32,
) -> void;
```
Creates a hole in the client's Tx sequence space, making it look like we missed a packet
 from the client

### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| `bytes` | `u32` | Number of bytes to advance the client sequence number without emitting a packet |

## client_message
```resynth
resynth fn client_message (
    send_ack: bool = true,
    seq: type = U32,
    ack: type = U32,
    frag_off: u16 = 0x0000,
    =>
    *collect_args: bytes,
) -> PktGen;
```
Sends a message from client to server, advancing the sequence number.
 By default also emits an ACK from the server in response (`send_ack: true`).
 Use `send_ack: false` to suppress the ACK, for example when building
 out-of-order or reassembly test cases.

### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| `send_ack` | `bool` | If true, emit an ACK from the server after the data segment _(default: `true`)_ |
| `seq` | `type` | Override the TCP sequence number for this segment _(default: `U32`)_ |
| `ack` | `type` | Override the TCP acknowledgement number for this segment _(default: `U32`)_ |
| `frag_off` | `u16` | IP fragment offset (in 8-byte units) for the enclosing IP datagram _(default: `0x0000`)_ |
| `…` | `bytes` | Zero or more additional values |

### Returns

| Type |
| ---- |
| `PktGen` |

## client_raw_segment
```resynth
resynth fn client_raw_segment (
    seq: type = U32,
    ack: type = U32,
    =>
    *collect_args: bytes,
) -> bytes;
```
Returns TCP header + payload bytes only (no Ethernet or IP header) for
 a client-to-server segment, advancing the sequence number. Returns
 `bytes` rather than `Pkt`. Use this with `ipv4::frag` to build
 IP-fragmented TCP segments.

### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| `seq` | `type` | Override the TCP sequence number for this segment _(default: `U32`)_ |
| `ack` | `type` | Override the TCP acknowledgement number for this segment _(default: `U32`)_ |
| `…` | `bytes` | Zero or more additional values |

### Returns

| Type |
| ---- |
| `bytes` |

## client_reset
```resynth
resynth fn client_reset (
) -> Pkt;
```
Send a RST packet from the client

### Returns

| Type |
| ---- |
| `Pkt` |

## client_segment
```resynth
resynth fn client_segment (
    seq: type = U32,
    ack: type = U32,
    =>
    *collect_args: bytes,
) -> Pkt;
```
Returns a single data segment from client to server, advancing the
 sequence number. Does not emit an ACK. Returns a `Pkt` (complete
 Ethernet+IP+TCP packet) rather than a `PktGen`.

### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| `seq` | `type` | Override the TCP sequence number for this segment _(default: `U32`)_ |
| `ack` | `type` | Override the TCP acknowledgement number for this segment _(default: `U32`)_ |
| `…` | `bytes` | Zero or more additional values |

### Returns

| Type |
| ---- |
| `Pkt` |

## open
```resynth
resynth fn open (
) -> PktGen;
```
Performs a TCP 3-way handshake

### Returns

| Type |
| ---- |
| `PktGen` |

## server_ack
```resynth
resynth fn server_ack (
    seq: type = U32,
    ack: type = U32,
) -> Pkt;
```
Sends an ACK from the server

### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| `seq` | `type` | Override the TCP sequence number for this ACK _(default: `U32`)_ |
| `ack` | `type` | Override the TCP acknowledgement number for this ACK _(default: `U32`)_ |

### Returns

| Type |
| ---- |
| `Pkt` |

## server_close
```resynth
resynth fn server_close (
) -> PktGen;
```
Shutdown both sides of the TCP connection, with the server sending the first FIN

### Returns

| Type |
| ---- |
| `PktGen` |

## server_hdr
```resynth
resynth fn server_hdr (
    bytes: u32 = 0x00000000,
    csum: u16 = 0x0000,
) -> bytes;
```
Returns a TCP header only (no payload, no IP header) for a
 server-to-client segment, as `bytes`. The optional `bytes` argument
 declares how many payload bytes the header should account for in the
 sequence number, without actually emitting them. Use with `ipv4::frag`
 to craft fragmented packets where the TCP header lands in one fragment
 and the payload in another.

 The payload isn't known here, so the TCP checksum can't be computed. It is zero
 unless you pass the right value as `csum`, so a receiver that checks it will
 discard the reassembled segment.

### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| `bytes` | `u32` | Number of payload bytes to advance the sequence number by, without emitting them _(default: `0x00000000`)_ |
| `csum` | `u16` | Value for the TCP checksum field _(default: `0x0000`)_ |

### Returns

| Type |
| ---- |
| `bytes` |

## server_hole
```resynth
resynth fn server_hole (
    bytes: u32,
) -> void;
```
Creates a hole in the server's Tx sequence space, making it look like we missed a packet
 from the server

### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| `bytes` | `u32` | Number of bytes to advance the server sequence number without emitting a packet |

## server_message
```resynth
resynth fn server_message (
    send_ack: bool = true,
    seq: type = U32,
    ack: type = U32,
    frag_off: u16 = 0x0000,
    =>
    *collect_args: bytes,
) -> PktGen;
```
Sends a message from server to client, advancing the sequence number.
 By default also emits an ACK from the client in response (`send_ack: true`).
 Use `send_ack: false` to suppress the ACK, for example when building
 out-of-order or reassembly test cases.

### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| `send_ack` | `bool` | If true, emit an ACK from the client after the data segment _(default: `true`)_ |
| `seq` | `type` | Override the TCP sequence number for this segment _(default: `U32`)_ |
| `ack` | `type` | Override the TCP acknowledgement number for this segment _(default: `U32`)_ |
| `frag_off` | `u16` | IP fragment offset (in 8-byte units) for the enclosing IP datagram _(default: `0x0000`)_ |
| `…` | `bytes` | Zero or more additional values |

### Returns

| Type |
| ---- |
| `PktGen` |

## server_raw_segment
```resynth
resynth fn server_raw_segment (
    seq: type = U32,
    ack: type = U32,
    =>
    *collect_args: bytes,
) -> bytes;
```
Returns TCP header + payload bytes only (no Ethernet or IP header) for
 a server-to-client segment, advancing the sequence number. Returns
 `bytes` rather than `Pkt`. Use this with `ipv4::frag` to build
 IP-fragmented TCP segments.

### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| `seq` | `type` | Override the TCP sequence number for this segment _(default: `U32`)_ |
| `ack` | `type` | Override the TCP acknowledgement number for this segment _(default: `U32`)_ |
| `…` | `bytes` | Zero or more additional values |

### Returns

| Type |
| ---- |
| `bytes` |

## server_reset
```resynth
resynth fn server_reset (
) -> Pkt;
```
Send a RST packet from the server

### Returns

| Type |
| ---- |
| `Pkt` |

## server_segment
```resynth
resynth fn server_segment (
    seq: type = U32,
    ack: type = U32,
    =>
    *collect_args: bytes,
) -> Pkt;
```
Returns a single data segment from server to client, advancing the
 sequence number. Does not emit an ACK. Returns a `Pkt` (complete
 Ethernet+IP+TCP packet) rather than a `PktGen`.

### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| `seq` | `type` | Override the TCP sequence number for this segment _(default: `U32`)_ |
| `ack` | `type` | Override the TCP acknowledgement number for this segment _(default: `U32`)_ |
| `…` | `bytes` | Zero or more additional values |

### Returns

| Type |
| ---- |
| `Pkt` |
