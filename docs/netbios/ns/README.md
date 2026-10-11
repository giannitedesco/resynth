 # NetBIOS Name Service
## Index


### Modules

| Module | Description |
| ------ | ----------- |
| [opcode](opcode/README.md) | NetBIOS Name Service Opcodes |
| [rcode](rcode/README.md) | NetBIOS Name Service Response codes |
| [rrtype](rrtype/README.md) | NetBIOS Name Service RR types |

### Functions

| Function | Returns | Description |
| -------- | ------- | ----------- |
| [flags](#flags) | `u16` | Returns netbios-ns flags |
| [name_entry](#name_entry) | `bytes` | Build a single name table entry for an NBSTAT RDATA block. |
| [name_flags](#name_flags) | `u16` | Build a name flags field for an NBSTAT name table entry (RFC 1002 §4.2.18). |
| [nb_flags](#nb_flags) | `u16` | Build the NB_FLAGS field for an NB resource record RDATA (RFC 1002 §4.2.1.1). |
| [nbstat_rdata](#nbstat_rdata) | `bytes` | Build the complete RDATA section for an NBSTAT resource record. |
| [statistics](#statistics) | `bytes` | Build the 64-byte statistics block appended to every NBSTAT RDATA section. |



## flags
```resynth
resynth fn flags (
    opcode: u8,
    response: bool = false,
    aa: bool = false,
    tc: bool = false,
    rd: bool = false,
    ra: bool = false,
    z: bool = false,
    ad: bool = false,
    b: bool = false,
    rcode: u8 = 0x00,
) -> u16;
```
Returns netbios-ns flags

### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| `opcode` | `u8` | NetBIOS name service opcode |
| `response` | `bool` | If true, this is a response; if false, a query _(default: `false`)_ |
| `aa` | `bool` | Authoritative Answer flag _(default: `false`)_ |
| `tc` | `bool` | Truncation flag _(default: `false`)_ |
| `rd` | `bool` | Recursion Desired flag _(default: `false`)_ |
| `ra` | `bool` | Recursion Available flag _(default: `false`)_ |
| `z` | `bool` | Reserved (Z) bit _(default: `false`)_ |
| `ad` | `bool` | Must be zero (maps to DNS AD bit) _(default: `false`)_ |
| `b` | `bool` | Broadcast/multicast flag _(default: `false`)_ |
| `rcode` | `u8` | Response code _(default: `0x00`)_ |

### Returns

| Type |
| ---- |
| `u16` |

## name_entry
```resynth
resynth fn name_entry (
    suffix: u8 = 0x00,
    flags: u16 = 0x0400,
    =>
    *collect_args: bytes,
) -> bytes;
```
Build a single name table entry for an NBSTAT RDATA block.

 Pads the name to 15 bytes (space-filled), appends the one-byte suffix and
 two-byte flags. Each entry is exactly 18 bytes and is consumed by
 `netbios::ns::nbstat_rdata()`.

 The default suffix (0x00) is the workstation service. Common suffixes:
 0x00 = workstation, 0x03 = messenger (logged-in user), 0x20 = file server.

 The default flags (0x0400) represent an active, unique, B-node name;
 use `netbios::ns::name_flags()` to construct non-default values.

### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| `suffix` | `u8` | One-byte NetBIOS name suffix (service type) _(default: `0x00`)_ |
| `flags` | `u16` | Two-byte name flags field _(default: `0x0400`)_ |
| `…` | `bytes` | Zero or more additional values |

### Returns

| Type |
| ---- |
| `bytes` |

## name_flags
```resynth
resynth fn name_flags (
    ont: u8 = 0x00,
    active: bool = true,
    group: bool = false,
    drg: bool = false,
    cnf: bool = false,
    prm: bool = false,
    reserved: u16 = 0x0000,
) -> u16;
```
Build a name flags field for an NBSTAT name table entry (RFC 1002 §4.2.18).

 Flags layout (MSB first): G(1) ONT(2) DRG(1) CNF(1) ACT(1) PRM(1) reserved(9)

 ONT values: 0=B-node, 1=P-node, 2=M-node, 3=H-node.
 The default produces 0x0400: active, unique name, B-node.

 Pass `reserved:` with a non-zero value to exercise DPI engine behaviour on
 unexpected reserved-bit patterns.

### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| `ont` | `u8` | Owner Node Type: 0=B-node, 1=P-node, 2=M-node, 3=H-node _(default: `0x00`)_ |
| `active` | `bool` | Name is active _(default: `true`)_ |
| `group` | `bool` | Group name (true) or unique name (false) _(default: `false`)_ |
| `drg` | `bool` | Name is in the process of being deregistered _(default: `false`)_ |
| `cnf` | `bool` | Name is in conflict _(default: `false`)_ |
| `prm` | `bool` | Permanent node name (not registered via NBNS) _(default: `false`)_ |
| `reserved` | `u16` | Reserved bits (bits 8-0); normally zero _(default: `0x0000`)_ |

### Returns

| Type |
| ---- |
| `u16` |

## nb_flags
```resynth
resynth fn nb_flags (
    group: bool = false,
    ont: u8 = 0x00,
    reserved: u16 = 0x0000,
) -> u16;
```
Build the NB_FLAGS field for an NB resource record RDATA (RFC 1002 §4.2.1.1).

 Flags layout (MSB first): G(1) ONT(2) reserved(13)

 ONT values: 0=B-node, 1=P-node, 2=M-node, 3=H-node.
 The default produces 0x0000: unique name, B-node.

 Pass `reserved:` with a non-zero value to exercise DPI engine behaviour on
 unexpected reserved-bit patterns.

### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| `group` | `bool` | Group name (true) or unique name (false) _(default: `false`)_ |
| `ont` | `u8` | Owner Node Type: 0=B-node, 1=P-node, 2=M-node, 3=H-node _(default: `0x00`)_ |
| `reserved` | `u16` | Reserved bits (bits 12-0); normally zero _(default: `0x0000`)_ |

### Returns

| Type |
| ---- |
| `u16` |

## nbstat_rdata
```resynth
resynth fn nbstat_rdata (
    =>
    *collect_args: bytes,
) -> bytes;
```
Build the complete RDATA section for an NBSTAT resource record.

 Accepts `netbios::ns::name_entry()` values as collect arguments, prepends
 the one-byte name count (derived from the total length), and appends a
 zeroed 64-byte statistics block.

 The name count wraps around if there are more than 255 entries.

 To include a MAC address in the statistics block, append
 `netbios::ns::statistics("|aa bb cc dd ee ff|")` manually and omit this
 function in favour of assembling the RDATA yourself.

### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| `…` | `bytes` | Zero or more additional values |

### Returns

| Type |
| ---- |
| `bytes` |

## statistics
```resynth
resynth fn statistics (
    =>
    *collect_args: bytes,
) -> bytes;
```
Build the 64-byte statistics block appended to every NBSTAT RDATA section.

 The block contains a 6-byte unit ID (MAC address) followed by 58 bytes of
 counters. Pass the MAC address as the collect argument; omit it to use all
 zeros.

### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| `…` | `bytes` | Zero or more additional values |

### Returns

| Type |
| ---- |
| `bytes` |
