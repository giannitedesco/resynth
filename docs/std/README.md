 # Standard types

 Core type conversion and utility functions available in every resynth program.
## Index


### Functions

| Function | Returns | Description |
| -------- | ------- | ----------- |
| [be16](#be16) | `bytes` | Encode a 16bit integer into 2 big-endian bytes |
| [be32](#be32) | `bytes` | Encode a 32bit integer into 4 big-endian bytes |
| [be64](#be64) | `bytes` | Encode a 64bit integer into 8 big-endian bytes |
| [le16](#le16) | `bytes` | Encode a 16bit integer into 2 little-endian bytes |
| [le32](#le32) | `bytes` | Encode a 32bit integer into 4 little-endian bytes |
| [le64](#le64) | `bytes` | Encode a 64bit integer into 8 little-endian bytes |
| [len_be16](#len_be16) | `bytes` | Prefix a buffer with a 16-bit big-endian length field |
| [len_be32](#len_be32) | `bytes` | Prefix a buffer with a 32-bit big-endian length field |
| [len_be64](#len_be64) | `bytes` | Prefix a buffer with a 64-bit big-endian length field |
| [len_le16](#len_le16) | `bytes` | Prefix a buffer with a 16-bit little-endian length field |
| [len_le32](#len_le32) | `bytes` | Prefix a buffer with a 32-bit little-endian length field |
| [len_le64](#len_le64) | `bytes` | Prefix a buffer with a 64-bit little-endian length field |
| [len_u8](#len_u8) | `bytes` | Prefix a buffer with an 8-bit byte length field |
| [u8](#u8) | `bytes` | Convert an integer into a one-byte string |



## be16
```resynth
resynth fn be16 (
    val: u16,
) -> bytes;
```
Encode a 16bit integer into 2 big-endian bytes

### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| `val` | `u16` | Integer value to encode |

### Returns

| Type |
| ---- |
| `bytes` |

## be32
```resynth
resynth fn be32 (
    val: u32,
) -> bytes;
```
Encode a 32bit integer into 4 big-endian bytes

### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| `val` | `u32` | Integer value to encode |

### Returns

| Type |
| ---- |
| `bytes` |

## be64
```resynth
resynth fn be64 (
    val: u64,
) -> bytes;
```
Encode a 64bit integer into 8 big-endian bytes

### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| `val` | `u64` | Integer value to encode |

### Returns

| Type |
| ---- |
| `bytes` |

## le16
```resynth
resynth fn le16 (
    val: u16,
) -> bytes;
```
Encode a 16bit integer into 2 little-endian bytes

### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| `val` | `u16` | Integer value to encode |

### Returns

| Type |
| ---- |
| `bytes` |

## le32
```resynth
resynth fn le32 (
    val: u32,
) -> bytes;
```
Encode a 32bit integer into 4 little-endian bytes

### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| `val` | `u32` | Integer value to encode |

### Returns

| Type |
| ---- |
| `bytes` |

## le64
```resynth
resynth fn le64 (
    val: u64,
) -> bytes;
```
Encode a 64bit integer into 8 little-endian bytes

### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| `val` | `u64` | Integer value to encode |

### Returns

| Type |
| ---- |
| `bytes` |

## len_be16
```resynth
resynth fn len_be16 (
    adjust: u16 = 0x0000,
    =>
    *collect_args: bytes,
) -> bytes;
```
Prefix a buffer with a 16-bit big-endian length field

 Prepends a 2-byte big-endian encoding of `len(payload) + adjust` to the payload bytes.

 The length wraps around if it doesn\'t fit in the field.

### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| `adjust` | `u16` | Adjustment value added to the computed length before encoding _(default: `0x0000`)_ |
| `…` | `bytes` | Zero or more additional values |

### Returns

| Type |
| ---- |
| `bytes` |

## len_be32
```resynth
resynth fn len_be32 (
    adjust: u32 = 0x00000000,
    =>
    *collect_args: bytes,
) -> bytes;
```
Prefix a buffer with a 32-bit big-endian length field

 Prepends a 4-byte big-endian encoding of `len(payload) + adjust` to the payload bytes.

 The length wraps around if it doesn\'t fit in the field.

### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| `adjust` | `u32` | Adjustment value added to the computed length before encoding _(default: `0x00000000`)_ |
| `…` | `bytes` | Zero or more additional values |

### Returns

| Type |
| ---- |
| `bytes` |

## len_be64
```resynth
resynth fn len_be64 (
    adjust: u64 = 0x0000000000000000,
    =>
    *collect_args: bytes,
) -> bytes;
```
Prefix a buffer with a 64-bit big-endian length field

 Prepends an 8-byte big-endian encoding of `len(payload) + adjust` to the payload bytes.

 The length wraps around if it doesn\'t fit in the field.

### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| `adjust` | `u64` | Adjustment value added to the computed length before encoding _(default: `0x0000000000000000`)_ |
| `…` | `bytes` | Zero or more additional values |

### Returns

| Type |
| ---- |
| `bytes` |

## len_le16
```resynth
resynth fn len_le16 (
    adjust: u16 = 0x0000,
    =>
    *collect_args: bytes,
) -> bytes;
```
Prefix a buffer with a 16-bit little-endian length field

 Prepends a 2-byte little-endian encoding of `len(payload) + adjust` to the payload bytes.

 The length wraps around if it doesn\'t fit in the field.

### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| `adjust` | `u16` | Adjustment value added to the computed length before encoding _(default: `0x0000`)_ |
| `…` | `bytes` | Zero or more additional values |

### Returns

| Type |
| ---- |
| `bytes` |

## len_le32
```resynth
resynth fn len_le32 (
    adjust: u32 = 0x00000000,
    =>
    *collect_args: bytes,
) -> bytes;
```
Prefix a buffer with a 32-bit little-endian length field

 Prepends a 4-byte little-endian encoding of `len(payload) + adjust` to the payload bytes.

 The length wraps around if it doesn\'t fit in the field.

### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| `adjust` | `u32` | Adjustment value added to the computed length before encoding _(default: `0x00000000`)_ |
| `…` | `bytes` | Zero or more additional values |

### Returns

| Type |
| ---- |
| `bytes` |

## len_le64
```resynth
resynth fn len_le64 (
    adjust: u64 = 0x0000000000000000,
    =>
    *collect_args: bytes,
) -> bytes;
```
Prefix a buffer with a 64-bit little-endian length field

 Prepends an 8-byte little-endian encoding of `len(payload) + adjust` to the payload bytes.

 The length wraps around if it doesn\'t fit in the field.

### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| `adjust` | `u64` | Adjustment value added to the computed length before encoding _(default: `0x0000000000000000`)_ |
| `…` | `bytes` | Zero or more additional values |

### Returns

| Type |
| ---- |
| `bytes` |

## len_u8
```resynth
resynth fn len_u8 (
    adjust: u8 = 0x00,
    =>
    *collect_args: bytes,
) -> bytes;
```
Prefix a buffer with an 8-bit byte length field

 Prepends a single byte encoding of `len(payload) + adjust` to the payload bytes.

 The length wraps around if it doesn\'t fit in the field.

### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| `adjust` | `u8` | Adjustment value added to the computed length before encoding _(default: `0x00`)_ |
| `…` | `bytes` | Zero or more additional values |

### Returns

| Type |
| ---- |
| `bytes` |

## u8
```resynth
resynth fn u8 (
    val: u8,
) -> bytes;
```
Convert an integer into a one-byte string

### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| `val` | `u8` | Integer value to encode as a single byte |

### Returns

| Type |
| ---- |
| `bytes` |
