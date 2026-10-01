 # Text / Byte-String Functions

 String and byte-buffer manipulation — concatenation, length, encoding, and hex conversion.
## Index


### Functions

| Function | Returns | Description |
| -------- | ------- | ----------- |
| [concat](#concat) | `bytes` | Concatenate strings |
| [crlflines](#crlflines) | `bytes` | join strings with CRLF line-endings |
| [len](#len) | `u64` | Return the length of a string (or strings) |

### Constants

| Name | Value |
| ---- | ----- |
| CRLF | `(bytes)"\|0d 0a\|"` |



## concat
```resynth
resynth fn concat (
    =>
    *collect_args: bytes,
) -> bytes;
```
Concatenate strings

### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| `…` | `bytes` | Zero or more additional values |

### Returns

| Type |
| ---- |
| `bytes` |

## crlflines
```resynth
resynth fn crlflines (
    =>
    *collect_args: bytes,
) -> bytes;
```
join strings with CRLF line-endings

### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| `…` | `bytes` | Zero or more additional values |

### Returns

| Type |
| ---- |
| `bytes` |

## len
```resynth
resynth fn len (
    =>
    *collect_args: bytes,
) -> u64;
```
Return the length of a string (or strings)

### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| `…` | `bytes` | Zero or more additional values |

### Returns

| Type |
| ---- |
| `u64` |
