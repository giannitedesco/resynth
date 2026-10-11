 # Buffers and File I/O

 Buffered I/O — read from and write to byte buffers and files.
## Index


### Classes

| Class | Description |
| ----- | ----------- |
| [BufIO](BufIO.md) | Buffered I/O |

### Functions

| Function | Returns | Description |
| -------- | ------- | ----------- |
| [bufio](#bufio) | [BufIO](../io/BufIO.md) | Create a `BufIO` buffer from one or more byte strings, from which bytes can be consumed in sequential chunks using `read(n)` and `read_all()`. This is useful for splitting a pre-assembled payload across multiple packets — for example, sending the first 15 bytes of a TLS record in one TCP segment and the rest in another. |
| [file](#file) | `bytes` | Load the contents of a file into a string |



## bufio
```resynth
resynth fn bufio (
    =>
    *collect_args: bytes,
) -> BufIO;
```
Create a `BufIO` buffer from one or more byte strings, from which bytes
 can be consumed in sequential chunks using `read(n)` and `read_all()`.
 This is useful for splitting a pre-assembled payload across multiple
 packets — for example, sending the first 15 bytes of a TLS record in one
 TCP segment and the rest in another.

### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| `…` | `bytes` | Zero or more additional values |

### Returns

| Type |
| ---- |
| [BufIO](../io/BufIO.md) |

## file
```resynth
resynth fn file (
    filename: bytes,
) -> bytes;
```
Load the contents of a file into a string

### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| `filename` | `bytes` | Path to the file to load |

### Returns

| Type |
| ---- |
| `bytes` |
