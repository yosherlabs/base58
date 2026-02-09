# base58 (Zig)
Fast Base58 and Base58Check encoding/decoding for Zig, with both runtime and comptime APIs.

This library intentionally ships one alphabet preset: Bitcoin Base58.

`123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz`

## What this library can do
- Runtime Base58 `encode` and `decode`.
- Runtime Base58Check `encode` and `decode` (version + payload + checksum validation).
- Compile-time Base58 and Base58Check encode/decode helpers.
- Strict error handling (`InvalidCharacter`, `InvalidChecksum`, `BufferTooSmall`, `DecodedTooLong`, and more).
- Upper-bound sizing helpers so you can allocate fixed buffers safely.
- Optional decode size caps for untrusted input.

## Runtime usage
Import the module:

```zig
const base58 = @import("base58");
```

### `encode`
```zig
const std = @import("std");
const base58 = @import("base58");

pub fn main() !void {
    const decoded = "Hello World!";
    var out: [base58.getEncodedLengthUpperBound(decoded.len)]u8 = undefined;

    const encoded = try base58.encode(&out, decoded);
    std.debug.print("{s}\n", .{encoded}); // 2NEpo7TZRRrLZSi2U
}
```

### `decode`
```zig
const std = @import("std");
const base58 = @import("base58");

pub fn main() !void {
    const encoded = "2NEpo7TZRRrLZSi2U";
    var out: [base58.getDecodedLengthUpperBound(encoded.len)]u8 = undefined;

    const decoded = try base58.decode(&out, encoded);
    std.debug.print("{s}\n", .{decoded}); // Hello World!
}
```

## Compile-time usage

### `comptimeEncode`
```zig
const std = @import("std");
const base58 = @import("base58");

test "comptime encode example" {
    const encoded = comptime base58.comptimeEncode("Hello World!");
    try std.testing.expectEqualStrings("2NEpo7TZRRrLZSi2U", &encoded);
}
```

### `comptimeDecode`
```zig
const std = @import("std");
const base58 = @import("base58");

test "comptime decode example" {
    const decoded = comptime base58.comptimeDecode("2NEpo7TZRRrLZSi2U");
    try std.testing.expectEqualStrings("Hello World!", &decoded);
}
```

## Other useful APIs
- Base58 decode cap:
  - `base58.decodeWithMaxDecodedLength(dest, source, max_decoded_len)`
- Base58Check:
  - `base58.encodeCheck(dest, version, payload)`
  - `base58.decodeCheck(dest, encoded)`
  - `base58.decodeCheckWithMaxPayloadLength(dest, encoded, max_payload_len)`
- Comptime Base58Check:
  - `base58.comptimeEncodeCheck(version, payload)`
  - `base58.comptimeDecodeCheck(encoded)`
- Buffer sizing:
  - `base58.getEncodedLengthUpperBound(decoded_len)`
  - `base58.getDecodedLengthUpperBound(encoded_len)`
  - `base58.getEncodedCheckLengthUpperBound(payload_len)`
  - `base58.getDecodedCheckPayloadLengthUpperBound(encoded_len)`

## Notes
- `encode`/`decode` reject overlapping `dest` and `source` with `error.OverlappingBuffers`.
- For better bounds on a concrete input slice, use:
  - `getEncodedLengthUpperBoundForSlice(...)`
  - `getDecodedLengthUpperBoundForSlice(...)`
  - `getDecodedCheckPayloadLengthUpperBoundForSlice(...)`
