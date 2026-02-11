# base58 (Zig)
Fast Base58 and Base58Check encoding/decoding for Zig, with both runtime and comptime APIs.

This library intentionally ships one alphabet preset: Bitcoin Base58.

`123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz`

## What this library can do
- Runtime Base58 `encode` and `decode`.
- Runtime Base58Check `encode` and `decode` (version + payload + checksum validation).
- Compile-time Base58 and Base58Check encode/decode helpers.
- Strict error handling:
  (`InvalidCharacter`, `InvalidChecksum`, `BufferTooSmall`, `DecodedTooLong`, and more).
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
    var out: [base58.get_encoded_length_upper_bound(decoded.len)]u8 = undefined;

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
    var out: [base58.get_decoded_length_upper_bound(encoded.len)]u8 = undefined;

    const decoded = try base58.decode(&out, encoded);
    std.debug.print("{s}\n", .{decoded}); // Hello World!
}
```

## Compile-time usage

### `comptime_encode`
```zig
const std = @import("std");
const base58 = @import("base58");

test "comptime encode example" {
    const encoded = comptime base58.comptime_encode("Hello World!");
    try std.testing.expectEqualStrings("2NEpo7TZRRrLZSi2U", &encoded);
}
```

### `comptime_decode`
```zig
const std = @import("std");
const base58 = @import("base58");

test "comptime decode example" {
    const decoded = comptime base58.comptime_decode("2NEpo7TZRRrLZSi2U");
    try std.testing.expectEqualStrings("Hello World!", &decoded);
}
```

## Other useful APIs
- Base58 decode cap:
  - `base58.decode_with_max_decoded_length(dest, source, max_decoded_len)`
- Base58Check:
  - `base58.encode_check(dest, version, payload)`
  - `base58.decode_check(dest, encoded)`
  - `base58.decode_check_with_max_payload_length(dest, encoded, max_payload_len)`
- Comptime Base58Check:
  - `base58.comptime_encode_check(version, payload)`
  - `base58.comptime_decode_check(encoded)`
- Buffer sizing:
  - `base58.get_encoded_length_upper_bound(decoded_len)`
  - `base58.get_decoded_length_upper_bound(encoded_len)`
  - `base58.get_encoded_check_length_upper_bound(payload_len)`
  - `base58.get_decoded_check_payload_length_upper_bound(encoded_len)`

## Notes
- `encode`/`decode` reject overlapping `dest` and `source` with `error.OverlappingBuffers`.
- For better bounds on a concrete input slice, use:
  - `get_encoded_length_upper_bound_for_slice(...)`
  - `get_decoded_length_upper_bound_for_slice(...)`
  - `get_decoded_check_payload_length_upper_bound_for_slice(...)`
