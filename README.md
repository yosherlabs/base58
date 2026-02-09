# Base58
Base58 is a Base58 library written in Zig.

This package ships a single preset: the Bitcoin Base58 alphabet.
Only the bitcoin alphabet is supported: `123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz`.

## API
- `bitcoin.Encoder.encode(dest, source)` and `bitcoin.Decoder.decode(dest, source)` for normal Base58.
- `bitcoin.Decoder.decodeWithMaxDecodedLen(dest, source, max_decoded_len)` to cap decode output/work for untrusted input.
- `bitcoin.CheckEncoder.encode(dest, version, payload)` and `bitcoin.CheckDecoder.decode(dest, source)` for Base58Check.
- `bitcoin.CheckDecoder.decodeWithMaxPayloadLen(dest, source, max_payload_len)` for capped Base58Check decode.
- `comptimeEncode`, `comptimeDecode`, `comptimeEncodeCheck`, `comptimeDecodeCheck` for compile-time encoding/decoding.
- `get*LengthUpperBound(...)` helpers for buffer sizing.

`encode`/`decode` APIs reject overlapping `dest` and `source` buffers with `error.OverlappingBuffers`.
