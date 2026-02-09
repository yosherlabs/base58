const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;

pub const Error = error{
    InvalidCharacter,
    InvalidChecksum,
    DecodedTooShort,
    DecodedTooLong,
    BufferTooSmall,
};

pub const bitcoin_alphabet_chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".*;

const invalid_char: u8 = 0xff;
const checksum_len: usize = 4;
const max_usize = std.math.maxInt(usize);
const bitcoin_char_to_index = buildCharToIndexTable(bitcoin_alphabet_chars);

pub const DecodedCheck = struct {
    version: u8,
    payload: []const u8,
};

pub fn DecodedCheckComptime(comptime payload_len: usize) type {
    return struct {
        version: u8,
        payload: [payload_len]u8,
    };
}

/// Base58 codecs.
/// This package intentionally ships only the Bitcoin alphabet preset.
pub const Codecs = struct {
    alphabet_chars: [58]u8,
    Encoder: Base58Encoder,
    Decoder: Base58Decoder,
    CheckEncoder: Base58CheckEncoder,
    CheckDecoder: Base58CheckDecoder,
};

pub const bitcoin = Codecs{
    .alphabet_chars = bitcoin_alphabet_chars,
    .Encoder = Base58Encoder.init(bitcoin_alphabet_chars),
    .Decoder = Base58Decoder.init(bitcoin_alphabet_chars),
    .CheckEncoder = Base58CheckEncoder.init(bitcoin_alphabet_chars),
    .CheckDecoder = Base58CheckDecoder.init(bitcoin_alphabet_chars),
};

pub const Base58Encoder = struct {
    alphabet_chars: [58]u8,

    pub fn init(alphabet_chars: [58]u8) Base58Encoder {
        var char_in_alphabet = [_]bool{false} ** 256;
        for (alphabet_chars) |c| {
            assert(!char_in_alphabet[c]);
            char_in_alphabet[c] = true;
        }
        return Base58Encoder{
            .alphabet_chars = alphabet_chars,
        };
    }

    /// Returns a safe upper bound for encoded output size.
    pub fn calcSizeUpperBound(encoder: *const Base58Encoder, source_len: usize) usize {
        _ = encoder;
        if (source_len == 0) return 0;
        return scaledUpperBound(source_len, 138, 100);
    }

    /// Returns a tighter upper bound for a concrete source slice.
    pub fn calcSizeUpperBoundForSlice(encoder: *const Base58Encoder, source: []const u8) usize {
        _ = encoder;
        const leading_zeros = countLeadingZeroBytes(source);
        const significant_len = source.len - leading_zeros;
        if (significant_len == 0) return leading_zeros;
        return checkedAddOrMax(leading_zeros, scaledUpperBound(significant_len, 138, 100));
    }

    /// Encodes `source` into `dest` and returns the written slice.
    pub fn encode(encoder: *const Base58Encoder, dest: []u8, source: []const u8) Error![]const u8 {
        var length: usize = 0;
        try encodeChunkToDigits(dest, &length, source);

        const leading_zeros = countLeadingZeroBytes(source);
        try appendZeroValues(dest, &length, leading_zeros);

        var i: usize = 0;
        while (i < length) : (i += 1) {
            dest[i] = encoder.alphabet_chars[dest[i]];
        }
        std.mem.reverse(u8, dest[0..length]);
        return dest[0..length];
    }
};

pub const Base58Decoder = struct {
    alphabet_chars: [58]u8,
    char_to_index: [256]u8,

    pub fn init(alphabet_chars: [58]u8) Base58Decoder {
        var result = Base58Decoder{
            .alphabet_chars = alphabet_chars,
            .char_to_index = [_]u8{invalid_char} ** 256,
        };

        var char_in_alphabet = [_]bool{false} ** 256;
        for (alphabet_chars, 0..) |c, i| {
            assert(!char_in_alphabet[c]);
            result.char_to_index[c] = @intCast(i);
            char_in_alphabet[c] = true;
        }

        return result;
    }

    /// Returns a safe upper bound for decoded output size.
    pub fn calcSizeUpperBound(decoder: *const Base58Decoder, source_len: usize) usize {
        _ = decoder;
        return source_len;
    }

    /// Returns a tighter upper bound for a concrete source slice.
    pub fn calcSizeUpperBoundForSlice(decoder: *const Base58Decoder, source: []const u8) usize {
        const leading_ones = countLeadingZeroChars(source, decoder.alphabet_chars[0]);
        const significant_len = source.len - leading_ones;
        if (significant_len == 0) return leading_ones;
        return checkedAddOrMax(leading_ones, scaledUpperBound(significant_len, 11, 15));
    }

    /// Decodes `source` into `dest` and returns the written slice.
    pub fn decode(decoder: *const Base58Decoder, dest: []u8, source: []const u8) Error![]const u8 {
        return decoder.decodeWithMaxDecodedLen(dest, source, max_usize);
    }

    /// Decodes `source` into `dest` with a hard cap for decoded size.
    /// Useful for untrusted input where callers want to bound work and output.
    pub fn decodeWithMaxDecodedLen(decoder: *const Base58Decoder, dest: []u8, source: []const u8, max_decoded_len: usize) Error![]const u8 {
        var length: usize = 0;
        const leading_ones = countLeadingZeroChars(source, decoder.alphabet_chars[0]);
        if (leading_ones > max_decoded_len) return error.DecodedTooLong;

        for (source) |c| {
            var carry: u32 = decoder.char_to_index[c];
            if (carry == @as(u32, invalid_char)) return error.InvalidCharacter;

            var i: usize = 0;
            while (i < length) : (i += 1) {
                carry += @as(u32, dest[i]) * 58;
                dest[i] = @truncate(carry);
                carry >>= 8;
            }

            while (carry > 0) : (carry >>= 8) {
                if (length == max_decoded_len) return error.DecodedTooLong;
                if (length == dest.len) return error.BufferTooSmall;
                dest[length] = @truncate(carry);
                length += 1;
            }

            // Keep checking progressively to fail early on oversized decodes.
            if (length > max_decoded_len - leading_ones) return error.DecodedTooLong;
        }

        var i: usize = 0;
        while (i < leading_ones) : (i += 1) {
            if (length == max_decoded_len) return error.DecodedTooLong;
            if (length == dest.len) return error.BufferTooSmall;
            dest[length] = 0;
            length += 1;
        }

        std.mem.reverse(u8, dest[0..length]);
        return dest[0..length];
    }
};

pub const Base58CheckEncoder = struct {
    encoder: Base58Encoder,

    pub fn init(alphabet_chars: [58]u8) Base58CheckEncoder {
        return Base58CheckEncoder{
            .encoder = Base58Encoder.init(alphabet_chars),
        };
    }

    /// Returns a safe upper bound for encoded Base58Check output size.
    pub fn calcSizeUpperBound(check_encoder: *const Base58CheckEncoder, payload_len: usize) usize {
        return check_encoder.encoder.calcSizeUpperBound(checkedAddOrMax(payload_len, 1 + checksum_len));
    }

    /// Encodes `version + payload + checksum(version+payload)` into Base58.
    pub fn encode(check_encoder: *const Base58CheckEncoder, dest: []u8, version: u8, payload: []const u8) Error![]const u8 {
        const check = checksumVersionPayload(version, payload);

        var length: usize = 0;
        const version_buf = [_]u8{version};
        try encodeChunkToDigits(dest, &length, &version_buf);
        try encodeChunkToDigits(dest, &length, payload);
        try encodeChunkToDigits(dest, &length, &check);

        const leading_zeros = countLeadingZeroBytesCheck(version, payload, check);
        try appendZeroValues(dest, &length, leading_zeros);

        var i: usize = 0;
        while (i < length) : (i += 1) {
            dest[i] = check_encoder.encoder.alphabet_chars[dest[i]];
        }
        std.mem.reverse(u8, dest[0..length]);
        return dest[0..length];
    }
};

pub const Base58CheckDecoder = struct {
    decoder: Base58Decoder,

    pub fn init(alphabet_chars: [58]u8) Base58CheckDecoder {
        return Base58CheckDecoder{
            .decoder = Base58Decoder.init(alphabet_chars),
        };
    }

    /// Returns a safe upper bound for decoded bytes (including version+checksum).
    pub fn calcSizeUpperBound(check_decoder: *const Base58CheckDecoder, source_len: usize) usize {
        return check_decoder.decoder.calcSizeUpperBound(source_len);
    }

    /// Returns a tighter upper bound for decoded bytes (including version+checksum).
    pub fn calcSizeUpperBoundForSlice(check_decoder: *const Base58CheckDecoder, source: []const u8) usize {
        return check_decoder.decoder.calcSizeUpperBoundForSlice(source);
    }

    /// Returns a safe upper bound for payload length after successful Base58Check decode.
    pub fn calcPayloadSizeUpperBound(check_decoder: *const Base58CheckDecoder, source_len: usize) usize {
        const decoded_upper = check_decoder.calcSizeUpperBound(source_len);
        return if (decoded_upper < 1 + checksum_len) 0 else decoded_upper - (1 + checksum_len);
    }

    /// Returns a tighter upper bound for payload length after successful Base58Check decode.
    pub fn calcPayloadSizeUpperBoundForSlice(check_decoder: *const Base58CheckDecoder, source: []const u8) usize {
        const decoded_upper = check_decoder.calcSizeUpperBoundForSlice(source);
        return if (decoded_upper < 1 + checksum_len) 0 else decoded_upper - (1 + checksum_len);
    }

    /// Decodes Base58Check bytes, validates checksum, and returns version + payload view.
    pub fn decode(check_decoder: *const Base58CheckDecoder, dest: []u8, source: []const u8) Error!DecodedCheck {
        const decoded = try check_decoder.decoder.decode(dest, source);
        if (decoded.len < 1 + checksum_len) return error.DecodedTooShort;

        const check_start = decoded.len - checksum_len;
        const expected = checksum(decoded[0..check_start]);
        if (!std.mem.eql(u8, decoded[check_start..], expected[0..])) {
            return error.InvalidChecksum;
        }

        return DecodedCheck{
            .version = decoded[0],
            .payload = decoded[1..check_start],
        };
    }

    /// Decodes Base58Check with an explicit payload-size cap.
    pub fn decodeWithMaxPayloadLen(check_decoder: *const Base58CheckDecoder, dest: []u8, source: []const u8, max_payload_len: usize) Error!DecodedCheck {
        const max_decoded_len = std.math.add(usize, max_payload_len, 1 + checksum_len) catch return error.DecodedTooLong;
        const decoded = try check_decoder.decoder.decodeWithMaxDecodedLen(dest, source, max_decoded_len);
        if (decoded.len < 1 + checksum_len) return error.DecodedTooShort;

        const check_start = decoded.len - checksum_len;
        const expected = checksum(decoded[0..check_start]);
        if (!std.mem.eql(u8, decoded[check_start..], expected[0..])) {
            return error.InvalidChecksum;
        }

        if (check_start - 1 > max_payload_len) return error.DecodedTooLong;

        return DecodedCheck{
            .version = decoded[0],
            .payload = decoded[1..check_start],
        };
    }
};

pub fn getEncodedLengthUpperBound(decoded_len: usize) usize {
    return bitcoin.Encoder.calcSizeUpperBound(decoded_len);
}

pub fn getEncodedLengthUpperBoundForSlice(decoded: []const u8) usize {
    return bitcoin.Encoder.calcSizeUpperBoundForSlice(decoded);
}

pub fn getDecodedLengthUpperBound(encoded_len: usize) usize {
    return bitcoin.Decoder.calcSizeUpperBound(encoded_len);
}

pub fn getDecodedLengthUpperBoundForSlice(encoded: []const u8) usize {
    return bitcoin.Decoder.calcSizeUpperBoundForSlice(encoded);
}

pub fn decodeWithMaxDecodedLength(dest: []u8, encoded: []const u8, max_decoded_len: usize) Error![]const u8 {
    return bitcoin.Decoder.decodeWithMaxDecodedLen(dest, encoded, max_decoded_len);
}

pub fn getEncodedCheckLengthUpperBound(payload_len: usize) usize {
    return bitcoin.CheckEncoder.calcSizeUpperBound(payload_len);
}

pub fn getDecodedCheckPayloadLengthUpperBound(encoded_len: usize) usize {
    return bitcoin.CheckDecoder.calcPayloadSizeUpperBound(encoded_len);
}

pub fn getDecodedCheckPayloadLengthUpperBoundForSlice(encoded: []const u8) usize {
    return bitcoin.CheckDecoder.calcPayloadSizeUpperBoundForSlice(encoded);
}

pub fn decodeCheckWithMaxPayloadLength(dest: []u8, encoded: []const u8, max_payload_len: usize) Error!DecodedCheck {
    return bitcoin.CheckDecoder.decodeWithMaxPayloadLen(dest, encoded, max_payload_len);
}

pub fn comptimeGetEncodedLength(comptime decoded: []const u8) usize {
    @setEvalBranchQuota(100_000);
    var buffer: [getEncodedLengthUpperBound(decoded.len)]u8 = undefined;
    const encoded = bitcoin.Encoder.encode(&buffer, decoded) catch unreachable;
    return encoded.len;
}

pub fn comptimeEncode(comptime decoded: []const u8) [comptimeGetEncodedLength(decoded)]u8 {
    @setEvalBranchQuota(100_000);
    var buffer: [getEncodedLengthUpperBound(decoded.len)]u8 = undefined;
    const encoded = bitcoin.Encoder.encode(&buffer, decoded) catch unreachable;

    const out_len = comptime comptimeGetEncodedLength(decoded);
    var out: [out_len]u8 = undefined;
    @memcpy(out[0..], encoded[0..out_len]);
    return out;
}

pub fn comptimeGetDecodedLength(comptime encoded: []const u8) usize {
    @setEvalBranchQuota(100_000);
    var buffer = std.mem.zeroes([getDecodedLengthUpperBound(encoded.len)]u8);
    var length: usize = 0;

    for (encoded) |c| {
        var carry: u32 = bitcoin_char_to_index[c];
        if (carry == @as(u32, invalid_char)) unreachable;

        var i: usize = 0;
        while (i < length) : (i += 1) {
            carry += @as(u32, buffer[i]) * 58;
            buffer[i] = @truncate(carry);
            carry >>= 8;
        }
        while (carry > 0) : (carry >>= 8) {
            buffer[length] = @truncate(carry);
            length += 1;
        }
    }

    const leading_ones = countLeadingZeroChars(encoded, bitcoin_alphabet_chars[0]);
    length += leading_ones;
    return length;
}

pub fn comptimeDecode(comptime encoded: []const u8) [comptimeGetDecodedLength(encoded)]u8 {
    @setEvalBranchQuota(100_000);
    var buffer = std.mem.zeroes([getDecodedLengthUpperBound(encoded.len)]u8);
    var length: usize = 0;

    for (encoded) |c| {
        var carry: u32 = bitcoin_char_to_index[c];
        if (carry == @as(u32, invalid_char)) unreachable;

        var i: usize = 0;
        while (i < length) : (i += 1) {
            carry += @as(u32, buffer[i]) * 58;
            buffer[i] = @truncate(carry);
            carry >>= 8;
        }
        while (carry > 0) : (carry >>= 8) {
            buffer[length] = @truncate(carry);
            length += 1;
        }
    }

    const leading_ones = countLeadingZeroChars(encoded, bitcoin_alphabet_chars[0]);
    tryAppendLeadingZerosComptime(&buffer, &length, leading_ones);
    std.mem.reverse(u8, buffer[0..length]);

    const out_len = comptime comptimeGetDecodedLength(encoded);
    var out: [out_len]u8 = undefined;
    @memcpy(out[0..], buffer[0..out_len]);
    return out;
}

pub fn comptimeGetEncodedCheckLength(comptime version: u8, comptime payload: []const u8) usize {
    @setEvalBranchQuota(100_000);
    var buffer: [getEncodedCheckLengthUpperBound(payload.len)]u8 = undefined;
    const encoded = bitcoin.CheckEncoder.encode(&buffer, version, payload) catch unreachable;
    return encoded.len;
}

pub fn comptimeEncodeCheck(comptime version: u8, comptime payload: []const u8) [comptimeGetEncodedCheckLength(version, payload)]u8 {
    @setEvalBranchQuota(100_000);
    var buffer: [getEncodedCheckLengthUpperBound(payload.len)]u8 = undefined;
    const encoded = bitcoin.CheckEncoder.encode(&buffer, version, payload) catch unreachable;

    const out_len = comptime comptimeGetEncodedCheckLength(version, payload);
    var out: [out_len]u8 = undefined;
    @memcpy(out[0..], encoded[0..out_len]);
    return out;
}

pub fn comptimeGetDecodedCheckPayloadLength(comptime encoded: []const u8) usize {
    @setEvalBranchQuota(100_000);
    const decoded = comptimeDecode(encoded);
    if (decoded.len < 1 + checksum_len) unreachable;

    const check_start = decoded.len - checksum_len;
    const expected = checksum(decoded[0..check_start]);
    if (!std.mem.eql(u8, decoded[check_start..], expected[0..])) unreachable;
    return check_start - 1;
}

pub fn comptimeDecodeCheck(comptime encoded: []const u8) DecodedCheckComptime(comptimeGetDecodedCheckPayloadLength(encoded)) {
    @setEvalBranchQuota(100_000);
    const decoded = comptimeDecode(encoded);
    if (decoded.len < 1 + checksum_len) unreachable;

    const check_start = decoded.len - checksum_len;
    const expected = checksum(decoded[0..check_start]);
    if (!std.mem.eql(u8, decoded[check_start..], expected[0..])) unreachable;

    const payload_len = comptime comptimeGetDecodedCheckPayloadLength(encoded);
    var out: DecodedCheckComptime(payload_len) = undefined;
    out.version = decoded[0];
    @memcpy(out.payload[0..], decoded[1 .. 1 + payload_len]);
    return out;
}

fn encodeChunkToDigits(dest: []u8, length: *usize, chunk: []const u8) Error!void {
    for (chunk) |r| {
        var carry: u32 = r;

        var i: usize = 0;
        while (i < length.*) : (i += 1) {
            carry += @as(u32, dest[i]) << 8;
            dest[i] = @intCast(carry % 58);
            carry /= 58;
        }

        while (carry > 0) : (carry /= 58) {
            if (length.* == dest.len) return error.BufferTooSmall;
            dest[length.*] = @intCast(carry % 58);
            length.* += 1;
        }
    }
}

fn tryAppendLeadingZerosComptime(buffer: []u8, length: *usize, leading_zeros: usize) void {
    var i: usize = 0;
    while (i < leading_zeros) : (i += 1) {
        if (length.* == buffer.len) unreachable;
        buffer[length.*] = 0;
        length.* += 1;
    }
}

fn appendZeroValues(dest: []u8, length: *usize, zero_count: usize) Error!void {
    var i: usize = 0;
    while (i < zero_count) : (i += 1) {
        if (length.* == dest.len) return error.BufferTooSmall;
        dest[length.*] = 0;
        length.* += 1;
    }
}

fn buildCharToIndexTable(alphabet_chars: [58]u8) [256]u8 {
    var table = [_]u8{invalid_char} ** 256;
    for (alphabet_chars, 0..) |c, i| {
        table[c] = @intCast(i);
    }
    return table;
}

fn checkedAddOrMax(a: usize, b: usize) usize {
    return std.math.add(usize, a, b) catch max_usize;
}

fn scaledUpperBound(len: usize, mul: usize, div: usize) usize {
    const product = std.math.mul(usize, len, mul) catch return max_usize;
    const scaled = @divTrunc(product, div);
    return checkedAddOrMax(scaled, 1);
}

fn countLeadingZeroBytes(input: []const u8) usize {
    var count: usize = 0;
    while (count < input.len and input[count] == 0) : (count += 1) {}
    return count;
}

fn countLeadingZeroChars(input: []const u8, zero_char: u8) usize {
    var count: usize = 0;
    while (count < input.len and input[count] == zero_char) : (count += 1) {}
    return count;
}

fn countLeadingZeroBytesCheck(version: u8, payload: []const u8, check: [checksum_len]u8) usize {
    var count: usize = 0;

    if (version != 0) return 0;
    count += 1;

    for (payload) |b| {
        if (b != 0) return count;
        count += 1;
    }
    for (check) |b| {
        if (b != 0) return count;
        count += 1;
    }
    return count;
}

fn checksum(data: []const u8) [checksum_len]u8 {
    var h1: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(data, &h1, .{});

    var h2: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&h1, &h2, .{});

    return .{ h2[0], h2[1], h2[2], h2[3] };
}

fn checksumVersionPayload(version: u8, payload: []const u8) [checksum_len]u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    const version_buf = [_]u8{version};
    hasher.update(&version_buf);
    hasher.update(payload);

    var h1: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    hasher.final(&h1);

    var h2: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&h1, &h2, .{});
    return .{ h2[0], h2[1], h2[2], h2[3] };
}

test "bitcoin base58 vectors roundtrip" {
    var encode_buffer: [256]u8 = undefined;
    var decode_buffer: [256]u8 = undefined;
    for (testingData()) |d| {
        const encoded = try bitcoin.Encoder.encode(&encode_buffer, d.decoded);
        try testing.expectEqualStrings(d.encoded, encoded);

        const decoded = try bitcoin.Decoder.decode(&decode_buffer, d.encoded);
        try testing.expectEqualSlices(u8, d.decoded, decoded);
    }
}

test "bitcoin base58 supports empty slices" {
    var encode_buffer: [8]u8 = undefined;
    var decode_buffer: [8]u8 = undefined;

    const encoded = try bitcoin.Encoder.encode(&encode_buffer, "");
    try testing.expectEqual(@as(usize, 0), encoded.len);

    const decoded = try bitcoin.Decoder.decode(&decode_buffer, "");
    try testing.expectEqual(@as(usize, 0), decoded.len);
}

test "bitcoin base58 returns InvalidCharacter" {
    var buffer: [64]u8 = undefined;
    try testing.expectError(error.InvalidCharacter, bitcoin.Decoder.decode(&buffer, "0"));
    try testing.expectError(error.InvalidCharacter, bitcoin.Decoder.decode(&buffer, "O"));
    try testing.expectError(error.InvalidCharacter, bitcoin.Decoder.decode(&buffer, "I"));
    try testing.expectError(error.InvalidCharacter, bitcoin.Decoder.decode(&buffer, "l"));
}

test "bitcoin base58 returns BufferTooSmall" {
    var encode_buffer: [16]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, bitcoin.Encoder.encode(&encode_buffer, "Hello World!"));

    var decode_buffer: [11]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, bitcoin.Decoder.decode(&decode_buffer, "2NEpo7TZRRrLZSi2U"));
}

test "bitcoin base58 bounds are safe for known vectors" {
    for (testingData()) |d| {
        try testing.expect(getEncodedLengthUpperBoundForSlice(d.decoded) >= d.encoded.len);
        try testing.expect(getDecodedLengthUpperBoundForSlice(d.encoded) >= d.decoded.len);
    }
}

test "bitcoin base58check known vector" {
    const version: u8 = 0;
    const payload = [_]u8{ 248, 145, 115, 3, 191, 168, 239, 36, 242, 146, 232, 250, 20, 25, 178, 4, 96, 186, 6, 77 };
    const encoded = "1PfJpZsjreyVrqeoAfabrRwwjQyoSQMmHH";

    var decode_buffer: [256]u8 = undefined;
    const decoded = try bitcoin.CheckDecoder.decode(&decode_buffer, encoded);
    try testing.expectEqual(version, decoded.version);
    try testing.expectEqualSlices(u8, &payload, decoded.payload);

    var encode_buffer: [256]u8 = undefined;
    const encoded_roundtrip = try bitcoin.CheckEncoder.encode(&encode_buffer, version, &payload);
    try testing.expectEqualStrings(encoded, encoded_roundtrip);
}

test "bitcoin base58check returns InvalidChecksum" {
    var buffer: [256]u8 = undefined;
    try testing.expectError(error.InvalidChecksum, bitcoin.CheckDecoder.decode(&buffer, "1PfJpZsjreyVrqeoAfabrRwwjQyoSQMmHJ"));
}

test "bitcoin base58check returns DecodedTooShort" {
    var buffer: [64]u8 = undefined;
    try testing.expectError(error.DecodedTooShort, bitcoin.CheckDecoder.decode(&buffer, "1111"));
}

test "bitcoin base58check bounds are safe" {
    const version: u8 = 0;
    const payload = [_]u8{0} ** 16;

    var encoded_buffer: [256]u8 = undefined;
    const encoded = try bitcoin.CheckEncoder.encode(&encoded_buffer, version, &payload);

    try testing.expect(getEncodedCheckLengthUpperBound(payload.len) >= encoded.len);
    try testing.expect(getDecodedLengthUpperBoundForSlice(encoded) >= (payload.len + 1 + checksum_len));
    try testing.expect(getDecodedCheckPayloadLengthUpperBoundForSlice(encoded) >= payload.len);
}

test "comptime base58 wrappers" {
    const td = comptime testingData();
    inline for (td) |d| {
        const encoded = comptimeEncode(d.decoded);
        try testing.expectEqualStrings(d.encoded, &encoded);

        const decoded = comptimeDecode(d.encoded);
        try testing.expectEqualSlices(u8, d.decoded, &decoded);
    }
}

test "comptime base58check wrappers" {
    const version: u8 = 0;
    const payload = [_]u8{ 248, 145, 115, 3, 191, 168, 239, 36, 242, 146, 232, 250, 20, 25, 178, 4, 96, 186, 6, 77 };
    const encoded = comptimeEncodeCheck(version, &payload);
    try testing.expectEqualStrings("1PfJpZsjreyVrqeoAfabrRwwjQyoSQMmHH", &encoded);

    const decoded = comptimeDecodeCheck("1PfJpZsjreyVrqeoAfabrRwwjQyoSQMmHH");
    try testing.expectEqual(version, decoded.version);
    try testing.expectEqualSlices(u8, &payload, &decoded.payload);
}

test "bitcoin base58 upper-bound helpers saturate on overflow" {
    try testing.expectEqual(max_usize, bitcoin.Encoder.calcSizeUpperBound(max_usize));
    try testing.expectEqual(max_usize, bitcoin.CheckEncoder.calcSizeUpperBound(max_usize));
}

test "bitcoin base58 decodeWithMaxDecodedLen enforces cap" {
    var decode_buffer: [256]u8 = undefined;

    try testing.expectError(error.DecodedTooLong, bitcoin.Decoder.decodeWithMaxDecodedLen(&decode_buffer, "11111", 4));
    const exact = try bitcoin.Decoder.decodeWithMaxDecodedLen(&decode_buffer, "11111", 5);
    try testing.expectEqual(@as(usize, 5), exact.len);

    const source = [_]u8{0xff} ** 33;
    var encode_buffer: [256]u8 = undefined;
    const encoded = try bitcoin.Encoder.encode(&encode_buffer, &source);
    try testing.expectError(error.DecodedTooLong, bitcoin.Decoder.decodeWithMaxDecodedLen(&decode_buffer, encoded, 32));
}

test "bitcoin base58check decodeWithMaxPayloadLen enforces cap" {
    const encoded = "1PfJpZsjreyVrqeoAfabrRwwjQyoSQMmHH";

    var decode_buffer: [256]u8 = undefined;
    const ok = try bitcoin.CheckDecoder.decodeWithMaxPayloadLen(&decode_buffer, encoded, 20);
    try testing.expectEqual(@as(u8, 0), ok.version);
    try testing.expectEqual(@as(usize, 20), ok.payload.len);

    try testing.expectError(error.DecodedTooLong, bitcoin.CheckDecoder.decodeWithMaxPayloadLen(&decode_buffer, encoded, 19));
}

test "bitcoin base58 random roundtrip property" {
    var prng = std.Random.DefaultPrng.init(0xa12b_c34d_e56f_7788);
    const random = prng.random();

    var decoded_source: [256]u8 = undefined;
    var encoded_buffer_a: [512]u8 = undefined;
    var encoded_buffer_b: [512]u8 = undefined;
    var decoded_buffer: [256]u8 = undefined;

    var i: usize = 0;
    while (i < 2000) : (i += 1) {
        const decoded_len = random.uintLessThan(usize, decoded_source.len + 1);
        random.bytes(decoded_source[0..decoded_len]);

        const encoded = try bitcoin.Encoder.encode(&encoded_buffer_a, decoded_source[0..decoded_len]);
        const decoded = try bitcoin.Decoder.decode(&decoded_buffer, encoded);
        try testing.expectEqualSlices(u8, decoded_source[0..decoded_len], decoded);

        const encoded_again = try bitcoin.Encoder.encode(&encoded_buffer_b, decoded);
        try testing.expectEqualStrings(encoded, encoded_again);
    }
}

test "bitcoin base58check random roundtrip property" {
    var prng = std.Random.DefaultPrng.init(0x8ee7_6612_03ab_4d55);
    const random = prng.random();

    var payload_buffer: [128]u8 = undefined;
    var encoded_buffer_a: [512]u8 = undefined;
    var encoded_buffer_b: [512]u8 = undefined;
    var decoded_buffer: [256]u8 = undefined;

    var i: usize = 0;
    while (i < 1000) : (i += 1) {
        const payload_len = random.uintLessThan(usize, payload_buffer.len + 1);
        random.bytes(payload_buffer[0..payload_len]);
        const version = random.int(u8);

        const encoded = try bitcoin.CheckEncoder.encode(&encoded_buffer_a, version, payload_buffer[0..payload_len]);
        const decoded = try bitcoin.CheckDecoder.decode(&decoded_buffer, encoded);
        try testing.expectEqual(version, decoded.version);
        try testing.expectEqualSlices(u8, payload_buffer[0..payload_len], decoded.payload);

        const encoded_again = try bitcoin.CheckEncoder.encode(&encoded_buffer_b, decoded.version, decoded.payload);
        try testing.expectEqualStrings(encoded, encoded_again);
    }
}

test "bitcoin base58 rejects all non-alphabet bytes" {
    var decode_buffer: [8]u8 = undefined;
    var source: [1]u8 = undefined;

    for (0..256) |i| {
        source[0] = @intCast(i);
        if (bitcoin_char_to_index[source[0]] == invalid_char) {
            try testing.expectError(error.InvalidCharacter, bitcoin.Decoder.decode(&decode_buffer, &source));
        }
    }
}

test "bitcoin base58 random garbage either fails or canonicalizes" {
    var prng = std.Random.DefaultPrng.init(0x16bc_9f22_4451_7a20);
    const random = prng.random();

    var garbage: [96]u8 = undefined;
    var decoded_buffer: [256]u8 = undefined;
    var encoded_buffer: [256]u8 = undefined;
    var decoded_buffer_again: [256]u8 = undefined;

    var i: usize = 0;
    while (i < 1500) : (i += 1) {
        const garbage_len = random.uintLessThan(usize, garbage.len + 1);
        random.bytes(garbage[0..garbage_len]);

        if (bitcoin.Decoder.decode(&decoded_buffer, garbage[0..garbage_len])) |decoded| {
            const encoded = try bitcoin.Encoder.encode(&encoded_buffer, decoded);
            const decoded_again = try bitcoin.Decoder.decode(&decoded_buffer_again, encoded);
            try testing.expectEqualSlices(u8, decoded, decoded_again);
        } else |err| switch (err) {
            error.InvalidCharacter => {},
            else => return err,
        }
    }
}

test "bitcoin base58 additional known vectors" {
    const cases = [_]struct {
        hex: []const u8,
        encoded: []const u8,
    }{
        .{ .hex = "", .encoded = "" },
        .{ .hex = "61", .encoded = "2g" },
        .{ .hex = "626262", .encoded = "a3gV" },
        .{ .hex = "636363", .encoded = "aPEr" },
        .{ .hex = "73696d706c792061206c6f6e6720737472696e67", .encoded = "2cFupjhnEsSn59qHXstmK2ffpLv2" },
        .{ .hex = "00eb15231dfceb60925886b67d065299925915aeb172c06647", .encoded = "1NS17iag9jJgTHD1VXjvLCEnZuQ3rJDE9L" },
        .{ .hex = "516b6fcd0f", .encoded = "ABnLTmg" },
        .{ .hex = "bf4f89001e670274dd", .encoded = "3SEo3LWLoPntC" },
        .{ .hex = "572e4794", .encoded = "3EFU7m" },
        .{ .hex = "ecac89cad93923c02321", .encoded = "EJDM8drfXA6uyA" },
        .{ .hex = "10c8511e", .encoded = "Rt5zm" },
        .{ .hex = "00000000000000000000", .encoded = "1111111111" },
        .{ .hex = "000111d38e5fc9071ffcd20b4a763cc9ae4f252bb4e48fd66a835e252ada93ff480d6dd43dc62a641155a5", .encoded = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz" },
    };

    var decode_from_hex_buffer: [1024]u8 = undefined;
    var encode_buffer: [2048]u8 = undefined;
    var decode_buffer: [1024]u8 = undefined;

    for (cases) |c| {
        const decoded_from_hex = try std.fmt.hexToBytes(&decode_from_hex_buffer, c.hex);
        const encoded = try bitcoin.Encoder.encode(&encode_buffer, decoded_from_hex);
        try testing.expectEqualStrings(c.encoded, encoded);

        const decoded = try bitcoin.Decoder.decode(&decode_buffer, c.encoded);
        try testing.expectEqualSlices(u8, decoded_from_hex, decoded);
    }
}

test "bitcoin base58 decode boundary failure matrix" {
    var decode_buffer: [128]u8 = undefined;

    const invalid_samples = [_][]const u8{
        "0",
        "O",
        "I",
        "l",
        "11111111111111111111111111111110",
        "1111111111111111111111111111111!",
        "1111111111111111111111111111111;",
        "1111111111111111111111111111111_",
        "\x80",
        "\xff",
    };
    for (invalid_samples) |sample| {
        try testing.expectError(error.InvalidCharacter, bitcoin.Decoder.decode(&decode_buffer, sample));
    }

    try testing.expectError(error.DecodedTooLong, bitcoin.Decoder.decodeWithMaxDecodedLen(&decode_buffer, "111111111111111111111111111111111", 32));
    try testing.expectError(error.BufferTooSmall, bitcoin.Decoder.decode(decode_buffer[0..11], "2NEpo7TZRRrLZSi2U"));
}

test "bitcoin base58check boundary failure matrix" {
    var decode_buffer: [256]u8 = undefined;

    try testing.expectError(error.DecodedTooShort, bitcoin.CheckDecoder.decode(&decode_buffer, "1111"));
    try testing.expectError(error.InvalidChecksum, bitcoin.CheckDecoder.decode(&decode_buffer, "1PfJpZsjreyVrqeoAfabrRwwjQyoSQMmHJ"));
    try testing.expectError(error.InvalidCharacter, bitcoin.CheckDecoder.decode(&decode_buffer, "1PfJpZsjreyVrqeoAfabrRwwjQyoSQMmH0"));
    try testing.expectError(error.DecodedTooLong, bitcoin.CheckDecoder.decodeWithMaxPayloadLen(&decode_buffer, "1PfJpZsjreyVrqeoAfabrRwwjQyoSQMmHH", 19));
}

test "bitcoin base58check encode buffer boundaries" {
    const version: u8 = 0;
    const payload = [_]u8{ 248, 145, 115, 3, 191, 168, 239, 36, 242, 146, 232, 250, 20, 25, 178, 4, 96, 186, 6, 77 };
    const expected = "1PfJpZsjreyVrqeoAfabrRwwjQyoSQMmHH";

    var exact: [expected.len]u8 = undefined;
    const encoded_exact = try bitcoin.CheckEncoder.encode(&exact, version, &payload);
    try testing.expectEqualStrings(expected, encoded_exact);

    var short: [expected.len - 1]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, bitcoin.CheckEncoder.encode(&short, version, &payload));

    var padded: [96]u8 = undefined;
    @memset(&padded, 0xAA);
    const encoded_padded = try bitcoin.CheckEncoder.encode(&padded, version, &payload);
    try testing.expectEqualStrings(expected, encoded_padded);
    for (padded[encoded_padded.len..]) |b| try testing.expectEqual(@as(u8, 0xAA), b);
}

test "bitcoin base58check decode buffer boundaries" {
    const encoded = "1PfJpZsjreyVrqeoAfabrRwwjQyoSQMmHH";
    const decoded_len = 1 + 20 + checksum_len;

    var exact: [decoded_len]u8 = undefined;
    const decoded_exact = try bitcoin.CheckDecoder.decode(&exact, encoded);
    try testing.expectEqual(@as(usize, 20), decoded_exact.payload.len);

    var short: [decoded_len - 1]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, bitcoin.CheckDecoder.decode(&short, encoded));

    var padded: [decoded_len + 16]u8 = undefined;
    @memset(&padded, 0xAA);
    const decoded_padded = try bitcoin.CheckDecoder.decode(&padded, encoded);
    const used = 1 + decoded_padded.payload.len + checksum_len;
    for (padded[used..]) |b| try testing.expectEqual(@as(u8, 0xAA), b);
}

const TestData = struct {
    encoded: []const u8,
    decoded: []const u8,
};

fn testingData() []const TestData {
    return &[_]TestData{
        .{ .encoded = "", .decoded = "" },
        .{ .encoded = "USm3fpXnKG5EUBx2ndxBDMPVciP5hGey2Jh4NDv6gmeo1LkMeiKrLJUUBk6Z", .decoded = "The quick brown fox jumps over the lazy dog." },
        .{ .encoded = "2NEpo7TZRRrLZSi2U", .decoded = "Hello World!" },
        .{ .encoded = "11233QC4", .decoded = &[_]u8{ 0, 0, 40, 127, 180, 205 } },
        .{ .encoded = "1", .decoded = &[_]u8{0} },
        .{ .encoded = "2", .decoded = &[_]u8{1} },
        .{ .encoded = "21", .decoded = &[_]u8{58} },
        .{ .encoded = "211", .decoded = &[_]u8{ 13, 36 } },
        .{ .encoded = "1211", .decoded = &[_]u8{ 0, 13, 36 } },
        .{ .encoded = "111211", .decoded = &[_]u8{ 0, 0, 0, 13, 36 } },
    };
}
