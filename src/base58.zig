const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;

pub const Error = error{
    InvalidCharacter,
    InvalidChecksum,
    DecodedTooShort,
    DecodedTooLong,
    BufferTooSmall,
    OverlappingBuffers,
};

/// Bitcoin alphabet.
pub const alphabet_chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".*;

const invalid_char: u8 = 0xff;
const checksum_len: usize = 4;
const max_usize = std.math.maxInt(usize);
const char_to_index = buildCharToIndexTable(alphabet_chars);

comptime {
    assert(checksum_len == 4);
    assert(invalid_char == 0xff);
    assert(alphabet_chars.len == 58);
    assert(alphabet_chars[0] == '1');

    var char_in_alphabet = [_]bool{false} ** 256;
    for (alphabet_chars) |c| {
        assert(!char_in_alphabet[c]);
        char_in_alphabet[c] = true;
    }

    assert(char_to_index['1'] == 0);
    assert(char_to_index['z'] == 57);
    assert(char_to_index['0'] == invalid_char);
}

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

pub const Base58Encoder = struct {
    /// Returns a safe upper bound for encoded output size.
    pub fn calcSizeUpperBound(encoder: *const Base58Encoder, source_len: usize) usize {
        _ = encoder;
        if (source_len == 0) return 0;

        const upper_bound = scaledUpperBound(source_len, 138, 100);
        assert(upper_bound >= 1);
        return upper_bound;
    }

    /// Returns a tighter upper bound for a concrete source slice.
    pub fn calcSizeUpperBoundForSlice(encoder: *const Base58Encoder, source: []const u8) usize {
        _ = encoder;
        const leading_zeros = countLeadingZeroBytes(source);
        assert(leading_zeros <= source.len);
        const significant_len = source.len - leading_zeros;
        assert(significant_len + leading_zeros == source.len);
        if (significant_len == 0) return leading_zeros;

        const upper_bound = checkedAddOrMax(leading_zeros, scaledUpperBound(significant_len, 138, 100));
        assert(upper_bound >= leading_zeros);
        return upper_bound;
    }

    /// Encodes `source` into `dest` and returns the written slice.
    pub fn encode(encoder: *const Base58Encoder, dest: []u8, source: []const u8) Error![]const u8 {
        _ = encoder;
        if (!@inComptime() and slicesOverlap(dest, source)) return error.OverlappingBuffers;

        var length: usize = 0;
        try encodeChunkToDigits(dest, &length, source);

        const leading_zeros = countLeadingZeroBytes(source);
        try appendZeroValues(dest, &length, leading_zeros);

        var i: usize = 0;
        while (i < length) : (i += 1) {
            const digit = dest[i];
            assert(digit < alphabet_chars.len);
            dest[i] = alphabet_chars[digit];
        }
        assert(length <= dest.len);
        std.mem.reverse(u8, dest[0..length]);
        return dest[0..length];
    }
};

pub const Base58Decoder = struct {
    /// Returns a safe upper bound for decoded output size.
    pub fn calcSizeUpperBound(decoder: *const Base58Decoder, source_len: usize) usize {
        _ = decoder;
        return source_len;
    }

    /// Returns a tighter upper bound for a concrete source slice.
    pub fn calcSizeUpperBoundForSlice(decoder: *const Base58Decoder, source: []const u8) usize {
        _ = decoder;
        const leading_ones = countLeadingZeroChars(source, alphabet_chars[0]);
        assert(leading_ones <= source.len);
        const significant_len = source.len - leading_ones;
        assert(significant_len + leading_ones == source.len);
        if (significant_len == 0) return leading_ones;

        const upper_bound = checkedAddOrMax(leading_ones, scaledUpperBound(significant_len, 11, 15));
        assert(upper_bound >= leading_ones);
        return upper_bound;
    }

    /// Decodes `source` into `dest` and returns the written slice.
    pub fn decode(decoder: *const Base58Decoder, dest: []u8, source: []const u8) Error![]const u8 {
        return decoder.decodeWithMaxDecodedLen(dest, source, max_usize);
    }

    /// Decodes `source` into `dest` with a hard cap for decoded size.
    /// Useful for untrusted input where callers want to bound work and output.
    pub fn decodeWithMaxDecodedLen(decoder: *const Base58Decoder, dest: []u8, source: []const u8, max_decoded_len: usize) Error![]const u8 {
        _ = decoder;
        if (!@inComptime() and slicesOverlap(dest, source)) return error.OverlappingBuffers;

        var length: usize = 0;
        const leading_ones = countLeadingZeroChars(source, alphabet_chars[0]);
        assert(leading_ones <= source.len);
        if (leading_ones > max_decoded_len) return error.DecodedTooLong;
        assert(leading_ones <= max_decoded_len);

        for (source) |c| {
            var carry: u32 = char_to_index[c];
            if (carry == @as(u32, invalid_char)) return error.InvalidCharacter;
            assert(carry < 58);

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
            assert(length <= max_decoded_len - leading_ones);
            assert(length <= dest.len);
        }

        var i: usize = 0;
        while (i < leading_ones) : (i += 1) {
            if (length == max_decoded_len) return error.DecodedTooLong;
            if (length == dest.len) return error.BufferTooSmall;
            dest[length] = 0;
            length += 1;
        }

        assert(length <= max_decoded_len);
        assert(length <= dest.len);
        std.mem.reverse(u8, dest[0..length]);
        return dest[0..length];
    }
};

pub const Base58CheckEncoder = struct {
    /// Returns a safe upper bound for encoded Base58Check output size.
    pub fn calcSizeUpperBound(check_encoder: *const Base58CheckEncoder, payload_len: usize) usize {
        _ = check_encoder;
        const encoder = Base58Encoder{};
        const expanded_payload_len = checkedAddOrMax(payload_len, 1 + checksum_len);
        assert(expanded_payload_len >= payload_len);
        return encoder.calcSizeUpperBound(expanded_payload_len);
    }

    /// Encodes `version + payload + checksum(version+payload)` into Base58.
    pub fn encode(check_encoder: *const Base58CheckEncoder, dest: []u8, version: u8, payload: []const u8) Error![]const u8 {
        _ = check_encoder;
        if (!@inComptime() and slicesOverlap(dest, payload)) return error.OverlappingBuffers;

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
            dest[i] = alphabet_chars[dest[i]];
        }
        std.mem.reverse(u8, dest[0..length]);
        return dest[0..length];
    }
};

pub const Base58CheckDecoder = struct {
    /// Returns a safe upper bound for decoded bytes (including version+checksum).
    pub fn calcSizeUpperBound(check_decoder: *const Base58CheckDecoder, source_len: usize) usize {
        _ = check_decoder;
        const decoder = Base58Decoder{};
        return decoder.calcSizeUpperBound(source_len);
    }

    /// Returns a tighter upper bound for decoded bytes (including version+checksum).
    pub fn calcSizeUpperBoundForSlice(check_decoder: *const Base58CheckDecoder, source: []const u8) usize {
        _ = check_decoder;
        const decoder = Base58Decoder{};
        return decoder.calcSizeUpperBoundForSlice(source);
    }

    /// Returns a safe upper bound for payload length after successful Base58Check decode.
    pub fn calcPayloadSizeUpperBound(check_decoder: *const Base58CheckDecoder, source_len: usize) usize {
        const decoded_upper = check_decoder.calcSizeUpperBound(source_len);
        if (decoded_upper < 1 + checksum_len) return 0;

        const payload_upper = decoded_upper - (1 + checksum_len);
        assert(payload_upper + (1 + checksum_len) == decoded_upper);
        return payload_upper;
    }

    /// Returns a tighter upper bound for payload length after successful Base58Check decode.
    pub fn calcPayloadSizeUpperBoundForSlice(check_decoder: *const Base58CheckDecoder, source: []const u8) usize {
        const decoded_upper = check_decoder.calcSizeUpperBoundForSlice(source);
        if (decoded_upper < 1 + checksum_len) return 0;

        const payload_upper = decoded_upper - (1 + checksum_len);
        assert(payload_upper + (1 + checksum_len) == decoded_upper);
        return payload_upper;
    }

    /// Decodes Base58Check bytes, validates checksum, and returns version + payload view.
    pub fn decode(check_decoder: *const Base58CheckDecoder, dest: []u8, source: []const u8) Error!DecodedCheck {
        _ = check_decoder;
        const decoder = Base58Decoder{};
        const decoded = try decoder.decode(dest, source);
        if (decoded.len < 1 + checksum_len) return error.DecodedTooShort;

        const check_start = decoded.len - checksum_len;
        assert(check_start >= 1);
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
        _ = check_decoder;
        const max_decoded_len = std.math.add(usize, max_payload_len, 1 + checksum_len) catch return error.DecodedTooLong;
        assert(max_decoded_len >= 1 + checksum_len);
        const decoder = Base58Decoder{};
        const decoded = try decoder.decodeWithMaxDecodedLen(dest, source, max_decoded_len);
        if (decoded.len < 1 + checksum_len) return error.DecodedTooShort;

        const check_start = decoded.len - checksum_len;
        assert(check_start >= 1);
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

pub const Encoder = Base58Encoder{};
pub const Decoder = Base58Decoder{};
pub const CheckEncoder = Base58CheckEncoder{};
pub const CheckDecoder = Base58CheckDecoder{};

pub fn encode(dest: []u8, decoded: []const u8) Error![]const u8 {
    return Encoder.encode(dest, decoded);
}

pub fn decode(dest: []u8, encoded: []const u8) Error![]const u8 {
    return Decoder.decode(dest, encoded);
}

pub fn encodeCheck(dest: []u8, version: u8, payload: []const u8) Error![]const u8 {
    return CheckEncoder.encode(dest, version, payload);
}

pub fn decodeCheck(dest: []u8, encoded: []const u8) Error!DecodedCheck {
    return CheckDecoder.decode(dest, encoded);
}

pub fn getEncodedLengthUpperBound(decoded_len: usize) usize {
    return Encoder.calcSizeUpperBound(decoded_len);
}

pub fn getEncodedLengthUpperBoundForSlice(decoded: []const u8) usize {
    return Encoder.calcSizeUpperBoundForSlice(decoded);
}

pub fn getDecodedLengthUpperBound(encoded_len: usize) usize {
    return Decoder.calcSizeUpperBound(encoded_len);
}

pub fn getDecodedLengthUpperBoundForSlice(encoded: []const u8) usize {
    return Decoder.calcSizeUpperBoundForSlice(encoded);
}

pub fn decodeWithMaxDecodedLength(dest: []u8, encoded: []const u8, max_decoded_len: usize) Error![]const u8 {
    return Decoder.decodeWithMaxDecodedLen(dest, encoded, max_decoded_len);
}

pub fn getEncodedCheckLengthUpperBound(payload_len: usize) usize {
    return CheckEncoder.calcSizeUpperBound(payload_len);
}

pub fn getDecodedCheckPayloadLengthUpperBound(encoded_len: usize) usize {
    return CheckDecoder.calcPayloadSizeUpperBound(encoded_len);
}

pub fn getDecodedCheckPayloadLengthUpperBoundForSlice(encoded: []const u8) usize {
    return CheckDecoder.calcPayloadSizeUpperBoundForSlice(encoded);
}

pub fn decodeCheckWithMaxPayloadLength(dest: []u8, encoded: []const u8, max_payload_len: usize) Error!DecodedCheck {
    return CheckDecoder.decodeWithMaxPayloadLen(dest, encoded, max_payload_len);
}

pub fn comptimeGetEncodedLength(comptime decoded: []const u8) usize {
    @setEvalBranchQuota(100_000);
    var buffer: [getEncodedLengthUpperBound(decoded.len)]u8 = undefined;
    const encoded = Encoder.encode(&buffer, decoded) catch unreachable;
    return encoded.len;
}

pub fn comptimeEncode(comptime decoded: []const u8) [comptimeGetEncodedLength(decoded)]u8 {
    @setEvalBranchQuota(100_000);
    var buffer: [getEncodedLengthUpperBound(decoded.len)]u8 = undefined;
    const encoded = Encoder.encode(&buffer, decoded) catch unreachable;

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
        var carry: u32 = char_to_index[c];
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

    const leading_ones = countLeadingZeroChars(encoded, alphabet_chars[0]);
    length += leading_ones;
    return length;
}

pub fn comptimeDecode(comptime encoded: []const u8) [comptimeGetDecodedLength(encoded)]u8 {
    @setEvalBranchQuota(100_000);
    var buffer = std.mem.zeroes([getDecodedLengthUpperBound(encoded.len)]u8);
    var length: usize = 0;

    for (encoded) |c| {
        var carry: u32 = char_to_index[c];
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

    const leading_ones = countLeadingZeroChars(encoded, alphabet_chars[0]);
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
    const encoded = CheckEncoder.encode(&buffer, version, payload) catch unreachable;
    return encoded.len;
}

pub fn comptimeEncodeCheck(comptime version: u8, comptime payload: []const u8) [comptimeGetEncodedCheckLength(version, payload)]u8 {
    @setEvalBranchQuota(100_000);
    var buffer: [getEncodedCheckLengthUpperBound(payload.len)]u8 = undefined;
    const encoded = CheckEncoder.encode(&buffer, version, payload) catch unreachable;

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
            assert(dest[i] < 58);
            carry /= 58;
        }

        while (carry > 0) : (carry /= 58) {
            if (length.* == dest.len) return error.BufferTooSmall;
            dest[length.*] = @intCast(carry % 58);
            assert(dest[length.*] < 58);
            length.* += 1;
        }
    }
    assert(length.* <= dest.len);
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
    assert(length.* <= dest.len);
}

fn buildCharToIndexTable(alphabet: [58]u8) [256]u8 {
    var table = [_]u8{invalid_char} ** 256;
    for (alphabet, 0..) |c, i| {
        assert(table[c] == invalid_char);
        table[c] = @intCast(i);
    }
    return table;
}

fn checkedAddOrMax(a: usize, b: usize) usize {
    const sum = std.math.add(usize, a, b) catch return max_usize;
    assert(sum >= a);
    assert(sum >= b);
    return sum;
}

fn scaledUpperBound(len: usize, mul: usize, div: usize) usize {
    assert(div != 0);
    const product = std.math.mul(usize, len, mul) catch return max_usize;
    assert(product >= len or len == 0 or mul == 0);
    const scaled = @divTrunc(product, div);
    return checkedAddOrMax(scaled, 1);
}

fn countLeadingZeroBytes(input: []const u8) usize {
    var count: usize = 0;
    while (count < input.len and input[count] == 0) : (count += 1) {}
    assert(count <= input.len);
    return count;
}

fn countLeadingZeroChars(input: []const u8, zero_char: u8) usize {
    var count: usize = 0;
    while (count < input.len and input[count] == zero_char) : (count += 1) {}
    assert(count <= input.len);
    return count;
}

fn slicesOverlap(a: []const u8, b: []const u8) bool {
    if (a.len == 0 or b.len == 0) return false;

    const a_start: usize = @intFromPtr(a.ptr);
    const b_start: usize = @intFromPtr(b.ptr);
    if (a_start <= b_start) return b_start - a_start < a.len;
    return a_start - b_start < b.len;
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

test "base58 vectors roundtrip" {
    var encode_buffer: [256]u8 = undefined;
    var decode_buffer: [256]u8 = undefined;
    for (testingData()) |d| {
        const encoded = try Encoder.encode(&encode_buffer, d.decoded);
        try testing.expectEqualStrings(d.encoded, encoded);

        const decoded = try Decoder.decode(&decode_buffer, d.encoded);
        try testing.expectEqualSlices(u8, d.decoded, decoded);
    }
}

test "base58 supports empty slices" {
    var encode_buffer: [8]u8 = undefined;
    var decode_buffer: [8]u8 = undefined;

    const encoded = try Encoder.encode(&encode_buffer, "");
    try testing.expectEqual(@as(usize, 0), encoded.len);

    const decoded = try Decoder.decode(&decode_buffer, "");
    try testing.expectEqual(@as(usize, 0), decoded.len);
}

test "base58 returns InvalidCharacter" {
    var buffer: [64]u8 = undefined;
    try testing.expectError(error.InvalidCharacter, Decoder.decode(&buffer, "0"));
    try testing.expectError(error.InvalidCharacter, Decoder.decode(&buffer, "O"));
    try testing.expectError(error.InvalidCharacter, Decoder.decode(&buffer, "I"));
    try testing.expectError(error.InvalidCharacter, Decoder.decode(&buffer, "l"));
}

test "base58 returns BufferTooSmall" {
    var encode_buffer: [16]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, Encoder.encode(&encode_buffer, "Hello World!"));

    var decode_buffer: [11]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, Decoder.decode(&decode_buffer, "2NEpo7TZRRrLZSi2U"));
}

test "base58 rejects overlapping buffers" {
    var overlap: [64]u8 = undefined;
    @memset(&overlap, 0);
    overlap[0] = 0xff;
    overlap[1] = 1;
    try testing.expectError(error.OverlappingBuffers, Encoder.encode(overlap[0..], overlap[0..2]));

    const encoded = "2NEpo7TZRRrLZSi2U";
    @memcpy(overlap[0..encoded.len], encoded);
    try testing.expectError(error.OverlappingBuffers, Decoder.decode(overlap[0..], overlap[0..encoded.len]));
}

test "base58 bounds are safe for known vectors" {
    for (testingData()) |d| {
        try testing.expect(getEncodedLengthUpperBoundForSlice(d.decoded) >= d.encoded.len);
        try testing.expect(getDecodedLengthUpperBoundForSlice(d.encoded) >= d.decoded.len);
    }
}

test "base58check known vector" {
    const version: u8 = 0;
    const payload = [_]u8{ 248, 145, 115, 3, 191, 168, 239, 36, 242, 146, 232, 250, 20, 25, 178, 4, 96, 186, 6, 77 };
    const encoded = "1PfJpZsjreyVrqeoAfabrRwwjQyoSQMmHH";

    var decode_buffer: [256]u8 = undefined;
    const decoded = try CheckDecoder.decode(&decode_buffer, encoded);
    try testing.expectEqual(version, decoded.version);
    try testing.expectEqualSlices(u8, &payload, decoded.payload);

    var encode_buffer: [256]u8 = undefined;
    const encoded_roundtrip = try CheckEncoder.encode(&encode_buffer, version, &payload);
    try testing.expectEqualStrings(encoded, encoded_roundtrip);
}

test "base58check returns InvalidChecksum" {
    var buffer: [256]u8 = undefined;
    try testing.expectError(error.InvalidChecksum, CheckDecoder.decode(&buffer, "1PfJpZsjreyVrqeoAfabrRwwjQyoSQMmHJ"));
}

test "base58check returns DecodedTooShort" {
    var buffer: [64]u8 = undefined;
    try testing.expectError(error.DecodedTooShort, CheckDecoder.decode(&buffer, "1111"));
}

test "base58check rejects overlapping buffers" {
    const version: u8 = 0;
    const payload = [_]u8{ 248, 145, 115, 3, 191, 168, 239, 36, 242, 146, 232, 250, 20, 25, 178, 4, 96, 186, 6, 77 };

    var overlap: [256]u8 = undefined;
    @memset(&overlap, 0);
    @memcpy(overlap[0..payload.len], &payload);
    try testing.expectError(error.OverlappingBuffers, CheckEncoder.encode(overlap[0..], version, overlap[0..payload.len]));

    const encoded = "1PfJpZsjreyVrqeoAfabrRwwjQyoSQMmHH";
    @memcpy(overlap[0..encoded.len], encoded);
    try testing.expectError(error.OverlappingBuffers, CheckDecoder.decode(overlap[0..], overlap[0..encoded.len]));
}

test "base58check bounds are safe" {
    const version: u8 = 0;
    const payload = [_]u8{0} ** 16;

    var encoded_buffer: [256]u8 = undefined;
    const encoded = try CheckEncoder.encode(&encoded_buffer, version, &payload);

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

test "base58 upper-bound helpers saturate on overflow" {
    try testing.expectEqual(max_usize, Encoder.calcSizeUpperBound(max_usize));
    try testing.expectEqual(max_usize, CheckEncoder.calcSizeUpperBound(max_usize));
}

test "base58 decodeWithMaxDecodedLen enforces cap" {
    var decode_buffer: [256]u8 = undefined;

    try testing.expectError(error.DecodedTooLong, Decoder.decodeWithMaxDecodedLen(&decode_buffer, "11111", 4));
    const exact = try Decoder.decodeWithMaxDecodedLen(&decode_buffer, "11111", 5);
    try testing.expectEqual(@as(usize, 5), exact.len);

    const source = [_]u8{0xff} ** 33;
    var encode_buffer: [256]u8 = undefined;
    const encoded = try Encoder.encode(&encode_buffer, &source);
    try testing.expectError(error.DecodedTooLong, Decoder.decodeWithMaxDecodedLen(&decode_buffer, encoded, 32));
}

test "base58check decodeWithMaxPayloadLen enforces cap" {
    const encoded = "1PfJpZsjreyVrqeoAfabrRwwjQyoSQMmHH";

    var decode_buffer: [256]u8 = undefined;
    const ok = try CheckDecoder.decodeWithMaxPayloadLen(&decode_buffer, encoded, 20);
    try testing.expectEqual(@as(u8, 0), ok.version);
    try testing.expectEqual(@as(usize, 20), ok.payload.len);

    try testing.expectError(error.DecodedTooLong, CheckDecoder.decodeWithMaxPayloadLen(&decode_buffer, encoded, 19));
}

test "base58 random roundtrip property" {
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

        const encoded = try Encoder.encode(&encoded_buffer_a, decoded_source[0..decoded_len]);
        const decoded = try Decoder.decode(&decoded_buffer, encoded);
        try testing.expectEqualSlices(u8, decoded_source[0..decoded_len], decoded);

        const encoded_again = try Encoder.encode(&encoded_buffer_b, decoded);
        try testing.expectEqualStrings(encoded, encoded_again);
    }
}

test "base58check random roundtrip property" {
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

        const encoded = try CheckEncoder.encode(&encoded_buffer_a, version, payload_buffer[0..payload_len]);
        const decoded = try CheckDecoder.decode(&decoded_buffer, encoded);
        try testing.expectEqual(version, decoded.version);
        try testing.expectEqualSlices(u8, payload_buffer[0..payload_len], decoded.payload);

        const encoded_again = try CheckEncoder.encode(&encoded_buffer_b, decoded.version, decoded.payload);
        try testing.expectEqualStrings(encoded, encoded_again);
    }
}

test "base58 rejects all non-alphabet bytes" {
    var decode_buffer: [8]u8 = undefined;
    var source: [1]u8 = undefined;

    for (0..256) |i| {
        source[0] = @intCast(i);
        if (char_to_index[source[0]] == invalid_char) {
            try testing.expectError(error.InvalidCharacter, Decoder.decode(&decode_buffer, &source));
        }
    }
}

test "base58 random garbage either fails or canonicalizes" {
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

        if (Decoder.decode(&decoded_buffer, garbage[0..garbage_len])) |decoded| {
            const encoded = try Encoder.encode(&encoded_buffer, decoded);
            const decoded_again = try Decoder.decode(&decoded_buffer_again, encoded);
            try testing.expectEqualSlices(u8, decoded, decoded_again);
        } else |err| switch (err) {
            error.InvalidCharacter => {},
            else => return err,
        }
    }
}

test "base58 additional known vectors" {
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
        const encoded = try Encoder.encode(&encode_buffer, decoded_from_hex);
        try testing.expectEqualStrings(c.encoded, encoded);

        const decoded = try Decoder.decode(&decode_buffer, c.encoded);
        try testing.expectEqualSlices(u8, decoded_from_hex, decoded);
    }
}

test "base58 decode boundary failure matrix" {
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
        try testing.expectError(error.InvalidCharacter, Decoder.decode(&decode_buffer, sample));
    }

    try testing.expectError(error.DecodedTooLong, Decoder.decodeWithMaxDecodedLen(&decode_buffer, "111111111111111111111111111111111", 32));
    try testing.expectError(error.BufferTooSmall, Decoder.decode(decode_buffer[0..11], "2NEpo7TZRRrLZSi2U"));
}

test "base58check boundary failure matrix" {
    var decode_buffer: [256]u8 = undefined;

    try testing.expectError(error.DecodedTooShort, CheckDecoder.decode(&decode_buffer, "1111"));
    try testing.expectError(error.InvalidChecksum, CheckDecoder.decode(&decode_buffer, "1PfJpZsjreyVrqeoAfabrRwwjQyoSQMmHJ"));
    try testing.expectError(error.InvalidCharacter, CheckDecoder.decode(&decode_buffer, "1PfJpZsjreyVrqeoAfabrRwwjQyoSQMmH0"));
    try testing.expectError(error.DecodedTooLong, CheckDecoder.decodeWithMaxPayloadLen(&decode_buffer, "1PfJpZsjreyVrqeoAfabrRwwjQyoSQMmHH", 19));
}

test "base58check encode buffer boundaries" {
    const version: u8 = 0;
    const payload = [_]u8{ 248, 145, 115, 3, 191, 168, 239, 36, 242, 146, 232, 250, 20, 25, 178, 4, 96, 186, 6, 77 };
    const expected = "1PfJpZsjreyVrqeoAfabrRwwjQyoSQMmHH";

    var exact: [expected.len]u8 = undefined;
    const encoded_exact = try CheckEncoder.encode(&exact, version, &payload);
    try testing.expectEqualStrings(expected, encoded_exact);

    var short: [expected.len - 1]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, CheckEncoder.encode(&short, version, &payload));

    var padded: [96]u8 = undefined;
    @memset(&padded, 0xAA);
    const encoded_padded = try CheckEncoder.encode(&padded, version, &payload);
    try testing.expectEqualStrings(expected, encoded_padded);
    for (padded[encoded_padded.len..]) |b| try testing.expectEqual(@as(u8, 0xAA), b);
}

test "base58check decode buffer boundaries" {
    const encoded = "1PfJpZsjreyVrqeoAfabrRwwjQyoSQMmHH";
    const decoded_len = 1 + 20 + checksum_len;

    var exact: [decoded_len]u8 = undefined;
    const decoded_exact = try CheckDecoder.decode(&exact, encoded);
    try testing.expectEqual(@as(usize, 20), decoded_exact.payload.len);

    var short: [decoded_len - 1]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, CheckDecoder.decode(&short, encoded));

    var padded: [decoded_len + 16]u8 = undefined;
    @memset(&padded, 0xAA);
    const decoded_padded = try CheckDecoder.decode(&padded, encoded);
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
