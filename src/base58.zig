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
const char_to_index = build_char_to_index_table(alphabet_chars);
const known_check_version: u8 = 0;
const known_check_payload = [_]u8{
    248, 145, 115, 3,  191, 168, 239, 36,  242, 146,
    232, 250, 20,  25, 178, 4,   96,  186, 6,   77,
};
const known_check_encoded = "1PfJpZsjreyVrqeoAfabrRwwjQyoSQMmHH";

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

pub fn decoded_check_comptime(comptime payload_len: usize) type {
    return struct {
        version: u8,
        payload: [payload_len]u8,
    };
}

pub const Base58Encoder = struct {
    /// Returns a safe upper bound for encoded output size.
    pub fn calc_size_upper_bound(self: *const Base58Encoder, source_len: usize) usize {
        _ = self;
        if (source_len == 0) return 0;

        const upper_bound = scaled_upper_bound(source_len, 138, 100);
        assert(upper_bound >= 1);
        return upper_bound;
    }

    /// Returns a tighter upper bound for a concrete source slice.
    pub fn calc_size_upper_bound_for_slice(self: *const Base58Encoder, source: []const u8) usize {
        _ = self;
        const leading_zeros = count_leading_zero_bytes(source);
        assert(leading_zeros <= source.len);
        const significant_len = source.len - leading_zeros;
        assert(significant_len + leading_zeros == source.len);
        if (significant_len == 0) return leading_zeros;

        const upper_bound = checked_add_or_max(
            leading_zeros,
            scaled_upper_bound(significant_len, 138, 100),
        );
        assert(upper_bound >= leading_zeros);
        return upper_bound;
    }

    /// Encodes `source` into `dest` and returns the written slice.
    pub fn encode(self: *const Base58Encoder, dest: []u8, source: []const u8) Error![]const u8 {
        _ = self;
        if (!@inComptime() and slices_overlap(dest, source)) return error.OverlappingBuffers;

        var length: usize = 0;
        try encode_chunk_to_digits(dest, &length, source);

        const leading_zeros = count_leading_zero_bytes(source);
        try append_zero_values(dest, &length, leading_zeros);

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
    pub fn calc_size_upper_bound(self: *const Base58Decoder, source_len: usize) usize {
        _ = self;
        return source_len;
    }

    /// Returns a tighter upper bound for a concrete source slice.
    pub fn calc_size_upper_bound_for_slice(self: *const Base58Decoder, source: []const u8) usize {
        _ = self;
        const leading_ones = count_leading_zero_chars(source, alphabet_chars[0]);
        assert(leading_ones <= source.len);
        const significant_len = source.len - leading_ones;
        assert(significant_len + leading_ones == source.len);
        if (significant_len == 0) return leading_ones;

        const upper_bound = checked_add_or_max(
            leading_ones,
            scaled_upper_bound(significant_len, 11, 15),
        );
        assert(upper_bound >= leading_ones);
        return upper_bound;
    }

    /// Decodes `source` into `dest` and returns the written slice.
    pub fn decode(self: *const Base58Decoder, dest: []u8, source: []const u8) Error![]const u8 {
        return self.decode_with_max_decoded_len(dest, source, max_usize);
    }

    /// Decodes `source` into `dest` with a hard cap for decoded size.
    /// Useful for untrusted input where callers want to bound work and output.
    pub fn decode_with_max_decoded_len(
        self: *const Base58Decoder,
        dest: []u8,
        source: []const u8,
        max_decoded_len: usize,
    ) Error![]const u8 {
        _ = self;
        if (!@inComptime() and slices_overlap(dest, source)) return error.OverlappingBuffers;

        var length: usize = 0;
        const leading_ones = count_leading_zero_chars(source, alphabet_chars[0]);
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
    pub fn calc_size_upper_bound(self: *const Base58CheckEncoder, payload_len: usize) usize {
        _ = self;
        const base58_encoder = Base58Encoder{};
        const expanded_payload_len = checked_add_or_max(payload_len, 1 + checksum_len);
        assert(expanded_payload_len >= payload_len);
        return base58_encoder.calc_size_upper_bound(expanded_payload_len);
    }

    /// Encodes `version + payload + checksum(version+payload)` into Base58.
    pub fn encode(
        self: *const Base58CheckEncoder,
        dest: []u8,
        version: u8,
        payload: []const u8,
    ) Error![]const u8 {
        _ = self;
        if (!@inComptime() and slices_overlap(dest, payload)) return error.OverlappingBuffers;

        const check = checksum_version_payload(version, payload);

        var length: usize = 0;
        const version_buf = [_]u8{version};
        try encode_chunk_to_digits(dest, &length, &version_buf);
        try encode_chunk_to_digits(dest, &length, payload);
        try encode_chunk_to_digits(dest, &length, &check);

        const leading_zeros = count_leading_zero_bytes_check(version, payload, check);
        try append_zero_values(dest, &length, leading_zeros);

        var i: usize = 0;
        while (i < length) : (i += 1) {
            assert(dest[i] < alphabet_chars.len);
            dest[i] = alphabet_chars[dest[i]];
        }
        assert(length <= dest.len);
        std.mem.reverse(u8, dest[0..length]);
        return dest[0..length];
    }
};

pub const Base58CheckDecoder = struct {
    /// Returns a safe upper bound for decoded bytes (including version+checksum).
    pub fn calc_size_upper_bound(self: *const Base58CheckDecoder, source_len: usize) usize {
        _ = self;
        const base58_decoder = Base58Decoder{};
        return base58_decoder.calc_size_upper_bound(source_len);
    }

    /// Returns a tighter upper bound for decoded bytes (including version+checksum).
    pub fn calc_size_upper_bound_for_slice(
        self: *const Base58CheckDecoder,
        source: []const u8,
    ) usize {
        _ = self;
        const base58_decoder = Base58Decoder{};
        return base58_decoder.calc_size_upper_bound_for_slice(source);
    }

    /// Returns a safe upper bound for payload length after successful Base58Check decode.
    pub fn calc_payload_size_upper_bound(
        self: *const Base58CheckDecoder,
        source_len: usize,
    ) usize {
        const decoded_upper = self.calc_size_upper_bound(source_len);
        if (decoded_upper < 1 + checksum_len) return 0;

        const payload_upper = decoded_upper - (1 + checksum_len);
        assert(payload_upper + (1 + checksum_len) == decoded_upper);
        return payload_upper;
    }

    /// Returns a tighter upper bound for payload length after successful Base58Check decode.
    pub fn calc_payload_size_upper_bound_for_slice(
        self: *const Base58CheckDecoder,
        source: []const u8,
    ) usize {
        const decoded_upper = self.calc_size_upper_bound_for_slice(source);
        if (decoded_upper < 1 + checksum_len) return 0;

        const payload_upper = decoded_upper - (1 + checksum_len);
        assert(payload_upper + (1 + checksum_len) == decoded_upper);
        return payload_upper;
    }

    /// Decodes Base58Check bytes, validates checksum, and returns version + payload view.
    pub fn decode(
        self: *const Base58CheckDecoder,
        dest: []u8,
        source: []const u8,
    ) Error!DecodedCheck {
        _ = self;
        const base58_decoder = Base58Decoder{};
        const decoded = try base58_decoder.decode(dest, source);
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
    pub fn decode_with_max_payload_len(
        self: *const Base58CheckDecoder,
        dest: []u8,
        source: []const u8,
        max_payload_len: usize,
    ) Error!DecodedCheck {
        _ = self;
        const max_decoded_len = std.math.add(
            usize,
            max_payload_len,
            1 + checksum_len,
        ) catch return error.DecodedTooLong;
        assert(max_decoded_len >= 1 + checksum_len);
        const base58_decoder = Base58Decoder{};
        const decoded = try base58_decoder.decode_with_max_decoded_len(dest, source, max_decoded_len);
        if (decoded.len < 1 + checksum_len) return error.DecodedTooShort;

        const check_start = decoded.len - checksum_len;
        assert(check_start >= 1);
        const expected = checksum(decoded[0..check_start]);
        if (!std.mem.eql(u8, decoded[check_start..], expected[0..])) {
            return error.InvalidChecksum;
        }

        const payload_len = check_start - 1;
        if (payload_len > max_payload_len) return error.DecodedTooLong;
        assert(payload_len <= max_payload_len);

        return DecodedCheck{
            .version = decoded[0],
            .payload = decoded[1..check_start],
        };
    }
};

pub const encoder = Base58Encoder{};
pub const decoder = Base58Decoder{};
pub const check_encoder = Base58CheckEncoder{};
pub const check_decoder = Base58CheckDecoder{};

pub fn encode(dest: []u8, decoded: []const u8) Error![]const u8 {
    return encoder.encode(dest, decoded);
}

pub fn decode(dest: []u8, encoded: []const u8) Error![]const u8 {
    return decoder.decode(dest, encoded);
}

pub fn encode_check(dest: []u8, version: u8, payload: []const u8) Error![]const u8 {
    return check_encoder.encode(dest, version, payload);
}

pub fn decode_check(dest: []u8, encoded: []const u8) Error!DecodedCheck {
    return check_decoder.decode(dest, encoded);
}

pub fn get_encoded_length_upper_bound(decoded_len: usize) usize {
    return encoder.calc_size_upper_bound(decoded_len);
}

pub fn get_encoded_length_upper_bound_for_slice(decoded: []const u8) usize {
    return encoder.calc_size_upper_bound_for_slice(decoded);
}

pub fn get_decoded_length_upper_bound(encoded_len: usize) usize {
    return decoder.calc_size_upper_bound(encoded_len);
}

pub fn get_decoded_length_upper_bound_for_slice(encoded: []const u8) usize {
    return decoder.calc_size_upper_bound_for_slice(encoded);
}

pub fn decode_with_max_decoded_length(
    dest: []u8,
    encoded: []const u8,
    max_decoded_len: usize,
) Error![]const u8 {
    return decoder.decode_with_max_decoded_len(dest, encoded, max_decoded_len);
}

pub fn get_encoded_check_length_upper_bound(payload_len: usize) usize {
    return check_encoder.calc_size_upper_bound(payload_len);
}

pub fn get_decoded_check_payload_length_upper_bound(encoded_len: usize) usize {
    return check_decoder.calc_payload_size_upper_bound(encoded_len);
}

pub fn get_decoded_check_payload_length_upper_bound_for_slice(encoded: []const u8) usize {
    return check_decoder.calc_payload_size_upper_bound_for_slice(encoded);
}

pub fn decode_check_with_max_payload_length(
    dest: []u8,
    encoded: []const u8,
    max_payload_len: usize,
) Error!DecodedCheck {
    return check_decoder.decode_with_max_payload_len(dest, encoded, max_payload_len);
}

pub fn comptime_get_encoded_length(comptime decoded: []const u8) usize {
    @setEvalBranchQuota(100_000);
    var buffer: [get_encoded_length_upper_bound(decoded.len)]u8 = undefined;
    const encoded = encoder.encode(&buffer, decoded) catch unreachable;
    return encoded.len;
}

pub fn comptime_encode(comptime decoded: []const u8) [comptime_get_encoded_length(decoded)]u8 {
    @setEvalBranchQuota(100_000);
    var buffer: [get_encoded_length_upper_bound(decoded.len)]u8 = undefined;
    const encoded = encoder.encode(&buffer, decoded) catch unreachable;

    const out_len = comptime comptime_get_encoded_length(decoded);
    var out: [out_len]u8 = undefined;
    @memcpy(out[0..], encoded[0..out_len]);
    return out;
}

pub fn comptime_get_decoded_length(comptime encoded: []const u8) usize {
    @setEvalBranchQuota(100_000);
    var buffer = std.mem.zeroes([get_decoded_length_upper_bound(encoded.len)]u8);
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
            if (length == buffer.len) unreachable;
            buffer[length] = @truncate(carry);
            length += 1;
        }
    }

    const leading_ones = count_leading_zero_chars(encoded, alphabet_chars[0]);
    length += leading_ones;
    return length;
}

pub fn comptime_decode(comptime encoded: []const u8) [comptime_get_decoded_length(encoded)]u8 {
    @setEvalBranchQuota(100_000);
    var buffer = std.mem.zeroes([get_decoded_length_upper_bound(encoded.len)]u8);
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
            if (length == buffer.len) unreachable;
            buffer[length] = @truncate(carry);
            length += 1;
        }
    }

    const leading_ones = count_leading_zero_chars(encoded, alphabet_chars[0]);
    try_append_leading_zeros_comptime(&buffer, &length, leading_ones);
    std.mem.reverse(u8, buffer[0..length]);

    const out_len = comptime comptime_get_decoded_length(encoded);
    var out: [out_len]u8 = undefined;
    @memcpy(out[0..], buffer[0..out_len]);
    return out;
}

pub fn comptime_get_encoded_check_length(comptime version: u8, comptime payload: []const u8) usize {
    @setEvalBranchQuota(100_000);
    var buffer: [get_encoded_check_length_upper_bound(payload.len)]u8 = undefined;
    const encoded = check_encoder.encode(&buffer, version, payload) catch unreachable;
    return encoded.len;
}

pub fn comptime_encode_check(
    comptime version: u8,
    comptime payload: []const u8,
) [comptime_get_encoded_check_length(version, payload)]u8 {
    @setEvalBranchQuota(100_000);
    var buffer: [get_encoded_check_length_upper_bound(payload.len)]u8 = undefined;
    const encoded = check_encoder.encode(&buffer, version, payload) catch unreachable;

    const out_len = comptime comptime_get_encoded_check_length(version, payload);
    var out: [out_len]u8 = undefined;
    @memcpy(out[0..], encoded[0..out_len]);
    return out;
}

pub fn comptime_get_decoded_check_payload_length(comptime encoded: []const u8) usize {
    @setEvalBranchQuota(100_000);
    const decoded = comptime_decode(encoded);
    if (decoded.len < 1 + checksum_len) unreachable;

    const check_start = decoded.len - checksum_len;
    const expected = checksum(decoded[0..check_start]);
    if (!std.mem.eql(u8, decoded[check_start..], expected[0..])) unreachable;
    return check_start - 1;
}

pub fn comptime_decode_check(
    comptime encoded: []const u8,
) decoded_check_comptime(comptime_get_decoded_check_payload_length(encoded)) {
    @setEvalBranchQuota(100_000);
    const decoded = comptime_decode(encoded);
    if (decoded.len < 1 + checksum_len) unreachable;

    const check_start = decoded.len - checksum_len;
    const expected = checksum(decoded[0..check_start]);
    if (!std.mem.eql(u8, decoded[check_start..], expected[0..])) unreachable;

    const payload_len = comptime comptime_get_decoded_check_payload_length(encoded);
    var out: decoded_check_comptime(payload_len) = undefined;
    out.version = decoded[0];
    @memcpy(out.payload[0..], decoded[1 .. 1 + payload_len]);
    return out;
}

fn encode_chunk_to_digits(dest: []u8, length: *usize, chunk: []const u8) Error!void {
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

fn try_append_leading_zeros_comptime(buffer: []u8, length: *usize, leading_zeros: usize) void {
    var i: usize = 0;
    while (i < leading_zeros) : (i += 1) {
        if (length.* == buffer.len) unreachable;
        buffer[length.*] = 0;
        length.* += 1;
    }
}

fn append_zero_values(dest: []u8, length: *usize, zero_count: usize) Error!void {
    var i: usize = 0;
    while (i < zero_count) : (i += 1) {
        if (length.* == dest.len) return error.BufferTooSmall;
        dest[length.*] = 0;
        length.* += 1;
    }
    assert(length.* <= dest.len);
}

fn build_char_to_index_table(alphabet: [58]u8) [256]u8 {
    var table = [_]u8{invalid_char} ** 256;
    for (alphabet, 0..) |c, i| {
        assert(table[c] == invalid_char);
        table[c] = @intCast(i);
    }
    return table;
}

fn checked_add_or_max(a: usize, b: usize) usize {
    const sum = std.math.add(usize, a, b) catch return max_usize;
    assert(sum >= a);
    assert(sum >= b);
    return sum;
}

fn scaled_upper_bound(len: usize, mul: usize, div: usize) usize {
    assert(div != 0);
    const product = std.math.mul(usize, len, mul) catch return max_usize;
    assert(product >= len or len == 0 or mul == 0);
    const scaled = @divTrunc(product, div);
    return checked_add_or_max(scaled, 1);
}

fn count_leading_zero_bytes(input: []const u8) usize {
    var count: usize = 0;
    while (count < input.len and input[count] == 0) : (count += 1) {}
    assert(count <= input.len);
    return count;
}

fn count_leading_zero_chars(input: []const u8, zero_char: u8) usize {
    var count: usize = 0;
    while (count < input.len and input[count] == zero_char) : (count += 1) {}
    assert(count <= input.len);
    return count;
}

fn slices_overlap(a: []const u8, b: []const u8) bool {
    if (a.len == 0 or b.len == 0) return false;

    const a_start: usize = @intFromPtr(a.ptr);
    const b_start: usize = @intFromPtr(b.ptr);
    if (a_start <= b_start) return b_start - a_start < a.len;
    return a_start - b_start < b.len;
}

fn count_leading_zero_bytes_check(version: u8, payload: []const u8, check: [checksum_len]u8) usize {
    var count: usize = 0;
    const max_count = 1 + payload.len + check.len;

    if (version != 0) return 0;
    count += 1;
    assert(count <= max_count);

    for (payload) |b| {
        if (b != 0) {
            assert(count <= max_count);
            return count;
        }
        count += 1;
        assert(count <= max_count);
    }
    for (check) |b| {
        if (b != 0) {
            assert(count <= max_count);
            return count;
        }
        count += 1;
        assert(count <= max_count);
    }
    assert(count == max_count);
    return count;
}

fn checksum(data: []const u8) [checksum_len]u8 {
    var h1: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(data, &h1, .{});

    var h2: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&h1, &h2, .{});

    return .{ h2[0], h2[1], h2[2], h2[3] };
}

fn checksum_version_payload(version: u8, payload: []const u8) [checksum_len]u8 {
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
    for (testing_data()) |d| {
        const encoded = try encoder.encode(&encode_buffer, d.decoded);
        try testing.expectEqualStrings(d.encoded, encoded);

        const decoded = try decoder.decode(&decode_buffer, d.encoded);
        try testing.expectEqualSlices(u8, d.decoded, decoded);
    }
}

test "base58 supports empty slices" {
    var encode_buffer: [8]u8 = undefined;
    var decode_buffer: [8]u8 = undefined;

    const encoded = try encoder.encode(&encode_buffer, "");
    try testing.expectEqual(@as(usize, 0), encoded.len);

    const decoded = try decoder.decode(&decode_buffer, "");
    try testing.expectEqual(@as(usize, 0), decoded.len);
}

test "base58 returns InvalidCharacter" {
    var buffer: [64]u8 = undefined;
    try testing.expectError(error.InvalidCharacter, decoder.decode(&buffer, "0"));
    try testing.expectError(error.InvalidCharacter, decoder.decode(&buffer, "O"));
    try testing.expectError(error.InvalidCharacter, decoder.decode(&buffer, "I"));
    try testing.expectError(error.InvalidCharacter, decoder.decode(&buffer, "l"));
}

test "base58 returns BufferTooSmall" {
    var encode_buffer: [16]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, encoder.encode(&encode_buffer, "Hello World!"));

    var decode_buffer: [11]u8 = undefined;
    try testing.expectError(
        error.BufferTooSmall,
        decoder.decode(&decode_buffer, "2NEpo7TZRRrLZSi2U"),
    );
}

test "base58 rejects overlapping buffers" {
    var overlap: [64]u8 = undefined;
    @memset(&overlap, 0);
    overlap[0] = 0xff;
    overlap[1] = 1;
    try testing.expectError(error.OverlappingBuffers, encoder.encode(overlap[0..], overlap[0..2]));

    const encoded = "2NEpo7TZRRrLZSi2U";
    @memcpy(overlap[0..encoded.len], encoded);
    try testing.expectError(
        error.OverlappingBuffers,
        decoder.decode(overlap[0..], overlap[0..encoded.len]),
    );
}

test "base58 bounds are safe for known vectors" {
    for (testing_data()) |d| {
        try testing.expect(get_encoded_length_upper_bound_for_slice(d.decoded) >= d.encoded.len);
        try testing.expect(get_decoded_length_upper_bound_for_slice(d.encoded) >= d.decoded.len);
    }
}

test "base58check known vector" {
    var decode_buffer: [256]u8 = undefined;
    const decoded = try check_decoder.decode(&decode_buffer, known_check_encoded);
    try testing.expectEqual(known_check_version, decoded.version);
    try testing.expectEqualSlices(u8, &known_check_payload, decoded.payload);

    var encode_buffer: [256]u8 = undefined;
    const encoded_roundtrip = try check_encoder.encode(
        &encode_buffer,
        known_check_version,
        &known_check_payload,
    );
    try testing.expectEqualStrings(known_check_encoded, encoded_roundtrip);
}

test "base58check returns InvalidChecksum" {
    var buffer: [256]u8 = undefined;
    try testing.expectError(
        error.InvalidChecksum,
        check_decoder.decode(&buffer, "1PfJpZsjreyVrqeoAfabrRwwjQyoSQMmHJ"),
    );
}

test "base58check returns DecodedTooShort" {
    var buffer: [64]u8 = undefined;
    try testing.expectError(error.DecodedTooShort, check_decoder.decode(&buffer, "1111"));
}

test "base58check rejects overlapping buffers" {
    var overlap: [256]u8 = undefined;
    @memset(&overlap, 0);
    @memcpy(overlap[0..known_check_payload.len], &known_check_payload);
    try testing.expectError(
        error.OverlappingBuffers,
        check_encoder.encode(overlap[0..], known_check_version, overlap[0..known_check_payload.len]),
    );

    @memcpy(overlap[0..known_check_encoded.len], known_check_encoded);
    try testing.expectError(
        error.OverlappingBuffers,
        check_decoder.decode(overlap[0..], overlap[0..known_check_encoded.len]),
    );
}

test "base58check bounds are safe" {
    const version: u8 = 0;
    const payload = [_]u8{0} ** 16;

    var encoded_buffer: [256]u8 = undefined;
    const encoded = try check_encoder.encode(&encoded_buffer, version, &payload);

    try testing.expect(get_encoded_check_length_upper_bound(payload.len) >= encoded.len);
    try testing.expect(
        get_decoded_length_upper_bound_for_slice(encoded) >= (payload.len + 1 + checksum_len),
    );
    try testing.expect(get_decoded_check_payload_length_upper_bound_for_slice(encoded) >= payload.len);
}

test "comptime base58 wrappers" {
    const td = comptime testing_data();
    inline for (td) |d| {
        const encoded = comptime_encode(d.decoded);
        try testing.expectEqualStrings(d.encoded, &encoded);

        const decoded = comptime_decode(d.encoded);
        try testing.expectEqualSlices(u8, d.decoded, &decoded);
    }
}

test "comptime base58check wrappers" {
    const encoded = comptime_encode_check(known_check_version, &known_check_payload);
    try testing.expectEqualStrings(known_check_encoded, &encoded);

    const decoded = comptime_decode_check(known_check_encoded);
    try testing.expectEqual(known_check_version, decoded.version);
    try testing.expectEqualSlices(u8, &known_check_payload, &decoded.payload);
}

test "base58 upper-bound helpers saturate on overflow" {
    try testing.expectEqual(max_usize, encoder.calc_size_upper_bound(max_usize));
    try testing.expectEqual(max_usize, check_encoder.calc_size_upper_bound(max_usize));
}

test "base58 decode_with_max_decoded_len enforces cap" {
    var decode_buffer: [256]u8 = undefined;

    try testing.expectError(
        error.DecodedTooLong,
        decoder.decode_with_max_decoded_len(&decode_buffer, "11111", 4),
    );
    const exact = try decoder.decode_with_max_decoded_len(&decode_buffer, "11111", 5);
    try testing.expectEqual(@as(usize, 5), exact.len);

    const source = [_]u8{0xff} ** 33;
    var encode_buffer: [256]u8 = undefined;
    const encoded = try encoder.encode(&encode_buffer, &source);
    try testing.expectError(
        error.DecodedTooLong,
        decoder.decode_with_max_decoded_len(&decode_buffer, encoded, 32),
    );
}

test "base58check decode_with_max_payload_len enforces cap" {
    var decode_buffer: [256]u8 = undefined;
    const ok = try check_decoder.decode_with_max_payload_len(&decode_buffer, known_check_encoded, 20);
    try testing.expectEqual(@as(u8, 0), ok.version);
    try testing.expectEqual(@as(usize, 20), ok.payload.len);

    try testing.expectError(
        error.DecodedTooLong,
        check_decoder.decode_with_max_payload_len(&decode_buffer, known_check_encoded, 19),
    );
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

        const encoded = try encoder.encode(&encoded_buffer_a, decoded_source[0..decoded_len]);
        const decoded = try decoder.decode(&decoded_buffer, encoded);
        try testing.expectEqualSlices(u8, decoded_source[0..decoded_len], decoded);

        const encoded_again = try encoder.encode(&encoded_buffer_b, decoded);
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

        const encoded = try check_encoder.encode(
            &encoded_buffer_a,
            version,
            payload_buffer[0..payload_len],
        );
        const decoded = try check_decoder.decode(&decoded_buffer, encoded);
        try testing.expectEqual(version, decoded.version);
        try testing.expectEqualSlices(u8, payload_buffer[0..payload_len], decoded.payload);

        const encoded_again = try check_encoder.encode(
            &encoded_buffer_b,
            decoded.version,
            decoded.payload,
        );
        try testing.expectEqualStrings(encoded, encoded_again);
    }
}

test "base58 rejects all non-alphabet bytes" {
    var decode_buffer: [8]u8 = undefined;
    var source: [1]u8 = undefined;

    for (0..256) |i| {
        source[0] = @intCast(i);
        if (char_to_index[source[0]] == invalid_char) {
            try testing.expectError(
                error.InvalidCharacter,
                decoder.decode(&decode_buffer, &source),
            );
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

        if (decoder.decode(&decoded_buffer, garbage[0..garbage_len])) |decoded| {
            const encoded = try encoder.encode(&encoded_buffer, decoded);
            const decoded_again = try decoder.decode(&decoded_buffer_again, encoded);
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
        .{
            .hex = "73696d706c792061206c6f6e6720737472696e67",
            .encoded = "2cFupjhnEsSn59qHXstmK2ffpLv2",
        },
        .{
            .hex = "00eb15231dfceb60925886b67d065299925915aeb172c06647",
            .encoded = "1NS17iag9jJgTHD1VXjvLCEnZuQ3rJDE9L",
        },
        .{ .hex = "516b6fcd0f", .encoded = "ABnLTmg" },
        .{ .hex = "bf4f89001e670274dd", .encoded = "3SEo3LWLoPntC" },
        .{ .hex = "572e4794", .encoded = "3EFU7m" },
        .{ .hex = "ecac89cad93923c02321", .encoded = "EJDM8drfXA6uyA" },
        .{ .hex = "10c8511e", .encoded = "Rt5zm" },
        .{ .hex = "00000000000000000000", .encoded = "1111111111" },
        .{
            .hex = "000111d38e5fc9071ffcd20b4a763cc9ae4f252bb4e48fd66a835e252ada93ff480d6dd43" ++
                "dc62a" ++
                "641155a5",
            .encoded = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz",
        },
    };

    var decode_from_hex_buffer: [1024]u8 = undefined;
    var encode_buffer: [2048]u8 = undefined;
    var decode_buffer: [1024]u8 = undefined;

    for (cases) |c| {
        const decoded_from_hex = try std.fmt.hexToBytes(&decode_from_hex_buffer, c.hex);
        const encoded = try encoder.encode(&encode_buffer, decoded_from_hex);
        try testing.expectEqualStrings(c.encoded, encoded);

        const decoded = try decoder.decode(&decode_buffer, c.encoded);
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
        try testing.expectError(error.InvalidCharacter, decoder.decode(&decode_buffer, sample));
    }

    try testing.expectError(
        error.DecodedTooLong,
        decoder.decode_with_max_decoded_len(&decode_buffer, "111111111111111111111111111111111", 32),
    );
    try testing.expectError(
        error.BufferTooSmall,
        decoder.decode(decode_buffer[0..11], "2NEpo7TZRRrLZSi2U"),
    );
}

test "base58check boundary failure matrix" {
    var decode_buffer: [256]u8 = undefined;

    try testing.expectError(error.DecodedTooShort, check_decoder.decode(&decode_buffer, "1111"));
    try testing.expectError(
        error.InvalidChecksum,
        check_decoder.decode(&decode_buffer, "1PfJpZsjreyVrqeoAfabrRwwjQyoSQMmHJ"),
    );
    try testing.expectError(
        error.InvalidCharacter,
        check_decoder.decode(&decode_buffer, "1PfJpZsjreyVrqeoAfabrRwwjQyoSQMmH0"),
    );
    try testing.expectError(
        error.DecodedTooLong,
        check_decoder.decode_with_max_payload_len(&decode_buffer, known_check_encoded, 19),
    );
}

test "base58check encode buffer boundaries" {
    var exact: [known_check_encoded.len]u8 = undefined;
    const encoded_exact = try check_encoder.encode(
        &exact,
        known_check_version,
        &known_check_payload,
    );
    try testing.expectEqualStrings(known_check_encoded, encoded_exact);

    var short: [known_check_encoded.len - 1]u8 = undefined;
    try testing.expectError(
        error.BufferTooSmall,
        check_encoder.encode(&short, known_check_version, &known_check_payload),
    );

    var padded: [96]u8 = undefined;
    @memset(&padded, 0xAA);
    const encoded_padded = try check_encoder.encode(
        &padded,
        known_check_version,
        &known_check_payload,
    );
    try testing.expectEqualStrings(known_check_encoded, encoded_padded);
    for (padded[encoded_padded.len..]) |b| try testing.expectEqual(@as(u8, 0xAA), b);
}

test "base58check decode buffer boundaries" {
    const decoded_len = 1 + 20 + checksum_len;

    var exact: [decoded_len]u8 = undefined;
    const decoded_exact = try check_decoder.decode(&exact, known_check_encoded);
    try testing.expectEqual(@as(usize, 20), decoded_exact.payload.len);

    var short: [decoded_len - 1]u8 = undefined;
    try testing.expectError(
        error.BufferTooSmall,
        check_decoder.decode(&short, known_check_encoded),
    );

    var padded: [decoded_len + 16]u8 = undefined;
    @memset(&padded, 0xAA);
    const decoded_padded = try check_decoder.decode(&padded, known_check_encoded);
    const used = 1 + decoded_padded.payload.len + checksum_len;
    for (padded[used..]) |b| try testing.expectEqual(@as(u8, 0xAA), b);
}

const TestData = struct {
    encoded: []const u8,
    decoded: []const u8,
};

fn testing_data() []const TestData {
    return &[_]TestData{
        .{ .encoded = "", .decoded = "" },
        .{
            .encoded = "USm3fpXnKG5EUBx2ndxBDMPVciP5hGey2Jh4NDv6gmeo1LkMeiKrLJUUBk6Z",
            .decoded = "The quick brown fox jumps over the lazy dog.",
        },
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
