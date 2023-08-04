const std = @import("std");
const Sha256 = std.crypto.hash.sha2.Sha256;
const testing = std.testing;

pub const WOTS = struct {
    const Self = @This();

    secret_key: [32][32]u8,
    public_key: [32][32]u8,

    pub fn generateKeyPair() Self {
        var secret_key: [32][32]u8 = undefined;
        var public_key: [32][32]u8 = undefined;

        for (&secret_key) |*key| {
            var temp: [32]u8 = undefined;
            std.crypto.random.bytes(&temp);
            key.* = temp;
        }

        var i: usize = 0;
        while (i < public_key.len) : (i += 1) {
            var key = secret_key[i];

            var j: usize = 0;
            while (j < 256) : (j += 1) {
                key = sha256(&key);
            }

            public_key[i] = key;
        }

        return Self{ .secret_key = secret_key, .public_key = public_key };
    }

    pub fn sign(self: *Self, message: []const u8) [32][32]u8 {
        var signature: [32][32]u8 = undefined;
        const hash: [32]u8 = sha256(message);

        var i: usize = 0;
        while (i < signature.len) : (i += 1) {
            var key = self.secret_key[i];
            const n = hash[i];

            var j: usize = 0;
            while (j < 256 - @as(usize, n)) : (j += 1) {
                key = sha256(&key);
            }

            signature[i] = key;
        }

        return signature;
    }

    pub fn verify(self: *Self, message: []const u8, signature: [32][32]u8) bool {
        var public_key: [32][32]u8 = undefined;
        const hash: [32]u8 = sha256(message);

        var i: usize = 0;
        while (i < public_key.len) : (i += 1) {
            var s = signature[i];
            const n = hash[i];

            var j: usize = 0;
            while (j < @as(usize, n)) : (j += 1) {
                s = sha256(&s);
            }

            public_key[i] = s;
        }

        for (public_key, 0..) |key, index| {
            if (!std.mem.eql(u8, &key, &self.public_key[index])) {
                return false;
            }
        }

        return true;
    }

    fn sha256(bytes: []const u8) [32]u8 {
        var hasher = Sha256.init(.{});
        var out: [32]u8 = undefined;

        hasher.update(bytes);
        hasher.final(out[0..]);

        return out;
    }
};

test "sign and verify" {
    var keypair = WOTS.generateKeyPair();
    const message = [5]u8{ 'h', 'e', 'l', 'l', 'o' };
    const signature = keypair.sign(&message);
    try testing.expect(keypair.verify(&message, signature));
}
