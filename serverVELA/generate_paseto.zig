const std = @import("std");

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    const key_pair = std.crypto.sign.Ed25519.KeyPair.generate(io);
    const raw_bytes = key_pair.secret_key.toBytes();
    const encoded_len = std.crypto.codecs.base64.encodedLen(raw_bytes.len,.standard);
    const b64 = try gpa.alloc(u8, encoded_len);
    defer gpa.free(b64);
    _ = try std.crypto.codecs.base64.encode(b64, &raw_bytes, .standard);
    var stdout_buffer: [1024]u8 = undefined;
    var stdout_file_writer: std.Io.File.Writer = .init(.stdout(), io, &stdout_buffer);
    const stdout_writer = &stdout_file_writer.interface;
    try stdout_writer.print("{s}\n", .{b64});
    try stdout_writer.flush();
}
