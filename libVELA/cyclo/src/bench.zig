const std = @import("std");
const ring = @import("root.zig");
const ring_ntt = @import("ring_ntt.zig");

pub fn main() !void {
    try run_benchmark(1024, 12289);
    std.debug.print("\n", .{});
    try run_benchmark(1024, 1125899906856961);
}

fn run_benchmark(comptime N: usize, comptime Q: u64) !void {
    const R = ring.Ring(N, Q);
    const NttPlan = ring_ntt.NttMul(N, Q);

    var prng = std.Random.DefaultPrng.init(0);
    const random = prng.random();

    // Generate random polynomials
    var a = R.zero();
    var b = R.zero();

    for (0..N) |i| {
        a.data[i] = random.intRangeAtMost(u64, 0, Q - 1);
        b.data[i] = random.intRangeAtMost(u64, 0, Q - 1);
    }

    // Init Plan
    var plan = try NttPlan.init();
    defer plan.deinit();

    const iterations = 1000;

    std.debug.print("Benchmarking N={d}, Q={d} with {d} iterations...\n", .{ N, Q, iterations });

    // Benchmark Naive Multiplication
    var timer = try std.time.Timer.start();
    for (0..iterations) |_| {
        const res = a.mul(b);
        std.mem.doNotOptimizeAway(res);
    }
    const naive_time = timer.read();
    const naive_avg = naive_time / iterations;

    std.debug.print("Naive Mul: {d} ns/op\n", .{naive_avg});

    // Benchmark NTT Multiplication
    timer.reset();
    for (0..iterations) |_| {
        const res = a.mulNtt(b, plan);
        std.mem.doNotOptimizeAway(res);
    }
    const ntt_time = timer.read();
    const ntt_avg = ntt_time / iterations;

    std.debug.print("NTT Mul:   {d} ns/op\n", .{ntt_avg});

    const speedup = @as(f64, @floatFromInt(naive_avg)) / @as(f64, @floatFromInt(ntt_avg));
    std.debug.print("Speedup:   {d:.2}x\n", .{speedup});
}
