const std = @import("std");
const ring = @import("root.zig");
const ring_ntt = @import("ring_ntt.zig");

test "matrixVectorMul correctness" {
    const N = 4;
    const Q = 17;
    const R = ring.Ring(N, Q);

    // 2x2 matrix
    // [ 2  1 ]
    // [ 1  2 ]
    // vector [ 1, 1 ]
    // result [ 3, 3 ]

    // In polynomial ring, these are constant polynomials.
    var two_coeffs = [_]i128{0} ** N;
    two_coeffs[0] = 2;
    var one_coeffs = [_]i128{0} ** N;
    one_coeffs[0] = 1;

    const two = R.fromCoeffs(two_coeffs);
    const one = R.fromCoeffs(one_coeffs);

    var row0 = [_]R{ two, one };
    var row1 = [_]R{ one, two };
    var matrix = [_][]const R{ &row0, &row1 };

    var vec = [_]R{ one, one };

    var out = [_]R{ R.zero(), R.zero() };

    R.matrixVectorMul(&matrix, &vec, &out);

    const three = R.fromCoeffs(.{ 3, 0, 0, 0 });
    try std.testing.expect(out[0].eq(three));
    try std.testing.expect(out[1].eq(three));
}

test "matrixVectorMulNttDomain correctness" {
    // Use N=64 to satisfy NTT requirements for Q=12289
    // 12289 = 96 * 128 + 1, so 12289 == 1 mod 2N
    const N = 64;
    const Q = 12289;
    const R = ring.Ring(N, Q);
    const NttMul = ring_ntt.NttMul(N, Q);
    const Dom = ring_ntt.NttDomain(N, Q);

    var plan = try NttMul.init();
    defer plan.deinit();

    // Matrix M = [ 1  0 ]
    //            [ 0  1 ]
    // Vector v = [ a, b ]
    // Result = [ a, b ]

    const one_poly = R.one();
    const zero_poly = R.zero();

    const one_ntt = Dom.init(&plan, one_poly);
    const zero_ntt = Dom.init(&plan, zero_poly);

    var row0 = [_]Dom{ one_ntt, zero_ntt };
    var row1 = [_]Dom{ zero_ntt, one_ntt };
    var matrix = [_][]const Dom{ &row0, &row1 };

    // Create test polynomials
    var a_coeffs = [_]i128{0} ** N;
    for (0..N) |i| a_coeffs[i] = @intCast(i);

    var b_coeffs = [_]i128{0} ** N;
    for (0..N) |i| b_coeffs[i] = @intCast(i + 10);

    const a_poly = R.fromCoeffs(a_coeffs);
    const b_poly = R.fromCoeffs(b_coeffs);

    const a_ntt = Dom.init(&plan, a_poly);
    const b_ntt = Dom.init(&plan, b_poly);

    var vec = [_]Dom{ a_ntt, b_ntt };
    var out = [_]Dom{ Dom.zero(), Dom.zero() };

    R.matrixVectorMulNttDomain(&matrix, &vec, &out, plan);

    const out0_poly = out[0].toRing(&plan);
    const out1_poly = out[1].toRing(&plan);

    try std.testing.expect(out0_poly.eq(a_poly));
    try std.testing.expect(out1_poly.eq(b_poly));
}

test "matrixVectorMulAdd correctness" {
    const N = 4;
    const Q = 17;
    const R = ring.Ring(N, Q);

    // Matrix A = [ 2 ] (1x1)
    // Vector x = [ 3 ]
    // out = [ 1 ]
    // result = 1 + 2*3 = 7.

    var coeffs_2 = [_]i128{0} ** N;
    coeffs_2[0] = 2;
    var coeffs_3 = [_]i128{0} ** N;
    coeffs_3[0] = 3;
    var coeffs_1 = [_]i128{0} ** N;
    coeffs_1[0] = 1;

    const two = R.fromCoeffs(coeffs_2);
    const three = R.fromCoeffs(coeffs_3);
    const one = R.fromCoeffs(coeffs_1);

    var row0 = [_]R{two};
    var matrix = [_][]const R{&row0};
    var vec = [_]R{three};
    var out = [_]R{one};

    R.matrixVectorMulAdd(&matrix, &vec, &out);

    const seven = R.fromCoeffs(.{ 7, 0, 0, 0 });
    try std.testing.expect(out[0].eq(seven));
}
