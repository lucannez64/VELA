# Changelog

## 2026-03-26 - Security Fixes

### Fixed Timing Leaks and Security Issues

- **ringSliceEqCt early return (src/root.zig:5339)**: Removed early return on length mismatch. Previously, if `lhs.len != rhs.len`, the function returned immediately without processing any data, creating a timing leak that could reveal whether slice lengths matched. Fixed to always iterate through all elements (min_len for data comparison, plus remaining elements from longer slice), and check length equality at the end.

- **Ring.eq not constant-time (src/root.zig:1172)**: Changed from `std.mem.eql(u64, &self.data, &other.data)` to XOR-based constant-time comparison. `std.mem.eql` may use early-termination optimizations that leak timing information about whether elements match.

- **Fq2.eq not constant-time (src/root.zig:1946)**: Changed from `self.c0 == other.c0 and self.c1 == other.c1` (which uses short-circuit evaluation) to bitwise XOR+OR: `(diff_c0 | diff_c1) == 0`. This ensures both comparisons always execute.

- **challengeU64 rejection sampling timing (src/root.zig:3739)**: The rejection sampling loop could iterate a variable number of times depending on hash outputs. Changed to fixed 8-trial loop with branchless first-valid selection to ensure constant execution time regardless of when a valid sample is found.

### Verification
All fixes verified with `zig build test`.
