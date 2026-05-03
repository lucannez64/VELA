const builtin = @import("builtin");

export fn __zig_probe_stack(frame_size: usize) void {
    _ = frame_size;
}

export var __stack_chk_guard: usize = @truncate(0xDEADBEEFCAFEBABE);
export fn __stack_chk_fail() noreturn {
    @panic("stack smashing detected");
}

comptime {
    if (builtin.os.tag == .windows) {
        _ = @import("compat_msvc_win.zig");
    }
}
