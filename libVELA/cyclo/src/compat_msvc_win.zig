export const _fltused: c_int = 0;
const dummy_vtable: usize = 0;
export const @"??_7type_info@@6B@": *const anyopaque = @ptrCast(&dummy_vtable);
export fn ___chkstk_ms() callconv(.c) void {}

// Zig 0.16's Windows debug self-info may reference this optional ntdll API from
// static libraries. The MSVC import library does not always expose it, so provide
// a conservative fallback that makes stack-info DLL notifications unavailable.
export fn LdrRegisterDllNotification(
    flags: u32,
    notification_function: ?*const anyopaque,
    context: ?*anyopaque,
    cookie: ?*?*anyopaque,
) callconv(.winapi) c_long {
    _ = flags;
    _ = notification_function;
    _ = context;
    _ = cookie;
    return -1073741822; // STATUS_NOT_IMPLEMENTED
}
