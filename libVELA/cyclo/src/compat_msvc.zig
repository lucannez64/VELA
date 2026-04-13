// Export _fltused for MSVC compatibility
export const _fltused: c_int = 0;
// Export dummy vftable for std::type_info (MSVC C++ RTTI) referenced by Rust std
// Using a null pointer or pointing to a dummy value is safer than undefined.
// Since it's a vtable pointer, pointing to a dummy struct is safer if dereferenced.
const dummy_vtable: usize = 0;
export const @"??_7type_info@@6B@": *const anyopaque = @ptrCast(&dummy_vtable);

// GNU-style stack protector stubs required when Zig debug mode is linked against
// the MSVC linker, which does not provide these symbols from its own CRT.
export var __stack_chk_guard: usize = 0xDEADBEEFCAFEBABE;
export fn __stack_chk_fail() noreturn {
    @panic("stack smashing detected");
}
// MSVC-convention stack probe emitted by Zig for large stack frame allocations.
// The OS guard page handles real probing; this stub satisfies the linker.
export fn ___chkstk_ms() void {}
