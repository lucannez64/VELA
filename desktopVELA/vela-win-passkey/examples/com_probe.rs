//! Manual COM probe with raw FFI (no windows crate) — activate the
//! registered provider and call `GetLockStatus` exactly as an external
//! WebAuthn client would.

use std::os::raw::{c_int, c_void};

#[link(name = "ole32")]
unsafe extern "system" {
    fn CoInitializeEx(pvreserved: *mut c_void, dwcoinit: u32) -> c_int;
    fn CoCreateInstance(
        rclsid: *const u32, // GUID laid out flat
        punkouter: *mut c_void,
        dwclscontext: u32,
        riid: *const u32,
        ppv: *mut *mut c_void,
    ) -> c_int;
}

const CLSCTX_LOCAL_SERVER: u32 = 0x4;
const COINIT_MULTITHREADED: u32 = 0x0;

fn guid(d1: u32, d2: u16, d3: u16, d4: [u8; 8]) -> [u32; 4] {
    // Memory layout of a GUID: Data1 (LE u32), Data2 (LE u16), Data3 (LE
    // u16), Data4 (raw bytes). Packed into LE u32 words: word1 = Data1,
    // word2 = Data3<<16 | Data2 (little-endian in memory yields Data2's
    // bytes first), word3/4 = Data4 halves read as LE u32.
    let hi = u32::from_le_bytes([d4[0], d4[1], d4[2], d4[3]]);
    let lo = u32::from_le_bytes([d4[4], d4[5], d4[6], d4[7]]);
    [d1, (u32::from(d3) << 16) | u32::from(d2), hi, lo]
}

fn main() {
    unsafe {
        let hr_init = CoInitializeEx(std::ptr::null_mut(), COINIT_MULTITHREADED);
        eprintln!("CoInitializeEx: {hr_init:#010x}");

        let clsid = guid(0xf9b5_94a7, 0x0e49, 0x4c9e, [0x83, 0x38, 0xf6, 0xd3, 0x0b, 0xce, 0x33, 0xc4]);
        let iid = guid(0xd26b_cf6f, 0xb54c, 0x43ff, [0x9f, 0x06, 0xd5, 0xbf, 0x14, 0x86, 0x25, 0xf7]);
        let mut ppv: *mut c_void = std::ptr::null_mut();
        let hr = CoCreateInstance(
            clsid.as_ptr(),
            std::ptr::null_mut(),
            CLSCTX_LOCAL_SERVER,
            iid.as_ptr(),
            &mut ppv,
        );
        eprintln!("CoCreateInstance: {hr:#010x}");
        if hr != 0 {
            std::process::exit(1);
        }
        eprintln!("activated; calling GetLockStatus via raw vtable");
        let vtable = *(ppv as *mut *mut c_void) as *const *mut c_void;
        let get_lock_status: unsafe extern "system" fn(*mut c_void, *mut i32) -> c_int =
            std::mem::transmute(vtable.add(6).read());
        let mut status: i32 = 1;
        let call_hr = get_lock_status(ppv, &mut status);
        eprintln!("GetLockStatus: hr={call_hr:#010x} status={status} (0=locked, 1=unlocked)");
        std::process::exit(if call_hr == 0 { 0 } else { 1 });
    }
}
