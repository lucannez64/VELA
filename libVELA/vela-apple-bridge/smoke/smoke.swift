// CI smoke: prove Swift can call the VELA Rust core over the C ABI.
// Built on the host (macOS) against the same code that ships in the XCFramework.
import Foundation
import VelaCore

func take(_ ptr: UnsafeMutablePointer<CChar>?) -> String {
    guard let ptr = ptr else { return "" }
    defer { vela_ffi_free_string(ptr) }
    return String(cString: ptr)
}

let version = take(vela_ffi_version())
print("version:", version)
precondition(version.hasPrefix("vela-apple-bridge/"), "unexpected version: \(version)")

let strength = "{\"password\":\"Abcdefgh123!\"}".withCString { take(vela_ffi_password_strength_json($0)) }
print("password strength:", strength)
precondition(strength.contains("score"), "no strength score: \(strength)")

// Exercises the post-quantum signing keygen + RNG through the core.
let identity = take(vela_ffi_generate_identity_json())
precondition(identity.contains("hybrid_ek_b64"), "no identity keys: \(identity)")
print("identity keys generated ok")

print("SWIFT <-> RUST FFI OK")
