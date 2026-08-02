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

// Exercises the post-quantum signing keygen + RNG through the core, and the
// handle API that replaced the key-returning one (audit C-1): the response
// carries public halves and a sealed blob, never a private key.
let sealKey = [UInt8](repeating: 4, count: 32)
let identity = sealKey.withUnsafeBufferPointer { take(vela_ffi_identity_create($0.baseAddress, $0.count)) }
precondition(identity.contains("hybrid_ek_b64"), "no identity keys: \(identity)")
precondition(identity.contains("sealed_b64"), "no sealed identity: \(identity)")
precondition(!identity.contains("hybrid_sk"), "private signing key crossed the FFI: \(identity)")
precondition(!identity.contains("share_dk"), "share secret key crossed the FFI: \(identity)")
print("identity handle created ok, no private key in the response")

print("SWIFT <-> RUST FFI OK")
