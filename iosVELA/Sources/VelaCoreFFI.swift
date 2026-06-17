import Foundation
import VelaCore

/// Thin Swift wrapper over the VELA Rust core's C ABI (the `VelaCore` module
/// vended by VelaCore.xcframework). All payloads are UTF-8 JSON; every returned
/// pointer is freed here.
enum VelaCoreFFI {
    private static func consume(_ ptr: UnsafeMutablePointer<CChar>?) -> String {
        guard let ptr = ptr else { return "" }
        defer { vela_ffi_free_string(ptr) }
        return String(cString: ptr)
    }

    private static func json(_ object: [String: Any]) -> String {
        guard let data = try? JSONSerialization.data(withJSONObject: object),
              let string = String(data: data, encoding: .utf8) else { return "{}" }
        return string
    }

    /// e.g. "vela-apple-bridge/0.1.0"
    static func version() -> String {
        consume(vela_ffi_version())
    }

    /// Returns the password-strength JSON from the shared core.
    static func passwordStrengthJSON(_ password: String) -> String {
        json(["password": password]).withCString { consume(vela_ffi_password_strength_json($0)) }
    }

    /// Generates a fresh device identity (hybrid PQ + classical keys) JSON.
    static func generateIdentityJSON() -> String {
        consume(vela_ffi_generate_identity_json())
    }
}
