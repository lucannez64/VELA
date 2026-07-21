import AuthenticationServices
import Foundation
#if canImport(UIKit)
import UIKit
#endif

/// Runs WebAuthn/FIDO2 registration and assertion ceremonies against a
/// physical security key (SPEC.md §4.3's "registered WebAuthn/FIDO2 recovery
/// credential"), independent of this device's own biometrics — the whole
/// point of the recovery credential is that it survives losing every Apple
/// device signed into this account.
///
/// The server (via `webauthn-rs`) speaks the standard WebAuthn JSON
/// dictionary: challenge/user.id/credential ids are base64url strings, and
/// the credential response it expects back is the same
/// `{id, rawId, type, response: {...}}` shape used by `navigator.credentials`
/// in a browser — this class translates between that JSON and
/// `AuthenticationServices`' native types.
@MainActor
final class WebAuthnCeremony: NSObject {
    struct Failure: LocalizedError {
        let message: String
        var errorDescription: String? { message }
    }

    private var continuation: CheckedContinuation<ASAuthorization, Error>?

    /// Run a registration ceremony. `optionsJSON` is the (already-unwrapped)
    /// `PublicKeyCredentialCreationOptions` dictionary from the server.
    /// Returns the attestation response JSON to POST back to
    /// `/recovery/webauthn/register/finish`.
    func register(optionsJSON: [String: Any]) async throws -> [String: Any] {
        guard let rpID = (optionsJSON["rp"] as? [String: Any])?["id"] as? String else {
            throw Failure(message: "Missing relying party id in server response")
        }
        guard let challengeB64 = optionsJSON["challenge"] as? String,
              let challenge = Self.base64URLDecode(challengeB64) else {
            throw Failure(message: "Missing/invalid challenge in server response")
        }
        let user = optionsJSON["user"] as? [String: Any] ?? [:]
        guard let userIDB64 = user["id"] as? String, let userID = Self.base64URLDecode(userIDB64) else {
            throw Failure(message: "Missing/invalid user id in server response")
        }
        let userName = (user["name"] as? String) ?? "vela-user"
        let displayName = (user["displayName"] as? String) ?? "VELA recovery key"

        let provider = ASAuthorizationSecurityKeyPublicKeyCredentialProvider(relyingPartyIdentifier: rpID)
        let request = provider.createCredentialRegistrationRequest(
            challenge: challenge, displayName: displayName, name: userName, userID: userID)

        if let excluded = optionsJSON["excludeCredentials"] as? [[String: Any]] {
            request.excludedCredentials = excluded.compactMap { entry in
                guard let idB64 = entry["id"] as? String, let id = Self.base64URLDecode(idB64) else { return nil }
                return ASAuthorizationSecurityKeyPublicKeyCredentialDescriptor(
                    credentialID: id, transports: [.usb, .nfc, .bluetooth])
            }
        }

        let authorization = try await perform(request)
        guard let credential = authorization.credential as? ASAuthorizationSecurityKeyPublicKeyCredentialRegistration,
              let attestationObject = credential.rawAttestationObject else {
            throw Failure(message: "Security key did not return a registration credential")
        }

        return [
            "id": Self.base64URLEncode(credential.credentialID),
            "rawId": Self.base64URLEncode(credential.credentialID),
            "type": "public-key",
            "response": [
                "clientDataJSON": Self.base64URLEncode(credential.rawClientDataJSON),
                "attestationObject": Self.base64URLEncode(attestationObject),
            ],
        ]
    }

    /// Run an assertion ceremony. `optionsJSON` is the (already-unwrapped)
    /// `PublicKeyCredentialRequestOptions` dictionary from the server.
    /// Returns the assertion response JSON to POST back to
    /// `/recovery/recover`.
    func assert(optionsJSON: [String: Any]) async throws -> [String: Any] {
        guard let challengeB64 = optionsJSON["challenge"] as? String,
              let challenge = Self.base64URLDecode(challengeB64) else {
            throw Failure(message: "Missing/invalid challenge in server response")
        }
        let rpID = (optionsJSON["rpId"] as? String) ?? (optionsJSON["rp_id"] as? String)
        guard let rpID = rpID else {
            throw Failure(message: "Missing relying party id in server response")
        }

        let provider = ASAuthorizationSecurityKeyPublicKeyCredentialProvider(relyingPartyIdentifier: rpID)
        let request = provider.createCredentialAssertionRequest(challenge: challenge)

        if let allowed = optionsJSON["allowCredentials"] as? [[String: Any]] {
            request.allowedCredentials = allowed.compactMap { entry in
                guard let idB64 = entry["id"] as? String, let id = Self.base64URLDecode(idB64) else { return nil }
                return ASAuthorizationSecurityKeyPublicKeyCredentialDescriptor(
                    credentialID: id, transports: [.usb, .nfc, .bluetooth])
            }
        }

        let authorization = try await perform(request)
        guard let credential = authorization.credential as? ASAuthorizationSecurityKeyPublicKeyCredentialAssertion else {
            throw Failure(message: "Security key did not return an assertion credential")
        }

        return [
            "id": Self.base64URLEncode(credential.credentialID),
            "rawId": Self.base64URLEncode(credential.credentialID),
            "type": "public-key",
            "response": [
                "clientDataJSON": Self.base64URLEncode(credential.rawClientDataJSON),
                "authenticatorData": Self.base64URLEncode(credential.rawAuthenticatorData),
                "signature": Self.base64URLEncode(credential.signature),
                "userHandle": credential.userID.map { Self.base64URLEncode($0) } ?? "",
            ],
        ]
    }

    private func perform(_ request: ASAuthorizationRequest) async throws -> ASAuthorization {
        try await withCheckedThrowingContinuation { [weak self] cont in
            guard let self = self else {
                cont.resume(throwing: Failure(message: "WebAuthn ceremony was deallocated"))
                return
            }
            self.continuation = cont
            let controller = ASAuthorizationController(authorizationRequests: [request])
            controller.delegate = self
            controller.presentationContextProvider = self
            controller.performRequests()
        }
    }

    /// The server wraps its WebAuthn options in a `publicKey` field (mirroring
    /// what a browser would pass to `navigator.credentials.create/get`), on
    /// top of our own `public_key` HTTP response field — unwrap either shape.
    static func unwrapPublicKey(_ dict: [String: Any]) -> [String: Any] {
        if let inner = dict["publicKey"] as? [String: Any] { return inner }
        if let inner = dict["public_key"] as? [String: Any] { return unwrapPublicKey(inner) }
        return dict
    }

    static func base64URLDecode(_ value: String) -> Data? {
        var base64 = value.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        let padding = (4 - base64.count % 4) % 4
        base64 += String(repeating: "=", count: padding)
        return Data(base64Encoded: base64)
    }

    static func base64URLEncode(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

extension WebAuthnCeremony: ASAuthorizationControllerDelegate {
    func authorizationController(controller: ASAuthorizationController, didCompleteWithAuthorization authorization: ASAuthorization) {
        continuation?.resume(returning: authorization)
        continuation = nil
    }

    func authorizationController(controller: ASAuthorizationController, didCompleteWithError error: Error) {
        continuation?.resume(throwing: error)
        continuation = nil
    }
}

extension WebAuthnCeremony: ASAuthorizationControllerPresentationContextProviding {
    func presentationAnchor(for controller: ASAuthorizationController) -> ASPresentationAnchor {
        #if canImport(UIKit) && !VELA_APP_EXTENSION
        let window = UIApplication.shared.connectedScenes
            .compactMap { $0 as? UIWindowScene }
            .flatMap { $0.windows }
            .first { $0.isKeyWindow }
        return window ?? ASPresentationAnchor()
        #else
        // Never actually reached: WebAuthnCeremony is only invoked from the
        // main app's recovery screens, not the AutoFill extension — this
        // branch exists purely so the file still compiles under the
        // extension target's APPLICATION_EXTENSION_API_ONLY restriction.
        return ASPresentationAnchor()
        #endif
    }
}
