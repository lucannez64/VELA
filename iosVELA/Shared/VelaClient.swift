import Foundation

/// Async URLSession client for the VELA server (default `https://vault.klyt.eu`).
///
/// Implements the SPEC §§6-8 client surface used by Phase 4: account register,
/// the challenge/verify auth handshake, PASETO session with `X-New-Token`
/// renewal, the chunk sync protocol, sharing, and recovery-share storage.
/// The server only ever sees opaque ciphertext — all crypto happens via the core.
actor VelaClient {
    struct ServerError: LocalizedError {
        let status: Int
        let body: String
        var errorDescription: String? { "server \(status): \(body)" }
    }

    let baseURL: URL
    private let session: URLSession
    private var token: String?

    init(baseURL: URL = URL(string: "https://vault.klyt.eu")!,
         token: String? = nil,
         session: URLSession = .shared) {
        self.baseURL = baseURL
        self.token = token
        self.session = session
    }

    var currentToken: String? { token }
    func setToken(_ token: String?) { self.token = token }

    // MARK: - Health / account / auth

    struct Health: Decodable { let status: String }

    func health() async throws -> Health {
        try await request("GET", "/health", auth: false)
    }

    struct RegisterResponse: Decodable {
        let user_id: String
        let device_id: String
        let token: String?
    }

    func register(hybridEK: String, hybridVK: String, deviceName: String, deviceType: String = "ios") async throws -> RegisterResponse {
        let body: [String: Any] = [
            "hybrid_ek": hybridEK, "hybrid_vk": hybridVK,
            "device_name": deviceName, "device_type": deviceType,
        ]
        let resp: RegisterResponse = try await request("POST", "/account/register", json: body, auth: false)
        if let t = resp.token { token = t }
        return resp
    }

    struct ChallengeResponse: Decodable { let challenge: String }

    func challenge() async throws -> String {
        let resp: ChallengeResponse = try await request("GET", "/auth/challenge", auth: false)
        return resp.challenge
    }

    struct VerifyResponse: Decodable {
        let token: String
        let user_id: String
    }

    func verify(deviceID: String, challenge: String, signature: String,
                deviceName: String? = nil, deviceType: String? = nil) async throws -> VerifyResponse {
        var body: [String: Any] = [
            "device_id": deviceID, "challenge": challenge, "signature": signature,
        ]
        if let deviceName = deviceName { body["device_name"] = deviceName }
        if let deviceType = deviceType { body["device_type"] = deviceType }
        let resp: VerifyResponse = try await request("POST", "/auth/verify", json: body, auth: false)
        token = resp.token
        return resp
    }

    func logout() async throws {
        _ = try await requestRaw("POST", "/auth/logout", body: nil)
        token = nil
    }

    // MARK: - Vault sync (chunk protocol)

    struct ChunkMeta: Decodable {
        let chunk_id: String
        let version: Int
        let lamport_clock: Int
        let last_writer: String?
    }
    struct SyncManifest: Decodable { let chunks: [ChunkMeta] }

    func syncManifest() async throws -> SyncManifest {
        try await request("GET", "/vault/sync", auth: true)
    }

    /// A fetched chunk: the base64 ciphertext (ready for `decryptVaultChunk`) and its version.
    struct FetchedChunk {
        let ciphertextBase64: String
        let version: Int
        let lamportClock: Int
    }

    func getChunk(_ chunkID: String) async throws -> FetchedChunk {
        let (data, http) = try await requestRaw("GET", "/vault/chunk/\(chunkID)", body: nil)
        // Server returns the stored base64 ciphertext as the body.
        let ciphertextB64 = String(decoding: data, as: UTF8.self)
        let version = Int(http.value(forHTTPHeaderField: "X-Chunk-Version") ?? "") ?? 0
        let lamport = Int(http.value(forHTTPHeaderField: "X-Lamport-Clock") ?? "") ?? 0
        return FetchedChunk(ciphertextBase64: ciphertextB64, version: version, lamportClock: lamport)
    }

    /// Upload a chunk. `ifMatch` = 0 to insert, else the current version. Returns the new version.
    func putChunk(_ chunkID: String, ciphertextBase64: String, ifMatch: Int, lamportClock: Int) async throws -> Int {
        guard let raw = Data(base64Encoded: ciphertextBase64) else {
            throw ServerError(status: 0, body: "invalid ciphertext base64")
        }
        let (data, _) = try await requestRaw(
            "PUT", "/vault/chunk/\(chunkID)", body: raw,
            headers: ["If-Match": String(ifMatch), "X-Lamport-Clock": String(lamportClock),
                      "Content-Type": "application/octet-stream"]
        )
        struct PutResp: Decodable { let version: Int }
        return (try? JSONDecoder().decode(PutResp.self, from: data))?.version ?? (ifMatch + 1)
    }

    // MARK: - Sharing

    struct ShareSendResponse: Decodable {
        let inbox_id: String
        let share_id: String
    }

    func sendShare(recipientUserID: String, capsuleBase64: String) async throws -> ShareSendResponse {
        try await request("POST", "/share/send",
                          json: ["recipient_user_id": recipientUserID, "capsule": capsuleBase64], auth: true)
    }

    struct InboxItem: Decodable {
        let id: String
        let sender_user_id: String
        let capsule: String
        let created_at: String
    }
    struct InboxResponse: Decodable {
        let items: [InboxItem]
        let has_more: Bool
    }

    func shareInbox(limit: Int = 50) async throws -> InboxResponse {
        try await request("GET", "/share/inbox?limit=\(limit)", auth: true)
    }

    func deleteInboxItem(_ id: String) async throws {
        _ = try await requestRaw("DELETE", "/share/inbox/\(id)", body: nil)
    }

    struct LinkedShareItem: Decodable, Identifiable {
        let id: String
        let sender_user_id: String
        let recipient_user_id: String
        let capsule: String
        let created_at: String
        let updated_at: String
        let revoked: Bool
    }
    struct LinkedSharesResponse: Decodable { let items: [LinkedShareItem] }

    func linkedShares() async throws -> [LinkedShareItem] {
        let resp: LinkedSharesResponse = try await request("GET", "/share/linked", auth: true)
        return resp.items
    }

    func deleteLinkedShare(_ id: String) async throws {
        _ = try await requestRaw("DELETE", "/share/linked/\(id)", body: nil)
    }

    // MARK: - Devices

    struct DeviceInfo: Decodable, Identifiable {
        let id: String
        let name: String
        let device_type: String
        let enrolled_by: String?
        let last_active: String?
        let revoked: Bool
        let pending: Bool
        let created_at: String
    }
    struct ListDevicesResponse: Decodable { let devices: [DeviceInfo] }

    func listDevices() async throws -> [DeviceInfo] {
        let resp: ListDevicesResponse = try await request("GET", "/devices", auth: true)
        return resp.devices
    }

    func revokeDevice(targetDeviceID: String) async throws {
        let _: EmptyResponse = try await request("POST", "/device/revoke",
                                                 json: ["target_device_id": targetDeviceID], auth: true)
    }

    // MARK: - Enrollment (joining side)

    struct CapsuleResponse: Decodable { let capsule: String }

    /// Download this device's one-shot RMS capsule (cleared server-side after).
    func getCapsule() async throws -> String {
        let resp: CapsuleResponse = try await request("GET", "/device/capsule", auth: true)
        return resp.capsule
    }

    struct EnrollmentPackageResponse: Decodable { let ciphertext: String }

    /// Fetch an enrollment package by token (no auth — the token is the secret).
    func getEnrollmentPackage(token: String) async throws -> String {
        let resp: EnrollmentPackageResponse = try await request("GET", "/device/enrollment-package/\(token)", auth: false)
        return resp.ciphertext
    }

    // MARK: - Recovery share

    func putRecoveryShare(_ shareBase64: String) async throws {
        let _: EmptyResponse = try await request("PUT", "/recovery/share", json: ["share": shareBase64], auth: true)
    }

    struct RecoveryShareResponse: Decodable { let share: String }

    func getRecoveryShare() async throws -> String {
        let resp: RecoveryShareResponse = try await request("GET", "/recovery/share", auth: true)
        return resp.share
    }

    func deleteRecoveryShare() async throws {
        _ = try await requestRaw("DELETE", "/recovery/share", body: nil)
    }

    // MARK: - Request plumbing

    private struct EmptyResponse: Decodable {
        init() {}
        init(from decoder: Decoder) throws {}
    }

    private func request<T: Decodable>(_ method: String, _ path: String,
                                       json: [String: Any]? = nil, auth: Bool = true) async throws -> T {
        let body = try json.map { try JSONSerialization.data(withJSONObject: $0) }
        var headers: [String: String] = [:]
        if json != nil { headers["Content-Type"] = "application/json" }
        let (data, _) = try await requestRaw(method, path, body: body, headers: headers, auth: auth)
        if T.self == EmptyResponse.self { return EmptyResponse() as! T }
        return try JSONDecoder().decode(T.self, from: data)
    }

    @discardableResult
    private func requestRaw(_ method: String, _ path: String, body: Data?,
                            headers: [String: String] = [:], auth: Bool = true) async throws -> (Data, HTTPURLResponse) {
        guard let url = URL(string: path, relativeTo: baseURL) else {
            throw ServerError(status: 0, body: "bad path \(path)")
        }
        var req = URLRequest(url: url)
        req.httpMethod = method
        req.httpBody = body
        for (k, v) in headers { req.setValue(v, forHTTPHeaderField: k) }
        if auth, let token = token {
            req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }

        let (data, response) = try await session.data(for: req)
        guard let http = response as? HTTPURLResponse else {
            throw ServerError(status: 0, body: "no HTTP response")
        }
        // Sliding-session renewal: adopt a rotated token when offered.
        if let newToken = http.value(forHTTPHeaderField: "X-New-Token"), !newToken.isEmpty {
            token = newToken
        }
        guard (200..<300).contains(http.statusCode) else {
            throw ServerError(status: http.statusCode, body: String(decoding: data, as: UTF8.self))
        }
        return (data, http)
    }
}
