import Foundation
import SwiftUI

/// Lists the account's devices and revokes them (not the current device).
@MainActor
final class DevicesViewModel: ObservableObject {
    @Published var devices: [VelaClient.DeviceInfo] = []
    @Published var webSessions: [VelaClient.WebSessionInfo] = []
    @Published var status = ""
    @Published var busy = false

    private let account: AccountViewModel

    init(account: AccountViewModel) { self.account = account }

    var currentDeviceID: String? { account.deviceID }

    func refresh() {
        run("Loading") { [self] in
            guard let client = account.makeClient() else { throw Fail("register first") }
            async let deviceList = client.listDevices()
            async let sessionList = client.listWebSessions()
            let (list, sessions) = try await (deviceList, sessionList)
            await account.adoptToken(from: client)
            devices = list
            webSessions = sessions
            return "\(list.filter { !$0.revoked }.count) active device(s)"
        }
    }

    func revoke(_ device: VelaClient.DeviceInfo) {
        run("Revoking") { [self] in
            guard let client = account.makeClient() else { throw Fail("register first") }
            try await client.revokeDevice(targetDeviceID: device.id)
            let list = try await client.listDevices()
            await account.adoptToken(from: client)
            devices = list
            AuditLog.shared.record("device_revoked", device.name)
            return "Revoked \(device.name)"
        }
    }

    func revokeWebSession(_ session: VelaClient.WebSessionInfo) {
        run("Revoking web session") { [self] in
            guard let client = account.makeClient() else { throw Fail("register first") }
            try await client.revokeWebSession(id: session.id)
            let sessions = try await client.listWebSessions()
            await account.adoptToken(from: client)
            webSessions = sessions
            AuditLog.shared.record("web_session_revoked", session.mode)
            return "Web session revoked"
        }
    }

    private func run(_ label: String, _ work: @escaping () async throws -> String) {
        busy = true
        status = "\(label)…"
        Task { @MainActor in
            do { status = try await work() }
            catch { status = "\(label) failed: \(error.localizedDescription)" }
            busy = false
        }
    }

    private struct Fail: LocalizedError {
        let message: String
        init(_ m: String) { message = m }
        var errorDescription: String? { message }
    }
}
