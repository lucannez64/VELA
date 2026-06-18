import Foundation
import SwiftUI

/// Lists the account's devices and revokes them (not the current device).
@MainActor
final class DevicesViewModel: ObservableObject {
    @Published var devices: [VelaClient.DeviceInfo] = []
    @Published var status = ""
    @Published var busy = false

    private let account: AccountViewModel

    init(account: AccountViewModel) { self.account = account }

    var currentDeviceID: String? { account.deviceID }

    func refresh() {
        run("Loading devices") { [self] in
            guard let client = account.makeClient() else { throw Fail("register first") }
            let list = try await client.listDevices()
            await account.adoptToken(from: client)
            devices = list
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
