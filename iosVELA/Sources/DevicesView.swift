import SwiftUI

/// Lists the account's enrolled devices; revoke any except the current one.
struct DevicesView: View {
    @StateObject private var vm: DevicesViewModel

    init(account: AccountViewModel) {
        _vm = StateObject(wrappedValue: DevicesViewModel(account: account))
    }

    var body: some View {
        List {
            Section("Enrolled Devices") {
                if vm.devices.isEmpty {
                    Text("No devices").foregroundStyle(.secondary)
                }
                ForEach(vm.devices) { device in
                    row(device)
                }
            }

            Section("Temporary Web Sessions") {
                if vm.webSessions.isEmpty {
                    Text("No active web sessions").foregroundStyle(.secondary)
                }
                ForEach(vm.webSessions) { session in
                    webSessionRow(session)
                }
            }

            if !vm.status.isEmpty {
                Section { Text(vm.status).font(.callout).foregroundStyle(.secondary) }
            }
        }
        .navigationTitle("Devices")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .navigationBarTrailing) {
                Button { vm.refresh() } label: { Image(systemName: "arrow.clockwise") }
                    .accessibilityIdentifier("refreshDevicesButton")
            }
        }
        .onAppear { vm.refresh() }
        // Auto-refresh web sessions every 30 s so a session approved by another
        // enrolled device becomes visible without a manual refresh.
        .onReceive(Timer.publish(every: 30, on: .main, in: .common).autoconnect()) { _ in
            vm.refresh()
        }
    }

    private func row(_ device: VelaClient.DeviceInfo) -> some View {
        let isCurrent = device.id == vm.currentDeviceID
        return HStack {
            Image(systemName: device.device_type == "ios" ? "iphone" : "desktopcomputer")
                .foregroundStyle(device.revoked ? Color.secondary : Color.green)
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text(device.name)
                    if isCurrent { tag("This device", .green) }
                    if device.pending { tag("Pending", .orange) }
                    if device.revoked { tag("Revoked", .red) }
                }
                Text(device.device_type).font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            if !isCurrent && !device.revoked {
                Button("Revoke", role: .destructive) { vm.revoke(device) }
                    .buttonStyle(.bordered)
            }
        }
    }

    private func webSessionRow(_ session: VelaClient.WebSessionInfo) -> some View {
        HStack {
            Image(systemName: "globe")
                .foregroundStyle(session.mode == "rw" ? Color.purple : Color.green)
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text("Web Browser")
                    tag(session.mode == "rw" ? "RW" : "RO",
                        session.mode == "rw" ? .purple : .green)
                }
                if let exp = session.expires_at {
                    Text("Expires \(exp.prefix(16).replacingOccurrences(of: "T", with: " "))")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
            Spacer()
            Button("Revoke", role: .destructive) { vm.revokeWebSession(session) }
                .buttonStyle(.bordered)
        }
    }

    private func tag(_ text: String, _ color: Color) -> some View {
        Text(text)
            .font(.caption2.bold())
            .padding(.horizontal, 6).padding(.vertical, 2)
            .background(color.opacity(0.2))
            .foregroundStyle(color)
            .clipShape(Capsule())
    }
}
