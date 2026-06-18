import SwiftUI

/// Lists the account's enrolled devices; revoke any except the current one.
struct DevicesView: View {
    @StateObject private var vm: DevicesViewModel

    init(account: AccountViewModel) {
        _vm = StateObject(wrappedValue: DevicesViewModel(account: account))
    }

    var body: some View {
        List {
            if vm.devices.isEmpty {
                Text("No devices").foregroundStyle(.secondary)
            }
            ForEach(vm.devices) { device in
                row(device)
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

    private func tag(_ text: String, _ color: Color) -> some View {
        Text(text)
            .font(.caption2.bold())
            .padding(.horizontal, 6).padding(.vertical, 2)
            .background(color.opacity(0.2))
            .foregroundStyle(color)
            .clipShape(Capsule())
    }
}
