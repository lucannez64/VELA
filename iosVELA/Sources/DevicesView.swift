import SwiftUI

/// Lists the account's enrolled devices; revoke any except the current one.
struct DevicesView: View {
    @StateObject private var vm: DevicesViewModel

    @Environment(\.ink) private var ink
    @Environment(\.dismiss) private var dismiss

    init(account: AccountViewModel) {
        _vm = StateObject(wrappedValue: DevicesViewModel(account: account))
    }

    var body: some View {
        ZStack {
            ink.bg.ignoresSafeArea()
            ScrollView {
                VStack(alignment: .leading, spacing: 0) {
                    BackHead(title: "More / Devices") { dismiss() }
                        .arrive(0)

                    HStack(alignment: .center) {
                        InstrumentHeading(eyebrow: "03 / This device",
                                          title: "Your devices.",
                                          subtitle: "Every device that can open your vault.")
                        InstrumentIconButton(icon: .refresh, label: "Refresh") { vm.refresh() }
                            .disabled(vm.busy)
                            .accessibilityIdentifier("refreshDevicesButton")
                    }
                    .arrive(1)

                    GroupLabel(text: "01 / Enrolled devices")
                        .arrive(2)
                    InstrumentGroup {
                        if vm.devices.isEmpty {
                            FineText("No devices yet.").padding(15)
                        } else {
                            ForEach(vm.devices.indices, id: \.self) { index in
                                if index > 0 { GroupDivider() }
                                deviceRow(vm.devices[index])
                            }
                        }
                    }
                    .disabled(vm.busy)
                    .arrive(3)

                    GroupLabel(text: "02 / Web sessions")
                        .arrive(4)
                    InstrumentGroup {
                        if vm.webSessions.isEmpty {
                            FineText("No active web sessions.").padding(15)
                        } else {
                            ForEach(vm.webSessions.indices, id: \.self) { index in
                                if index > 0 { GroupDivider() }
                                webSessionRow(vm.webSessions[index])
                            }
                        }
                    }
                    .disabled(vm.busy)
                    .arrive(5)

                    if !vm.status.isEmpty {
                        FineText(vm.status, size: 10)
                            .padding(.top, 2)
                    }
                }
                .padding(.horizontal, 20)
                .padding(.top, 10)
                .padding(.bottom, 32)
            }
            .scrollIndicators(.hidden)
        }
        .toolbar(.hidden, for: .navigationBar)
        .onAppear { vm.refresh() }
        // Auto-refresh web sessions every 30 s so a session approved by another
        // enrolled device becomes visible without a manual refresh.
        .onReceive(Timer.publish(every: 30, on: .main, in: .common).autoconnect()) { _ in
            vm.refresh()
        }
    }

    private func deviceRow(_ device: VelaClient.DeviceInfo) -> some View {
        let isCurrent = device.id == vm.currentDeviceID
        let glyph: InstrumentIconName = (device.device_type == "ios" || device.device_type == "android")
            ? .phone : .device
        return HStack(spacing: 11) {
            InstrumentAvatar(icon: glyph)
            VStack(alignment: .leading, spacing: 5) {
                Text(device.name)
                    .font(InstrumentFont.medium(13))
                    .foregroundColor(ink.text)
                    .lineLimit(1)
                    .truncationMode(.tail)
                HStack(spacing: 6) {
                    Text(device.device_type)
                        .font(InstrumentFont.body(10))
                        .foregroundColor(ink.muted)
                        .lineLimit(1)
                    if isCurrent { InstrumentTag(text: "This device", kind: .ok) }
                    if device.pending { InstrumentTag(text: "Pending", kind: .plain) }
                    if device.revoked { InstrumentTag(text: "Revoked", kind: .risk) }
                }
            }
            Spacer(minLength: 8)
            if !isCurrent && !device.revoked {
                revokeButton { vm.revoke(device) }
            }
        }
        .padding(.horizontal, 15)
        .padding(.vertical, 12)
        .frame(minHeight: 63)
    }

    private func webSessionRow(_ session: VelaClient.WebSessionInfo) -> some View {
        let readWrite = session.mode == "rw"
        return HStack(spacing: 11) {
            InstrumentAvatar(icon: .globe)
            VStack(alignment: .leading, spacing: 5) {
                HStack(spacing: 6) {
                    Text("Web browser")
                        .font(InstrumentFont.medium(13))
                        .foregroundColor(ink.text)
                        .lineLimit(1)
                    InstrumentTag(text: readWrite ? "RW" : "RO",
                                  kind: readWrite ? TagKind.risk : TagKind.ok)
                }
                if let exp = session.expires_at {
                    FineText("Expires \(exp.prefix(16).replacingOccurrences(of: "T", with: " "))", size: 10)
                } else {
                    FineText("No expiry set", size: 10)
                }
            }
            Spacer(minLength: 8)
            revokeButton { vm.revokeWebSession(session) }
        }
        .padding(.horizontal, 15)
        .padding(.vertical, 12)
        .frame(minHeight: 63)
    }

    private func revokeButton(_ action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Text("Revoke")
                .font(InstrumentFont.body(11))
                .foregroundColor(ink.red)
                .padding(.horizontal, 12)
                .padding(.vertical, 8)
                .overlay(Capsule().stroke(ink.red.opacity(0.3), lineWidth: 1))
                .contentShape(Capsule())
        }
        .buttonStyle(PressScaleStyle())
    }
}
