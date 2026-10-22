import SwiftUI
import UIKit

/// Shown when a vault exists on the device but the session is locked: the
/// Instrument halo, a breathing biometric key, and the password fallback.
struct UnlockView: View {
    @ObservedObject var vm: VaultViewModel
    @ObservedObject var accountVM: AccountViewModel
    @State private var password = ""
    @State private var confirmReset = false
    @State private var breathe = false
    @FocusState private var passwordFocused: Bool

    @Environment(\.ink) private var ink
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    private var usesPassword: Bool { vm.unlockMode == .password }

    var body: some View {
        ZStack {
            ink.bg.ignoresSafeArea()
            ScrollView {
                VStack(spacing: 0) {
                    InstrumentBrand(trailingLabel: "Vault locked").arrive(0)
                    LockOrbit {
                        InstrumentIcon(name: .lock, size: 42, color: ink.violet)
                    }
                    .padding(.bottom, 22)
                    .arrive(1, distance: 16)
                    VStack(spacing: 0) {
                        MonoLabel("Your private space")
                        Text("Still yours.")
                            .font(InstrumentFont.display(34))
                            .tracking(-1.5)
                            .foregroundColor(ink.text)
                            .padding(.top, 14)
                        FineText(usesPassword
                                 ? "Your vault is locked.\nOpen it with your master password."
                                 : "Your vault is locked.\nOpen it with Face ID or Touch ID.",
                                 alignment: .center)
                            .frame(maxWidth: 240)
                            .padding(.top, 15)
                            .padding(.bottom, 25)
                    }
                    .padding(.top, 22)
                    .arrive(2)

                    if let error = vm.errorMessage {
                        Text(error)
                            .font(InstrumentFont.body(11))
                            .foregroundColor(ink.red)
                            .multilineTextAlignment(.center)
                            .padding(.bottom, 16)
                            .transition(.opacity)
                    }

                    Group {
                        if usesPassword { passwordControls } else { biometricControls }
                    }
                    .arrive(3)

                    FineText("Your keys stay on your devices.", size: 9).padding(.top, 30)
                    Button("Reset this device") { confirmReset = true }
                        .font(InstrumentFont.body(10))
                        .foregroundColor(ink.faint)
                        .padding(.top, 14)
                        .padding(.bottom, 24)
                        .accessibilityIdentifier("unlockResetButton")
                }
                .padding(.horizontal, 20)
                .padding(.top, 10)
            }
            .scrollIndicators(.hidden)
            .scrollDismissesKeyboard(.interactively)
        }
        .animation(.easeOut(duration: 0.2), value: vm.errorMessage)
        .alert("Reset this device?", isPresented: $confirmReset) {
            Button("Reset", role: .destructive) {
                vm.wipe()
                accountVM.signOut()
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("This will erase local vault data on this device. You'll need to re-enroll from another device or your recovery method.")
        }
        .onChange(of: vm.errorMessage) { message in
            if message != nil { UINotificationFeedbackGenerator().notificationOccurred(.error) }
        }
    }

    private var biometricControls: some View {
        VStack(spacing: 0) {
            Button {
                UIImpactFeedbackGenerator(style: .medium).impactOccurred()
                vm.unlock()
            } label: {
                InstrumentIcon(name: .fingerprint, size: 34, color: ink.violet)
                    .frame(width: 72, height: 72)
                    .background(RoundedRectangle(cornerRadius: 25, style: .continuous).fill(ink.panel))
                    .overlay(
                        RoundedRectangle(cornerRadius: 25, style: .continuous)
                            .stroke(ink.violet.opacity(breathe ? 1 : 0.6), lineWidth: 1)
                    )
                    .scaleEffect(breathe ? 1.03 : 1)
                    .contentShape(RoundedRectangle(cornerRadius: 25))
            }
            .buttonStyle(PressScaleStyle())
            .accessibilityLabel("Unlock with Face ID")
            .accessibilityIdentifier("unlockButton")
            .onAppear {
                guard !reduceMotion else { return }
                withAnimation(.easeInOut(duration: 1.8).repeatForever(autoreverses: true)) { breathe = true }
            }
            FineText("Touch to unlock", size: 10).padding(.top, 12)
        }
    }

    private var passwordControls: some View {
        VStack(spacing: 18) {
            VStack(alignment: .leading, spacing: 8) {
                MonoLabel("Master password")
                SecureField("", text: $password)
                    .font(InstrumentFont.body(13))
                    .foregroundColor(ink.text)
                    .tint(ink.violet)
                    .textContentType(.password)
                    .focused($passwordFocused)
                    .padding(.horizontal, 14)
                    .frame(minHeight: 48)
                    .background(RoundedRectangle(cornerRadius: 14).fill(ink.panel))
                    .overlay(RoundedRectangle(cornerRadius: 14).stroke(passwordFocused ? ink.violet : ink.line2, lineWidth: 1))
                    .accessibilityLabel("Master password")
                    .accessibilityIdentifier("unlockPasswordField")
                    .onSubmit(submit)
            }
            InstrumentPill(text: "Unlock vault", icon: .lock, style: .primary, fullWidth: true,
                           enabled: !password.isEmpty, action: submit)
                .accessibilityIdentifier("unlockButton")
        }
    }

    private func submit() {
        guard !password.isEmpty else { return }
        let entered = password
        password = ""
        vm.unlock(password: entered)
    }
}
