import SwiftUI
import UIKit

/// Item details in the Instrument layout: centred back header, large glyph
/// with favourite toggle, one bordered card per field (each with copy), a
/// dot-matrix authenticator with a countdown ring, card art, Edit / Share,
/// and a deliberate two-step delete.
struct ItemDetailScreen: View {
    @ObservedObject var vm: VaultViewModel
    let itemID: String
    var onShare: (() -> Void)? = nil

    @EnvironmentObject private var toast: ToastCenter
    @Environment(\.ink) private var ink
    @Environment(\.dismiss) private var dismiss

    @State private var revealed = false
    @State private var editing = false
    @State private var confirmDelete = false
    @State private var favoritePop = false
    @State private var revealedFields: Set<String> = []

    private var item: VaultItem? { vm.items.first { $0.id == itemID } }

    var body: some View {
        ZStack {
            ink.bg.ignoresSafeArea()
            if let item {
                content(item)
            } else {
                FineText("This item was removed.", size: 13)
            }
        }
        .toolbar(.hidden, for: .navigationBar)
        .sheet(isPresented: $editing) {
            if let item { AddEditItemView(vm: vm, editing: item) }
        }
        .sheet(isPresented: $confirmDelete) {
            if let item {
                DeleteSheet(name: item.name, onDelete: {
                    confirmDelete = false
                    UINotificationFeedbackGenerator().notificationOccurred(.warning)
                    // Let the sheet finish closing before popping the detail.
                    DispatchQueue.main.asyncAfter(deadline: .now() + 0.35) {
                        dismiss()
                        vm.delete(item)
                        toast.show("\(item.name) deleted.")
                    }
                }, onKeep: { confirmDelete = false })
                .presentationDetents([.height(300)])
                .environment(\.ink, ink)
            }
        }
    }

    private func content(_ item: VaultItem) -> some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                BackHead(title: "Vault / \(item.kindLabel)") { dismiss() }.arrive(0)
                header(item).padding(.top, 12).padding(.bottom, 22).arrive(1)
                fields(item).arrive(2)
                richDetails(item).arrive(3)
                HStack(spacing: 9) {
                    InstrumentPill(text: "Edit item", icon: .pen, fullWidth: true) { editing = true }
                        .accessibilityIdentifier("editButton")
                    if let onShare, !item.shared {
                        InstrumentPill(text: "Share item", icon: .share, style: .primary, fullWidth: true, action: onShare)
                            .accessibilityIdentifier("shareItemButton")
                    }
                }
                .padding(.vertical, 20)
                .arrive(3)
                Button { confirmDelete = true } label: {
                    HStack(spacing: 8) {
                        InstrumentIcon(name: .trash, size: 15, color: ink.red)
                        Text("Delete item").font(InstrumentFont.body(12)).foregroundColor(ink.red)
                    }
                    .frame(maxWidth: .infinity, minHeight: 44)
                    .overlay(Capsule().stroke(ink.red.opacity(0.3), lineWidth: 1))
                    .contentShape(Capsule())
                }
                .buttonStyle(PressScaleStyle())
                .accessibilityIdentifier("deleteButton")
                .arrive(4)
                MonoLabel("Encrypted · Only you hold the keys", size: 8)
                    .frame(maxWidth: .infinity)
                    .padding(.top, 14)
            }
            .padding(.horizontal, 20)
            .padding(.top, 10)
            .padding(.bottom, 24)
        }
        .scrollIndicators(.hidden)
    }

    private func header(_ item: VaultItem) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                InstrumentAvatar(icon: item.glyph, large: true)
                Spacer()
                InstrumentIconButton(icon: .star, label: item.favorite ? "Remove from favourites" : "Add to favourites",
                                     tint: item.favorite ? ink.lime : ink.text) {
                    toggleFavorite(item)
                }
                .scaleEffect(favoritePop ? 1.18 : 1)
                .accessibilityIdentifier("favoriteButton")
            }
            Text(item.name)
                .font(InstrumentFont.display(27))
                .tracking(-1.2)
                .foregroundColor(ink.text)
                .lineLimit(2)
                .padding(.top, 16)
            FineText("\(siteOrKind(item)) · Updated \(relativeAge(item.updatedDate))").padding(.top, 7)
        }
    }

    @ViewBuilder private func fields(_ item: VaultItem) -> some View {
        VStack(spacing: 0) {
            switch item.kind {
            case .login:
                if let username = item.username, !username.isEmpty {
                    InstrumentField(label: "Username", value: username, onCopy: { copy("Username", username) })
                }
                if let password = item.password, !password.isEmpty {
                    InstrumentField(label: "Password", value: password, secret: true, revealed: revealed,
                                    onReveal: { withAnimation(.instrument(0.25)) { revealed.toggle() } },
                                    revealID: "revealButton", onCopy: { copy("Password", password) })
                }
                if let secret = item.totp, !secret.isEmpty {
                    TotpField(secret: secret) { code in copy("Authenticator code", code) }
                }
                if let url = item.url, !url.isEmpty {
                    InstrumentField(label: "Website", value: url.displayHost, onCopy: { copy("Website", url) })
                }
            case .creditCard:
                let digits = (item.number ?? "").filter(\.isNumber)
                let grouped = stride(from: 0, to: digits.count, by: 4).map { i -> String in
                    let start = digits.index(digits.startIndex, offsetBy: i)
                    let end = digits.index(start, offsetBy: min(4, digits.count - i))
                    return String(digits[start..<end])
                }.joined(separator: " ")
                CardArt(label: "\(item.name) / \(cardBrand(digits))",
                        number: revealed ? grouped : "•••• •••• •••• \(digits.suffix(4))",
                        holder: item.cardholderName ?? "Cardholder",
                        expiry: (item.exp ?? "").replacingOccurrences(of: "/", with: " / "))
                    .animation(.instrument(0.3), value: revealed)
                if !digits.isEmpty {
                    InstrumentField(label: "Card number", value: grouped, secret: true, revealed: revealed,
                                    onReveal: { withAnimation(.instrument(0.25)) { revealed.toggle() } },
                                    revealID: "revealButton", onCopy: { copy("Card number", digits) })
                }
                if let holder = item.cardholderName, !holder.isEmpty {
                    InstrumentField(label: "Cardholder", value: holder, onCopy: { copy("Cardholder", holder) })
                }
                if let exp = item.exp, !exp.isEmpty {
                    InstrumentField(label: "Expires", value: exp, mono: true, onCopy: { copy("Expiry", exp) })
                }
                if let cvv = item.cvv, !cvv.isEmpty {
                    InstrumentField(label: "Security code", value: cvv, secret: true, revealed: revealed,
                                    onReveal: { revealed.toggle() }, onCopy: { copy("Security code", cvv) })
                }
                if let pin = item.pin, !pin.isEmpty {
                    InstrumentField(label: "PIN", value: pin, secret: true, revealed: revealed,
                                    onReveal: { revealed.toggle() }, onCopy: { copy("PIN", pin) })
                }
            case .secureNote:
                InstrumentField(label: "Note", value: item.content ?? "", copyID: "copyNoteButton", onCopy: { copy("Note", item.content ?? "") })
            default:
                if let email = item.email { InstrumentField(label: "Email", value: email, onCopy: { copy("Email", email) }) }
                if let filename = item.filename { InstrumentField(label: "File", value: filename) }
            }
            if let notes = item.notes, !notes.isEmpty, item.kind != .secureNote {
                InstrumentField(label: "Notes", value: notes, onCopy: { copy("Notes", notes) })
            }
        }
    }

    /// Folder and tags, custom fields and other websites (schema 2).
    @ViewBuilder private func richDetails(_ item: VaultItem) -> some View {
        let org = vm.organization
        let folder = org.path(of: item.folderId)
        let tags = (item.tagIds ?? []).compactMap { org.tagName($0) }
        VStack(alignment: .leading, spacing: 0) {
            if !folder.isEmpty || !tags.isEmpty {
                VStack(alignment: .leading, spacing: 10) {
                    MonoLabel("Organised", color: ink.faint, size: 8)
                    if !folder.isEmpty {
                        HStack(spacing: 8) {
                            InstrumentIcon(name: .vault, size: 15, color: ink.violet)
                            Text(folder).font(InstrumentFont.body(13)).foregroundColor(ink.text)
                        }
                    }
                    if !tags.isEmpty {
                        HStack(spacing: 6) {
                            ForEach(tags, id: \.self) { tag in InstrumentTag(text: "# \(tag)") }
                        }
                    }
                }
                .padding(.horizontal, 15)
                .padding(.vertical, 14)
                .frame(maxWidth: .infinity, alignment: .leading)
                .instrumentPanel(radius: 17, border: ink.line, fill: ink.panel)
                .padding(.bottom, 9)
                .accessibilityIdentifier("organisedCard")
            }
            ForEach(item.customFieldDrafts) { field in
                if field.kind == .concealed {
                    InstrumentField(label: field.label, value: field.text, secret: true,
                                    revealed: revealedFields.contains(field.id),
                                    onReveal: { toggleReveal(field.id) },
                                    onCopy: { copy(field.label, field.text) })
                } else if field.kind == .text {
                    InstrumentField(label: field.label, value: field.text, onCopy: { copy(field.label, field.text) })
                } else {
                    InstrumentField(label: field.label, value: field.displayValue)
                }
            }
            ForEach(item.additionalURLDrafts) { entry in
                InstrumentField(label: "Also on · \(entry.mode?.title ?? "custom rule")", value: entry.url.displayHost,
                                onCopy: { copy("Website", entry.url) })
            }
        }
    }

    private func toggleReveal(_ id: String) {
        withAnimation(.instrument(0.25)) {
            if revealedFields.contains(id) { revealedFields.remove(id) } else { revealedFields.insert(id) }
        }
    }

    private func copy(_ label: String, _ value: String) {
        Clipboard.copySecurely(value)
        UINotificationFeedbackGenerator().notificationOccurred(.success)
        toast.show("\(label) copied. Clears in 20 seconds.")
    }

    private func toggleFavorite(_ item: VaultItem) {
        var updated = item
        updated.favorite.toggle()
        UIImpactFeedbackGenerator(style: .light).impactOccurred()
        withAnimation(.spring(response: 0.25, dampingFraction: 0.45)) { favoritePop = true }
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.18) {
            withAnimation(.spring(response: 0.3, dampingFraction: 0.6)) { favoritePop = false }
        }
        vm.update(updated)
    }

    private func siteOrKind(_ item: VaultItem) -> String {
        if item.kind == .login, let url = item.url, !url.displayHost.isEmpty { return url.displayHost }
        return item.kindLabel
    }

    private func cardBrand(_ digits: String) -> String {
        if digits.hasPrefix("4") { return "Visa" }
        if let two = Int(digits.prefix(2)), (51...55).contains(two) || (22...27).contains(two) { return "Mastercard" }
        if digits.hasPrefix("34") || digits.hasPrefix("37") { return "Amex" }
        return "Card"
    }
}

func relativeAge(_ date: Date?) -> String {
    guard let date else { return "recently" }
    let days = Int(Date().timeIntervalSince(date) / 86_400)
    switch days {
    case ..<1: return "today"
    case 1: return "yesterday"
    case 2..<30: return "\(days) days ago"
    case 30..<365: return days / 30 == 1 ? "1 month ago" : "\(days / 30) months ago"
    default: return days / 365 == 1 ? "1 year ago" : "\(days / 365) years ago"
    }
}

/// One bordered field card: mono label, value, optional reveal + copy.
struct InstrumentField: View {
    let label: String
    let value: String
    var secret: Bool = false
    var revealed: Bool = true
    var onReveal: (() -> Void)? = nil
    var mono: Bool = false
    var revealID: String? = nil
    var copyID: String? = nil
    var onCopy: (() -> Void)? = nil

    @Environment(\.ink) private var ink

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            MonoLabel(label, color: ink.faint, size: 8)
            HStack(spacing: 0) {
                Text(secret && !revealed ? String(repeating: "•", count: min(max(value.count, 8), 14)) : value)
                    .font(secret || mono ? InstrumentFont.mono(12) : InstrumentFont.body(13))
                    .foregroundColor(ink.text)
                    .lineSpacing(4)
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.top, 9)
                    .id(revealed)
                    .transition(.opacity)
                if secret, let onReveal {
                    InstrumentIconButton(icon: revealed ? .eyeoff : .eye, label: revealed ? "Hide \(label)" : "Reveal \(label)",
                                         size: 38, bordered: false, tint: ink.muted, action: onReveal)
                        .accessibilityIdentifier(revealID ?? "reveal-\(label)")
                }
                if let onCopy {
                    InstrumentIconButton(icon: .copy, label: "Copy \(label.lowercased())", size: 38, iconSize: 17,
                                         bordered: false, tint: ink.muted, action: onCopy)
                        .accessibilityIdentifier(copyID ?? "copy-\(label)")
                }
            }
        }
        .padding(.horizontal, 15)
        .padding(.vertical, 14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .instrumentPanel(radius: 17, border: ink.line, fill: ink.panel)
        .padding(.bottom, 9)
    }
}

/// Authenticator field: dot readout, smooth countdown ring, copy.
struct TotpField: View {
    let secret: String
    let onCopy: (String) -> Void

    @Environment(\.ink) private var ink

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            MonoLabel("Authenticator", color: ink.faint, size: 8)
            if let totp = TOTP(string: secret) {
                TimelineView(.periodic(from: .now, by: 1)) { context in
                    let code = totp.code(at: context.date)
                    let left = totp.secondsRemaining(at: context.date)
                    HStack(spacing: 10) {
                        DotMatrix(value: code, pitch: 3.8)
                        Spacer(minLength: 0)
                        CountdownRing(secondsLeft: left, period: totp.period)
                        InstrumentIconButton(icon: .copy, label: "Copy authenticator code", iconSize: 17,
                                             bordered: false, tint: ink.muted) { onCopy(code) }
                            .accessibilityIdentifier("copyTotpButton")
                    }
                    .padding(.top, 15)
                }
            } else {
                FineText("This setup key isn't valid.", size: 12).padding(.top, 15)
            }
        }
        .padding(.horizontal, 15)
        .padding(.vertical, 14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .instrumentPanel(radius: 17, border: ink.line, fill: ink.panel)
        .padding(.bottom, 9)
    }
}

/// Ring that drains with the code's lifetime and turns red near the end.
struct CountdownRing: View {
    let secondsLeft: Int
    let period: Int

    @Environment(\.ink) private var ink

    var body: some View {
        let fraction = CGFloat(secondsLeft) / CGFloat(max(period, 1))
        ZStack {
            Circle().stroke(ink.line2, lineWidth: 2)
            Circle()
                .trim(from: 0, to: fraction)
                .stroke(secondsLeft <= 5 ? ink.red : ink.violet, style: StrokeStyle(lineWidth: 2, lineCap: .round))
                .rotationEffect(.degrees(-90))
                .animation(fraction > 0.97 ? nil : .linear(duration: 1), value: fraction)
            Text("\(secondsLeft)").font(InstrumentFont.mono(9)).foregroundColor(ink.muted)
        }
        .frame(width: 30, height: 30)
        .padding(2)
        .accessibilityLabel("\(secondsLeft) seconds left")
    }
}

/// Payment card art: violet bloom from the top right on deep ink.
struct CardArt: View {
    let label: String
    let number: String
    let holder: String
    let expiry: String

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                MonoLabel(label, color: Color(hex: 0xA9A0BC))
                Spacer()
                InstrumentIcon(name: .card, size: 22, color: Color(hex: 0xF3F2EF))
            }
            Text(number)
                .font(InstrumentFont.mono(17))
                .tracking(0.85)
                .foregroundColor(Color(hex: 0xF3F2EF))
                .padding(.top, 28)
                .padding(.bottom, 22)
                .contentTransition(.opacity)
            HStack {
                Text(holder.uppercased()).font(InstrumentFont.body(11)).foregroundColor(Color(hex: 0xC4BDD1)).lineLimit(1)
                Spacer()
                MonoLabel(expiry, color: Color(hex: 0xA9A0BC))
            }
        }
        .padding(22)
        .frame(maxWidth: .infinity, minHeight: 185, alignment: .topLeading)
        .background(
            GeometryReader { geo in
                ZStack {
                    Color(hex: 0x181620)
                    RadialGradient(colors: [Color(rgba: 0x8A68CE65), Color(rgba: 0x8A68CE00)],
                                   center: .topTrailing, startRadius: 0, endRadius: geo.size.width * 1.1)
                }
            }
        )
        .clipShape(RoundedRectangle(cornerRadius: 22, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 22, style: .continuous).stroke(Color(rgba: 0xB99FFF30), lineWidth: 1))
        .padding(.top, 10)
        .padding(.bottom, 20)
    }
}

private struct DeleteSheet: View {
    let name: String
    let onDelete: () -> Void
    let onKeep: () -> Void

    @Environment(\.ink) private var ink

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Capsule().fill(ink.faint.opacity(0.5)).frame(width: 32, height: 4).frame(maxWidth: .infinity).padding(.bottom, 14)
            Text("Delete \(name)?")
                .font(InstrumentFont.display(22))
                .tracking(-0.6)
                .foregroundColor(ink.text)
                .padding(.bottom, 10)
            FineText("This permanently removes the item from your vault.")
            Button(action: onDelete) {
                HStack(spacing: 8) {
                    InstrumentIcon(name: .trash, size: 15, color: .white)
                    Text("Delete item permanently").font(InstrumentFont.body(12)).foregroundColor(.white)
                }
                .frame(maxWidth: .infinity, minHeight: 44)
                .background(Capsule().fill(ink.red))
                .contentShape(Capsule())
            }
            .buttonStyle(PressScaleStyle())
            .accessibilityIdentifier("confirmDeleteButton")
            .padding(.top, 20)
            InstrumentPill(text: "Keep item", fullWidth: true, action: onKeep).padding(.top, 10)
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 20)
        .padding(.top, 10)
        .background(ink.bg.ignoresSafeArea())
    }
}

/// Keeps the edge-swipe back gesture with the navigation bar hidden.
extension UINavigationController: UIGestureRecognizerDelegate {
    override open func viewDidLoad() {
        super.viewDidLoad()
        interactivePopGestureRecognizer?.delegate = self
    }

    public func gestureRecognizerShouldBegin(_ gestureRecognizer: UIGestureRecognizer) -> Bool {
        viewControllers.count > 1
    }
}
