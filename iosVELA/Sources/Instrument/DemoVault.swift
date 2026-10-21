#if DEBUG
import Foundation

/// Sample items for `VELA_DEMO=1` CI screenshots, mirroring the prototype's
/// vault (docs/mobile-redesign-instrument.html). Debug builds only.
enum DemoVault {
    static func items() -> [VaultItem] {
        var proton = VaultItem.newLogin(name: "Proton", url: "https://proton.me", username: "alex@example.test",
                                        password: "c7#Vq9!mT2@wLp4z", totp: "JBSWY3DPEHPK3PXP")
        proton.favorite = true

        var github = VaultItem.newLogin(name: "GitHub", url: "https://github.com", username: "alex-demo",
                                        password: "h7$Kp2!qR8vN#x3m", totp: nil)
        github.favorite = true

        // Short and reused on purpose, so the attention card shows.
        let figma = VaultItem.newLogin(name: "Figma", url: "https://figma.com", username: "alex@studio.example",
                                       password: "summer24", totp: nil)

        var visa = VaultItem.newCard(name: "Everyday Visa", number: "4242424242424242", exp: "08/29", cvv: "123",
                                     pin: nil, cardholderName: "Alex Demo", notes: nil)
        visa.favorite = true

        let codes = VaultItem.newNote(name: "Recovery codes",
                                      content: "proton: 4F7K-22QX-9MTR\ngithub: 81c2-55af-0d93")

        var music = VaultItem.newLogin(name: "Music account", url: "https://music.example", username: "alex@example.test",
                                       password: "summer24", totp: nil)
        let old = Date().addingTimeInterval(-400 * 86_400)
        music.createdAt = ISO8601DateFormatter().string(from: old)
        music.updatedAt = music.createdAt

        return [proton, github, figma, visa, codes, music]
    }

    /// Turns on folders/tags and decorates GitHub with richer fields so CI
    /// screenshots exercise the schema-2 screens.
    @MainActor
    static func decorate(_ vm: VaultViewModel) {
        do {
            try vm.enableCollections()
            try vm.mutateOrganization(.createFolder(name: "Work", parentID: nil))
            try vm.mutateOrganization(.createFolder(name: "Personal", parentID: nil))
            try vm.mutateOrganization(.createTag(name: "2FA"))
            try vm.mutateOrganization(.createTag(name: "Shared"))
            guard let work = vm.organization.folders.first(where: { $0.name == "Work" }),
                  let twoFA = vm.organization.tags.first(where: { $0.name == "2FA" }),
                  var github = vm.items.first(where: { $0.name == "GitHub" }) else { return }
            try vm.mutateOrganization(.createFolder(name: "Code", parentID: work.id))
            let code = vm.organization.folders.first(where: { $0.name == "Code" })
            github.folderId = code?.id ?? work.id
            github.tagIds = [twoFA.id]
            var email = CustomFieldDraft(kind: .text)
            email.label = "Recovery email"
            email.text = "alex@example.test"
            var pin = CustomFieldDraft(kind: .concealed)
            pin.label = "Backup PIN"
            pin.text = "4821"
            var sso = CustomFieldDraft(kind: .boolean)
            sso.label = "SSO enforced"
            sso.flag = true
            github.customFields = [email.record, pin.record, sso.record]
            var gist = AdditionalURLDraft()
            gist.url = "https://gist.github.com"
            github.additionalUrls = [gist.record]
            vm.update(github)
            let now = VaultClock.nowISO8601()
            var identity = VaultItem(firstName: "Alex", lastName: "Demo", ssn: "",
                                     item_type: "identity", id: UUID().uuidString, name: "Personal identity",
                                     createdAt: now, updatedAt: now)
            identity.identityDetails = .object([
                "email": .string("alex@example.test"), "company": .string("Example Studio"),
                "addresses": .array([.object([
                    "id": .string(UUID().uuidString.lowercased()), "label": .string("Home"),
                    "line1": .string("10 Example Street"), "city": .string("Paris"),
                    "postalCode": .string("75001"), "countryCode": .string("FR"),
                ])]),
            ])
            vm.add(identity)
        } catch {
            vm.errorMessage = error.localizedDescription
        }
    }
}
#endif
