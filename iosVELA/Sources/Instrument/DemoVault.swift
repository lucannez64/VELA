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
}
#endif
