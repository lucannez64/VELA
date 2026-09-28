import AuthenticationServices
import SwiftUI

/// VELA's AutoFill Credential Provider. iOS hands us the service identifiers
/// (the domain/app the user is filling); we biometric-unlock the shared vault,
/// show matching logins, and return the chosen one as an `ASPasswordCredential`.
///
/// iOS 18 also lets a provider insert arbitrary text into a field
/// (`prepareInterfaceForUserChoosingTextToInsert`), which is the only supported
/// way to offer a credit card: the system inserts one value at a time, so a
/// posted card is presented as its number, expiry, CVV and cardholder
/// separately. The extension declares `ProvidesTextToInsert` in `project.yml`.
final class CredentialProviderViewController: ASCredentialProviderViewController {

    // MARK: AutoFill entry points

    /// Show the list of credentials that match `serviceIdentifiers`.
    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        present(queries: serviceIdentifiers.map { $0.identifier })
    }

    /// Try to provide a credential without UI. We always require a biometric
    /// unlock first, so ask iOS to show our interface instead.
    override func provideCredentialWithoutUserInteraction(for credentialIdentity: ASPasswordCredentialIdentity) {
        extensionContext.cancelRequest(
            withError: NSError(domain: ASExtensionErrorDomain,
                               code: ASExtensionError.userInteractionRequired.rawValue)
        )
    }

    /// User tapped a specific suggestion: unlock and offer just that service.
    override func prepareInterfaceToProvideCredential(for credentialIdentity: ASPasswordCredentialIdentity) {
        present(queries: [credentialIdentity.serviceIdentifier.identifier])
    }

    /// iOS 18+: the user chose "insert text". Offer every stored card's
    /// insertable values; the system inserts the one they pick.
    @available(iOS 18.0, *)
    override func prepareInterfaceForUserChoosingTextToInsert() {
        presentInsertables()
    }

    // MARK: - UI

    private func present(queries: [String]) {
        let model = CredentialListModel(
            queries: queries,
            onPick: { [weak self] item in
                self?.extensionContext.completeRequest(
                    withSelectedCredential: ASPasswordCredential(user: item.username ?? "", password: item.password ?? "")
                )
            },
            onCancel: { [weak self] in self?.cancel() }
        )
        presentView(model)
    }

    @available(iOS 18.0, *)
    private func presentInsertables() {
        let model = CredentialListModel(
            queries: [],
            textInsertMode: true,
            onInsert: { [weak self] text in
                self?.extensionContext.completeRequest(withTextToInsert: text, completionHandler: nil)
            },
            onCancel: { [weak self] in self?.cancel() }
        )
        presentView(model)
    }

    private func cancel() {
        extensionContext.cancelRequest(
            withError: NSError(domain: ASExtensionErrorDomain,
                               code: ASExtensionError.userCanceled.rawValue)
        )
    }

    private func presentView(_ model: CredentialListModel) {
        let host = UIHostingController(rootView: CredentialListView(model: model))
        addChild(host)
        host.view.frame = view.bounds
        host.view.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        view.addSubview(host.view)
        host.didMove(toParent: self)
    }
}
