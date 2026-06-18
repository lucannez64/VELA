import AuthenticationServices
import SwiftUI

/// VELA's AutoFill Credential Provider. iOS hands us the service identifiers
/// (the domain/app the user is filling); we biometric-unlock the shared vault,
/// show matching logins, and return the chosen one as an `ASPasswordCredential`.
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

    // MARK: - UI

    private func present(queries: [String]) {
        let model = CredentialListModel(
            queries: queries,
            onPick: { [weak self] item in
                self?.extensionContext.completeRequest(
                    withSelectedCredential: ASPasswordCredential(user: item.username ?? "", password: item.password ?? "")
                )
            },
            onCancel: { [weak self] in
                self?.extensionContext.cancelRequest(
                    withError: NSError(domain: ASExtensionErrorDomain,
                                       code: ASExtensionError.userCanceled.rawValue)
                )
            }
        )

        let host = UIHostingController(rootView: CredentialListView(model: model))
        addChild(host)
        host.view.frame = view.bounds
        host.view.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        view.addSubview(host.view)
        host.didMove(toParent: self)
    }
}
