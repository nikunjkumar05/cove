import AuthenticationServices
import CryptoKit

@_exported import CoveCore
import Foundation

final class PasskeyProviderImpl: PasskeyProvider, @unchecked Sendable {
    private func credentialSummary(_ credentialId: Data) -> String {
        let prefix = credentialId.prefix(4).map { String(format: "%02x", $0) }.joined()
        return "len=\(credentialId.count) prefix=\(prefix)"
    }

    func isPrfSupported() -> Bool {
        // PRF is guaranteed on iOS 18.4+ (our minimum deployment target)
        true
    }

    func createPasskey(rpId: String, userId: Data, challenge: Data) throws -> Data {
        precondition(!Thread.isMainThread, "createPasskey must not be called from the main thread")

        let delegate = PasskeyDelegate()
        let controller: ASAuthorizationController

        // setup + performRequests must happen on main (UI requirement)
        controller = DispatchQueue.main.sync {
            let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(
                relyingPartyIdentifier: rpId
            )

            let request = provider.createCredentialRegistrationRequest(
                challenge: challenge,
                name: "Cove Wallet",
                userID: userId
            )
            request.prf = .checkForSupport

            let ctrl = ASAuthorizationController(authorizationRequests: [request])
            ctrl.delegate = delegate
            ctrl.presentationContextProvider = delegate
            ctrl.performRequests()
            return ctrl
        }

        // wait on calling thread (Rust worker) — main is free for delegate callbacks
        _ = controller
        let credential = try delegate.waitForResult()

        guard
            let registration =
            credential as? ASAuthorizationPlatformPublicKeyCredentialRegistration
        else {
            throw PasskeyError.CreationFailed("unexpected credential type")
        }

        guard let prfOutput = registration.prf else {
            Log.warn("[PASSKEY] registration PRF output is nil")
            throw PasskeyError.PrfUnsupportedProvider
        }

        Log.info("[PASSKEY] registration PRF supported: \(prfOutput.isSupported)")

        guard prfOutput.isSupported else {
            Log.warn("[PASSKEY] registration PRF is unsupported by this passkey provider")
            throw PasskeyError.PrfUnsupportedProvider
        }

        return registration.credentialID
    }

    func authenticateWithPrf(
        rpId: String, credentialId: Data, prfSalt: Data, challenge: Data
    ) throws -> Data {
        precondition(
            !Thread.isMainThread,
            "authenticateWithPrf must not be called from the main thread"
        )

        let delegate = PasskeyDelegate()
        let controller: ASAuthorizationController

        controller = DispatchQueue.main.sync {
            let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(
                relyingPartyIdentifier: rpId
            )

            let request = provider.createCredentialAssertionRequest(
                challenge: challenge
            )

            request.allowedCredentials = [
                ASAuthorizationPlatformPublicKeyCredentialDescriptor(
                    credentialID: credentialId
                ),
            ]

            request.prf = .inputValues(.init(saltInput1: prfSalt))

            let ctrl = ASAuthorizationController(authorizationRequests: [request])
            ctrl.delegate = delegate
            ctrl.presentationContextProvider = delegate
            ctrl.performRequests()
            return ctrl
        }

        _ = controller
        let credential = try delegate.waitForResult()

        guard
            let assertion =
            credential as? ASAuthorizationPlatformPublicKeyCredentialAssertion
        else {
            throw PasskeyError.AuthenticationFailed("unexpected credential type")
        }

        if assertion.prf == nil {
            Log.error("[PASSKEY] assertion.prf is nil — authenticator did not return PRF output")
        }

        guard let prfKey = assertion.prf?.first else { throw PasskeyError.AuthenticationFailed("PRF output not available") }

        let prfOutput = prfKey.withUnsafeBytes { Data($0) }

        guard prfOutput.count >= 32 else {
            throw PasskeyError.AuthenticationFailed(
                "PRF output too short: \(prfOutput.count) bytes, need 32"
            )
        }

        return prfOutput.prefix(32)
    }

    func checkPasskeyPresence(rpId: String, credentialId: Data) -> PasskeyCredentialPresence {
        precondition(
            !Thread.isMainThread,
            "checkPasskeyPresence must not be called from the main thread"
        )

        let credentialSummary = credentialSummary(credentialId)
        Log.info("[PASSKEY] presence check start rpId=\(rpId) credential=\(credentialSummary)")

        let delegate = PasskeyExistenceDelegate()
        let controller: ASAuthorizationController

        controller = DispatchQueue.main.sync {
            let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(
                relyingPartyIdentifier: rpId
            )

            let request = provider.createCredentialAssertionRequest(
                challenge: Data(count: 32)
            )

            request.allowedCredentials = [
                ASAuthorizationPlatformPublicKeyCredentialDescriptor(
                    credentialID: credentialId
                ),
            ]

            let ctrl = ASAuthorizationController(authorizationRequests: [request])
            ctrl.delegate = delegate
            ctrl.presentationContextProvider = delegate
            ctrl.performRequests(options: .preferImmediatelyAvailableCredentials)
            return ctrl
        }

        // .notInteractive returns almost instantly when no credential exists.
        // if iOS doesn't respond quickly enough to prove presence or absence,
        // treat the result as indeterminate instead of assuming success.
        let gotResult = delegate.semaphore.wait(timeout: .now() + 1.0)

        if gotResult == .timedOut {
            Log.warn(
                "[PASSKEY] presence check timed out after 1s rpId=\(rpId) credential=\(credentialSummary)"
            )
            DispatchQueue.main.async { controller.cancel() }
            return .indeterminate
        }

        Log.info(
            "[PASSKEY] presence check resolved rpId=\(rpId) credential=\(credentialSummary) presence=\(delegate.presence)"
        )
        return delegate.presence
    }

    func discoverAndAuthenticateWithPrf(
        rpId: String, prfSalt: Data, challenge: Data
    ) throws -> DiscoveredPasskeyResult {
        precondition(
            !Thread.isMainThread,
            "discoverAndAuthenticateWithPrf must not be called from the main thread"
        )

        let delegate = PasskeyDelegate()
        let controller: ASAuthorizationController

        controller = DispatchQueue.main.sync {
            let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(
                relyingPartyIdentifier: rpId
            )

            let request = provider.createCredentialAssertionRequest(
                challenge: challenge
            )

            // no allowedCredentials — discoverable credential
            request.allowedCredentials = []

            request.prf = .inputValues(.init(saltInput1: prfSalt))

            let ctrl = ASAuthorizationController(authorizationRequests: [request])
            ctrl.delegate = delegate
            ctrl.presentationContextProvider = delegate
            ctrl.performRequests()
            return ctrl
        }

        _ = controller
        let credential = try delegate.waitForResult()

        guard
            let assertion =
            credential as? ASAuthorizationPlatformPublicKeyCredentialAssertion
        else {
            throw PasskeyError.NoCredentialFound
        }

        guard let prfKey = assertion.prf?.first else { throw PasskeyError.AuthenticationFailed("PRF output not available") }

        let prfOutput = prfKey.withUnsafeBytes { Data($0) }

        guard prfOutput.count >= 32 else {
            throw PasskeyError.AuthenticationFailed(
                "PRF output too short: \(prfOutput.count) bytes, need 32"
            )
        }

        return DiscoveredPasskeyResult(
            prfOutput: prfOutput.prefix(32),
            credentialId: assertion.credentialID
        )
    }
}

// MARK: - PasskeyDelegate

private class PasskeyDelegate: NSObject, ASAuthorizationControllerDelegate,
    ASAuthorizationControllerPresentationContextProviding
{
    private let semaphore = DispatchSemaphore(value: 0)
    private var result: Result<ASAuthorizationCredential, Error>?

    func waitForResult() throws -> ASAuthorizationCredential {
        let status = semaphore.wait(timeout: .now() + 120)
        if status == .timedOut { throw PasskeyError.AuthenticationFailed("passkey operation timed out after 120s") }
        guard let result else { throw PasskeyError.AuthenticationFailed("no result received from delegate") }
        return try result.get()
    }

    func presentationAnchor(for _: ASAuthorizationController) -> ASPresentationAnchor {
        let scenes = UIApplication.shared.connectedScenes
        let windowScene = scenes.first as? UIWindowScene
        return windowScene?.keyWindow ?? ASPresentationAnchor()
    }

    func authorizationController(
        controller _: ASAuthorizationController,
        didCompleteWithAuthorization authorization: ASAuthorization
    ) {
        result = .success(authorization.credential)
        semaphore.signal()
    }

    func authorizationController(
        controller _: ASAuthorizationController,
        didCompleteWithError error: Error
    ) {
        if let authError = error as? ASAuthorizationError {
            switch authError.code {
            case .canceled:
                result = .failure(PasskeyError.UserCancelled)
            default:
                result = .failure(
                    PasskeyError.AuthenticationFailed(error.localizedDescription)
                )
            }
        } else {
            result = .failure(
                PasskeyError.AuthenticationFailed(error.localizedDescription)
            )
        }
        semaphore.signal()
    }
}

// MARK: - PasskeyExistenceDelegate

/// Lightweight delegate for non-interactive passkey existence checks
///
/// Only cares about whether the credential exists, not the actual assertion.
/// `.notInteractive` means no matching credential and no UI was shown
private class PasskeyExistenceDelegate: NSObject, ASAuthorizationControllerDelegate,
    ASAuthorizationControllerPresentationContextProviding
{
    let semaphore = DispatchSemaphore(value: 0)
    var presence: PasskeyCredentialPresence = .indeterminate
    private var didRequestPresentationAnchor = false

    func presentationAnchor(for _: ASAuthorizationController) -> ASPresentationAnchor {
        didRequestPresentationAnchor = true
        let scenes = UIApplication.shared.connectedScenes
        let windowScene = scenes.first as? UIWindowScene
        return windowScene?.keyWindow ?? ASPresentationAnchor()
    }

    func authorizationController(
        controller _: ASAuthorizationController,
        didCompleteWithAuthorization _: ASAuthorization
    ) {
        presence = .present
        Log.info("[PASSKEY] presence check authorization succeeded")
        semaphore.signal()
    }

    func authorizationController(
        controller _: ASAuthorizationController,
        didCompleteWithError error: Error
    ) {
        if let authError = error as? ASAuthorizationError {
            if authError.code == .notInteractive {
                presence = .missing
                Log.info(
                    "[PASSKEY] presence check classified missing code=\(authError.code.rawValue) requested_ui=\(didRequestPresentationAnchor) description=\(error.localizedDescription)"
                )
            } else if authError.code == .canceled, !didRequestPresentationAnchor {
                presence = .missing
                Log.info(
                    "[PASSKEY] presence check classified missing after silent cancellation code=\(authError.code.rawValue) requested_ui=\(didRequestPresentationAnchor) description=\(error.localizedDescription)"
                )
            } else {
                Log.warn(
                    "[PASSKEY] presence check failed with auth error code=\(authError.code.rawValue) requested_ui=\(didRequestPresentationAnchor) description=\(error.localizedDescription)"
                )
            }
        } else {
            Log.warn("[PASSKEY] presence check failed with non-auth error: \(error.localizedDescription)")
        }
        semaphore.signal()
    }
}
