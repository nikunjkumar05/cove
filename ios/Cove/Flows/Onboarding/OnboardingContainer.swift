import SwiftUI

@_exported import CoveCore

@Observable
final class OnboardingManager: OnboardingManagerReconciler, @unchecked Sendable {
    let rust: RustOnboardingManager
    let app: AppManager
    var step: OnboardingStep
    var isComplete = false
    var restoreError: String?

    init(app: AppManager) {
        self.app = app
        self.step = app.isTermsAccepted ? .cloudCheck : .terms
        self.rust = RustOnboardingManager()
        self.rust.listenForUpdates(reconciler: self)
    }

    func dispatch(_ action: OnboardingAction) {
        rust.dispatch(action: action)
    }

    func reconcile(message: OnboardingReconcileMessage) {
        DispatchQueue.main.async { [weak self] in
            guard let self else { return }
            switch message {
            case let .stepChanged(newStep):
                self.step = newStep
            case .complete:
                self.isComplete = true
            case let .restoreError(error):
                self.restoreError = error
            }
        }
    }
}

struct OnboardingContainer: View {
    @State var manager: OnboardingManager
    let onComplete: () -> Void

    var body: some View {
        stepView(for: manager.step)
            .onChange(of: manager.isComplete) { _, complete in
                if complete {
                    manager.app.reloadWallets()

                    // auto-select first restored wallet so user lands in it
                    if let wallet = manager.app.wallets.first { manager.app.selectWallet(wallet.id) }

                    onComplete()
                }
            }
    }

    @ViewBuilder
    func stepView(for step: OnboardingStep) -> some View {
        switch step {
        case .terms:
            TermsAndConditionsView {
                manager.app.agreeToTerms()
                manager.dispatch(.acceptTerms)
            }

        case .cloudCheck:
            CloudCheckView { hasBackup in
                manager.dispatch(.cloudCheckComplete(hasBackup: hasBackup))
            }

        case .restoreOffer:
            CloudRestoreOfferView(
                onRestore: {
                    manager.restoreError = nil
                    manager.dispatch(.startRestore)
                },
                onSkip: { manager.dispatch(.skipRestore) },
                errorMessage: manager.restoreError
            )

        case .restoring:
            DeviceRestoreView(
                onComplete: { manager.dispatch(.restoreComplete) },
                onError: { error in manager.dispatch(.restoreFailed(error: error)) }
            )
        }
    }
}

// MARK: - Cloud Check View

private struct CloudCheckView: View {
    private static let retryDelays: [Duration] = [.seconds(1), .seconds(2), .seconds(2), .seconds(3), .seconds(5), .seconds(10)]
    private static var maxAttempts: Int {
        retryDelays.count + 1
    }

    let onCloudCheckComplete: (Bool) -> Void

    var body: some View {
        CloudCheckContent()
            .task {
                let hasBackup = await Task.detached(priority: .userInitiated) {
                    await Self.checkForCloudBackup { _ in }
                }.value
                onCloudCheckComplete(hasBackup)
            }
    }

    private static func checkForCloudBackup(onAttempt: @Sendable (Int) async -> Void) async -> Bool {
        guard FileManager.default.ubiquityIdentityToken != nil else {
            Log.info("[ONBOARDING] iCloud not available")
            return false
        }

        let cloud = CloudStorage(cloudStorage: CloudStorageAccessImpl())
        for attempt in 1 ... maxAttempts {
            await onAttempt(attempt)
            Log.info("[ONBOARDING] calling hasAnyCloudBackup attempt=\(attempt)/\(maxAttempts)")
            let hasBackup = (try? cloud.hasAnyCloudBackup()) == true
            Log.info("[ONBOARDING] hasAnyCloudBackup returned: \(hasBackup) attempt=\(attempt)/\(maxAttempts)")
            if hasBackup { return true }
            guard attempt < maxAttempts else { break }
            try? await Task.sleep(for: retryDelays[attempt - 1])
        }

        return false
    }
}

private struct CloudCheckContent: View {
    var body: some View {
        VStack(spacing: 0) {
            Spacer(minLength: 0)

            OnboardingStatusHero(
                systemImage: "icloud",
                pulse: true,
                iconSize: 22
            )

            Spacer()
                .frame(height: 44)

            VStack(spacing: 10) {
                Text("Looking for iCloud backup...")
                    .font(OnboardingRecoveryTypography.compactTitle)
                    .foregroundStyle(.white)
                    .multilineTextAlignment(.center)

                Text("This only takes a moment")
                    .font(OnboardingRecoveryTypography.body)
                    .foregroundStyle(.coveLightGray.opacity(0.7))
                    .multilineTextAlignment(.center)
            }
            .padding(.horizontal, 24)

            Spacer(minLength: 0)
        }
        .padding(.horizontal, 28)
        .padding(.top, 18)
        .padding(.bottom, 28)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .onboardingRecoveryBackground()
    }
}

#Preview("Cloud Check") {
    CloudCheckContent()
}
