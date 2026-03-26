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
                    if let wallet = manager.app.wallets.first {
                        manager.app.selectWallet(wallet.id)
                    }

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
            CloudCheckView(manager: manager)

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

    let manager: OnboardingManager
    @State private var progress: Double = 0

    var body: some View {
        VStack(spacing: 24) {
            Spacer()

            // decorative icon
            ZStack {
                Circle()
                    .fill(Color.duskBlue.opacity(0.4))
                    .frame(width: 100, height: 100)
                    .shadow(color: Color(red: 0.165, green: 0.353, blue: 0.545).opacity(0.5), radius: 30)

                Circle()
                    .stroke(
                        LinearGradient(
                            colors: [.btnGradientLight, .btnGradientDark],
                            startPoint: .topLeading,
                            endPoint: .bottomTrailing
                        ),
                        lineWidth: 2
                    )
                    .frame(width: 100, height: 100)

                Image(systemName: "magnifyingglass")
                    .font(.system(size: 36, weight: .medium))
                    .foregroundStyle(.white)
            }

            VStack(spacing: 12) {
                Text("Checking for cloud backup...")
                    .font(.title3)
                    .fontWeight(.medium)
                    .foregroundStyle(.white)

                ProgressView()
                    .controlSize(.regular)
                    .tint(.white)

                ProgressView(value: progress)
                    .tint(.white)
                    .frame(width: 200)
                    .opacity(progress > 0 ? 1 : 0)
            }

            Spacer()
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background {
            ZStack {
                Color.midnightBlue

                RadialGradient(
                    stops: [
                        .init(color: Color(red: 0.165, green: 0.353, blue: 0.545).opacity(0.9), location: 0),
                        .init(color: Color(red: 0.118, green: 0.227, blue: 0.361).opacity(0.4), location: 0.45),
                        .init(color: .clear, location: 0.85),
                    ],
                    center: .init(x: 0.35, y: 0.18),
                    startRadius: 0,
                    endRadius: 400
                )

                RadialGradient(
                    stops: [
                        .init(color: Color(red: 0.118, green: 0.290, blue: 0.420).opacity(0.8), location: 0),
                        .init(color: .clear, location: 0.75),
                    ],
                    center: .init(x: 0.75, y: 0.12),
                    startRadius: 0,
                    endRadius: 300
                )
            }
            .ignoresSafeArea()
        }
        .task {
            let hasBackup = await Task.detached(priority: .userInitiated) {
                await Self.checkForCloudBackup { attempt in
                    await MainActor.run {
                        withAnimation(.easeInOut(duration: 0.3)) {
                            progress = Double(attempt) / Double(maxAttempts)
                        }
                    }
                }
            }.value
            manager.dispatch(.cloudCheckComplete(hasBackup: hasBackup))
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
