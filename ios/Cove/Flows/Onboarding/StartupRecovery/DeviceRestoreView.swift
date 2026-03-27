import SwiftUI

@_exported import CoveCore

struct DeviceRestoreView: View {
    let onComplete: () -> Void
    let onError: (String) -> Void

    enum RestorePhase: Equatable {
        case restoring
        case complete(CloudBackupRestoreReport)
        case error(String)

        static func == (lhs: RestorePhase, rhs: RestorePhase) -> Bool {
            switch (lhs, rhs) {
            case (.restoring, .restoring): true
            case (.complete, .complete): true
            case let (.error(a), .error(b)): a == b
            default: false
            }
        }
    }

    @State private var phase: RestorePhase = .restoring
    @State private var backupManager = CloudBackupManager.shared
    @State private var hasStartedRestore = false
    @State private var hasDeliveredCompletion = false
    @State private var timeoutTask: Task<Void, Never>?

    private let restoreTimeout: Duration = .seconds(120)

    private var restoreProgress: CloudBackupRestoreProgress? {
        backupManager.restoreProgress
    }

    private var combinedRestoreProgress: Double {
        guard let restoreProgress else { return 0 }

        switch restoreProgress.stage {
        case .finding:
            return 0

        case .downloading:
            guard let total = restoreProgress.total, total > 0 else { return 0 }
            let totalWork = Double(total) * 2
            return Double(restoreProgress.completed) / totalWork

        case .restoring:
            guard let total = restoreProgress.total, total > 0 else { return 0 }
            let totalWork = Double(total) * 2
            return Double(total + restoreProgress.completed) / totalWork
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            Spacer(minLength: 0)

            heroIcon

            Spacer()
                .frame(height: 44)

            titleContent

            if case .restoring = phase {
                Spacer()
                    .frame(height: 18)

                OnboardingThinProgressBar(progress: combinedRestoreProgress)
            }

            Spacer(minLength: 28)

            bottomContent
        }
        .padding(.horizontal, 28)
        .padding(.top, 18)
        .padding(.bottom, 28)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
        .onboardingRecoveryBackground()
        .task {
            guard !hasStartedRestore else { return }
            startRestore()
        }
        .onDisappear {
            timeoutTask?.cancel()
        }
        .onChange(of: backupManager.status) { _, _ in
            syncPhaseWithManager()
        }
        .onChange(of: backupManager.restoreReport) { _, _ in
            syncPhaseWithManager()
        }
    }

    @ViewBuilder
    private var heroIcon: some View {
        switch phase {
        case .restoring:
            OnboardingStatusHero(
                systemImage: "icloud.and.arrow.down",
                pulse: true,
                iconSize: 22
            )

        case .complete:
            OnboardingStatusHero(
                systemImage: "checkmark",
                tint: .lightGreen,
                fillColor: Color.lightGreen.opacity(0.12),
                iconSize: 26
            )

        case .error:
            ZStack {
                Circle()
                    .fill(Color.red.opacity(0.12))
                    .frame(width: 118, height: 118)

                Circle()
                    .stroke(Color.red.opacity(0.2), lineWidth: 1)
                    .frame(width: 118, height: 118)

                Image(systemName: "exclamationmark.triangle.fill")
                    .font(.system(size: 40, weight: .semibold))
                    .foregroundStyle(.red)
            }
        }
    }

    @ViewBuilder
    private var titleContent: some View {
        switch phase {
        case .restoring:
            VStack(spacing: 10) {
                Text("Restoring from iCloud...")
                    .font(.system(size: 18, weight: .bold, design: .rounded))
                    .foregroundStyle(.white)
                    .multilineTextAlignment(.center)

                Text("This might take a few minutes")
                    .font(.system(size: 14, weight: .medium, design: .rounded))
                    .foregroundStyle(.coveLightGray.opacity(0.7))
                    .multilineTextAlignment(.center)
            }
            .padding(.horizontal, 12)

        case .complete:
            VStack(spacing: 10) {
                Text("You’re all set")
                    .font(.system(size: 18, weight: .bold, design: .rounded))
                    .foregroundStyle(.white)
                    .multilineTextAlignment(.center)

                Text("Your wallets have been restored.")
                    .font(.system(size: 14, weight: .medium, design: .rounded))
                    .foregroundStyle(.coveLightGray.opacity(0.7))
                    .multilineTextAlignment(.center)
            }
            .padding(.horizontal, 12)

        case .error:
            VStack(spacing: 12) {
                Text("Restore Failed")
                    .font(.system(size: 34, weight: .bold, design: .rounded))
                    .foregroundStyle(.white)
                    .multilineTextAlignment(.center)

                Text("Something went wrong while restoring your wallets")
                    .font(.system(size: 18, weight: .medium, design: .rounded))
                    .foregroundStyle(.coveLightGray.opacity(0.76))
                    .multilineTextAlignment(.center)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .padding(.horizontal, 8)
        }
    }

    @ViewBuilder
    private var bottomContent: some View {
        switch phase {
        case .restoring:
            EmptyView()

        case let .complete(report):
            VStack(spacing: 16) {
                if report.walletsFailed > 0 {
                    warningCard(message: "\(report.walletsFailed) wallet(s) could not be restored")
                }

                Button {
                    finishRestore()
                } label: {
                    Text("Done")
                }
                .buttonStyle(OnboardingPrimaryButtonStyle())
            }

        case let .error(message):
            VStack(spacing: 18) {
                warningCard(message: message)

                Button {
                    startRestore()
                } label: {
                    Text("Retry")
                }
                .buttonStyle(OnboardingPrimaryButtonStyle())
            }
        }
    }

    private func warningCard(message: String) -> some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: "exclamationmark.triangle.fill")
                .font(.system(size: 14, weight: .semibold))
                .foregroundStyle(.orange)
                .padding(.top, 2)

            Text(message)
                .font(.system(size: 14, weight: .medium, design: .rounded))
                .foregroundStyle(.orange.opacity(0.92))
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            RoundedRectangle(cornerRadius: 18, style: .continuous)
                .fill(Color.orange.opacity(0.1))
        )
        .overlay(
            RoundedRectangle(cornerRadius: 18, style: .continuous)
                .stroke(Color.orange.opacity(0.3), lineWidth: 1)
        )
    }

    private func startRestore() {
        timeoutTask?.cancel()
        phase = .restoring
        hasStartedRestore = true
        hasDeliveredCompletion = false
        backupManager.dispatch(action: .restoreFromCloudBackup)

        timeoutTask = Task {
            try? await Task.sleep(for: restoreTimeout)
            guard !Task.isCancelled else { return }

            await MainActor.run {
                guard case .restoring = phase else { return }
                phase = .error("Restore timed out. Please try again.")
            }
        }
    }

    private func finishRestore() {
        guard !hasDeliveredCompletion else { return }
        hasDeliveredCompletion = true
        onComplete()
    }

    private func syncPhaseWithManager() {
        switch backupManager.status {
        case let .error(message):
            timeoutTask?.cancel()
            if case .restoring = phase {
                phase = .error(message)
                onError(message)
            }

        case .enabled:
            guard let report = backupManager.restoreReport else { return }
            timeoutTask?.cancel()
            if case .complete = phase { return }
            phase = .complete(report)

        default:
            break
        }
    }
}
