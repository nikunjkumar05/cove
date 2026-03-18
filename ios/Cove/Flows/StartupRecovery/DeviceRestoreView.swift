import SwiftUI

@_exported import CoveCore

struct DeviceRestoreView: View {
    let onComplete: () -> Void
    let onError: (String) -> Void

    enum RestorePhase {
        case wiping
        case bootstrapping
        case restoring
        case complete(CloudBackupRestoreReport)
        case error(String)
    }

    @State private var phase: RestorePhase = .wiping
    @State private var progress: (completed: UInt32, total: UInt32)?
    private let backupManager = CloudBackupManager.shared

    var body: some View {
        VStack(spacing: 24) {
            Spacer()

            Image(systemName: "icloud.and.arrow.down")
                .font(.system(size: 64))
                .foregroundStyle(.blue)

            Text("Restoring from Cloud")
                .font(.title)
                .fontWeight(.bold)

            phaseContent

            Spacer()
        }
        .padding()
        .task {
            await runRestore()
        }
    }

    @ViewBuilder
    private var phaseContent: some View {
        switch phase {
        case .wiping:
            VStack(spacing: 12) {
                ProgressView()
                Text("Preparing...")
                    .foregroundStyle(.secondary)
            }

        case .bootstrapping:
            VStack(spacing: 12) {
                ProgressView()
                Text("Initializing...")
                    .foregroundStyle(.secondary)
            }

        case .restoring:
            VStack(spacing: 12) {
                if let progress {
                    ProgressView(
                        value: Double(progress.completed),
                        total: Double(max(progress.total, 1))
                    )
                    .padding(.horizontal, 40)

                    Text("Restoring wallets (\(progress.completed)/\(progress.total))")
                        .foregroundStyle(.secondary)
                } else {
                    ProgressView()
                    Text("Restoring wallets...")
                        .foregroundStyle(.secondary)
                }
            }

        case let .complete(report):
            VStack(spacing: 12) {
                Image(systemName: "checkmark.circle.fill")
                    .font(.system(size: 32))
                    .foregroundStyle(.green)

                Text("Restored \(report.walletsRestored) wallet(s)")
                    .foregroundStyle(.secondary)

                if report.walletsFailed > 0 {
                    Text("\(report.walletsFailed) wallet(s) could not be restored")
                        .font(.caption)
                        .foregroundStyle(.orange)
                }
            }

        case let .error(message):
            VStack(spacing: 16) {
                Image(systemName: "exclamationmark.triangle.fill")
                    .font(.system(size: 32))
                    .foregroundStyle(.red)

                Text(message)
                    .multilineTextAlignment(.center)
                    .foregroundStyle(.secondary)
                    .padding(.horizontal, 32)

                Button {
                    phase = .wiping
                    Task { await runRestore() }
                } label: {
                    Text("Retry")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
            }
        }
    }

    private func runRestore() async {
        // clear stale state from any prior attempt
        await MainActor.run {
            backupManager.progress = nil
            backupManager.restoreReport = nil
        }

        // step 1: wipe local data
        phase = .wiping
        wipeLocalData()

        // step 2: re-bootstrap
        phase = .bootstrapping
        resetBootstrapForRestore()
        do {
            _ = try await bootstrapWithTimeout()
        } catch {
            phase = .error("Bootstrap failed: \(error.localizedDescription)")
            return
        }

        // step 3: kick off cloud restore
        phase = .restoring
        backupManager.rust.restoreFromCloudBackup()

        // step 4: observe state changes until we reach enabled or error
        await observeRestoreCompletion()
    }

    private func bootstrapWithTimeout() async throws -> String? {
        try await withThrowingTaskGroup(of: BootstrapResult.self) { group in
            group.addTask { try await .completed(warning: bootstrap()) }
            group.addTask { try await self.watchdog() }

            guard let result = try await group.next() else {
                throw RestoreError.timeout
            }
            group.cancelAll()

            switch result {
            case let .completed(warning): return warning
            case .timedOut: throw RestoreError.timeout
            }
        }
    }

    private func watchdog() async throws -> BootstrapResult {
        try await Task.sleep(for: .seconds(15))
        cancelBootstrap()
        return .timedOut
    }

    private func observeRestoreCompletion() async {
        // poll state at 100ms intervals
        while !Task.isCancelled {
            try? await Task.sleep(for: .milliseconds(100))

            let currentState = backupManager.state
            let currentProgress = backupManager.progress
            let report = backupManager.restoreReport

            await MainActor.run {
                self.progress = currentProgress
            }

            switch currentState {
            case .enabled:
                if let report {
                    phase = .complete(report)
                    try? await Task.sleep(for: .seconds(1))
                    onComplete()
                    return
                }

            case let .error(msg):
                phase = .error(msg)
                onError(msg)
                return

            case .disabled:
                // restore failed and state was reset
                if report != nil {
                    phase = .error("Restore failed — all wallets could not be recovered")
                    return
                }

            default:
                continue
            }
        }
    }
}

private enum BootstrapResult {
    case completed(warning: String?)
    case timedOut
}

private enum RestoreError: LocalizedError {
    case timeout

    var errorDescription: String? {
        switch self {
        case .timeout:
            "Bootstrap timed out during restore"
        }
    }
}
