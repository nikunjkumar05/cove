import SwiftUI

struct CloudBackupDetailScreen: View {
    @State private var manager = CloudBackupDetailManager()
    @State private var syncHealth: ICloudDriveHelper.SyncHealth = .noFiles
    @State private var showRecreateConfirmation = false
    @State private var showReinitializeConfirmation = false

    private var isVerifying: Bool {
        if case .verifying = manager.verification { return true }
        return false
    }

    private var hasVerificationResult: Bool {
        switch manager.verification {
        case .verified, .failed, .cancelled: true
        default: false
        }
    }

    private var isCancelled: Bool {
        if case .cancelled = manager.verification { return true }
        return false
    }

    var body: some View {
        Form {
            if isVerifying, !hasVerificationResult {
                Section {
                    VStack {
                        ProgressView("Verifying cloud backup...")
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 8)
                }
            } else if let detail = manager.detail, !isCancelled {
                DetailFormContent(
                    detail: detail,
                    syncHealth: syncHealth,
                    manager: manager
                )
            }

            VerificationSection(
                manager: manager,
                onRecreate: { showRecreateConfirmation = true },
                onReinitialize: { showReinitializeConfirmation = true }
            )
        }
        .navigationTitle("Cloud Backup")
        .navigationBarTitleDisplayMode(.inline)
        .task {
            refreshSyncHealth()
            manager.dispatch(.refreshDetail)
        }
        .onChange(of: manager.detail) { _, _ in
            refreshSyncHealth()
        }
        .onChange(of: manager.verification) { _, _ in
            refreshSyncHealth()
        }
        .confirmationDialog(
            "Recreate Backup Index",
            isPresented: $showRecreateConfirmation,
            titleVisibility: .visible
        ) {
            Button("Recreate", role: .destructive) {
                manager.dispatch(.recreateManifest)
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text(
                "This will rebuild the backup index from wallets on this device. Wallets that only exist in the cloud backup will no longer be referenced."
            )
        }
        .confirmationDialog(
            "Reinitialize Cloud Backup",
            isPresented: $showReinitializeConfirmation,
            titleVisibility: .visible
        ) {
            Button("Reinitialize", role: .destructive) {
                manager.dispatch(.reinitializeBackup)
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text(
                "This will replace your entire cloud backup. Wallets that only exist in the current cloud backup will be lost."
            )
        }
    }

    private func refreshSyncHealth() {
        syncHealth = ICloudDriveHelper.shared.overallSyncHealth()
    }
}
