import SwiftUI

@_exported import CoveCore

struct CatastrophicErrorView: View {
    let onRestoreFromCloud: () -> Void
    let onWipeOnly: () -> Void

    enum CloudProbeState {
        case checking
        case available
        case unavailable
        case transientError
        case corrupt
    }

    @State private var cloudProbeState: CloudProbeState = .checking
    @State private var showWipeConfirmation = false

    var body: some View {
        VStack(spacing: 24) {
            Spacer()

            Image(systemName: "exclamationmark.triangle.fill")
                .font(.system(size: 64))
                .foregroundStyle(.red)

            Text("Encryption Key Error")
                .font(.title)
                .fontWeight(.bold)

            Text(
                "Your app's encryption key doesn't match the stored data. This is an unexpected error that shouldn't normally occur."
            )
            .multilineTextAlignment(.center)
            .foregroundStyle(.secondary)
            .padding(.horizontal, 32)

            cloudProbeContent

            Spacer()

            VStack(spacing: 16) {
                if case .available = cloudProbeState {
                    Button {
                        onRestoreFromCloud()
                    } label: {
                        HStack {
                            Image(systemName: "icloud.and.arrow.down")
                            Text("Restore from Cloud Backup")
                        }
                        .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.borderedProminent)
                }

                if case .transientError = cloudProbeState {
                    Button {
                        onRestoreFromCloud()
                    } label: {
                        HStack {
                            Image(systemName: "icloud.and.arrow.down")
                            Text("Restore from Cloud Backup")
                        }
                        .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.borderedProminent)

                    Text("Network may be unstable — restore may still work")
                        .font(.caption)
                        .foregroundStyle(.secondary)

                    Button {
                        cloudProbeState = .checking
                        probeCloud()
                    } label: {
                        Text("Retry Check")
                    }
                    .buttonStyle(.bordered)
                }

                if case .corrupt = cloudProbeState {
                    Text("Cloud backup data may be damaged")
                        .font(.caption)
                        .foregroundStyle(.orange)

                    Button {
                        onRestoreFromCloud()
                    } label: {
                        HStack {
                            Image(systemName: "icloud.and.arrow.down")
                            Text("Restore from Cloud Backup")
                        }
                        .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.borderedProminent)
                }

                Button {
                    contactSupport()
                } label: {
                    HStack {
                        Image(systemName: "envelope")
                        Text("Contact Support")
                    }
                    .frame(maxWidth: .infinity)
                }
                .buttonStyle(.bordered)

                Button(role: .destructive) {
                    showWipeConfirmation = true
                } label: {
                    Text("Wipe Local Data")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.bordered)
            }

            Spacer()
        }
        .padding()
        .task {
            probeCloud()
        }
        .alert("Wipe All Local Data?", isPresented: $showWipeConfirmation) {
            Button("Cancel", role: .cancel) {}
            Button("Wipe Data", role: .destructive) {
                wipeAndRestart()
            }
        } message: {
            Text(
                "This will permanently delete all wallet data on this device. Make sure you have your recovery phrases backed up. This cannot be undone."
            )
        }
    }

    @ViewBuilder
    private var cloudProbeContent: some View {
        switch cloudProbeState {
        case .checking:
            ProgressView()
                .padding(.top, 8)
        case .available, .unavailable, .transientError, .corrupt:
            EmptyView()
        }
    }

    private func probeCloud() {
        Task.detached {
            let cloud = CloudStorageAccessImpl()
            do {
                let exists = try cloud.hasCloudBackup()
                await MainActor.run {
                    cloudProbeState = exists ? .available : .unavailable
                }
            } catch let error as CloudStorageError {
                await MainActor.run {
                    switch error {
                    case .NotAvailable:
                        cloudProbeState = .transientError
                    default:
                        cloudProbeState = .corrupt
                    }
                }
            } catch {
                await MainActor.run {
                    cloudProbeState = .corrupt
                }
            }
        }
    }

    private func contactSupport() {
        if let url = URL(string: "mailto:feedback@covebitcoinwallet.com") {
            UIApplication.shared.open(url)
        }
    }

    private func wipeAndRestart() {
        wipeLocalData()
        onWipeOnly()
    }
}
