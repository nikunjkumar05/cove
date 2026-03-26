import SwiftUI

@_exported import CoveCore

private extension CloudOnlyOperation {
    var operatingRecordId: String? {
        if case let .operating(recordId) = self { return recordId }
        return nil
    }
}

struct DetailFormContent: View {
    let detail: CloudBackupDetail
    let syncHealth: ICloudDriveHelper.SyncHealth
    let manager: CloudBackupDetailManager

    private var showCloudOnlySection: Bool {
        switch manager.cloudOnly {
        case .notFetched: detail.cloudOnlyCount > 0
        case .loading: true
        case let .loaded(wallets): !wallets.isEmpty
        }
    }

    var body: some View {
        HeaderSection(lastSync: detail.lastSync, syncHealth: syncHealth)
        if !detail.backedUp.isEmpty {
            WalletSections(wallets: detail.backedUp)
        }
        if !detail.notBackedUp.isEmpty {
            WalletSections(wallets: detail.notBackedUp, showNotBackedUpBadge: true)
        }
        if showCloudOnlySection {
            CloudOnlySection(manager: manager)
        }
    }
}

struct HeaderSection: View {
    let lastSync: UInt64?
    let syncHealth: ICloudDriveHelper.SyncHealth

    var body: some View {
        Section {
            VStack(spacing: 8) {
                headerIcon
                    .font(.largeTitle)

                Text("Cloud Backup Active")
                    .fontWeight(.semibold)

                if let lastSync {
                    Text("Last synced \(formatDate(lastSync))")
                        .font(.caption)
                        .foregroundStyle(.secondary)

                    syncHealthLabel
                }
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical, 8)
        }
    }

    @ViewBuilder
    private var headerIcon: some View {
        switch syncHealth {
        case .allUploaded, .noFiles:
            Image(systemName: "checkmark.icloud.fill")
                .foregroundColor(.green)
        case .uploading:
            Image(systemName: "arrow.clockwise.icloud.fill")
                .foregroundColor(.blue)
        case .failed:
            Image(systemName: "exclamationmark.icloud.fill")
                .foregroundColor(.red)
        case .unavailable:
            Image(systemName: "checkmark.icloud.fill")
                .foregroundColor(.green)
        }
    }

    @ViewBuilder
    private var syncHealthLabel: some View {
        switch syncHealth {
        case .allUploaded:
            Label("All files synced to iCloud", systemImage: "checkmark.circle.fill")
                .font(.caption)
                .foregroundStyle(.green)
        case .uploading:
            HStack(spacing: 4) {
                ProgressView()
                    .controlSize(.mini)
                Text("Syncing to iCloud...")
            }
            .font(.caption)
            .foregroundStyle(.secondary)
        case let .failed(message):
            Label("Sync error: \(message)", systemImage: "exclamationmark.triangle.fill")
                .font(.caption)
                .foregroundStyle(.red)
        case .noFiles, .unavailable:
            EmptyView()
        }
    }

    private func formatDate(_ timestamp: UInt64) -> String {
        let date = Date(timeIntervalSince1970: TimeInterval(timestamp))
        return date.formatted(date: .abbreviated, time: .shortened)
    }
}

struct CloudOnlySection: View {
    let manager: CloudBackupDetailManager
    @State private var selectedWallet: CloudBackupWalletItem?
    @State private var walletToDelete: CloudBackupWalletItem?

    private var isOperating: Bool {
        manager.cloudOnlyOperation.operatingRecordId != nil
    }

    var body: some View {
        Section(header: Text("Not on This Device")) {
            switch manager.cloudOnly {
            case .notFetched, .loading:
                HStack {
                    ProgressView()
                        .padding(.trailing, 8)
                    Text("Loading...")
                }
                .foregroundStyle(.secondary)
                .task {
                    manager.dispatch(.fetchCloudOnly)
                }

            case let .loaded(wallets):
                ForEach(wallets, id: \.name) { item in
                    Button {
                        selectedWallet = item
                    } label: {
                        HStack {
                            if manager.cloudOnlyOperation.operatingRecordId == item.recordId {
                                ProgressView()
                                    .padding(.trailing, 8)
                            }
                            WalletItemRow(item: item)
                        }
                    }
                    .foregroundStyle(.primary)
                    .disabled(isOperating)
                }

                if case let .failed(error) = manager.cloudOnlyOperation {
                    Text(error)
                        .font(.caption)
                        .foregroundStyle(.red)
                }
            }
        }
        .confirmationDialog(
            selectedWallet?.name ?? "Wallet",
            isPresented: Binding(
                get: { selectedWallet != nil },
                set: { if !$0 { selectedWallet = nil } }
            ),
            titleVisibility: .visible
        ) {
            if let item = selectedWallet, let recordId = item.recordId {
                Button("Restore to This Device") {
                    manager.dispatch(.restoreCloudWallet(recordId: recordId))
                }
                Button("Delete from iCloud", role: .destructive) {
                    walletToDelete = item
                }
            }
            Button("Cancel", role: .cancel) {}
        }
        .alert(
            "Delete \(walletToDelete?.name ?? "wallet")?",
            isPresented: Binding(
                get: { walletToDelete != nil },
                set: { if !$0 { walletToDelete = nil } }
            )
        ) {
            if let item = walletToDelete, let recordId = item.recordId {
                Button("Delete", role: .destructive) {
                    manager.dispatch(.deleteCloudWallet(recordId: recordId))
                }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("This wallet backup will be permanently removed from iCloud")
        }
    }
}

struct WalletSections: View {
    let wallets: [CloudBackupWalletItem]
    var showNotBackedUpBadge = false

    private var groupedWallets: [(key: GroupKey, items: [CloudBackupWalletItem])] {
        Dictionary(grouping: wallets) {
            GroupKey(network: $0.network, walletMode: $0.walletMode)
        }
        .map { ($0.key, $0.value) }
        .sorted { $0.key < $1.key }
    }

    var body: some View {
        ForEach(groupedWallets, id: \.key) { group in
            Section(header: sectionHeader(for: group.key)) {
                ForEach(group.items, id: \.name) { item in
                    WalletItemRow(item: item)
                }
            }
        }
    }

    @ViewBuilder
    private func sectionHeader(for key: GroupKey) -> some View {
        if showNotBackedUpBadge {
            HStack {
                Text(key.title)
                Text("NOT BACKED UP")
                    .font(.caption2)
                    .fontWeight(.semibold)
                    .foregroundStyle(.white)
                    .padding(.horizontal, 6)
                    .padding(.vertical, 2)
                    .background(.red, in: Capsule())
            }
        } else {
            Text(key.title)
        }
    }
}

struct WalletItemRow: View {
    let item: CloudBackupWalletItem

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text(item.name)
                    .fontWeight(.medium)
                Spacer()
                StatusBadge(status: item.status)
            }

            HStack(spacing: 12) {
                IconLabel("globe", item.network.displayName())
                IconLabel("wallet.bifold", item.walletType.displayName())
                if let fingerprint = item.fingerprint {
                    IconLabel("touchid", fingerprint)
                }
            }
            .font(.caption)
            .foregroundStyle(.secondary)
        }
        .padding(.vertical, 2)
    }
}

private struct StatusBadge: View {
    let status: CloudBackupWalletStatus

    private var label: String {
        switch status {
        case .backedUp: "Backed up"
        case .notBackedUp: "Not backed up"
        case .deletedFromDevice: "Not on device"
        }
    }

    private var color: Color {
        switch status {
        case .backedUp: .green
        case .notBackedUp: .red
        case .deletedFromDevice: .orange
        }
    }

    var body: some View {
        Text(label)
            .font(.caption)
            .fontWeight(.medium)
            .foregroundColor(color)
            .padding(.horizontal, 8)
            .padding(.vertical, 3)
            .background(color.opacity(0.15), in: Capsule())
    }
}

private struct GroupKey: Hashable, Comparable {
    let network: Network
    let walletMode: WalletMode

    var title: String {
        switch walletMode {
        case .decoy: "\(network.displayName()) · Decoy"
        default: network.displayName()
        }
    }

    static func < (lhs: GroupKey, rhs: GroupKey) -> Bool {
        if lhs.network != rhs.network {
            return lhs.network.displayName() < rhs.network.displayName()
        }
        return lhs.walletMode == .main && rhs.walletMode != .main
    }
}
