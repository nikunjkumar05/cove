import SwiftUI

@_exported import CoveCore

/// Shown after the cloud backup check finds at least one backup
struct CloudRestoreOfferView: View {
    let onRestore: () -> Void
    let onSkip: () -> Void
    var errorMessage: String? = nil

    var body: some View {
        VStack(spacing: 0) {
            OnboardingStepIndicator(selected: 1)
                .padding(.top, 8)

            Spacer()
                .frame(height: 42)

            heroIcon

            Spacer()
                .frame(height: 44)

            VStack(spacing: 16) {
                Text("iCloud Backup Found")
                    .font(.system(size: 42, weight: .bold, design: .rounded))
                    .foregroundStyle(.white)
                    .multilineTextAlignment(.center)

                Text("A previous iCloud backup was found. Restore your wallet securely using your passkey.")
                    .font(.system(size: 20, weight: .medium, design: .rounded))
                    .foregroundStyle(.coveLightGray.opacity(0.76))
                    .multilineTextAlignment(.center)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .padding(.horizontal, 8)

            Spacer()
                .frame(height: 32)

            passkeyCard

            if let errorMessage {
                errorCard(message: errorMessage)
                    .padding(.top, 14)
                    .transition(.opacity.combined(with: .move(edge: .top)))
            }

            Spacer(minLength: 26)

            VStack(spacing: 16) {
                Button(action: onRestore) {
                    Text("Restore with Passkey")
                }
                .buttonStyle(OnboardingPrimaryButtonStyle())

                Button(action: onSkip) {
                    Text("Set Up as New")
                        .font(.system(size: 16, weight: .semibold, design: .rounded))
                        .foregroundStyle(Color.btnGradientLight.opacity(0.95))
                }
                .buttonStyle(.plain)
            }
        }
        .padding(.horizontal, 28)
        .padding(.top, 12)
        .padding(.bottom, 26)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
        .onboardingRecoveryBackground()
        .animation(.easeInOut(duration: 0.3), value: errorMessage)
    }

    private var heroIcon: some View {
        ZStack {
            Circle()
                .stroke(Color.btnGradientLight.opacity(0.12), lineWidth: 1)
                .frame(width: 118, height: 118)

            Circle()
                .stroke(Color.btnGradientLight.opacity(0.18), lineWidth: 1)
                .frame(width: 86, height: 86)

            Circle()
                .stroke(Color.btnGradientLight.opacity(0.24), lineWidth: 1)
                .frame(width: 58, height: 58)

            Circle()
                .fill(Color.duskBlue.opacity(0.4))
                .frame(width: 58, height: 58)

            Circle()
                .stroke(
                    LinearGradient(
                        colors: [.btnGradientLight, .btnGradientDark],
                        startPoint: .topLeading,
                        endPoint: .bottomTrailing
                    ),
                    lineWidth: 1.5
                )
                .frame(width: 58, height: 58)

            Image(systemName: "magnifyingglass")
                .font(.system(size: 22, weight: .semibold))
                .foregroundStyle(Color.btnGradientLight)
        }
    }

    private var passkeyCard: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Recommended")
                .font(.system(size: 11, weight: .semibold, design: .rounded))
                .foregroundStyle(Color.btnGradientLight.opacity(0.92))
                .frame(minWidth: 76)
                .padding(.horizontal, 10)
                .padding(.vertical, 5)
                .background(
                    Capsule()
                        .fill(Color.btnGradientLight.opacity(0.12))
                )

            HStack(spacing: 14) {
                Image(systemName: "person.badge.key")
                    .font(.system(size: 19, weight: .medium))
                    .foregroundStyle(Color.btnGradientLight)
                    .frame(width: 42, height: 42)
                    .background(
                        RoundedRectangle(cornerRadius: 12, style: .continuous)
                            .fill(Color.btnGradientLight.opacity(0.12))
                    )

                VStack(alignment: .leading, spacing: 4) {
                    Text("Passkey Restore")
                        .font(.system(size: 24, weight: .bold, design: .rounded))
                        .foregroundStyle(.white)

                    Text("Secured with iCloud Keychain")
                        .font(.system(size: 14, weight: .medium, design: .rounded))
                        .foregroundStyle(.coveLightGray.opacity(0.58))
                }

                Spacer()
            }

            Text("Your passkey is stored securely in iCloud Keychain and syncs across all your Apple devices.")
                .font(.system(size: 17, weight: .medium, design: .rounded))
                .foregroundStyle(.coveLightGray.opacity(0.74))
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(.horizontal, 18)
        .padding(.vertical, 18)
        .background(
            RoundedRectangle(cornerRadius: 22, style: .continuous)
                .fill(Color.duskBlue.opacity(0.48))
        )
        .overlay(
            RoundedRectangle(cornerRadius: 22, style: .continuous)
                .stroke(Color.coveLightGray.opacity(0.14), lineWidth: 1)
        )
    }

    private func errorCard(message: String) -> some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: "exclamationmark.triangle.fill")
                .font(.system(size: 14, weight: .semibold))
                .foregroundStyle(.orange)
                .padding(.top, 2)

            Text(message)
                .font(.system(size: 14, weight: .medium, design: .rounded))
                .foregroundStyle(.orange.opacity(0.95))
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
                .stroke(Color.orange.opacity(0.28), lineWidth: 1)
        )
    }
}
