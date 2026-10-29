import SwiftUI

/// A short-lived capsule near the bottom of a screen, for news that needs no
/// answer: "Address copied". VoiceOver hears it as an announcement.
///
/// A row raises one through the environment, and the screen that installs
/// `transientNoticePresenter()` draws it. Without a presenter the
/// announcement is still made, so a row never has to know where it sits.
extension EnvironmentValues {
    @Entry var showTransientNotice = ShowTransientNotice()
}

/// Raises a notice, called like a function: `showTransientNotice("…")`.
struct ShowTransientNotice {
    fileprivate var present: (@MainActor (LocalizedStringResource) -> Void)?

    @MainActor func callAsFunction(_ message: LocalizedStringResource) {
        AccessibilityNotification.Announcement(String(localized: message)).post()
        present?(message)
    }
}

extension View {
    /// Draw the notices raised anywhere below this view.
    func transientNoticePresenter() -> some View {
        modifier(TransientNoticePresenter())
    }
}

private struct TransientNoticePresenter: ViewModifier {
    /// How long a notice stays up.
    static let duration: Duration = .seconds(1.2)

    @State private var notice: Notice?

    private struct Notice: Equatable {
        let id = UUID()
        let message: LocalizedStringResource

        static func == (lhs: Notice, rhs: Notice) -> Bool { lhs.id == rhs.id }
    }

    func body(content: Content) -> some View {
        content
            .environment(\.showTransientNotice, ShowTransientNotice { message in
                notice = Notice(message: message)
            })
            .overlay(alignment: .bottom) {
                if let notice {
                    Text(notice.message)
                        .font(.subheadline.weight(.semibold))
                        .padding(.horizontal, 16)
                        .padding(.vertical, 10)
                        .background(.regularMaterial, in: Capsule())
                        .shadow(color: .black.opacity(0.15), radius: 8, y: 2)
                        .padding(.bottom, 24)
                        .transition(.move(edge: .bottom).combined(with: .opacity))
                        // Already announced; the drawn copy would be read twice.
                        .accessibilityHidden(true)
                        .allowsHitTesting(false)
                }
            }
            .animation(.snappy, value: notice)
            // Restarts with each notice, so a second copy keeps it up for the
            // full time rather than whatever was left of the first.
            .task(id: notice) {
                guard notice != nil else { return }
                try? await Task.sleep(for: Self.duration)
                guard !Task.isCancelled else { return }
                notice = nil
            }
    }
}
