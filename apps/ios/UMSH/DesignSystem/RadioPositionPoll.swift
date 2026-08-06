import SwiftUI

/// Keeps the radio's own position fresh for as long as a screen is showing
/// one.
///
/// The radio does not announce where it is. A receiver reports about a fix
/// a second and ordinary noise moves the reading, so a radio that pushed
/// them would transmit continuously — and wake the phone each time — for a
/// screen that may not even be open. Instead the screens that show a
/// position ask for one, and this is the asking: a sample on appear, then
/// one a minute for as long as the view is on screen.
///
/// `.task` is what makes "for as long as" true without any bookkeeping:
/// SwiftUI cancels it when the view goes away, which ends the loop. Leaving
/// the tab, pushing a detail, or backgrounding the app all stop the polling
/// on their own.
private struct RadioPositionPoll: ViewModifier {
    /// Whether the screen has a live reason to know. False stops the
    /// asking entirely — a radio that is not attached, or one with no
    /// receiver, would answer every sample with a refusal.
    let isNeeded: Bool
    let sample: (() async -> Void)?

    /// Once a minute. A tracker on foot moves metres in that time and the
    /// distances this feeds are rounded to tenths of a mile, so a faster
    /// cadence would spend the radio's battery redrawing the same numbers.
    private static let interval = Duration.seconds(60)

    func body(content: Content) -> some View {
        content.task(id: isNeeded) {
            guard isNeeded, let sample else { return }
            while !Task.isCancelled {
                await sample()
                do {
                    try await Task.sleep(for: Self.interval)
                } catch {
                    // Cancelled mid-wait, which is the view going away.
                    return
                }
            }
        }
    }
}

extension View {
    /// Sample the radio's position on appear and once a minute after, while
    /// `isNeeded`. See ``RadioPositionPoll``.
    func radioPositionPoll(
        isNeeded: Bool,
        sample: (() async -> Void)?
    ) -> some View {
        modifier(RadioPositionPoll(isNeeded: isNeeded, sample: sample))
    }
}
