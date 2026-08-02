import SwiftUI

/// Where the reader is in an open transcript, and what the last gesture has
/// already done.
///
/// Held by reference for the same reason the app root keeps its bookkeeping
/// that way: these change continuously while a finger is down, and none of them
/// is drawn. As view state, each write would invalidate a non-lazy stack of
/// hundreds of bubbles on every frame of a drag.
@MainActor
final class TranscriptScrollState {
    /// Following the live edge is an explicit, sticky mode. Appending a row can
    /// temporarily increase the measured distance from the bottom before the
    /// compensating scroll runs; that layout change must not look like the user
    /// scrolled away. Only user-driven scrolling can leave follow mode.
    var followsLatestMessage = true
    var userIsScrolling = false
    var distanceFromBottom: CGFloat = 0
    var viewportHeight: CGFloat = 0
    var contentHeight: CGFloat = 0
    /// How far the viewport sits below the top of the content, kept for
    /// restoring the viewport arithmetically after the window is edited around
    /// it. Zero at rest at the top: measured in the same space as
    /// `ScrollPosition.scrollTo(y:)`, which counts from the content's top, not
    /// the inset-relative `contentOffset`.
    var offsetFromContentTop: CGFloat = 0
    /// How far the top of the window sits above the viewport. Derived rather
    /// than observed: one geometry reading feeds every distance.
    var distanceFromTop: CGFloat {
        max(0, contentHeight - viewportHeight - distanceFromBottom)
    }
    /// At most one automatic page per gesture, so a single long pull cannot
    /// walk backward through the whole history.
    var pagedThisGesture = false
    /// The transcript is at rest — no finger down, no momentum, no bounce.
    /// Only then does growing the content above the viewport leave the reader
    /// where they were: with a finger down the pan gesture owns the offset
    /// outright, and during deceleration or the rubber-band settle the system
    /// is animating toward a point in the *old* content — either way the
    /// prepended rows shove the viewport a page up the history. Pages that
    /// arrive while the transcript is moving wait in `pendingOlderPage`.
    var isSettled = true
    var pendingOlderPage: PendingOlderPage?

    /// A page of older rows read while the transcript was moving, with the
    /// cursor the window began at when it was requested — the proof it still
    /// belongs to this window when it is finally applied.
    struct PendingOlderPage {
        let page: TranscriptPage
        let front: ChatMessageCursor
    }
}

/// Both distances the transcript reacts to, read in one observation.
///
/// Whole points on every axis: sub-pixel measurement jitter feeding a
/// state-write → layout → state-write loop is what wedged this view before.
struct TranscriptScrollMetrics: Equatable {
    let distanceFromBottom: CGFloat
    /// How far the reader has pulled past the top. Zero unless overscrolling.
    let overscrollAboveTop: CGFloat
    let viewportHeight: CGFloat
    let contentHeight: CGFloat
    let offsetFromContentTop: CGFloat
}

/// Which row to put back under the reader after the window grows above them.
/// The generation makes two restores to the same row distinct changes, so the
/// second one still fires.
struct TranscriptRestoreAnchor: Equatable {
    var messageID: String?
    var generation = 0
    /// Carry on to the live edge once the anchor is in place. Set when
    /// returning from far up the history: landing just short of the end first
    /// gives the animation a short distance to travel instead of a jump
    /// through thousands of messages that were never loaded.
    var thenScrollToBottom = false

    func moved(to id: String?, thenScrollToBottom: Bool = false) -> TranscriptRestoreAnchor {
        TranscriptRestoreAnchor(
            messageID: id,
            generation: generation + 1,
            thenScrollToBottom: thenScrollToBottom
        )
    }
}

/// The marker at a window edge that has more behind it.
///
/// Fixed height whether or not it is spinning: this sits at the boundary a page
/// lands on, and a row that changes size there moves the content the scroll
/// restore is trying to hold still.
struct TranscriptEdgeSpinner: View {
    let isLoading: Bool

    var body: some View {
        ProgressView()
            .opacity(isLoading ? 1 : 0)
            .frame(height: 28)
            .frame(maxWidth: .infinity)
    }
}

/// Offered when the window does not hold the newest messages, which is the one
/// state where scrolling down does not eventually arrive at the present.
struct JumpToLatestButton: View {
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            Label("Jump to Latest", systemImage: "arrow.down.to.line")
                .font(.footnote.weight(.medium))
                .padding(.horizontal, 12)
                .padding(.vertical, 7)
                .background(.regularMaterial, in: Capsule())
        }
        .buttonStyle(.plain)
        .padding(.bottom, 8)
        .shadow(radius: 3, y: 1)
    }
}
