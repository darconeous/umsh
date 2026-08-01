import Foundation

/// One loaded slice of a transcript, oldest first — the order it renders in.
struct TranscriptPage: Equatable, Sendable {
    var messages: [ChatMessageSummary] = []
    /// Storage holds messages older than this slice.
    var hasOlder = false
    /// Storage holds messages newer than this slice, so its bottom is not the
    /// live edge.
    var hasNewer = false

    static let empty = TranscriptPage()
}

/// Reads bounded slices of a conversation's transcript.
///
/// Bundled the way ``ChatMessageActions`` is: the thread view needs four
/// related reads, and four closures threaded through two intermediate views is
/// four chances for them to drift apart.
struct TranscriptLoader: Sendable {
    /// The newest `limit` messages. What opening a transcript asks for, and
    /// what returning to the live edge asks for again.
    var newest: @Sendable (_ address: String, _ limit: Int) async -> TranscriptPage
    /// The `limit` messages immediately older than `cursor`.
    var older: @Sendable (String, ChatMessageCursor, Int) async -> TranscriptPage
    /// The messages from `cursor` forward. Reading from the cursor's own row is
    /// how a window re-reads the extent it already holds, picking up edits and
    /// delivery changes without moving the reading position.
    var newer: @Sendable (String, ChatMessageCursor, _ including: Bool, Int) async -> TranscriptPage
    /// A window centred on one message, for opening a search result in place.
    /// `nil` when that message is no longer in the conversation.
    var around: @Sendable (String, _ messageID: String, _ radius: Int) async -> TranscriptPage?

    static let unavailable = TranscriptLoader(
        newest: { _, _ in .empty },
        older: { _, _, _ in .empty },
        newer: { _, _, _, _ in .empty },
        around: { _, _, _ in nil }
    )
}

/// A transcript row: a real message, or a collapsed run of one-or-more
/// consecutive gap placeholders shown as a single spinner.
enum TranscriptItem: Identifiable, Equatable {
    case message(ChatMessageSummary)
    case gap(id: String, count: Int)

    var id: String {
        switch self {
        case let .message(message): message.id
        case let .gap(id, _): "gap:\(id)"
        }
    }
}

/// The slice of a transcript a thread view currently holds, and what lies
/// beyond it in either direction.
///
/// A transcript is rendered without laziness — every bubble measures a
/// `UITextView` up front — so the window, not the conversation, is what bounds
/// the cost of having one open.
///
/// The rows the view actually renders are derived here, once per change, rather
/// than in `body`. A scroll writes the observed geometry back into view state,
/// so `body` runs on every frame of a drag; anything O(window) computed there
/// is paid per frame, and at the capacity below that is the difference between
/// a smooth scroll and a stuttering one.
struct TranscriptWindow: Equatable {
    /// How many messages open at the live edge, and how many each page toward
    /// history adds.
    static let pageSize = 100
    /// The most a window may hold before the older edge starts trimming the
    /// newer one. Paging back through a long history would otherwise rebuild
    /// the unbounded transcript one page at a time. Every row here is a live
    /// `UITextView`, so this is a comfort budget, not just a memory one.
    static let capacity = 400
    /// How much of a centred window sits either side of its anchor.
    static let focusRadius = 60

    private(set) var messages: [ChatMessageSummary] = []
    /// `messages` collapsed for display, recomputed only when they change.
    private(set) var rows: [TranscriptItem] = []
    /// The newest outbound message, which is the only one that shows delivery
    /// state. Absent while the live edge is unloaded: a mid-history bubble must
    /// not be captioned as the latest thing this phone sent.
    private(set) var lastOutboundID: String?

    var hasOlder = false
    var hasNewer = false
    var isLoadingOlder = false
    var isLoadingNewer = false
    /// The revision this window was read at, so a reload that changed no
    /// messages costs nothing.
    var loadedRevision = -1
    var hasLoadedOnce = false

    var oldestCursor: ChatMessageCursor? { messages.first?.cursor }
    var newestCursor: ChatMessageCursor? { messages.last?.cursor }

    mutating func replace(with page: TranscriptPage, revision: Int) {
        messages = page.messages
        hasOlder = page.hasOlder
        hasNewer = page.hasNewer
        loadedRevision = revision
        hasLoadedOnce = true
        rebuildDerived()
    }

    /// Take a page of older messages onto the front.
    ///
    /// Deliberately does not trim. Growing at the top and shrinking at the
    /// bottom want opposite scroll anchors — content added above should hold
    /// the bottom still, content removed below should hold the top still — and
    /// doing both in one layout pass means one of them loses and the transcript
    /// lurches under a moving finger. Trimming is left to ``trimToCapacity()``,
    /// which the view calls once scrolling has stopped.
    mutating func prepend(_ page: TranscriptPage) {
        messages.insert(contentsOf: page.messages, at: 0)
        hasOlder = page.hasOlder
        rebuildDerived()
    }

    /// Whether the window has grown past what it should hold on to.
    var exceedsCapacity: Bool { messages.count > Self.capacity }

    /// Drop the newest messages back to capacity. The newest edge is the one
    /// to give up while reading history: it is far below the viewport, and the
    /// live edge is one tap away, whereas the rows just above the reader are
    /// what they are reading. Returns whether anything was dropped.
    mutating func trimToCapacity() -> Bool {
        let overflow = messages.count - Self.capacity
        guard overflow > 0 else { return false }
        messages.removeLast(overflow)
        hasNewer = true
        rebuildDerived()
        return true
    }

    /// Take a page of newer messages onto the end, trimming the older edge to
    /// stay within capacity. Symmetric to ``prepend(_:)``: the reader is at the
    /// bottom, so the top is the edge that can move freely.
    mutating func append(_ page: TranscriptPage) {
        messages.append(contentsOf: page.messages)
        hasNewer = page.hasNewer
        let overflow = messages.count - Self.capacity
        if overflow > 0 {
            messages.removeFirst(overflow)
            hasOlder = true
        }
        rebuildDerived()
    }

    private mutating func rebuildDerived() {
        rows = Self.rows(from: messages)
        lastOutboundID = hasNewer
            ? nil
            : messages.last { $0.isOutbound && !$0.isDeleted }?.id
    }

    /// Collapse consecutive gap placeholders into a single `.gap` row so no two
    /// spinner bubbles ever render adjacently.
    ///
    /// A run is identified by its *newest* placeholder. A run can straddle the
    /// window's older edge, and identifying it by its oldest loaded placeholder
    /// would change that identity the moment a page of history arrives and
    /// extends the run backward — SwiftUI would see a row replaced rather than
    /// grown, at the seam, while the scroll position is being restored. Keyed
    /// at the newest end, prepended placeholders form their own row instead.
    static func rows(from messages: [ChatMessageSummary]) -> [TranscriptItem] {
        var items: [TranscriptItem] = []
        items.reserveCapacity(messages.count)
        var runEnd: String?
        var runCount = 0
        func flushGap() {
            if let end = runEnd, runCount > 0 {
                items.append(.gap(id: end, count: runCount))
            }
            runEnd = nil
            runCount = 0
        }
        for message in messages {
            if message.isGapPlaceholder {
                // A placeholder the engine deleted was filled by an edit (the
                // missing frame was an edit, not a standalone bubble): it no
                // longer holds a slot, so drop it. Any still-pending neighbors
                // stay contiguous and keep the collapsed spinner.
                if message.isDeleted { continue }
                runEnd = message.id
                runCount += 1
            } else {
                flushGap()
                items.append(.message(message))
            }
        }
        flushGap()
        return items
    }
}
