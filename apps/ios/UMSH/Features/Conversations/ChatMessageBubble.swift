import Combine
import SwiftUI
import UIKit

/// When the conversation picked up again after a lull.
///
/// The day is set apart from the time because they answer different questions:
/// scrolling through history the reader is looking for the day, and having
/// found it, wants to know the hour.
struct TranscriptDateSeparator: View {
    let date: Date

    /// Toggled at midnight so "Today" does not survive into tomorrow. The
    /// label is computed at render, and nothing else re-renders a row whose
    /// message has not changed.
    @State private var dayRollover = false

    var body: some View {
        (Text(day).fontWeight(.semibold) + Text(" \(time)"))
            .font(.caption2)
            .foregroundStyle(.secondary)
            .frame(maxWidth: .infinity)
            .padding(.vertical, 12)
            .onReceive(
                NotificationCenter.default
                    .publisher(for: .NSCalendarDayChanged)
                    .receive(on: DispatchQueue.main)
            ) { _ in dayRollover.toggle() }
    }

    private var time: String {
        date.formatted(date: .omitted, time: .shortened)
    }

    private var day: String {
        let calendar = Calendar.current
        if calendar.isDateInToday(date) { return "Today" }
        if calendar.isDateInYesterday(date) { return "Yesterday" }
        // Inside the last week a weekday name places a message better than a
        // date does; past that it stops being a landmark and the date is what
        // is left to go on.
        if let weekAgo = calendar.date(byAdding: .day, value: -6, to: Date.now),
           date >= calendar.startOfDay(for: weekAgo) {
            return date.formatted(.dateTime.weekday(.wide))
        }
        return date.formatted(date: .abbreviated, time: .omitted)
    }
}

/// The Messages bubble: a rounded rectangle with a tail curling out of the
/// bottom corner on the sender's side.
///
/// Only the last bubble of a run carries the tail. That is what makes several
/// consecutive messages read as one person talking rather than as several
/// separate remarks.
struct BubbleShape: Shape {
    static let cornerRadius: CGFloat = 17
    /// How far the tail reaches past the body of the bubble. The bubble keeps
    /// this much clear on its tail side, tail or no tail, so that every bubble
    /// of a run lines up whether or not it is the one carrying it.
    static let tailWidth: CGFloat = 6
    /// How far up the side the tail leaves the bubble.
    private static let tailRise: CGFloat = 13
    /// How far the underside scoops back up into the bubble before rejoining
    /// the bottom edge. This is the whole difference between a tail and a
    /// wedge: without the scoop the corner just looks pulled out of shape.
    private static let scoopDepth: CGFloat = 4.5
    private static let scoopLength: CGFloat = 12

    var isOutbound: Bool
    var showsTail: Bool

    func path(in rect: CGRect) -> Path {
        let path = outboundPath(in: rect)
        guard !isOutbound else { return path }
        // Mirrored rather than traced a second time. One closed outline fills
        // the same whichever way round it is wound, so the reflection needs no
        // correction — which is exactly what an added-on tail would have.
        return path.applying(
            CGAffineTransform(a: -1, b: 0, c: 0, d: 1, tx: 2 * rect.midX, ty: 0)
        )
    }

    /// The bubble as a single continuous outline, tail at the bottom right.
    ///
    /// One path, not a rounded rectangle with a tail added to it: the scoop
    /// under the tail is a bite taken *out* of the bottom edge, and a separate
    /// tail unioned onto a full rectangle can only ever add to it — the
    /// rectangle's own bottom edge fills the bite straight back in, leaving a
    /// wedge.
    private func outboundPath(in rect: CGRect) -> Path {
        let body = CGRect(
            x: rect.minX,
            y: rect.minY,
            width: max(0, rect.width - Self.tailWidth),
            height: rect.height
        )
        let radius = min(Self.cornerRadius, min(body.width, body.height) / 2)
        guard radius > 0 else { return Path(body) }
        guard showsTail else {
            return Path(roundedRect: body, cornerRadius: radius, style: .continuous)
        }

        let left = body.minX, right = body.maxX
        let top = body.minY, bottom = body.maxY
        let rise = min(Self.tailRise, body.height - radius)
        let scoop = min(Self.scoopLength, body.width - radius)

        var path = Path()
        path.move(to: CGPoint(x: left + radius, y: top))
        path.addLine(to: CGPoint(x: right - radius, y: top))
        path.addQuadCurve(
            to: CGPoint(x: right, y: top + radius),
            control: CGPoint(x: right, y: top)
        )
        // Down the side to where the tail begins.
        path.addLine(to: CGPoint(x: right, y: bottom - rise))
        // Out and down to the point, bulging as it goes.
        path.addCurve(
            to: CGPoint(x: right + Self.tailWidth, y: bottom),
            control1: CGPoint(x: right + Self.tailWidth * 0.7, y: bottom - rise * 0.55),
            control2: CGPoint(x: right + Self.tailWidth, y: bottom - rise * 0.2)
        )
        // Back under it: up into the bubble, then down to the bottom edge.
        path.addCurve(
            to: CGPoint(x: right - scoop, y: bottom),
            control1: CGPoint(x: right - 1, y: bottom - Self.scoopDepth),
            control2: CGPoint(x: right - scoop * 0.55, y: bottom - Self.scoopDepth)
        )
        path.addLine(to: CGPoint(x: left + radius, y: bottom))
        path.addQuadCurve(
            to: CGPoint(x: left, y: bottom - radius),
            control: CGPoint(x: left, y: bottom)
        )
        path.addLine(to: CGPoint(x: left, y: top + radius))
        path.addQuadCurve(
            to: CGPoint(x: left + radius, y: top),
            control: CGPoint(x: left, y: top)
        )
        path.closeSubpath()
        return path
    }
}

/// A placeholder bubble for a known sequence gap: an indeterminate spinner in
/// an inbound-styled bubble, holding the missing message's ordered position
/// until a repair fills or resolves it. One bubble stands for a whole run of
/// adjacent gaps.
struct GapPlaceholderBubble: View {
    let count: Int
    /// Reserve the avatar column a channel's inbound bubbles keep, so the
    /// spinner lines up with the messages around it instead of sitting a
    /// gutter's width to their left.
    var reservesAvatarGutter = false

    var body: some View {
        HStack(alignment: .bottom, spacing: ChatMessageBubble.gutterSpacing) {
            if reservesAvatarGutter {
                Color.clear.frame(width: ChatMessageBubble.avatarGutter, height: 1)
            }
            ProgressView()
                .controlSize(.small)
                .padding(.horizontal, 14)
                .padding(.vertical, 10)
                .background(
                    Color(uiColor: .systemGray5),
                    in: BubbleShape(isOutbound: false, showsTail: true)
                )
                .accessibilityLabel(
                    count > 1 ? "Waiting for \(count) missing messages" : "Waiting for a missing message"
                )
            Spacer(minLength: ChatMessageBubble.oppositeMargin)
        }
    }
}

struct ChatMessageBubble: View, @MainActor Equatable {
    /// The column a group's sender avatars sit in. Held open for every bubble
    /// of a run so they all start at the same place; shared with
    /// ``GapPlaceholderBubble`` so gap spinners line up too.
    static let avatarGutter: CGFloat = 28
    static let gutterSpacing: CGFloat = 6
    /// The narrowest the far margin may get, which is what stops a bubble from
    /// running the full width of the screen.
    static let oppositeMargin: CGFloat = 64

    let message: ChatMessageSummary
    /// How well the conversation this bubble belongs to is protected, which is
    /// what an outbound bubble is coloured by.
    let security: ConversationSecurity
    /// Where this message sits in its run, which decides the tail, the sender
    /// header, the avatar, and the space above it.
    var presentation = MessagePresentation()
    /// Quiet states (Delivered/Sent) only annotate the newest outbound
    /// message; older ones would repeat the same information on every row.
    var isMostRecentOutbound = false
    /// Who sent this, in a group conversation. Absent for a direct chat,
    /// where every inbound bubble has the same sender.
    var senderLabel: String?
    /// The sender's hint, which is what their avatar is derived from.
    var senderHint: MeshNodeHint?
    var onEdit: (() -> Void)?
    var onDelete: (() -> Void)?
    var onShowDetails: (() -> Void)?
    var onShowSender: (() -> Void)?
    /// React with a palette glyph, or withdraw by passing the one already
    /// chosen. The picker marks the current choice, so the same tap that
    /// selects also unselects.
    var onReact: ((String) -> Void)?

    @State private var showsOriginalBody = false

    /// The closures are not comparable, but they are derived from the message
    /// and only their presence changes what the menu offers; a bubble whose
    /// message, delivery annotation and place in its run are unchanged renders
    /// identically.
    ///
    /// `onShowDetails` and `onShowSender` are deliberately left out:
    /// `onShowDetails` is always provided, and `onShowSender`'s presence
    /// tracks `senderLabel`/`senderHint`, which are compared. If either ever
    /// becomes independently conditional, it must join this comparison.
    static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.message == rhs.message
            && lhs.security == rhs.security
            && lhs.presentation == rhs.presentation
            && lhs.isMostRecentOutbound == rhs.isMostRecentOutbound
            && lhs.senderLabel == rhs.senderLabel
            && lhs.senderHint == rhs.senderHint
            && (lhs.onEdit == nil) == (rhs.onEdit == nil)
            && (lhs.onDelete == nil) == (rhs.onDelete == nil)
            && (lhs.onReact == nil) == (rhs.onReact == nil)
    }

    private var isFailed: Bool {
        message.deliveryState?.lowercased() == "failed"
    }

    var body: some View {
        if message.isDeleted {
            // A tombstone, not a message: no bubble, no menu, no captions.
            Text(message.isOutbound ? "You deleted a message" : "Message deleted")
                .font(.caption)
                .italic()
                .foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, alignment: message.isOutbound ? .trailing : .leading)
                .padding(.horizontal, 8)
        } else if message.isUnavailable {
            // A gap whose repair failed: a subtle loss marker in its slot.
            Text("Message unavailable")
                .font(.caption)
                .italic()
                .foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal, 8)
        } else {
            HStack(alignment: .bottom, spacing: Self.gutterSpacing) {
                if message.isOutbound {
                    Spacer(minLength: Self.oppositeMargin)
                } else if senderLabel != nil {
                    gutter
                }
                VStack(alignment: message.isOutbound ? .trailing : .leading, spacing: 2) {
                    // Named once at the top of a run: the following lines are
                    // the same person still talking, and repeating them on
                    // every bubble is what makes a group chat unreadable.
                    if let senderLabel, presentation.isFirstInRun {
                        Text(senderLabel)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .padding(.horizontal, 12)
                    }
                    reactionsAndBubble
                        // The whole group — bubble and chips — is what the
                        // context menu lifts. The preview mask must cover the
                        // chips too or they are sliced at the bubble outline
                        // the moment the menu opens; a full-rect mask works
                        // because the lift keeps transparent pixels
                        // transparent, so the gaps around the chips show the
                        // dimmed transcript rather than a platter. (A custom
                        // preview view is NOT equivalent: those are backed by
                        // an opaque system platter.)
                        .contentShape(.contextMenuPreview, Rectangle())
                        .contextMenu {
                            menuItems
                        }
                        .alert("Original Message", isPresented: $showsOriginalBody) {
                            Button("OK", role: .cancel) {}
                        } message: {
                            Text(message.originalBody ?? "")
                        }
                    if let caption {
                        Text(caption)
                            .font(.caption2)
                            .fontWeight(isFailed ? .semibold : .regular)
                            .foregroundStyle(isFailed ? AnyShapeStyle(.red) : AnyShapeStyle(.secondary))
                            .padding(.horizontal, 4)
                    }
                }
                if !message.isOutbound { Spacer(minLength: Self.oppositeMargin) }
            }
        }
    }

    /// The avatar column beside a group's inbound bubbles. Every bubble in a
    /// run reserves it so they line up, and only the last one fills it — the
    /// avatar belongs beside the end of what that member said, as in Messages.
    @ViewBuilder
    private var gutter: some View {
        if presentation.isLastInRun, let senderHint {
            Button {
                onShowSender?()
            } label: {
                // The same deterministic avatar this member gets everywhere
                // else: derived from the hint their frames carry, so it is
                // stable before anyone knows who they are.
                PeerAvatar(hint: senderHint, diameter: Self.avatarGutter)
            }
            .buttonStyle(.plain)
            .disabled(onShowSender == nil)
            .accessibilityLabel(senderLabel ?? "Sender")
        } else {
            Color.clear.frame(width: Self.avatarGutter, height: 1)
        }
    }

    private var shape: BubbleShape {
        BubbleShape(isOutbound: message.isOutbound, showsTail: presentation.isLastInRun)
    }

    /// The bubble with its reaction chips laid out over the top corner — the
    /// unit the transcript shows and the context menu lifts.
    ///
    /// The chips are laid out here rather than floated as an overlay: an
    /// overlay that spills past its row gets composited under the
    /// neighbouring bubbles, each of which is a real UITextView. Reserving
    /// the overhang keeps them whole.
    private var reactionsAndBubble: some View {
        // The reserved strips above and outside the bubble are what the
        // cluster lives in: the chips sit high, the corner chip overhangs the
        // bubble's outer edge, and the thought-dot trail falls wholly outside
        // it — all without anything ever poking past the group's own bounds,
        // where the neighbouring rows (and the lift snapshot) would clip it.
        ZStack(alignment: message.isOutbound ? .topLeading : .topTrailing) {
            HStack(spacing: 6) {
                bubble
                if isFailed {
                    Image(systemName: "exclamationmark.circle.fill")
                        .font(.title3)
                        .foregroundStyle(.red)
                        .accessibilityLabel("Message not delivered")
                }
            }
            .padding(.top, message.reactions.isEmpty ? 0 : ReactionBadgeView.overhang)
            .padding(
                message.isOutbound ? .leading : .trailing,
                message.reactions.isEmpty ? 0 : ReactionBadgeView.outset
            )
            if !message.reactions.isEmpty {
                ReactionBadgeView(
                    reactions: message.reactions,
                    isOutbound: message.isOutbound,
                    security: security
                )
                .padding(.top, ReactionBadgeView.topInset)
                .padding(
                    message.isOutbound ? .leading : .trailing,
                    ReactionBadgeView.cornerInset
                )
            }
        }
    }

    @ViewBuilder
    private var menuItems: some View {
        if let onReact {
            // A palette picker renders as a row of glyphs with the
            // chosen one marked, and — unlike a row of toggles —
            // closes the menu when one is picked, which is what makes
            // reacting feel like one gesture rather than two.
            Picker(
                selection: Binding(
                    get: { message.myReaction?.glyph ?? "" },
                    // Picking either way is the same request: choose
                    // this glyph, or drop it if it was already ours.
                    set: { onReact($0) }
                )
            ) {
                ForEach(ReactionEmoji.palette, id: \.glyph) { entry in
                    Text(entry.glyph)
                        .accessibilityLabel(ReactionEmoji.name(for: entry.glyph))
                        .tag(entry.glyph)
                }
            } label: {
                // A menu renders a picker's label as a section
                // heading, and the glyphs need no caption; only an
                // empty label leaves them to speak for themselves.
                EmptyView()
            }
            .pickerStyle(.palette)
        }
        Button("Copy", systemImage: "doc.on.doc") {
            UIPasteboard.general.string = message.body
        }
        if message.originalBody != nil {
            Button("View Original", systemImage: "clock.arrow.circlepath") {
                showsOriginalBody = true
            }
        }
        if let onEdit {
            Button("Edit", systemImage: "pencil", action: onEdit)
        }
        if let onShowDetails {
            Button("Details", systemImage: "info.circle", action: onShowDetails)
        }
        if let onDelete {
            Button("Delete", systemImage: "trash", role: .destructive, action: onDelete)
        }
    }

    private var bubble: some View {
        SelectableMessageText(
            text: message.body,
            textColor: message.isOutbound ? .white : .label
        )
            .padding(.horizontal, 12)
            .padding(.vertical, 8)
            // The tail eats into the bubble's own side, so keep its width
            // clear of the text on whichever side it hangs off.
            .padding(message.isOutbound ? .trailing : .leading, BubbleShape.tailWidth)
            .background(
                message.isOutbound ? security.tint : Color(uiColor: .systemGray5),
                in: shape
            )
    }

    private var caption: String? {
        var parts: [String] = []
        if message.isEdited { parts.append("Edited") }
        if message.isReceivedLate { parts.append("Received late") }
        if message.isOutbound, let label = deliveryLabel { parts.append(label) }
        return parts.isEmpty ? nil : parts.joined(separator: " · ")
    }

    private var deliveryLabel: String? {
        guard let state = message.deliveryState else { return nil }
        switch state.lowercased() {
        case "failed": return "Not Delivered"
        case "acknowledged":
            // A recovery from failure is noteworthy on its own row, unlike a
            // routine "Delivered" which only annotates the newest message.
            if message.isDeliveredLate { return "Delivered Late" }
            return isMostRecentOutbound ? "Delivered" : nil
        case "sent": return isMostRecentOutbound ? "Sent" : nil
        default: return "Sending…"
        }
    }
}

/// UITextView-backed message body: pointer-driven selection (mouse or
/// trackpad drag, double-click for a word) works like any ordinary text,
/// which SwiftUI's `.textSelection(.enabled)` does not provide inside a
/// scroll view. Long presses are left to the bubble's context menu, as in
/// Messages; touch users select through the menu or a double tap.
private struct SelectableMessageText: UIViewRepresentable {
    let text: String
    /// Set explicitly because an outbound bubble is filled with a solid
    /// colour: the body text and any link the detector finds both have to stay
    /// legible against it, and a link left to its own devices would not be.
    let textColor: UIColor

    func makeUIView(context: Context) -> BubbleTextView {
        let view = BubbleTextView()
        view.isEditable = false
        view.isSelectable = true
        view.isScrollEnabled = false
        view.backgroundColor = .clear
        view.textContainerInset = .zero
        view.textContainer.lineFragmentPadding = 0
        view.font = .preferredFont(forTextStyle: .body)
        view.adjustsFontForContentSizeCategory = true
        view.dataDetectorTypes = .link
        apply(textColor, to: view)
        return view
    }

    func updateUIView(_ view: BubbleTextView, context: Context) {
        let body = Self.attributed(text, color: textColor)
        if view.attributedText != body {
            view.attributedText = body
        }
        if view.textColor != textColor {
            apply(textColor, to: view)
        }
    }

    /// The message body with `umsh:` URIs marked up as links.
    ///
    /// Only ours. `dataDetectorTypes` stays on and keeps everything else, and
    /// keeps doing it better than a pattern here could: it knows the schemes
    /// this device can actually act on, so `tel:` links where there is a phone
    /// and an unknown `scheme://` links only where an app has claimed it —
    /// never offering a link that would go nowhere.
    ///
    /// What it will not claim is an opaque path under a scheme it does not
    /// know, and `umsh:cs:EMERGENCY` is exactly that: no `//`, no authority,
    /// nothing generic to recognize. Marking it here costs the detector
    /// nothing, since it passes over ranges that already carry a link.
    private static func attributed(_ text: String, color: UIColor) -> NSAttributedString {
        let body = NSMutableAttributedString(
            string: text,
            attributes: [
                .font: UIFont.preferredFont(forTextStyle: .body),
                .foregroundColor: color
            ]
        )
        guard let umshURI else { return body }
        for match in umshURI.matches(in: text, range: NSRange(text.startIndex..., in: text)) {
            guard let range = Range(match.range, in: text),
                  let url = URL(string: String(text[range]))
            else { continue }
            body.addAttribute(.link, value: url, range: match.range)
        }
        return body
    }

    /// The three forms `umsh-uri` emits, with a payload that may be
    /// percent-encoded and — for a channel key — carry a query.
    ///
    /// The last character is matched apart from the rest so a URI ending a
    /// sentence does not swallow the full stop, or the comma in a list, or the
    /// bracket around an aside.
    private static let umshURI = try? NSRegularExpression(
        pattern: #"umsh:(?:n|cs|ck):[A-Za-z0-9\-._~%!$&'()*+,;=:@/?]*[A-Za-z0-9\-_~%$&*+=@/]"#,
        options: [.caseInsensitive]
    )

    private func apply(_ color: UIColor, to view: BubbleTextView) {
        view.textColor = color
        view.linkTextAttributes = [
            .foregroundColor: color,
            .underlineStyle: NSUnderlineStyle.single.rawValue
        ]
    }

    func sizeThatFits(
        _ proposal: ProposedViewSize,
        uiView: BubbleTextView,
        context: Context
    ) -> CGSize? {
        var width = proposal.width ?? .greatestFiniteMagnitude
        guard width > 0 else { return nil }
        if width.isFinite {
            // Propose whole points. Fractional widths make UITextView's
            // wrapping non-reproducible across layout passes, and any
            // non-convergent answer here can wedge SwiftUI in a layout loop.
            width = width.rounded(.down)
        }
        let measured = uiView.sizeThatFits(
            CGSize(width: width, height: .greatestFiniteMagnitude)
        )
        return CGSize(
            width: min(measured.width.rounded(.up), width),
            height: measured.height.rounded(.up)
        )
    }
}

final class BubbleTextView: UITextView {
    override func gestureRecognizerShouldBegin(
        _ gestureRecognizer: UIGestureRecognizer
    ) -> Bool {
        // Long press must fall through to the SwiftUI context menu on the
        // bubble; only pointer and double-tap selection stay on the text.
        if gestureRecognizer is UILongPressGestureRecognizer { return false }
        return super.gestureRecognizerShouldBegin(gestureRecognizer)
    }
}
