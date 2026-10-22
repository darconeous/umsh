import SwiftUI
import UIKit

extension ConversationSecurity {
    /// The tint as text on a light quote: who a quote names, and whom a
    /// reply is being written to. The open channels' green is too pale to
    /// read at that size, so it darkens in light mode.
    var quoteNameColor: Color {
        switch self {
        case .encrypted:
            .accentColor
        case .open:
            Color(uiColor: UIColor { traits in
                traits.userInterfaceStyle == .dark
                    ? .systemGreen
                    : UIColor(red: 0x24 / 255, green: 0x8A / 255, blue: 0x3D / 255, alpha: 1)
            })
        }
    }
}

extension MessageQuote {
    /// The one line a quote shows of the original.
    var line: String {
        switch state {
        case .present: Self.oneLine(body)
        case .deleted: "Message deleted"
        case .unavailable: "Message not available"
        }
    }

    /// Whether ``line`` stands in for the original rather than quoting it.
    var isPlaceholder: Bool { state != .present }

    /// `text` on one line, so a quote truncates at its edge rather than at
    /// the original's first line break.
    static func oneLine(_ text: String) -> String {
        text.split(whereSeparator: \.isNewline).joined(separator: " ")
    }
}

/// A reply's quote of the message it answers, at the top of its bubble: a
/// bar, who said it, and one line of what they said.
///
/// Tapping it shows the original, while there is one to show.
struct ReplyQuoteView: View {
    let quote: MessageQuote
    /// Who sent the original, or `nil` when the quote cannot say.
    let name: String?
    /// Whether the bubble carrying it is mine, which is what it is tinted
    /// against.
    let isOutbound: Bool
    let security: ConversationSecurity
    var onOpen: (() -> Void)?

    var body: some View {
        // A button only while there is an original to show: a disabled one
        // fades its label, and a quote of a missing original should read
        // as plainly as any other.
        if let onOpen, quote.state == .present, quote.targetID != nil {
            Button(action: onOpen) { content }
                .buttonStyle(.plain)
                .accessibilityLabel(accessibilityLabel)
                .accessibilityHint("Shows the original")
        } else {
            content
                .accessibilityElement(children: .ignore)
                .accessibilityLabel(accessibilityLabel)
        }
    }

    private var content: some View {
        VStack(alignment: .leading, spacing: 1) {
            if let name {
                Text(name)
                    .font(.footnote.weight(.semibold))
                    .foregroundStyle(nameColor)
            }
            Text(quote.line)
                .font(.subheadline)
                .italic(quote.isPlaceholder)
                .foregroundStyle(lineColor)
        }
        .lineLimit(1)
        .padding(.leading, 17)
        .padding(.trailing, 10)
        .padding(.vertical, 6)
        // Fills whatever width the bubble settles on; ``ReplyStack``
        // measures it at its ideal width so it never widens the bubble
        // past what it has to say.
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(background, in: RoundedRectangle(cornerRadius: 13, style: .continuous))
        .overlay(alignment: .leading) {
            RoundedRectangle(cornerRadius: 1.5, style: .continuous)
                .fill(barColor)
                .frame(width: 3)
                .padding(.vertical, 7)
                .padding(.leading, 7)
        }
        .contentShape(RoundedRectangle(cornerRadius: 13, style: .continuous))
    }

    private var background: Color {
        isOutbound ? .white.opacity(0.2) : Color.primary.opacity(0.06)
    }

    private var barColor: Color {
        isOutbound ? .white : security.tint
    }

    private var nameColor: Color {
        isOutbound ? .white : security.quoteNameColor
    }

    private var lineColor: Color {
        isOutbound ? .white.opacity(0.85) : .secondary
    }

    private var accessibilityLabel: String {
        if let name { "Reply to \(name): \(quote.line)" } else { "Reply to \(quote.line)" }
    }
}

/// A reply's quote stacked over its text, as wide as the wider of the two.
///
/// The text is a `UITextView`, which converges on its width only when it is
/// offered the bubble's width alone (see ``ChatMessageBubble``), so it is
/// never laid out beside anything. The quote is measured at its ideal width
/// and capped at what the text was offered; whichever is wider sets the
/// bubble, and the quote then fills it.
struct ReplyStack: Layout {
    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        guard subviews.count == 2 else { return .zero }
        let (quote, text) = (subviews[0], subviews[1])
        let textSize = text.sizeThatFits(ProposedViewSize(width: proposal.width, height: nil))
        let quoteIdeal = quote.sizeThatFits(.unspecified).width
        let width = min(max(quoteIdeal, textSize.width), proposal.width ?? .infinity)
        let quoteHeight = quote.sizeThatFits(ProposedViewSize(width: width, height: nil)).height
        return CGSize(width: width, height: quoteHeight + textSize.height)
    }

    func placeSubviews(
        in bounds: CGRect,
        proposal: ProposedViewSize,
        subviews: Subviews,
        cache: inout ()
    ) {
        guard subviews.count == 2 else { return }
        let (quote, text) = (subviews[0], subviews[1])
        let quoteHeight = quote.sizeThatFits(ProposedViewSize(width: bounds.width, height: nil)).height
        quote.place(
            at: bounds.origin,
            proposal: ProposedViewSize(width: bounds.width, height: quoteHeight)
        )
        text.place(
            at: CGPoint(x: bounds.minX, y: bounds.minY + quoteHeight),
            proposal: ProposedViewSize(width: bounds.width, height: nil)
        )
    }
}

/// Whom and what the draft replies to, at the top of the composer.
struct ComposerReplyStrip: View {
    let name: String
    let line: String
    let security: ConversationSecurity
    let cancel: () -> Void

    var body: some View {
        HStack(spacing: 8) {
            VStack(alignment: .leading, spacing: 1) {
                Text("Replying to \(name)")
                    .font(.footnote.weight(.semibold))
                    .foregroundStyle(security.quoteNameColor)
                Text(line)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }
            .lineLimit(1)
            .frame(maxWidth: .infinity, alignment: .leading)
            Button(action: cancel) {
                Image(systemName: "xmark.circle.fill")
                    .font(.title3)
                    .symbolRenderingMode(.hierarchical)
                    .foregroundStyle(.secondary)
            }
            .buttonStyle(.plain)
            .accessibilityLabel("Cancel Reply")
        }
        .padding(.leading, 17)
        .padding(.trailing, 8)
        .padding(.vertical, 6)
        .background(Color.primary.opacity(0.05), in: RoundedRectangle(cornerRadius: 14, style: .continuous))
        .overlay(alignment: .leading) {
            RoundedRectangle(cornerRadius: 1.5, style: .continuous)
                .fill(security.tint)
                .frame(width: 3)
                .padding(.vertical, 7)
                .padding(.leading, 7)
        }
    }
}

/// Dragging a bubble toward the middle of the screen to reply to it.
///
/// The drag only moves the row as drawn, never its layout, and a reply
/// arrow fades in behind it. Past ``threshold`` there is a tick, and letting
/// go there starts the reply.
struct ReplySwipe: ViewModifier {
    static let threshold: CGFloat = 56

    let isOutbound: Bool
    let onReply: (() -> Void)?

    @State private var offset: CGFloat = 0
    @State private var isArmed = false

    func body(content: Content) -> some View {
        if let onReply {
            content
                .offset(x: offset)
                .background(alignment: isOutbound ? .trailing : .leading) {
                    Image(systemName: "arrowshape.turn.up.left")
                        .font(.body.weight(.medium))
                        .foregroundStyle(.secondary)
                        .frame(width: 34, height: 34)
                        .background(Color(uiColor: .systemGray5), in: Circle())
                        .scaleEffect(0.6 + 0.4 * progress)
                        .opacity(progress)
                        .accessibilityHidden(true)
                }
                .gesture(
                    ReplySwipeGesture(
                        isOutbound: isOutbound,
                        changed: { translation in
                            offset = resisted(translation)
                            isArmed = abs(translation) >= Self.threshold
                        },
                        ended: {
                            if isArmed { onReply() }
                            isArmed = false
                            withAnimation(UMSHAnimation.accessory) { offset = 0 }
                        }
                    )
                )
                .sensoryFeedback(.impact(flexibility: .soft), trigger: isArmed) { _, armed in armed }
        } else {
            content
        }
    }

    private var progress: CGFloat {
        min(abs(offset) / Self.threshold, 1)
    }

    /// The drag followed one to one up to the mark, and grudgingly past it.
    private func resisted(_ translation: CGFloat) -> CGFloat {
        let toward = isOutbound ? min(translation, 0) : max(translation, 0)
        let distance = abs(toward)
        let resisted = distance <= Self.threshold
            ? distance
            : Self.threshold + (distance - Self.threshold) * 0.3
        return isOutbound ? -resisted : resisted
    }
}

/// The pan behind ``ReplySwipe``.
///
/// A UIKit recognizer rather than a SwiftUI drag, because it has to decide
/// at the first movement whether it is a reply swipe at all—horizontal,
/// toward the middle, and clear of the edge the back gesture starts
/// from—and if not, get out of the way of the transcript's scrolling.
private struct ReplySwipeGesture: UIGestureRecognizerRepresentable {
    /// The width at the screen's leading edge left to the back gesture.
    static let backEdge: CGFloat = 24

    let isOutbound: Bool
    let changed: (CGFloat) -> Void
    let ended: () -> Void

    func makeCoordinator(converter: CoordinateSpaceConverter) -> Coordinator {
        Coordinator()
    }

    func makeUIGestureRecognizer(context: Context) -> UIPanGestureRecognizer {
        let pan = UIPanGestureRecognizer()
        pan.delegate = context.coordinator
        return pan
    }

    func updateUIGestureRecognizer(_ recognizer: UIPanGestureRecognizer, context: Context) {
        context.coordinator.isOutbound = isOutbound
    }

    func handleUIGestureRecognizerAction(_ recognizer: UIPanGestureRecognizer, context: Context) {
        switch recognizer.state {
        case .changed:
            changed(recognizer.translation(in: recognizer.view).x)
        case .ended, .cancelled, .failed:
            ended()
        default:
            break
        }
    }

    final class Coordinator: NSObject, UIGestureRecognizerDelegate {
        var isOutbound = false

        func gestureRecognizerShouldBegin(_ recognizer: UIGestureRecognizer) -> Bool {
            guard let pan = recognizer as? UIPanGestureRecognizer else { return false }
            let velocity = pan.velocity(in: pan.view)
            let towardMiddle = isOutbound ? velocity.x < 0 : velocity.x > 0
            let start = pan.location(in: nil).x
            return towardMiddle
                && abs(velocity.x) > abs(velocity.y) * 1.5
                && start > ReplySwipeGesture.backEdge
        }

        /// The transcript scrolls only once this has declined, which it does
        /// at the first movement that is not a reply swipe.
        func gestureRecognizer(
            _ recognizer: UIGestureRecognizer,
            shouldBeRequiredToFailBy other: UIGestureRecognizer
        ) -> Bool {
            other is UIPanGestureRecognizer && other.view is UIScrollView
                && !(other.view is UITextView)
        }
    }
}
