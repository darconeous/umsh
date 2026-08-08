import SwiftUI

private enum ChipStyle { case mine, failed, theirs }

/// The reactions on one message, as thought bubbles over its top corner.
///
/// Its own shapes rather than anything grafted onto `BubbleShape`: that path
/// is one closed outline for a reason, and a chip is a separate object
/// floating over the bubble, not part of its silhouette.
struct ReactionBadgeView: View {
    /// How much room a reacted message must reserve above its bubble. The
    /// chips live mostly in that space, dipping only a little way onto the
    /// bubble's corner, so they never spill into the row above and be drawn
    /// under it — and so their page-colour halos are never sliced at the
    /// reserved space's edge.
    static let overhang: CGFloat = 30
    /// How much room is reserved on the bubble's *outer* side. The corner
    /// chip overhangs the bubble's edge by about half its width, and the
    /// thought-dot trail falls entirely outside the bubble, in this strip.
    static let outset: CGFloat = 32
    /// Insets keeping every part of the cluster — halos, count circles, the
    /// dot trail — inside the reserved space, where nothing can clip them.
    static let topInset: CGFloat = 6
    static let cornerInset: CGFloat = 15

    let reactions: [MessageReaction]
    /// The direction of the message being reacted to. Chips sit over its
    /// outer top corner, so everything mirrors with it.
    let isOutbound: Bool
    /// The conversation's protection, which colours our own chips the same as
    /// the bubbles we send here.
    let security: ConversationSecurity

    /// Identical reactions share a chip and carry a count — except one of ours
    /// that failed to send, which stays on its own so its faded state never
    /// gets averaged away by someone else's copy of the same glyph.
    fileprivate struct Chip: Identifiable {
        let id: String
        let glyph: String
        let count: Int
        let style: ChipStyle
    }

    private var chips: [Chip] {
        var grouped: [(glyph: String, count: Int, mine: Bool)] = []
        var failed: [Chip] = []
        for reaction in reactions {
            if reaction.isFailed {
                failed.append(
                    Chip(id: reaction.id, glyph: reaction.glyph, count: 1, style: .failed)
                )
            } else if let index = grouped.firstIndex(where: { $0.glyph == reaction.glyph }) {
                grouped[index].count += 1
                grouped[index].mine = grouped[index].mine || reaction.isMine
            } else {
                grouped.append((reaction.glyph, 1, reaction.isMine))
            }
        }
        return grouped.map {
            Chip(id: $0.glyph, glyph: $0.glyph, count: $0.count, style: $0.mine ? .mine : .theirs)
        } + failed
    }

    var body: some View {
        // Chips overlap like a hand of cards, the way Messages draws a
        // cluster of tapbacks: the chip nearest the bubble's corner — ours,
        // when we have one — sits in front, and it alone carries the
        // thought-dot trail down to the bubble. One trail per cluster; a
        // trail per chip reads as several thoughts instead of one.
        let ordered = orderedChips
        let cornerIndex = isOutbound ? 0 : ordered.count - 1
        HStack(spacing: -8) {
            ForEach(Array(ordered.enumerated()), id: \.element.id) { index, chip in
                ThoughtChip(
                    glyph: chip.glyph,
                    count: chip.count,
                    style: chip.style,
                    security: security,
                    // The dots trail off the message's outer side, away from
                    // the text they belong to.
                    mirrored: !isOutbound,
                    showsDots: index == cornerIndex
                )
                // Frontmost at the corner, receding away from it.
                .zIndex(Double(isOutbound ? ordered.count - index : index))
            }
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(accessibilityLabel)
    }

    /// Chips arranged so ours ends up nearest the bubble's corner: leading
    /// for an outbound message, trailing for an inbound one.
    private var orderedChips: [Chip] {
        let all = chips
        let mine = all.filter { $0.style != .theirs }
        let theirs = all.filter { $0.style == .theirs }
        return isOutbound ? mine + theirs : theirs + mine
    }

    /// Reactions have to read as text as well as colour and glyph.
    private var accessibilityLabel: String {
        "Reactions: " + reactions.map(\.accessibilityDescription).joined(separator: ", ")
    }
}

private struct ThoughtChip: View {
    /// A thought bubble is round. The glyph is sized to fit rather than the
    /// bubble stretched to hold it, so a chip is never a pill.
    private static let diameter: CGFloat = 34

    let glyph: String
    let count: Int
    let style: ChipStyle
    let security: ConversationSecurity
    /// Dots on the trailing side rather than the leading one.
    let mirrored: Bool
    /// Whether this chip carries the cluster's thought-dot trail — true only
    /// for the chip nearest the bubble's corner.
    let showsDots: Bool

    private var fill: Color {
        switch style {
        case .mine, .failed: security.tint
        case .theirs: Color(uiColor: .systemGray5)
        }
    }

    /// A reaction that could not be sent is the same chip, faded — enough to
    /// read as unfinished without dressing an ordinary tap up as an error.
    private var opacity: Double {
        style == .failed ? 0.5 : 1
    }

    /// A circle of the page colour, two points proud of whatever it backs.
    private var halo: some View {
        Circle()
            .fill(Color(uiColor: .systemBackground))
            .padding(-2)
    }

    var body: some View {
        Text(glyph)
            .font(.system(size: 19))
            .frame(width: Self.diameter, height: Self.diameter)
            .background(fill, in: Circle())
            // A ring of the page colour, so a grey chip on a grey bubble is
            // still a separate object — the chips sit on the bubble, and
            // without this the inbound pair merges into one shape.
            .background(halo)
            .overlay(alignment: mirrored ? .topTrailing : .topLeading) {
                // How many people sent this one, when it is more than one.
                // Its own small circle so the chip itself stays round.
                if count > 1 {
                    Text("\(count)")
                        .font(.system(size: 9, weight: .semibold))
                        .foregroundStyle(Color(uiColor: .label))
                        .frame(width: 14, height: 14)
                        .background(Color(uiColor: .systemBackground), in: Circle())
                        .offset(x: mirrored ? 5 : -5, y: -5)
                }
            }
            .overlay(alignment: mirrored ? .bottomTrailing : .bottomLeading) {
                // Two detached circles: what makes the cluster a thought
                // bubble rather than a badge. Sized and placed to fall away
                // from the chip toward the corner it sits over.
                if showsDots {
                    ZStack {
                        Circle()
                            .fill(fill)
                            .frame(width: 10, height: 10)
                            .background(halo)
                            .offset(x: mirrored ? 6 : -6, y: 6)
                        Circle()
                            .fill(fill)
                            .frame(width: 5, height: 5)
                            .background(halo)
                            .offset(x: mirrored ? 13 : -13, y: 13)
                    }
                }
            }
            .opacity(opacity)
    }
}

#Preview("Reactions") {
    VStack(alignment: .trailing, spacing: 24) {
        ReactionBadgeView(
            reactions: [
                MessageReaction(
                    body: "<3", isMine: true, senderAddress: nil, senderHint: nil,
                    sessionID: "1", handle: 1, wireID: 1, epoch: 0, isFailed: false
                )
            ],
            isOutbound: true,
            security: .encrypted
        )
        ReactionBadgeView(
            reactions: [
                MessageReaction(
                    body: "+1", isMine: false, senderAddress: "abc", senderHint: nil,
                    sessionID: "1", handle: 2, wireID: 2, epoch: 0, isFailed: false
                ),
                MessageReaction(
                    body: "haha", isMine: true, senderAddress: nil, senderHint: nil,
                    sessionID: "1", handle: 3, wireID: 3, epoch: 0, isFailed: true
                ),
            ],
            isOutbound: false,
            security: .open
        )
    }
    .padding()
}
