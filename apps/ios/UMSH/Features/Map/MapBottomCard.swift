import SwiftUI

/// How much of the card is showing.
///
/// Its own type rather than one nested in the generic card, so a view holding
/// the state does not have to name the card's content types to declare it.
enum MapCardDetent: CaseIterable {
    case peek
    case half
    case tall
}

extension MapCardDetent {
    /// How tall the card rests here, out of a region `availableHeight` tall.
    ///
    /// On the detent rather than inside the card because the map behind the
    /// card needs the same answer: this is how much of itself it cannot show,
    /// and a camera that does not know that aims at ground the card is
    /// sitting on. Two copies of the fractions would drift.
    ///
    /// Never the whole height, at any detent: the map has to stay visible
    /// enough to say where the list's contents are.
    func height(availableHeight: CGFloat, peekHeight: CGFloat) -> CGFloat {
        switch self {
        case .peek: peekHeight
        case .half: max(peekHeight, availableHeight * 0.45)
        case .tall: max(peekHeight, availableHeight * 0.88)
        }
    }
}

/// A panel that sits over the map and can be dragged between three heights.
///
/// A sheet would have been the idiomatic way to build this, and it is not
/// used: a sheet covers the tab bar, and the tabs have to stay reachable
/// while the map is open. So the card lives in the tab's own layout, its
/// glass running under the floating tab bar to the screen's bottom edge.
///
/// The drag follows Find My's rule for who owns a vertical swipe: while the
/// card is collapsed, the card does — the list cannot scroll at peek or
/// half, so pulling anywhere on the card moves the card. At tall the list
/// takes the vertical axis back for scrolling and the grabber and header
/// remain the card's drag surface. Horizontal swipes are never claimed, so
/// row swipe actions keep working.
struct MapBottomCard<Header: View, Content: View>: View {
    @Binding var detent: MapCardDetent
    /// How tall the card is allowed to get — the height of the region it is
    /// inset into. Supplied rather than measured: the card is what creates
    /// that region's inset, so measuring it from inside would be circular.
    let availableHeight: CGFloat
    /// How much of the bottom edge the floating tab bar covers. The card's
    /// frame runs underneath it — a panel that stopped short would leave a
    /// strip of map showing through the bar's glass — and its list runs down
    /// with it, rows frosting through the bar the way Find My's do. The same
    /// amount becomes the list's bottom scroll margin, so every row can
    /// scroll clear of the bar.
    var bottomInset: CGFloat = 0
    /// How much shows at the lowest detent. Supplied for the same reason as
    /// the rest of the geometry: what the card covers is a fact the map has
    /// to aim around, and the map cannot ask the card after the fact.
    let peekHeight: CGFloat
    @ViewBuilder var header: () -> Header
    @ViewBuilder var content: () -> Content

    /// Plain state rather than `@GestureState`: the automatic reset is
    /// instant, which made a drag that ends inside its starting detent snap
    /// home with no animation. Ending the gesture animates this back to
    /// zero by hand instead.
    @State private var dragOffset: CGFloat = 0
    /// Decided on the first movement and held for the rest of the gesture,
    /// so a swipe that starts horizontal stays a row's swipe even if the
    /// finger wanders.
    @State private var dragIsVertical: Bool?

    var body: some View {
        VStack(spacing: 0) {
            VStack(spacing: 8) {
                // The only thing saying the card moves, over a material that
                // is itself over a map — a fainter fill disappears into
                // whatever happens to be underneath.
                Capsule()
                    .fill(.secondary)
                    .frame(width: 40, height: 5)
                header()
            }
            .padding(.top, 8)
            .padding(.bottom, 10)
            .frame(maxWidth: .infinity)
            .contentShape(.rect)
            .gesture(dragGesture)
            .accessibilityElement(children: .contain)
            .accessibilityAction(named: "Expand") { move(by: 1) }
            .accessibilityAction(named: "Collapse") { move(by: -1) }

            content()
                .frame(maxHeight: .infinity, alignment: .top)
                // Collapsed, the vertical axis belongs to the card; the
                // list scrolls only at tall. Without this the two fight
                // over every swipe and the loser is whoever the reader
                // expected to win.
                .scrollDisabled(detent != .tall)
                // Margins rather than padding: scrollable content may run
                // under the tab bar — that is the point — but it has to be
                // able to scroll back out.
                .contentMargins(.bottom, bottomInset, for: .scrollContent)
                .contentMargins(.bottom, bottomInset, for: .scrollIndicators)
        }
        .frame(height: height + bottomInset, alignment: .top)
        .frame(maxWidth: .infinity)
        .clipShape(UnevenRoundedRectangle(topLeadingRadius: 16, topTrailingRadius: 16))
        .background(
            .regularMaterial,
            in: UnevenRoundedRectangle(topLeadingRadius: 16, topTrailingRadius: 16)
        )
        .shadow(color: .black.opacity(0.15), radius: 8, y: -2)
        .contentShape(.rect)
        // At tall this card-wide gesture stands down (`.subviews`) so the
        // list can scroll; the header's copy of the gesture is a subview's,
        // so the grabber still drags from anywhere the card can be.
        .gesture(dragGesture, including: detent == .tall ? .subviews : .all)
        .animation(.spring(response: 0.35, dampingFraction: 0.85), value: detent)
    }

    /// Where the top edge sits right now: the resting height adjusted by the
    /// finger (down is positive, so subtracting shrinks the card), with the
    /// travel past either end divided down — movement that still follows the
    /// finger, but reluctantly, which is what says "there is no more".
    private var height: CGFloat {
        let raw = restingHeight(for: detent) - dragOffset
        if raw > maxHeight { return maxHeight + (raw - maxHeight) / 4 }
        if raw < peekHeight { return peekHeight - (peekHeight - raw) / 4 }
        return raw
    }

    private var dragGesture: some Gesture {
        // Global space, without exception: the gesture rides a view that
        // moves with the drag, and translations measured in the moving
        // space feed back into the height that moves it — the finger holds
        // still, the card chases it, and the reading collapses to zero.
        // Screen space is the one place the finger's travel is just the
        // finger's travel.
        DragGesture(minimumDistance: 8, coordinateSpace: .global)
            .onChanged { value in
                if dragIsVertical == nil {
                    dragIsVertical = abs(value.translation.height)
                        >= abs(value.translation.width)
                }
                guard dragIsVertical == true else { return }
                dragOffset = value.translation.height
            }
            .onEnded { value in
                let wasVertical = dragIsVertical == true
                dragIsVertical = nil
                guard wasVertical else { return }
                // Where the finger was headed, not where it stopped, so a
                // flick reaches the next detent without having to travel
                // there.
                let projected = restingHeight(for: detent)
                    - value.predictedEndTranslation.height
                let target = MapCardDetent.allCases.min {
                    abs(restingHeight(for: $0) - projected)
                        < abs(restingHeight(for: $1) - projected)
                } ?? detent
                withAnimation(.spring(response: 0.35, dampingFraction: 0.85)) {
                    detent = target
                    dragOffset = 0
                }
            }
    }

    private func move(by steps: Int) {
        let order = MapCardDetent.allCases
        guard let index = order.firstIndex(of: detent) else { return }
        let next = min(max(index + steps, 0), order.count - 1)
        detent = order[next]
    }

    private func restingHeight(for detent: MapCardDetent) -> CGFloat {
        detent.height(availableHeight: availableHeight, peekHeight: peekHeight)
    }

    private var maxHeight: CGFloat { restingHeight(for: .tall) }
}
