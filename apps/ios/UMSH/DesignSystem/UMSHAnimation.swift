import SwiftUI

/// The app's shared motion vocabulary, and where each kind of motion belongs.
///
/// Most of what moves in this app moves because state arrived from somewhere
/// else—a store reload, a radio stream, a discovery scan—and landed as a
/// plain assignment resumed from an `await`. An async continuation carries no
/// animation, so those changes animate only where the view says what is worth
/// animating about them:
///
/// ```swift
/// .animation(UMSHAnimation.list, value: items.map(\.id))
/// ```
///
/// Keyed on the narrowest value that should move the view. The key matters as
/// much as the curve: a conversation summary changes on every delivery receipt
/// and draft keystroke, and a list keyed on the whole array would put its rows
/// in motion while the reader types.
///
/// Two other kinds of motion are not this, and do not belong here:
///
/// - A change the view itself causes—a drag settling, a map flying to a
///   node, a scroll gliding home—animates with `withAnimation` at the
///   gesture, where the cause is known.
/// - A *correction*—the transcript holding its viewport still across a
///   prepend or a trim—must be invisible, and suppresses animation with
///   `transaction.disablesAnimations` at the mutation. View-side animation is
///   never layered over transcript content for that reason; an overlay above
///   it, which moves no rows, is fine.
enum UMSHAnimation {
    /// Rows arriving, leaving, or reordering in a list published from storage
    /// or a live scan.
    static let list: Animation = .default

    /// A small piece of chrome appearing or leaving beside stable content:
    /// banner, badge, chip, button.
    static let accessory: Animation = .spring(duration: 0.2)
}
