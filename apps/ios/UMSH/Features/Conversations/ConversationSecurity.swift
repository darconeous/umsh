import SwiftUI

/// Who, besides the people in it, can read what is written in a conversation.
///
/// About the key rather than the kind of conversation: what decides this is
/// how the key that seals the messages is come by. A channel whose key is
/// derived from a name protects nothing from anyone who knows the name, and
/// that is true however the channel was joined.
enum ConversationSecurity: Hashable, Sendable {
    /// Sealed to a key only the participants hold: a direct chat, or a private
    /// channel whose key was distributed out of band.
    case encrypted
    /// Readable by anyone within earshot. A named channel derives its key from
    /// something that is not a secret, and `EMERGENCY` carries its traffic in
    /// the clear.
    case open

    /// The colour an outbound message and its send button wear.
    ///
    /// Not a warning. An open channel is a legitimate place to talk and much
    /// of the traffic on the mesh belongs there; the colour says who can read
    /// what is being written, which is something the writer should know
    /// without having to go and look it up.
    var tint: Color {
        switch self {
        case .encrypted: .accentColor
        case .open: .green
        }
    }
}

extension ConversationListItem {
    var security: ConversationSecurity {
        switch self {
        case .direct:
            .encrypted
        case let .channel(conversation):
            switch conversation.channel.kind {
            case .privateKey: .encrypted
            case .builtin, .named: .open
            }
        }
    }
}
