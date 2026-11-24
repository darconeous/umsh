package com.voria.umsh.models

enum class ChannelKind { Builtin, Named, PrivateKey }

/** A channel this phone holds, as one state read found it. */
data class ChannelSummary(
    /** The channel's UUID, uppercase, as the store keeps it. */
    val id: String,
    val kind: ChannelKind,
    /** `public` and `emergency` for the built-in channels. */
    val canonicalName: String?,
    val name: String?,
    val alias: String?,
    val channelIdHex: String,
    val tint: Octets,
    val regionCode: Octets?,
    val maxFloodHops: Int?,
    val joinedPhone: Boolean,
    val notificationsEnabled: Boolean,
    val joinedAtMs: Long?,
    /** Its conversation's address, when it has one. */
    val conversationAddress: String?,
)

/**
 * A channel name or invitation, read before anything is joined
 * (`channels.svg` 6–9): what it is, and how it meets the channels this
 * phone holds. The key is kept only as long as the preview is shown.
 */
class ChannelPreview(
    /** The text it was read from; joining hands it back to the core, which reads it again. */
    val input: String,
    /** True for an invitation that carries its key; false for a name. */
    val isPrivate: Boolean,
    /** The lowercase name the key derives from, for a name. */
    val canonicalName: String?,
    /** The name the invitation suggests, as written. */
    val displayName: String?,
    val key: Octets,
    val channelIdHex: String,
    val tint: Octets,
    /** The channel this phone already holds under the same key, joined or left. */
    val existing: ChannelSummary?,
    /** Another channel this phone holds called the same, ignoring case. */
    val nameConflict: ChannelSummary?,
) {
    /** Joining only updates a channel already joined (board 8). */
    val alreadyJoined: Boolean get() = existing?.joinedPhone == true

    /** The channel as a badge draws it: named as the invitation names it. */
    val summary: ChannelSummary
        get() = ChannelSummary(
            id = "",
            kind = if (isPrivate) ChannelKind.PrivateKey else ChannelKind.Named,
            canonicalName = canonicalName,
            name = displayName ?: canonicalName,
            alias = null,
            channelIdHex = channelIdHex,
            tint = tint,
            regionCode = null,
            maxFloodHops = null,
            joinedPhone = false,
            notificationsEnabled = false,
            joinedAtMs = null,
            conversationAddress = null,
        )
}

/** A channel joined: its ID, and its conversation when the join opened it. */
data class JoinedChannel(val channelId: String, val conversationAddress: String?)
