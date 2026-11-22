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
