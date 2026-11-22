package com.voria.umsh.models

/** A node hint: its bytes and the text the core rendered for them. */
data class NodeHint(val octets: Octets, val text: String) {
    /** The avatar fill, `0xRRGGBB`, or null for a hint shorter than three bytes. */
    val rgb: Int?
        get() = if (octets.size < 3) {
            null
        } else {
            ((octets[0].toInt() and 0xFF) shl 16) or
                ((octets[1].toInt() and 0xFF) shl 8) or
                (octets[2].toInt() and 0xFF)
        }
}

/** A node's role, from its advertisement's role code or its stored kind. */
enum class PeerRole(val code: Int?) {
    Repeater(1),
    Chat(2),
    Tracker(3),
    Sensor(4),
    Bridge(5),
    ChatRoom(6),
    TemporarySession(7),
    Unknown(null),
    ;

    companion object {
        /** The role a code names; [Unknown] for a code this app does not know. */
        fun forCode(code: Int): PeerRole = entries.firstOrNull { it.code == code } ?: Unknown
    }
}

/** Whether a node's advertisement carried a signature, and whether it held. */
enum class SignatureState { Unsigned, Valid, Invalid }

/** What a node said about itself in its latest advertisement. */
data class AdvertisedIdentity(
    val roleCode: Int,
    val capabilityBits: Int,
    val forwards: Boolean,
    val name: String?,
    val latitude: Double?,
    val longitude: Double?,
    val locationPrecision: Int?,
    val altitudeMeters: Int?,
    val timestamp: Long?,
    val signature: SignatureState,
) {
    val role: PeerRole get() = PeerRole.forCode(roleCode)
}

/** A node this phone knows, as one state read found it. */
data class PeerSummary(
    val id: Long,
    val address: String,
    val hint: NodeHint,
    val alias: String?,
    val advertisedName: String?,
    /** The node is the companion radio this phone set up. */
    val isCompanionRadio: Boolean,
    val storedRole: PeerRole,
    val advertised: AdvertisedIdentity?,
    val advertisementAuthenticated: Boolean,
    val advertisementReceivedAtMs: Long?,
    val lastHeardAtMs: Long?,
    val isSaved: Boolean,
    val isFavorite: Boolean,
    val isOnDeviceIdentity: Boolean,
    val notifyWhenHeard: Boolean,
) {
    /** The live advertisement's role when there is one, else the stored kind. */
    val role: PeerRole get() = advertised?.role ?: storedRole
}
