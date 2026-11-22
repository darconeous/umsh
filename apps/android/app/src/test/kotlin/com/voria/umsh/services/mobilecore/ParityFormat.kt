package com.voria.umsh.services.mobilecore

import com.voria.umsh.models.AdvertisedIdentity
import com.voria.umsh.models.AppStateSnapshot
import com.voria.umsh.models.ChannelKind
import com.voria.umsh.models.ChatMessage
import com.voria.umsh.models.ConversationPreview
import com.voria.umsh.models.DeliveryState
import com.voria.umsh.models.MessageRef
import com.voria.umsh.models.Octets
import com.voria.umsh.models.PeerRole
import com.voria.umsh.models.Presence
import com.voria.umsh.models.Quote
import com.voria.umsh.models.Reaction
import com.voria.umsh.models.Reception
import com.voria.umsh.models.RepeaterNeighbor
import com.voria.umsh.models.Repeats
import com.voria.umsh.models.SignatureState
import java.io.File
import java.util.Locale

/**
 * The parity goldens' text format
 * (`crates/umsh-mobile-core/src/app_core/parity/README.md`), rendered from
 * the app's models.
 */
object ParityFormat {
    val directory = File(System.getProperty("umsh.repoDir")!!, "crates/umsh-mobile-core/src/app_core/parity")

    // region State

    fun stateLines(state: AppStateSnapshot): List<String> {
        val lines = mutableListOf<String>()
        for (peer in state.peers) {
            val role = if (peer.storedRole == PeerRole.Unknown) "-" else peer.storedRole.name.lowercase()
            lines += "peer id=${peer.id} address=${str(peer.address)} hint=${str(peer.hint.text)}" +
                " alias=${opt(peer.alias, ::str)} advertised_name=${opt(peer.advertisedName, ::str)}" +
                " system_role=${if (peer.isCompanionRadio) "companionradio" else "-"} node_kind=$role" +
                " advertised=${opt(peer.advertised, ::identity)}" +
                " authenticated=${peer.advertisementAuthenticated}" +
                " received_at=${opt(peer.advertisementReceivedAtMs) { it.toString() }}" +
                " last_heard=${opt(peer.lastHeardAtMs) { it.toString() }} saved=${peer.isSaved}" +
                " favorite=${peer.isFavorite} on_device=${peer.isOnDeviceIdentity}" +
                " notify_when_heard=${peer.notifyWhenHeard}"
        }
        for (channel in state.channels) {
            val kind = when (channel.kind) {
                ChannelKind.Builtin -> "builtin"
                ChannelKind.Named -> "named"
                ChannelKind.PrivateKey -> "privatekey"
            }
            lines += "channel id=${str(channel.id)} kind=$kind" +
                " canonical_name=${opt(channel.canonicalName, ::str)} name=${opt(channel.name, ::str)}" +
                " alias=${opt(channel.alias, ::str)} channel_id_hex=${str(channel.channelIdHex)}" +
                " tint=${bytes(channel.tint)} region_code=${opt(channel.regionCode, ::bytes)}" +
                " max_flood_hops=${opt(channel.maxFloodHops) { it.toString() }}" +
                " joined_phone=${channel.joinedPhone}" +
                " notifications=${channel.notificationsEnabled} joined_at=${opt(channel.joinedAtMs) { it.toString() }}"
        }
        for (conversation in state.directConversations) {
            lines += "direct id=${conversation.id} peer=${str(conversation.peer.address)}" +
                " draft=${str(conversation.draftText)} unread=${conversation.unreadCount}" +
                " created=${conversation.createdAtMs}" +
                " notifications=${conversation.notificationsEnabled}" +
                " last=${opt(conversation.lastMessage, ::preview)}"
        }
        for (conversation in state.channelConversations) {
            lines += "channel_conversation id=${conversation.id}" +
                " channel=${str(conversation.channel.id)}" +
                " address=${str(conversation.address)} draft=${str(conversation.draftText)}" +
                " unread=${conversation.unreadCount} created=${conversation.createdAtMs}" +
                " last=${opt(conversation.lastMessage, ::preview)}"
        }
        for (report in state.neighborReports) {
            lines += "report reporter=${str(report.reporter.address)} neighbor=${neighbor(report.neighbor, state)}"
        }
        return lines
    }

    private fun identity(value: AdvertisedIdentity) = record(
        "role" to value.roleCode.toString(),
        "capabilities" to value.capabilityBits.toString(),
        "forwards" to value.forwards.toString(),
        "name" to opt(value.name, ::str),
        "latitude" to opt(value.latitude, ::float),
        "longitude" to opt(value.longitude, ::float),
        "precision" to opt(value.locationPrecision) { it.toString() },
        "altitude" to opt(value.altitudeMeters) { it.toString() },
        "timestamp" to opt(value.timestamp) { it.toString() },
        "signature" to when (value.signature) {
            SignatureState.Unsigned -> "unsigned"
            SignatureState.Valid -> "valid"
            SignatureState.Invalid -> "invalid"
        },
    )

    private fun preview(value: ConversationPreview) = record(
        "created" to value.createdAtMs.toString(),
        "body" to str(value.body),
        "outbound" to value.isOutbound.toString(),
        "deleted" to value.isDeleted.toString(),
        "sender_address" to opt(value.senderAddress, ::str),
        "sender_hint" to opt(value.senderHint, ::bytes),
        "status" to value.isStatus.toString(),
        "sender_node_hint" to opt(value.senderNodeHint?.text, ::str),
    )

    fun neighbor(value: RepeaterNeighbor, state: AppStateSnapshot) = record(
        "hint" to bytes(value.hint),
        "hint_text" to str(value.hintText),
        "name" to opt(value.name, ::str),
        "rssi" to opt(value.rssiDbm) { it.toString() },
        "snr" to opt(value.snrQuarterDb) { it.toString() },
        "last_heard_minutes" to opt(value.lastHeardMinutes) { it.toString() },
        "latitude" to opt(value.latitude, ::float),
        "longitude" to opt(value.longitude, ::float),
        "precision" to opt(value.locationPrecision) { it.toString() },
        "regions" to list(value.regionCodes.map(::bytes)),
        "reported_at" to value.reportedAtMs.toString(),
        "peer" to opt(value.peerAddress?.takeIf { address -> state.peers.any { it.address == address } }, ::str),
    )

    // endregion

    // region Transcript

    fun messageLine(message: ChatMessage) =
        "message id=${str(id(message.ref))}" +
            " cursor=${message.cursor.createdAtMs}/${message.cursor.rowId}" +
            " created=${message.createdAtMs} body=${str(message.body)}" +
            " outbound=${message.isOutbound} delivery=${opt(message.delivery, ::delivery)}" +
            " deleted=${message.isDeleted} edited=${message.isEdited}" +
            " wire=${opt(message.wireId) { it.toString() }} epoch=${opt(message.epoch) { it.toString() }}" +
            " presence=${presence(message.presence)} received_late=${message.isReceivedLate}" +
            " delivered_late=${message.isDeliveredLate}" +
            " delivered_flooded=${message.isDeliveredFlooded}" +
            " edit_of_unknown=${message.isEditOfUnknown} status=${message.isStatus}" +
            " forward_secret=${message.isForwardSecret}" +
            " original_body=${opt(message.originalBody, ::str)}" +
            " sender_address=${opt(message.senderAddress, ::str)}" +
            " sender_hint=${opt(message.senderHint, ::bytes)}" +
            " sender_handle=${opt(message.senderHandle, ::str)}" +
            " sender_node_hint=${opt(message.senderNodeHint?.text, ::str)}" +
            " reception=${opt(message.reception, ::reception)}" +
            " reactions=${list(message.reactions.map(::reaction))}" +
            " quote=${opt(message.quote, ::quote)}" +
            " repeats=${opt(message.repeats, ::repeats)}"

    private fun id(ref: MessageRef) = "${ref.sessionId}:${ref.handle}"

    private fun presence(value: Presence) = when (value) {
        Presence.Present -> "present"
        Presence.GapPending -> "gappending"
        Presence.GapIdle -> "gapidle"
        Presence.Unavailable -> "unavailable"
    }

    private fun delivery(value: DeliveryState) = value.name.lowercase()

    private fun reception(value: Reception) = record(
        "rssi" to opt(value.rssiDbm) { it.toString() },
        "snr" to opt(value.snrCentibels) { it.toString() },
        "lqi" to opt(value.lqi) { it.toString() },
        "hops" to opt(value.hopCount) { it.toString() },
        "routes" to list(value.routeHints.map(::bytes)),
        "authenticated" to value.sourceAuthenticated.toString(),
    )

    private fun reaction(value: Reaction) = record(
        "body" to str(value.body),
        "mine" to value.isMine.toString(),
        "sender_address" to opt(value.senderAddress, ::str),
        "sender_hint" to opt(value.senderHint, ::bytes),
        "target" to str(id(value.ref)),
        "wire" to opt(value.wireId) { it.toString() },
        "epoch" to opt(value.epoch) { it.toString() },
        "failed" to value.isFailed.toString(),
        "forward_secret" to value.isForwardSecret.toString(),
    )

    private fun quote(value: Quote): String = when (value) {
        Quote.Unavailable -> "unavailable"
        is Quote.Original -> record(
            "state" to if (value.isDeleted) "deleted" else "present",
            "target" to str(id(value.target)),
            "body" to str(value.body),
            "outbound" to value.isOutbound.toString(),
            "sender_address" to opt(value.senderAddress, ::str),
            "sender_handle" to opt(value.senderHandle, ::str),
            "sender_node_hint" to opt(value.senderNodeHint?.text, ::str),
        )
    }

    private fun repeats(value: Repeats) = record(
        "anonymous" to value.anonymous.toString(),
        "progress_at" to value.progressAtMs.toString(),
        "repeaters" to list(
            value.repeaters.map {
                record("hint" to bytes(it.hint), "text" to str(it.text), "peer" to opt(it.peerAddress, ::str))
            },
        ),
    )

    // endregion

    // region Values

    fun bytewise(a: String, b: String): Int {
        val x = a.toByteArray(Charsets.UTF_8)
        val y = b.toByteArray(Charsets.UTF_8)
        for (i in 0 until minOf(x.size, y.size)) {
            val d = (x[i].toInt() and 0xFF) - (y[i].toInt() and 0xFF)
            if (d != 0) return d
        }
        return x.size - y.size
    }

    fun <T> opt(value: T?, encode: (T) -> String) = value?.let(encode) ?: "-"

    private fun float(value: Double) = String.format(Locale.ROOT, "%.7f", value)

    fun bytes(value: Octets) = "x" + value.hex()

    private fun list(items: List<String>) = items.joinToString(",", "[", "]")

    private fun record(vararg fields: Pair<String, String>) =
        fields.joinToString(" ", "{", "}") { "${it.first}=${it.second}" }

    private fun str(value: String): String {
        val out = StringBuilder("\"")
        value.codePoints().forEach { c ->
            when {
                c == '\\'.code -> out.append("\\\\")
                c == '"'.code -> out.append("\\\"")
                c == '\n'.code -> out.append("\\n")
                c == '\r'.code -> out.append("\\r")
                c == '\t'.code -> out.append("\\t")
                c < 0x20 -> out.append("\\u{").append(Integer.toHexString(c)).append("}")
                else -> out.appendCodePoint(c)
            }
        }
        return out.append('"').toString()
    }

    // endregion
}
