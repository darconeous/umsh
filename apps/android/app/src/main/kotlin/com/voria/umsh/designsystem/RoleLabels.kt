package com.voria.umsh.designsystem

import android.icu.text.ListFormatter
import androidx.annotation.StringRes
import androidx.compose.runtime.Composable
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.res.stringResource
import com.voria.umsh.R
import com.voria.umsh.models.Capabilities
import com.voria.umsh.models.PeerRole
import com.voria.umsh.models.PeerSummary

/** The role's name, in the reader's language. */
@get:StringRes
val PeerRole.labelRes: Int
    get() = when (this) {
        PeerRole.Repeater -> R.string.role_repeater
        PeerRole.Chat -> R.string.role_chat
        PeerRole.Tracker -> R.string.role_tracker
        PeerRole.Sensor -> R.string.role_sensor
        PeerRole.Bridge -> R.string.role_bridge
        PeerRole.ChatRoom -> R.string.role_chat_room
        PeerRole.TemporarySession -> R.string.role_temporary_session
        PeerRole.Unknown -> R.string.role_unknown
    }

@Composable
fun PeerRole.label(): String = stringResource(labelRes)

/**
 * How a role byte is described: its name, or "Role 9" for one this app
 * has no name for. The node did claim something, so it stays visible.
 */
@Composable
fun roleLabelForCode(code: Int): String {
    val role = PeerRole.forCode(code)
    return if (role == PeerRole.Unknown) stringResource(R.string.role_code, code) else role.label()
}

/**
 * A peer row's second line: "Companion radio" for this phone's own radio,
 * else its role; null when the role is unknown and the row has one line.
 */
@Composable
fun peerRoleLine(peer: PeerSummary): String? = when {
    peer.isCompanionRadio -> stringResource(R.string.companion_radio)
    peer.role == PeerRole.Unknown -> null
    else -> peer.role.label()
}

/** Each capability's name, by its bit. */
@StringRes
fun capabilityLabelRes(capability: Int): Int? = when (capability) {
    Capabilities.REPEATER -> R.string.capability_repeater
    Capabilities.MOBILE -> R.string.capability_mobile
    Capabilities.TEXT_MESSAGES -> R.string.capability_text_messages
    Capabilities.TELEMETRY -> R.string.capability_telemetry
    Capabilities.CHAT_ROOM -> R.string.capability_chat_room
    Capabilities.COAP -> R.string.capability_coap
    else -> null
}

/** The names of the capabilities set, in wire order; bits with no name are left out. */
@Composable
fun Capabilities.named(): List<String> =
    Capabilities.NAMED.filter { contains(it) }.mapNotNull { capabilityLabelRes(it) }.map { stringResource(it) }

/** [named] as one list in the reader's language: "Mobile and Text messages". */
@Composable
fun Capabilities.listText(): String =
    ListFormatter.getInstance(LocalConfiguration.current.locales[0]).format(named())
