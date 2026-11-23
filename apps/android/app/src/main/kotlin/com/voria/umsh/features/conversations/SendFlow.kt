package com.voria.umsh.features.conversations

import androidx.annotation.StringRes
import com.voria.umsh.R
import com.voria.umsh.models.ChatMessage
import com.voria.umsh.models.Presence
import com.voria.umsh.models.ResendMode

/** What the composer is writing: a new message, a reply, or new words for one of mine. */
sealed interface ComposeMode {
    data object Plain : ComposeMode

    /** Replying to [message]: the strip above the field quotes it. */
    data class Replying(val message: ChatMessage) : ComposeMode

    /** New words for [message], in a field of their own: the draft is left alone. */
    data class Editing(val message: ChatMessage) : ComposeMode
}

/** What the thread must tell the person, once, as a dialog. */
sealed interface ThreadAlert {
    /** Send tapped while the radio is still connecting: nothing was tried. */
    data object StillConnecting : ThreadAlert

    /** A message refused before it was kept; its words stay in the composer. */
    data class NotSent(val error: Throwable) : ThreadAlert

    /** Kept but not sent (`composer.svg` 9's "Message submitted"), one body per [recorded]. */
    data class Submitted(val recorded: Boolean) : ThreadAlert

    /** Something other than a new message did not go out: [title] says what. */
    data class Failed(@param:StringRes val title: Int, val error: Throwable) : ThreadAlert
}

/** `EMERGENCY`'s warning, shown before a transmission there; [sends] when it is a new message. */
data class EmergencyPrompt(val sends: Boolean)

/** The resend dialog (`bubbles.svg` 5) for [message], worded by how the core would first send it. */
data class ResendPrompt(val message: ChatMessage, val mode: ResendMode) {
    /** First sent under forward secrecy: the dialog adds Send without forward secrecy. */
    val offersWithoutForwardSecrecy: Boolean get() = message.isForwardSecret
}

/** One item of the message menu (`bubbles.svg` 3), in the order it is drawn. */
enum class MenuItem(@param:StringRes val label: Int) {
    Reply(R.string.menu_reply),
    Copy(R.string.menu_copy),
    ViewOriginal(R.string.menu_view_original),
    TryAgain(R.string.menu_try_again),
    Resend(R.string.menu_resend),
    Edit(R.string.menu_edit),
    Details(R.string.menu_details),
    Delete(R.string.menu_delete),
}

/**
 * What the long-press menu offers for a message: only what its row's
 * `actions` say the core would take, besides Copy and Details, which are
 * the app's own. Pure, so the JVM tests cover each kind.
 */
object MessageMenu {
    /** Whether [message] has a menu at all: a deleted line, a gap or an unavailable one has none. */
    fun hasMenu(message: ChatMessage): Boolean = !message.isDeleted && message.presence == Presence.Present

    fun reactions(message: ChatMessage): Boolean = hasMenu(message) && message.actions.react

    fun items(message: ChatMessage): List<MenuItem> {
        if (!hasMenu(message)) return emptyList()
        val actions = message.actions
        return buildList {
            if (actions.reply) add(MenuItem.Reply)
            add(MenuItem.Copy)
            if (message.isOutbound && message.isEdited && message.originalBody != null) add(MenuItem.ViewOriginal)
            when (actions.resend) {
                ResendMode.InPlace -> add(MenuItem.TryAgain)
                ResendMode.AsNew -> add(MenuItem.Resend)
                null -> Unit
            }
            if (actions.edit) add(MenuItem.Edit)
            add(MenuItem.Details)
            if (actions.delete) add(MenuItem.Delete)
        }
    }
}
