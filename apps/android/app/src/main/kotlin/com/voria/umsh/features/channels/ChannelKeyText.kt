package com.voria.umsh.features.channels

import androidx.compose.runtime.saveable.Saver
import com.voria.umsh.core.ChannelKindRecord
import com.voria.umsh.core.MobileException
import com.voria.umsh.core.inspectChannelUri
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Text that may carry a private channel key (a channel invitation, typed,
 * pasted, scanned or opened as a link), on its way into saved state. The
 * key stays in this process (§3.8): [seal] puts a handle in the text's
 * place, which [open] turns back into the text while the process lives
 * (a rotation, a page leaving composition) and into nothing after process
 * death. Any other text passes through as it is.
 */
object ChannelKeyText {
    // A NUL no typed or scanned text holds, so a handle is never mistaken for text.
    private const val HANDLE = "\u0000held:"
    private val held = ConcurrentHashMap<String, String>()

    /** [text] for saved state: a handle when it holds a private channel key. */
    fun seal(text: String): String {
        if (!holdsKey(text)) return text
        held.entries.firstOrNull { it.value == text }?.let { return HANDLE + it.key }
        val id = UUID.randomUUID().toString()
        held[id] = text
        return HANDLE + id
    }

    /** What [saved] stood for; null for a handle from before the process started. */
    fun open(saved: String): String? = if (saved.startsWith(HANDLE)) held[saved.removePrefix(HANDLE)] else saved

    /** Whether [text] is a channel invitation carrying a private key, readable or not. */
    fun holdsKey(text: String): Boolean {
        val trimmed = text.trim()
        val scheme = trimmed.lowercase()
        if (KEY_PREFIXES.any { scheme.startsWith(it) }) return true
        return try {
            inspectChannelUri(trimmed).kind == ChannelKindRecord.PRIVATE_KEY
        } catch (_: MobileException) {
            false
        }
    }

    /** A text field's saver: the key-free text is restored; a key only within this process. */
    val FieldSaver: Saver<String, String> = Saver(save = { seal(it) }, restore = { open(it) ?: "" })

    // The direct-key spellings of a channel link (`inspect_channel_uri`), current and deprecated.
    private val KEY_PREFIXES = listOf("umsh:gk:", "umsh:ck:")
}
