package com.voria.umsh.services.notifications

import android.content.Context
import android.content.Intent
import android.content.pm.ShortcutInfo
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.Paint
import android.graphics.Typeface
import android.util.LruCache
import androidx.compose.ui.graphics.toArgb
import androidx.core.app.Person
import androidx.core.content.LocusIdCompat
import androidx.core.content.pm.ShortcutInfoCompat
import androidx.core.content.pm.ShortcutManagerCompat
import androidx.core.graphics.drawable.IconCompat
import com.voria.umsh.designsystem.AvatarStyle
import com.voria.umsh.designsystem.ChannelNaming
import com.voria.umsh.designsystem.FixedLight
import com.voria.umsh.services.mobilecore.AppLog

/**
 * Avatars drawn for notifications, which cannot host a composable: the
 * canonical peer avatar and the channel badge, from the same
 * [AvatarStyle] the app draws them with. Always a circle: the system masks
 * these to one regardless, and a shape that was meant beats a square with
 * its corners cut off (as iOS).
 */
object AvatarBitmaps {
    private const val SIZE_PX = 192
    private const val SEMIBOLD = 600

    private val cache = LruCache<String, Bitmap>(64)

    fun of(avatar: NoteAvatar): Bitmap? = when (avatar) {
        is NoteAvatar.Peer -> {
            val hint = avatar.peer.hint
            cached("p:${hint.octets.hex()}:${hint.text}") {
                render(AvatarStyle.peer(hint.octets.toByteArray(), hint.text), Typeface.MONOSPACE)
            }
        }
        is NoteAvatar.Channel -> {
            val channel = avatar.channel
            val builtin = when (ChannelNaming.builtin(channel)) {
                ChannelNaming.Builtin.Public -> FixedLight.publicChannel.toArgb() and 0xFFFFFF
                ChannelNaming.Builtin.Emergency -> FixedLight.emergencyChannel.toArgb() and 0xFFFFFF
                null -> null
            }
            val style = AvatarStyle.channel(ChannelNaming.lettering(channel), channel.tint.toByteArray(), builtin)
            cached("c:${style.fill}:${style.lines}") { render(style, Typeface.DEFAULT) }
        }
        NoteAvatar.None -> null
    }

    private fun cached(key: String, draw: () -> Bitmap): Bitmap = synchronized(cache) {
        cache.get(key) ?: draw().also { cache.put(key, it) }
    }

    /** The glyph lines stacked and centered as a group, on the fill. */
    private fun render(style: AvatarStyle, family: Typeface): Bitmap {
        val bitmap = Bitmap.createBitmap(SIZE_PX, SIZE_PX, Bitmap.Config.ARGB_8888)
        val canvas = Canvas(bitmap)
        val size = SIZE_PX.toFloat()
        val fill = Paint(Paint.ANTI_ALIAS_FLAG).apply { color = OPAQUE or style.fill }
        canvas.drawCircle(size / 2, size / 2, size / 2, fill)
        val lines = style.lines.filter { it.isNotEmpty() }
        if (lines.isEmpty()) return bitmap
        val text = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            color = if (style.whiteText) WHITE else BLACK
            textSize = size * style.fontRatio
            typeface = Typeface.create(family, SEMIBOLD, false)
            textAlign = Paint.Align.CENTER
        }
        val metrics = text.fontMetrics
        val lineHeight = metrics.descent - metrics.ascent
        val spacing = size * style.lineSpacingRatio
        val total = lineHeight * lines.size + spacing * (lines.size - 1)
        var baseline = (size - total) / 2 - metrics.ascent
        for (line in lines) {
            canvas.drawText(line, size / 2, baseline, text)
            baseline += lineHeight + spacing
        }
        return bitmap
    }

    private const val OPAQUE = -0x1000000
    private const val WHITE = -0x1
    private const val BLACK = -0x1000000
}

/** A notification's people: who speaks a line, and this phone. */
object NotificationPeople {
    fun person(key: String?, name: CharSequence, avatar: NoteAvatar): Person = Person.Builder()
        .setName(name)
        .setKey(key)
        .setIcon(AvatarBitmaps.of(avatar)?.let(IconCompat::createWithBitmap))
        .build()
}

/**
 * Conversation shortcuts (§6.2, D15): one dynamic, long-lived shortcut a
 * conversation, which is what puts its notification in the system's
 * Conversations section. No bubbles.
 */
class ConversationShortcuts(private val context: Context, private val open: (String) -> Intent) {
    fun push(address: String, title: CharSequence, person: Person?, avatar: NoteAvatar) {
        val shortcut = ShortcutInfoCompat.Builder(context, address)
            .setShortLabel(title)
            .setLongLived(true)
            .setLocusId(LocusIdCompat(address))
            .setCategories(setOf(ShortcutInfo.SHORTCUT_CATEGORY_CONVERSATION))
            .setIntent(open(address))
            .apply {
                person?.let(::setPerson)
                AvatarBitmaps.of(avatar)?.let { setIcon(IconCompat.createWithBitmap(it)) }
            }
            .build()
        try {
            ShortcutManagerCompat.pushDynamicShortcut(context, shortcut)
        } catch (error: RuntimeException) {
            // A limit reached or the launcher refusing: the notification still posts.
            AppLog.w(TAG, "conversation shortcut not pushed: ${error.javaClass.simpleName}")
        }
    }

    /** [addresses]' conversations are gone. */
    fun remove(addresses: Collection<String>) {
        if (addresses.isEmpty()) return
        runCatching { ShortcutManagerCompat.removeLongLivedShortcuts(context, addresses.toList()) }
            .onFailure { AppLog.w(TAG, "shortcuts not removed: ${it.javaClass.simpleName}") }
    }

    /** Every conversation's shortcut: the identity is being erased. */
    fun removeAll() {
        runCatching {
            val ids = ShortcutManagerCompat.getShortcuts(
                context,
                ShortcutManagerCompat.FLAG_MATCH_DYNAMIC or ShortcutManagerCompat.FLAG_MATCH_CACHED,
            ).map { it.id }
            ShortcutManagerCompat.removeAllDynamicShortcuts(context)
            if (ids.isNotEmpty()) ShortcutManagerCompat.removeLongLivedShortcuts(context, ids)
        }.onFailure { AppLog.w(TAG, "shortcuts not removed: ${it.javaClass.simpleName}") }
    }

    private companion object {
        const val TAG = "umsh.notify"
    }
}
