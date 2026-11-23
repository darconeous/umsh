package com.voria.umsh.designsystem

import android.graphics.Paint
import android.os.Build
import androidx.core.graphics.PaintCompat
import com.voria.umsh.models.ReactionKind

/**
 * Non-linguistic text: glyphs that are the same in every language. This file
 * alone is exempt from the `ComposeLiteralText` lint rule, so nothing that
 * reads as words belongs here.
 */
object Glyphs {
    /** The reaction palette, in the order the picker offers it (as iOS). */
    const val HEART = "🩷"
    const val THUMBS_UP = "👍"
    const val THUMBS_DOWN = "👎"
    const val LAUGH = "🤣"
    const val EXCLAIM = "‼️"
    const val QUESTION = "❓"

    val reactionPalette: List<Pair<String, ReactionKind>> = listOf(
        HEART to ReactionKind.Heart,
        THUMBS_UP to ReactionKind.ThumbsUp,
        THUMBS_DOWN to ReactionKind.ThumbsDown,
        LAUGH to ReactionKind.Laugh,
        EXCLAIM to ReactionKind.Exclaim,
        QUESTION to ReactionKind.Question,
    )

    /** What a reaction renders as: its palette glyph, or the one cluster it is. */
    fun reaction(kind: ReactionKind): String = when (kind) {
        ReactionKind.Heart -> HEART
        ReactionKind.ThumbsUp -> THUMBS_UP
        ReactionKind.ThumbsDown -> THUMBS_DOWN
        ReactionKind.Laugh -> LAUGH
        ReactionKind.Exclaim -> EXCLAIM
        ReactionKind.Question -> QUESTION
        is ReactionKind.Other -> kind.cluster
    }

    /** The reaction [glyph] stands for: a palette one, or the one cluster it is. */
    fun reactionKind(glyph: String): ReactionKind =
        reactionPalette.firstOrNull { it.first == glyph }?.second ?: ReactionKind.Other(glyph)

    /**
     * [glyph] as this phone's emoji font can draw it. The pink heart is
     * Emoji 15, in Android's font from Android 14; before that a font
     * without it shows the red heart instead of an empty box. The reaction
     * itself is unchanged: this is drawing only.
     */
    fun drawable(glyph: String): String = if (glyph == HEART && !pinkHeartDrawn) RED_HEART else glyph

    private const val RED_HEART = "❤️"

    private val pinkHeartDrawn: Boolean by lazy {
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE ||
            runCatching { PaintCompat.hasGlyph(Paint(), HEART) }.getOrDefault(true)
    }

    /** The separator inside identifier sequences, which are never resources. */
    const val MIDDLE_DOT = " · "
}
