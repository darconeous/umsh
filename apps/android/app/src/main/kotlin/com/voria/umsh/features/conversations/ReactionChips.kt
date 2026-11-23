package com.voria.umsh.features.conversations

import android.icu.text.NumberFormat
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.defaultMinSize
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.onClick
import androidx.compose.ui.semantics.role
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.voria.umsh.R
import com.voria.umsh.app.Tags
import com.voria.umsh.designsystem.Glyphs
import com.voria.umsh.designsystem.LocalFixedColors
import com.voria.umsh.designsystem.MessageSecurity
import com.voria.umsh.designsystem.pageColor
import com.voria.umsh.models.Reaction
import com.voria.umsh.models.ReactionKind

/** One chip: every reaction with one glyph, or one failed reaction of mine on its own. */
data class ReactionChip(
    val glyph: String,
    val count: Int,
    val style: Style,
    /** Mine in it went under a forward-secret session. */
    val forwardSecret: Boolean,
) {
    enum class Style { Mine, Failed, Theirs }

    /** The reaction the chip stands for, as a tap sends it. */
    val kind: ReactionKind get() = Glyphs.reactionKind(glyph)

    /** A key unique within one message's chips. */
    val key: String get() = if (style == Style.Failed) "failed:$glyph" else glyph

    companion object {
        /**
         * One chip per glyph with its count, mine first; a failed one of mine
         * stays on its own, faded, so someone else's copy never hides it. A
         * reaction whose body the core could not read has no glyph to show.
         */
        fun of(reactions: List<Reaction>): List<ReactionChip> {
            val grouped = LinkedHashMap<String, ReactionChip>()
            val failed = LinkedHashMap<String, ReactionChip>()
            for (reaction in reactions) {
                val glyph = reaction.kind?.let(Glyphs::reaction) ?: continue
                val forwardSecret = reaction.isMine && reaction.isForwardSecret
                if (reaction.isFailed) {
                    failed[glyph] = ReactionChip(glyph, 1, Style.Failed, forwardSecret)
                    continue
                }
                val chip = grouped[glyph]
                grouped[glyph] = if (chip == null) {
                    ReactionChip(glyph, 1, if (reaction.isMine) Style.Mine else Style.Theirs, forwardSecret)
                } else {
                    chip.copy(
                        count = chip.count + 1,
                        style = if (reaction.isMine) Style.Mine else chip.style,
                        forwardSecret = chip.forwardSecret || forwardSecret,
                    )
                }
            }
            val all = grouped.values.toList()
            return all.filter { it.style == Style.Mine } + all.filter { it.style == Style.Theirs } + failed.values
        }
    }
}

/**
 * The chips across a bubble's bottom edge (`replies-reactions.svg` board 5):
 * a page-colored ring sets each apart from the bubble; mine are filled with
 * the conversation's color, and a failed one of mine is faded.
 */
@Composable
internal fun ReactionChipRow(
    chips: List<ReactionChip>,
    security: MessageSecurity,
    modifier: Modifier = Modifier,
    /** A chip tapped: mine withdraws, another's adds it as mine. Null: the chips do nothing. */
    onChip: ((ReactionChip) -> Unit)? = null,
) {
    Row(modifier.testTag(Tags.REACTION_CHIPS), horizontalArrangement = Arrangement.spacedBy((-2).dp)) {
        chips.forEach { chip -> Chip(chip, security, onChip) }
    }
}

@Composable
private fun Chip(chip: ReactionChip, security: MessageSecurity, onChip: ((ReactionChip) -> Unit)?) {
    val colors = MaterialTheme.colorScheme
    val fixed = LocalFixedColors.current
    val own = fixed.sent(if (chip.forwardSecret) MessageSecurity.ForwardSecret else security)
    val (fill, text) = when (chip.style) {
        ReactionChip.Style.Mine, ReactionChip.Style.Failed -> own to fixed.onSent
        ReactionChip.Style.Theirs -> colors.surfaceContainerHigh to colors.onSurface
    }
    val locale = LocalConfiguration.current.locales[0]
    val glyph = Glyphs.drawable(chip.glyph)
    val description = when (chip.style) {
        ReactionChip.Style.Mine -> pluralStringResource(R.plurals.reaction_chip_yours, chip.count, glyph, chip.count)
        ReactionChip.Style.Theirs -> pluralStringResource(R.plurals.reaction_chip, chip.count, glyph, chip.count)
        ReactionChip.Style.Failed -> stringResource(R.string.reaction_failed, glyph)
    }
    Box(
        Modifier
            .testTag(Tags.reactionChip(chip.key))
            .clip(RoundedCornerShape(16.dp))
            .then(if (onChip != null) Modifier.clickable(role = Role.Button) { onChip(chip) } else Modifier)
            .clearAndSetSemantics {
                contentDescription = description
                if (onChip != null) {
                    role = Role.Button
                    onClick { onChip(chip); true }
                }
            }
            // A ring in the page's own color, so the chip reads as cut out of the bubble's edge.
            .background(pageColor(), RoundedCornerShape(16.dp))
            .padding(2.dp),
    ) {
        Row(
            Modifier
                .alpha(if (chip.style == ReactionChip.Style.Failed) FAILED_ALPHA else 1f)
                .background(fill, RoundedCornerShape(14.dp))
                // Grows with the text size: a fixed height would clip it.
                .heightIn(min = 28.dp)
                .defaultMinSize(minWidth = 32.dp)
                .padding(horizontal = 8.dp, vertical = 2.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(4.dp, Alignment.CenterHorizontally),
        ) {
            Text(glyph, fontSize = 15.sp, color = Color.Unspecified)
            if (chip.count > 1) {
                Text(
                    NumberFormat.getIntegerInstance(locale).format(chip.count.toLong()),
                    style = MaterialTheme.typography.labelMedium,
                    fontWeight = FontWeight.SemiBold,
                    color = text,
                )
            }
        }
    }
}

private const val FAILED_ALPHA = 0.5f
