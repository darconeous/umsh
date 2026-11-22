package com.voria.umsh.designsystem

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.size
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.text
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.Dp
import com.voria.umsh.R
import com.voria.umsh.models.ChannelSummary
import java.util.Locale

/**
 * A channel's badge (`avatars-and-badges.svg` board 3): a rounded square,
 * corner a quarter of its size, lettered in the system sans, semibold. The
 * fill comes from the channel's key; Public and EMERGENCY are fixed.
 *
 * TalkBack reads "Channel Hot Topic", or "Private channel 3F9A" for one
 * never named. Inside a merged row pass
 * [describe] = false.
 */
@Composable
fun ChannelBadge(
    channel: ChannelSummary,
    modifier: Modifier = Modifier,
    size: Dp = AvatarSize.List,
    describe: Boolean = true,
) {
    val fixed = UmshColors.fixed
    val builtinFill = when (ChannelNaming.builtin(channel)) {
        ChannelNaming.Builtin.Public -> fixed.publicChannel
        ChannelNaming.Builtin.Emergency -> fixed.emergencyChannel
        null -> null
    }
    val style = AvatarStyle.channel(
        lettering = ChannelNaming.lettering(channel),
        tint = channel.tint.toByteArray(),
        builtinFill = builtinFill?.let { it.toArgb() and 0xFFFFFF },
    )
    val semantics = when {
        !describe -> Modifier.clearAndSetSemantics {}
        // Never named: the identifier the badge shows, spelled, so two such
        // channels in a list sound different.
        ChannelNaming.title(channel) == ChannelTitle.Private -> {
            val description = identifierStringResource(
                R.string.channel_badge_private,
                channel.channelIdHex.uppercase(Locale.ROOT),
            )
            Modifier.clearAndSetSemantics { text = description }
        }
        else -> {
            val description = stringResource(R.string.channel_badge, channelTitle(channel))
            Modifier.clearAndSetSemantics { contentDescription = description }
        }
    }
    Box(
        modifier
            .size(size)
            .then(semantics)
            .background(opaque(style.fill), ChannelBadgeShape),
        contentAlignment = Alignment.Center,
    ) {
        StackedLettering(
            lines = style.lines,
            size = size,
            fontRatio = style.fontRatio,
            lineSpacingRatio = style.lineSpacingRatio,
            color = if (style.whiteText) Color.White else Color.Black,
            fontFamily = FontFamily.Default,
        )
    }
}

/** [channel]'s title, beside its badge. Elsewhere (fields, quotes) show the name as written. */
@Composable
fun channelTitle(channel: ChannelSummary): String = when (val title = ChannelNaming.title(channel)) {
    is ChannelTitle.Text -> title.text
    ChannelTitle.Public -> stringResource(R.string.channel_public)
    ChannelTitle.Emergency -> stringResource(R.string.channel_emergency)
    ChannelTitle.Private -> stringResource(R.string.channel_private)
}

/** `0xRRGGBB` as an opaque color. */
internal fun opaque(rgb: Int): Color = Color(OPAQUE or rgb)

private const val OPAQUE = -0x1000000
