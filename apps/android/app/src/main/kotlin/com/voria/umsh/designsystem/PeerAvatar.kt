package com.voria.umsh.designsystem

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.text
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.LineHeightStyle
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import com.voria.umsh.R
import com.voria.umsh.models.NodeHint
import com.voria.umsh.models.PeerSummary

/** The avatar sizes the designs use. */
object AvatarSize {
    val TopBar = 32.dp
    val List = 40.dp
    val Card = 56.dp
    val Page = 96.dp
}

/**
 * A peer's avatar (`avatars-and-badges.svg` board 1): its hint's color in
 * the outline its role gives it, the hint two over two in the monospace,
 * black or white by APCA. Drawn the same on light and dark surfaces: no
 * outline, tint or session state.
 *
 * TalkBack reads "Node hint AP5R" or "Favorite node, hint AP5R", the hint
 * spelled out. Inside a row that merges its children, pass
 * [describe] = false and the row speaks for it.
 */
@Composable
fun PeerAvatar(
    hint: NodeHint,
    shape: PeerAvatarShape,
    modifier: Modifier = Modifier,
    size: Dp = AvatarSize.List,
    favorite: Boolean = false,
    describe: Boolean = true,
) {
    val style = AvatarStyle.peer(hint.octets.toByteArray(), hint.text)
    val description = if (favorite) {
        identifierStringResource(R.string.avatar_favorite_node_hint, hint.text)
    } else {
        identifierStringResource(R.string.avatar_node_hint, hint.text)
    }
    val semantics = if (describe) {
        Modifier.clearAndSetSemantics { text = description }
    } else {
        Modifier.clearAndSetSemantics {}
    }
    Box(modifier.size(size).then(semantics)) {
        Box(
            Modifier.size(size).background(opaque(style.fill), PeerAvatarOutline(shape)),
            contentAlignment = Alignment.Center,
        ) {
            StackedLettering(
                lines = style.lines,
                size = size,
                fontRatio = style.fontRatio * shape.fontScale,
                lineSpacingRatio = style.lineSpacingRatio * shape.fontScale,
                color = if (style.whiteText) Color.White else Color.Black,
                fontFamily = FontFamily.Monospace,
                modifier = Modifier.offset(y = size * shape.textCenterOffsetRatio),
            )
        }
        if (favorite) {
            Box(
                Modifier
                    .align(Alignment.TopEnd)
                    .offset(x = size * 0.10f + size * 0.04f, y = -(size * 0.10f) - size * 0.04f)
                    .size(size * 0.36f)
                    .background(MaterialTheme.colorScheme.surface, CircleShape),
                contentAlignment = Alignment.Center,
            ) {
                Icon(
                    painterResource(R.drawable.ic_star),
                    contentDescription = null,
                    tint = UmshColors.fixed.favoriteStar,
                    modifier = Modifier.size(size * 0.28f),
                )
            }
        }
    }
}

/** A peer's avatar, from what one state read knows of it. */
@Composable
fun PeerAvatar(
    peer: PeerSummary,
    modifier: Modifier = Modifier,
    size: Dp = AvatarSize.List,
    favorite: Boolean = false,
    describe: Boolean = true,
) = PeerAvatar(peer.hint, PeerAvatarShape.of(peer), modifier, size, favorite, describe)

/**
 * One or two lines of glyphs, centered in a square of [size], sized from
 * it rather than from the font scale: the lettering is part of the shape.
 */
@Composable
internal fun StackedLettering(
    lines: List<String>,
    size: Dp,
    fontRatio: Float,
    lineSpacingRatio: Float,
    color: Color,
    fontFamily: FontFamily,
    modifier: Modifier = Modifier,
) {
    val density = LocalDensity.current
    // dp → sp through the density alone: `toSp` divides out the font
    // scale, so a larger text setting does not overflow the shape.
    val fontSize = with(density) { (size * fontRatio).toSp() }
    // A line box is about 1.2 em; the stack is drawn tighter by the ratio.
    val lineHeight = with(density) { (size * fontRatio * 1.2f + size * lineSpacingRatio).toSp() }
    Text(
        text = lines.filter { it.isNotEmpty() }.joinToString("\n"),
        modifier = modifier,
        color = color,
        maxLines = 2,
        softWrap = false,
        textAlign = TextAlign.Center,
        style = TextStyle(
            fontFamily = fontFamily,
            fontWeight = FontWeight.SemiBold,
            fontSize = fontSize,
            lineHeight = lineHeight,
            lineHeightStyle = LineHeightStyle(LineHeightStyle.Alignment.Center, LineHeightStyle.Trim.Both),
        ),
    )
}
