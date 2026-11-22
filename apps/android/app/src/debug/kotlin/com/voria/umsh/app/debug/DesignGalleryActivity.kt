package com.voria.umsh.app.debug

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.SystemBarStyle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ColorScheme
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Shape
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import com.voria.umsh.R
import com.voria.umsh.app.Tags
import com.voria.umsh.core.renderNodeHint
import com.voria.umsh.designsystem.AvatarSize
import com.voria.umsh.designsystem.AvatarStyle
import com.voria.umsh.designsystem.CanonicalAddress
import com.voria.umsh.designsystem.ChannelBadge
import com.voria.umsh.designsystem.ChannelBadgeShape
import com.voria.umsh.designsystem.ChannelNaming
import com.voria.umsh.designsystem.EmptyState
import com.voria.umsh.designsystem.FailureDialog
import com.voria.umsh.designsystem.FallbackDarkScheme
import com.voria.umsh.designsystem.FallbackLightScheme
import com.voria.umsh.designsystem.FixedColors
import com.voria.umsh.designsystem.FixedDark
import com.voria.umsh.designsystem.FixedLight
import com.voria.umsh.designsystem.FullShape
import com.voria.umsh.designsystem.Glyphs
import com.voria.umsh.designsystem.IdentifierText
import com.voria.umsh.designsystem.IdentifierTextStyle
import com.voria.umsh.designsystem.LocalFixedColors
import com.voria.umsh.designsystem.LocalWarningColors
import com.voria.umsh.designsystem.MessageSecurity
import com.voria.umsh.designsystem.PeerAvatar
import com.voria.umsh.designsystem.PeerAvatarOutline
import com.voria.umsh.designsystem.PeerAvatarShape
import com.voria.umsh.designsystem.UmshColors
import com.voria.umsh.designsystem.UmshTheme
import com.voria.umsh.designsystem.WarningColors
import com.voria.umsh.designsystem.WarningDark
import com.voria.umsh.designsystem.WarningLight
import com.voria.umsh.designsystem.ageText
import com.voria.umsh.designsystem.channelTitle
import com.voria.umsh.designsystem.dateLineText
import com.voria.umsh.designsystem.identifierStringResource
import com.voria.umsh.designsystem.label
import com.voria.umsh.designsystem.listText
import com.voria.umsh.designsystem.listTimeText
import com.voria.umsh.designsystem.roleLabelForCode
import com.voria.umsh.models.Capabilities
import com.voria.umsh.models.ChannelKind
import com.voria.umsh.models.ChannelSummary
import com.voria.umsh.models.NodeHint
import com.voria.umsh.models.Octets
import com.voria.umsh.models.PeerRole
import java.time.Instant

/**
 * Debug only: the design-language and avatars-and-badges boards redrawn
 * from the real components, for screenshots beside the drawings.
 *
 * `adb shell am start -n com.voria.umsh/.app.debug.DesignGalleryActivity
 *  --es board fixed --ez dark true`. Boards: colors-light, colors-dark,
 * fixed, type, shape, avatars, pfs, badges, components, radio, banners, icons; no board shows them
 * all. `--ez dynamic true` uses the wallpaper's colors instead of the
 * fallback scheme; `--ez dialog true` opens the failure dialog.
 */
class DesignGalleryActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        val dark = if (intent.hasExtra(EXTRA_DARK)) intent.getBooleanExtra(EXTRA_DARK, false) else null
        when (dark) {
            true -> enableEdgeToEdge(SystemBarStyle.dark(Color.Transparent.toArgb()), SystemBarStyle.dark(Color.Transparent.toArgb()))
            false -> enableEdgeToEdge(
                SystemBarStyle.light(Color.Transparent.toArgb(), Color.Black.toArgb()),
                SystemBarStyle.light(Color.Transparent.toArgb(), Color.Black.toArgb()),
            )
            null -> enableEdgeToEdge()
        }
        super.onCreate(savedInstanceState)
        val board = intent.getStringExtra(EXTRA_BOARD)
        val dynamic = intent.getBooleanExtra(EXTRA_DYNAMIC, false)
        val dialog = intent.getBooleanExtra(EXTRA_DIALOG, false)
        setContent {
            UmshTheme(darkTheme = dark ?: isSystemInDarkTheme(), fallbackScheme = !dynamic) {
                Surface(Modifier.fillMaxSize().testTag(Tags.DESIGN_GALLERY)) {
                    Column(
                        Modifier
                            .fillMaxSize()
                            .verticalScroll(rememberScrollState())
                            .safeDrawingPadding()
                            .padding(16.dp),
                        verticalArrangement = Arrangement.spacedBy(24.dp),
                    ) {
                        Board.entries.filter { board == null || it.key == board }.forEach { item ->
                            if (board == null) {
                                Text(stringResource(item.title), style = MaterialTheme.typography.titleSmall)
                            }
                            item.content(dialog)
                        }
                    }
                }
            }
        }
    }

    private enum class Board(val key: String, val title: Int, val content: @Composable (Boolean) -> Unit) {
        ColorsLight("colors-light", R.string.gallery_board_colors_light, {
            ColorRoles(FallbackLightScheme, WarningLight, R.string.gallery_colors_light)
        }),
        ColorsDark("colors-dark", R.string.gallery_board_colors_dark, {
            ColorRoles(FallbackDarkScheme, WarningDark, R.string.gallery_colors_dark)
        }),
        Fixed("fixed", R.string.gallery_board_fixed, { FixedColorsBoard() }),
        Type("type", R.string.gallery_board_type, { TypeBoard() }),
        Shape("shape", R.string.gallery_board_shape, { ShapeBoard() }),
        Avatars("avatars", R.string.gallery_board_avatars, { AvatarsBoard() }),
        Pfs("pfs", R.string.gallery_board_pfs, { PfsBoard() }),
        Badges("badges", R.string.gallery_board_badges, { BadgesBoard() }),
        Components("components", R.string.gallery_board_components, { ComponentsBoard(it) }),
        Radio("radio", R.string.gallery_board_radio, { RadioStatesBoard() }),
        Banners("banners", R.string.gallery_board_banners, { BannersBoard() }),
        Icons("icons", R.string.gallery_board_icons, { IconsBoard() }),
    }

    companion object {
        const val EXTRA_BOARD = "board"
        const val EXTRA_DARK = "dark"
        const val EXTRA_DYNAMIC = "dynamic"
        const val EXTRA_DIALOG = "dialog"
    }
}

private fun hexOf(color: Color): String = "#%06X".format(color.toArgb() and 0xFFFFFF)
private fun hexOf(rgb: Int): String = "#%06X".format(rgb)
private fun bytes(hex: String) = hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
private fun hint(hex: String) = NodeHint(Octets(bytes(hex)), renderNodeHint(bytes(hex)).text)

private fun channel(name: String?, tint: String, canonical: String? = null) = ChannelSummary(
    id = tint,
    kind = if (canonical != null) ChannelKind.Builtin else ChannelKind.PrivateKey,
    canonicalName = canonical,
    name = name,
    alias = null,
    channelIdHex = tint.take(4),
    tint = Octets(bytes(tint)),
    regionCode = null,
    maxFloodHops = null,
    joinedPhone = true,
    notificationsEnabled = true,
    joinedAtMs = null,
    conversationAddress = null,
)

/** The fill [ChannelBadge] draws for [channel], for its hex label. */
private fun badgeFill(channel: ChannelSummary, fixed: FixedColors): Int = when (ChannelNaming.builtin(channel)) {
    ChannelNaming.Builtin.Public -> fixed.publicChannel.toArgb() and 0xFFFFFF
    ChannelNaming.Builtin.Emergency -> fixed.emergencyChannel.toArgb() and 0xFFFFFF
    null -> AvatarStyle.channelBand(AvatarStyle.rgbOf(channel.tint.toByteArray())).fill
}

/** A board: a surface card with a title and subtitle, as the drawings frame each one. */
@Composable
private fun BoardCard(title: Int, subtitle: Int, content: @Composable () -> Unit) {
    Surface(
        color = MaterialTheme.colorScheme.surface,
        shape = RoundedCornerShape(4.dp),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Column {
                Text(stringResource(title), style = MaterialTheme.typography.headlineSmall)
                Text(
                    stringResource(subtitle),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            content()
        }
    }
}

@Composable
private fun ColorRoles(scheme: ColorScheme, warning: WarningColors, title: Int) {
    MaterialTheme(colorScheme = scheme, typography = MaterialTheme.typography) {
        BoardCard(title, R.string.gallery_colors_subtitle) {
            Swatch(R.string.gallery_role_primary, scheme.primary, scheme.onPrimary)
            Swatch(R.string.gallery_role_primary_container, scheme.primaryContainer, scheme.onPrimaryContainer)
            Swatch(R.string.gallery_role_secondary_container, scheme.secondaryContainer, scheme.onSecondaryContainer)
            Swatch(R.string.gallery_role_tertiary_container, scheme.tertiaryContainer, scheme.onTertiaryContainer)
            Swatch(R.string.gallery_role_error, scheme.error, scheme.onError)
            Swatch(R.string.gallery_role_error_container, scheme.errorContainer, scheme.onErrorContainer)
            Swatch(R.string.gallery_role_surface, scheme.surface, scheme.onSurface)
            Swatch(R.string.gallery_role_surface_container, scheme.surfaceContainer, scheme.onSurface)
            Swatch(R.string.gallery_role_surface_container_highest, scheme.surfaceContainerHighest, scheme.onSurface)
            Swatch(R.string.gallery_role_inverse_surface, scheme.inverseSurface, scheme.inverseOnSurface)
            Text(stringResource(R.string.gallery_role_added), style = MaterialTheme.typography.titleSmall)
            Swatch(R.string.gallery_role_warning_container, warning.container, warning.onContainer)
            Text(stringResource(R.string.gallery_role_lines), style = MaterialTheme.typography.titleSmall)
            Dot(R.string.gallery_role_on_surface_variant, scheme.onSurfaceVariant)
            Dot(R.string.gallery_role_outline, scheme.outline)
            Dot(R.string.gallery_role_outline_variant, scheme.outlineVariant)
        }
    }
}

@Composable
private fun Swatch(label: Int, color: Color, onColor: Color) {
    Row(
        Modifier
            .fillMaxWidth()
            .height(40.dp)
            .background(color, RoundedCornerShape(10.dp))
            .border(1.dp, MaterialTheme.colorScheme.outlineVariant, RoundedCornerShape(10.dp))
            .padding(horizontal = 16.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(stringResource(label), color = onColor, style = MaterialTheme.typography.bodyLarge, modifier = Modifier.weight(1f))
        IdentifierText(hexOf(color), color = onColor)
    }
}

@Composable
private fun Dot(label: Int, color: Color) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Box(Modifier.size(24.dp).background(color, CircleShape))
        Spacer(Modifier.width(12.dp))
        Text(stringResource(label), style = MaterialTheme.typography.bodyLarge, modifier = Modifier.weight(1f))
        IdentifierText(hexOf(color), color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

@Composable
private fun FixedColorsBoard() {
    BoardCard(R.string.gallery_fixed_title, R.string.gallery_fixed_subtitle) {
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            FixedPanel(FallbackLightScheme, FixedLight, R.string.gallery_light, Modifier.weight(1f))
            FixedPanel(FallbackDarkScheme, FixedDark, R.string.gallery_dark, Modifier.weight(1f))
        }
    }
}

@Composable
private fun FixedPanel(scheme: ColorScheme, fixed: FixedColors, title: Int, modifier: Modifier) {
    MaterialTheme(colorScheme = scheme, typography = MaterialTheme.typography) {
        CompositionLocalProvider(LocalFixedColors provides fixed) {
            Column(
                modifier
                    .background(scheme.surface, RoundedCornerShape(16.dp))
                    .border(1.dp, scheme.outlineVariant, RoundedCornerShape(16.dp))
                    .padding(12.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                Text(
                    stringResource(title),
                    color = scheme.onSurfaceVariant,
                    style = MaterialTheme.typography.bodyMedium,
                    modifier = Modifier.align(Alignment.CenterHorizontally),
                )
                listOf(
                    "8b60f5" to PeerAvatarShape.Circle,
                    "84811b" to PeerAvatarShape.Triangle,
                    "2f5d8a" to PeerAvatarShape.Hexagon,
                ).forEach { (hex, shape) ->
                    LabeledSwatch(hexOf(AvatarStyle.rgbOf(bytes(hex)))) { PeerAvatar(hint(hex), shape, size = AvatarSize.List) }
                }
                listOf(
                    channel("Public", "0a3c11", ChannelNaming.PUBLIC),
                    channel("EMERGENCY", "0b4d22", ChannelNaming.EMERGENCY),
                    channel("hike-club", "e9c46a"),
                ).forEach { summary ->
                    LabeledSwatch(hexOf(badgeFill(summary, fixed))) { ChannelBadge(summary) }
                }
                MessageSecurity.entries.forEach { security ->
                    LabeledSwatch(hexOf(fixed.sent(security))) {
                        Box(
                            Modifier.background(fixed.sent(security), FullShape).padding(horizontal = 16.dp, vertical = 6.dp),
                        ) {
                            Text(stringResource(R.string.gallery_sent), color = fixed.onSent, style = MaterialTheme.typography.labelLarge)
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun LabeledSwatch(hex: String, sample: @Composable () -> Unit) {
    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
        sample()
        IdentifierText(hex, color = MaterialTheme.colorScheme.onSurfaceVariant, style = IdentifierTextStyle)
    }
}

@Composable
private fun TypeBoard() {
    val type = MaterialTheme.typography
    BoardCard(R.string.gallery_type_title, R.string.gallery_type_subtitle) {
        TypeRow(R.string.gallery_type_headline_small, R.string.gallery_use_full_screen, R.string.gallery_sample_storage, type.headlineSmall)
        TypeRow(R.string.gallery_type_title_large, R.string.gallery_use_top_bar, R.string.gallery_sample_conversations, type.titleLarge)
        TypeRow(R.string.gallery_type_title_medium, R.string.gallery_use_pane, R.string.gallery_sample_ridge_medic, type.titleMedium)
        TypeRow(R.string.gallery_type_title_small, R.string.gallery_use_banner_title, R.string.gallery_sample_radio_disconnected, type.titleSmall)
        TypeRow(R.string.gallery_type_body_large, R.string.gallery_use_list, R.string.gallery_sample_copy, type.bodyLarge)
        TypeRow(R.string.gallery_type_body_medium, R.string.gallery_use_supporting, R.string.gallery_sample_repeater, type.bodyMedium)
        TypeRow(R.string.gallery_type_body_small, R.string.gallery_use_banner_detail, R.string.gallery_sample_battery, type.bodySmall)
        TypeRow(R.string.gallery_type_label_large, R.string.gallery_use_buttons, R.string.gallery_sample_details, type.labelLarge)
        TypeRow(R.string.gallery_type_label_medium, R.string.gallery_use_navigation, R.string.gallery_sample_conversations, type.labelMedium)
        TypeRow(R.string.gallery_type_label_small, R.string.gallery_use_badge_counts, R.string.gallery_sample_two, type.labelSmall)
        HorizontalDivider()
        Caption(R.string.gallery_type_monospace, null)
        IdentifierText("111thX6LZfHDZZKUs92febYZhYRcXddmzfzF2NvTkPNE")
        Text(
            stringResource(R.string.gallery_use_monospace),
            style = type.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

@Composable
private fun Caption(name: Int, use: Int?) {
    Row(Modifier.fillMaxWidth()) {
        Text(
            stringResource(name),
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.weight(1f),
        )
        if (use != null) {
            Text(stringResource(use), style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

@Composable
private fun TypeRow(name: Int, use: Int, sample: Int, style: TextStyle) {
    Column {
        Caption(name, use)
        Text(stringResource(sample), style = style)
    }
}

@Composable
private fun ShapeBoard() {
    val shapes = MaterialTheme.shapes
    BoardCard(R.string.gallery_shape_title, R.string.gallery_shape_subtitle) {
        ShapeRow(shapes.extraSmall, R.string.gallery_shape_extra_small, R.string.gallery_use_extra_small)
        ShapeRow(shapes.small, R.string.gallery_shape_small, R.string.gallery_use_small)
        ShapeRow(shapes.medium, R.string.gallery_shape_medium, R.string.gallery_use_medium)
        ShapeRow(shapes.large, R.string.gallery_shape_large, R.string.gallery_use_large)
        ShapeRow(shapes.extraLarge, R.string.gallery_shape_extra_large, R.string.gallery_use_extra_large)
        ShapeRow(FullShape, R.string.gallery_shape_full, R.string.gallery_use_full)
        HorizontalDivider()
        Text(stringResource(R.string.gallery_outlines), style = MaterialTheme.typography.titleSmall)
        Row(horizontalArrangement = Arrangement.spacedBy(20.dp)) {
            Outline(R.string.gallery_outline_circle) { PeerAvatar(hint("8b60f5"), PeerAvatarShape.Circle, size = 48.dp) }
            Outline(R.string.gallery_outline_triangle) { PeerAvatar(hint("84811b"), PeerAvatarShape.Triangle, size = 48.dp) }
            Outline(R.string.gallery_outline_hexagon) { PeerAvatar(hint("2f5d8a"), PeerAvatarShape.Hexagon, size = 48.dp) }
            Outline(R.string.gallery_outline_badge) { ChannelBadge(channel("Hot Topic", "1f6e73"), size = 48.dp) }
        }
    }
}

@Composable
private fun ShapeRow(shape: Shape, name: Int, use: Int) {
    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(16.dp)) {
        Box(Modifier.size(width = 72.dp, height = 56.dp).background(MaterialTheme.colorScheme.primaryContainer, shape))
        Column {
            Text(stringResource(name), style = MaterialTheme.typography.bodyLarge)
            Text(stringResource(use), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

@Composable
private fun Outline(label: Int, sample: @Composable () -> Unit) {
    Column(horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(8.dp)) {
        sample()
        Text(stringResource(label), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

@Composable
private fun AvatarsBoard() {
    BoardCard(R.string.gallery_avatars_title, R.string.gallery_avatars_subtitle) {
        listOf(
            Triple("a1b203", PeerRole.Chat, Capabilities.TEXT_MESSAGES),
            Triple("84811b", PeerRole.Repeater, Capabilities.REPEATER),
            Triple("5ea1b2", PeerRole.Tracker, Capabilities.MOBILE),
            Triple("8b60f5", PeerRole.Chat, 0),
        ).forEach { (hex, role, caps) ->
            val hint = hint(hex)
            val shape = PeerAvatarShape.of(role, Capabilities(caps))
            val white = AvatarStyle.peer(bytes(hex), hint.text).whiteText
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(16.dp)) {
                PeerAvatar(hint, shape, size = AvatarSize.List)
                Column {
                    IdentifierText(hexOf(AvatarStyle.rgbOf(bytes(hex))) + Glyphs.MIDDLE_DOT + hint.text, style = IdentifierTextStyle.copy(fontSize = MaterialTheme.typography.bodyLarge.fontSize))
                    Text(
                        stringResource(shapeDescription(shape, white)),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        }
        HorizontalDivider()
        Text(stringResource(R.string.gallery_sizes), style = MaterialTheme.typography.titleSmall)
        Row(
            Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceEvenly,
            verticalAlignment = Alignment.Bottom,
        ) {
            listOf(
                AvatarSize.TopBar to R.string.gallery_size_top_bar,
                AvatarSize.List to R.string.gallery_size_list,
                AvatarSize.Card to R.string.gallery_size_card,
                AvatarSize.Page to R.string.gallery_size_page,
            ).forEach { (size, label) -> SizedAvatar(size, label) }
        }
        HorizontalDivider()
        val ap5r = hint("8b60f5")
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text(
                    stringResource(
                        R.string.gallery_talkback,
                        identifierStringResource(R.string.avatar_node_hint, ap5r.text).text,
                    ),
                )
                Text(
                    stringResource(
                        R.string.gallery_favorite,
                        identifierStringResource(R.string.avatar_favorite_node_hint, ap5r.text).text,
                    ),
                )
            }
            PeerAvatar(ap5r, PeerAvatarShape.Circle, size = AvatarSize.List, favorite = true)
        }
    }
}

private fun shapeDescription(shape: PeerAvatarShape, white: Boolean) = when (shape) {
    PeerAvatarShape.Circle -> if (white) R.string.gallery_avatar_circle_white else R.string.gallery_avatar_circle_black
    PeerAvatarShape.Triangle -> if (white) R.string.gallery_avatar_triangle_white else R.string.gallery_avatar_triangle_black
    PeerAvatarShape.Hexagon -> if (white) R.string.gallery_avatar_hexagon_white else R.string.gallery_avatar_hexagon_black
}

@Composable
private fun SizedAvatar(size: Dp, label: Int) {
    Column(horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(8.dp)) {
        PeerAvatar(hint("8b60f5"), PeerAvatarShape.Circle, size = size)
        Text(stringResource(label), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

@Composable
private fun PfsBoard() {
    BoardCard(R.string.gallery_pfs_title, R.string.gallery_pfs_subtitle) {
        PfsPanel(FallbackLightScheme, R.string.gallery_pfs_light)
        PfsPanel(FallbackDarkScheme, R.string.gallery_pfs_dark)
    }
}

@Composable
private fun PfsPanel(scheme: ColorScheme, title: Int) {
    val fixed = UmshColors.fixed
    MaterialTheme(colorScheme = scheme, typography = MaterialTheme.typography) {
        Column(
            Modifier
                .fillMaxWidth()
                .background(scheme.surface, RoundedCornerShape(16.dp))
                .border(1.dp, scheme.outlineVariant, RoundedCornerShape(16.dp))
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            Text(stringResource(title), color = scheme.onSurfaceVariant, style = MaterialTheme.typography.bodyMedium)
            listOf(
                Triple(MessageSecurity.Encrypted, R.string.gallery_pfs_encrypted to R.string.gallery_pfs_encrypted_detail, R.string.gallery_pfs_sample_encrypted),
                Triple(MessageSecurity.Open, R.string.gallery_pfs_open to R.string.gallery_pfs_open_detail, R.string.gallery_pfs_sample_open),
                Triple(MessageSecurity.ForwardSecret, R.string.gallery_pfs_forward_secret to R.string.gallery_pfs_forward_secret_detail, R.string.gallery_pfs_sample_forward_secret),
            ).forEach { (security, labels, sample) ->
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text(stringResource(labels.first), color = scheme.onSurface, style = MaterialTheme.typography.titleSmall)
                        Text(stringResource(labels.second), color = scheme.onSurfaceVariant, style = MaterialTheme.typography.bodySmall)
                    }
                    Box(Modifier.background(fixed.sent(security), RoundedCornerShape(20.dp)).padding(horizontal = 14.dp, vertical = 8.dp)) {
                        Text(stringResource(sample), color = fixed.onSent, style = MaterialTheme.typography.bodyLarge)
                    }
                }
            }
        }
    }
}

@Composable
private fun BadgesBoard() {
    BoardCard(R.string.gallery_badges_title, R.string.gallery_badges_subtitle) {
        listOf(
            channel("Hot Topic", "1f6e73"),
            channel("hike-club", "e9c46a"),
            channel("one two 👍🏽 four five", "a8e0b0"),
            channel("🔥", "a03010"),
            channel("🔥 Hot Topic", "5b2a86"),
            channel("public", "0a3c11", ChannelNaming.PUBLIC),
            channel("EMERGENCY", "0b4d22", ChannelNaming.EMERGENCY),
            channel(null, "3f9ad0"),
        ).forEach { summary ->
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(16.dp)) {
                ChannelBadge(summary)
                Column {
                    Text(channelTitle(summary), style = MaterialTheme.typography.bodyLarge)
                    val name = summary.name
                    Text(
                        if (name != null) {
                            stringResource(R.string.gallery_badge_name, name)
                        } else {
                            stringResource(R.string.gallery_badge_never_named, summary.channelIdHex.uppercase())
                        },
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        }
    }
}

@Composable
private fun ComponentsBoard(openDialog: Boolean) {
    var dialog by remember { mutableStateOf(openDialog) }
    val now = remember { Instant.now() }
    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text(stringResource(R.string.gallery_components_address), style = MaterialTheme.typography.titleSmall)
        CanonicalAddress("Ju8QmN2rT5vXbC7kLpZ4wYhD9sFgE3aRtUiKqP6nM1xW", Modifier.fillMaxWidth())
        HorizontalDivider()
        Text(stringResource(R.string.gallery_components_times), style = MaterialTheme.typography.titleSmall)
        listOf(0L, 3_600L * 20, 86_400L * 3, 86_400L * 40).forEach { secondsAgo ->
            val at = now.minusSeconds(secondsAgo + 180)
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                Text(listTimeText(at, now))
                Text(dateLineText(at, now))
                Text(ageText(at, now))
            }
        }
        HorizontalDivider()
        Text(stringResource(R.string.gallery_components_roles), style = MaterialTheme.typography.titleSmall)
        Text(PeerRole.entries.map { it.label() }.joinToString(Glyphs.MIDDLE_DOT) + Glyphs.MIDDLE_DOT + roleLabelForCode(9))
        Text(Capabilities(0x3F).listText())
        HorizontalDivider()
        Text(stringResource(R.string.gallery_components_empty), style = MaterialTheme.typography.titleSmall)
        Box(Modifier.fillMaxWidth().height(180.dp).background(MaterialTheme.colorScheme.surfaceContainerLow, RoundedCornerShape(16.dp))) {
            EmptyState(R.drawable.ic_forum_outlined, stringResource(R.string.gallery_empty_line))
        }
        Button(onClick = { dialog = true }) { Text(stringResource(R.string.gallery_components_dialog)) }
    }
    if (dialog) {
        FailureDialog(
            title = stringResource(R.string.gallery_dialog_title),
            body = stringResource(R.string.gallery_dialog_body),
            reason = stringResource(R.string.gallery_dialog_reason),
            details = "SQLITE_FULL (13): database or disk is full · write app.sqlite",
            onDismiss = { dialog = false },
        )
    }
}
