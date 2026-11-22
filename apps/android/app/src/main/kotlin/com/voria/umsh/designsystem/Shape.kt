package com.voria.umsh.designsystem

import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Shapes
import androidx.compose.ui.unit.dp

/*
 * Shape (`design-language.svg` board 5): the Material 3 corner scale.
 *
 *   Extra small  4   text field top, tooltips
 *   Small        8   chips, snackbar
 *   Medium       12  cards
 *   Large        16  FAB, nav drawer, selected list row
 *   Extra large  28  dialogs, bottom sheet top
 *   Full             buttons, nav indicator, search bar, radio control
 */
val UmshShapes = Shapes(
    extraSmall = RoundedCornerShape(4.dp),
    small = RoundedCornerShape(8.dp),
    medium = RoundedCornerShape(12.dp),
    large = RoundedCornerShape(16.dp),
    extraLarge = RoundedCornerShape(28.dp),
)

/** Full radius: buttons, the navigation indicator, the search bar and the radio control. */
val FullShape = RoundedCornerShape(percent = 50)

/**
 * A channel badge: a square whose corners are a quarter of its size. Like
 * the avatar outlines, it comes from the canonical rules, never from the
 * theme's scale.
 */
val ChannelBadgeShape = RoundedCornerShape(percent = 25)
