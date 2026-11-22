package com.voria.umsh.designsystem

import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Shape
import androidx.compose.ui.graphics.drawOutline
import androidx.compose.ui.graphics.drawscope.translate
import androidx.compose.ui.unit.dp

/**
 * A list row's [background] (a swipe's strip stays beneath it) and, when
 * [selected], the highlight `conversations-tablet.svg` draws: [shape], 8 dp
 * in from the sides and 2 dp from the top and bottom. Drawn only: the
 * content stays where every row has it.
 */
internal fun Modifier.selectionBackground(selected: Boolean, background: Color, highlight: Color, shape: Shape): Modifier =
    drawBehind {
        drawRect(background)
        if (selected) {
            val inset = Offset(8.dp.toPx(), 2.dp.toPx())
            val outline = shape.createOutline(
                Size(size.width - 2 * inset.x, size.height - 2 * inset.y),
                layoutDirection,
                this,
            )
            translate(inset.x, inset.y) { drawOutline(outline, highlight) }
        }
    }
