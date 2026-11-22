package com.voria.umsh.designsystem

import androidx.compose.foundation.shape.CircleShape
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Rect
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Outline
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.Shape
import androidx.compose.ui.unit.Density
import androidx.compose.ui.unit.LayoutDirection
import kotlin.math.PI
import kotlin.math.acos
import kotlin.math.atan2
import kotlin.math.min
import kotlin.math.sin
import kotlin.math.sqrt
import kotlin.math.tan

/**
 * [PeerAvatarShape] as a Compose [Shape], with iOS `PeerAvatarOutline`'s
 * geometry: an equilateral triangle on the frame's bottom edge whose rounded
 * apex meets the top edge, and a flat-topped regular hexagon whose flat
 * edges are the frame's top and bottom. Both are as tall as the circle.
 */
class PeerAvatarOutline(private val shape: PeerAvatarShape) : Shape {
    override fun createOutline(size: Size, layoutDirection: LayoutDirection, density: Density): Outline {
        if (shape == PeerAvatarShape.Circle) return CircleShape.createOutline(size, layoutDirection, density)
        val side = min(size.width, size.height)
        val midX = size.width / 2
        val midY = size.height / 2
        val path = when (shape) {
            PeerAvatarShape.Triangle -> {
                val height = side * PeerAvatarShape.TRIANGLE_HEIGHT_RATIO
                val halfBase = height / sqrt(3f)
                val bottom = midY + side / 2
                roundedPolygon(
                    listOf(
                        Offset(midX, bottom - height),
                        Offset(midX + halfBase, bottom),
                        Offset(midX - halfBase, bottom),
                    ),
                    side * PeerAvatarShape.TRIANGLE_CORNER_RATIO,
                )
            }
            else -> {
                val top = midY - side / 2
                val bottom = midY + side / 2
                val halfWidth = side / sqrt(3f)
                val halfEdge = halfWidth / 2
                roundedPolygon(
                    listOf(
                        Offset(midX - halfWidth, midY),
                        Offset(midX - halfEdge, top),
                        Offset(midX + halfEdge, top),
                        Offset(midX + halfWidth, midY),
                        Offset(midX + halfEdge, bottom),
                        Offset(midX - halfEdge, bottom),
                    ),
                    side * PeerAvatarShape.HEXAGON_CORNER_RATIO,
                )
            }
        }
        return Outline.Generic(path)
    }

    override fun equals(other: Any?) = other is PeerAvatarOutline && other.shape == shape

    override fun hashCode() = shape.hashCode()

    private companion object {
        /** A closed polygon whose corners are arcs tangent to both adjoining edges. */
        fun roundedPolygon(vertices: List<Offset>, radius: Float): Path {
            val path = Path()
            val first = vertices.first()
            val last = vertices.last()
            path.moveTo((first.x + last.x) / 2, (first.y + last.y) / 2)
            for (index in vertices.indices) {
                val vertex = vertices[index]
                val previous = vertices[(index + vertices.size - 1) % vertices.size]
                val next = vertices[(index + 1) % vertices.size]
                val toPrevious = (previous - vertex).normalized()
                val toNext = (next - vertex).normalized()
                val angle = acos((toPrevious.x * toNext.x + toPrevious.y * toNext.y).coerceIn(-1f, 1f))
                val tangentDistance = radius / tan(angle / 2)
                val start = vertex + toPrevious * tangentDistance
                val end = vertex + toNext * tangentDistance
                val center = vertex + (toPrevious + toNext).normalized() * (radius / sin(angle / 2))
                path.lineTo(start.x, start.y)
                val startAngle = atan2(start.y - center.y, start.x - center.x)
                var sweep = atan2(end.y - center.y, end.x - center.x) - startAngle
                if (sweep > PI) sweep -= (2 * PI).toFloat()
                if (sweep < -PI) sweep += (2 * PI).toFloat()
                path.arcTo(
                    Rect(center, radius),
                    Math.toDegrees(startAngle.toDouble()).toFloat(),
                    Math.toDegrees(sweep.toDouble()).toFloat(),
                    forceMoveTo = false,
                )
            }
            path.close()
            return path
        }

        fun Offset.normalized(): Offset {
            val length = getDistance()
            return if (length == 0f) this else this / length
        }
    }
}
