package com.voria.umsh.designsystem

import com.voria.umsh.models.Capabilities
import com.voria.umsh.models.PeerRole
import com.voria.umsh.models.PeerSummary

/**
 * The outline a peer's avatar is drawn in, which says what kind of node it
 * is: a circle for one that chats, a triangle for one that carries traffic,
 * a hexagon for everything else. Pure Kotlin; [PeerAvatarOutline] draws it.
 */
enum class PeerAvatarShape {
    Circle,
    Triangle,
    Hexagon,
    ;

    /** How far below the middle the lettering sits, as a fraction of the size: the triangle's incenter. */
    val textCenterOffsetRatio: Float
        get() = when (this) {
            Circle, Hexagon -> 0f
            Triangle -> 0.5f - TRIANGLE_HEIGHT_RATIO / 3f
        }

    /** The lettering's size relative to the circle's, so it fits a shape with less room. */
    val fontScale: Float
        get() = when (this) {
            Circle, Hexagon -> 1f
            Triangle -> 0.9f
        }

    companion object {
        /**
         * First match wins: the Chat capability or the chat role is a
         * circle; the repeater or bridge role a triangle (the repeater
         * capability bit alone is not); anything else a hexagon.
         */
        fun of(role: PeerRole, capabilities: Capabilities?): PeerAvatarShape = when {
            capabilities?.contains(Capabilities.TEXT_MESSAGES) == true || role == PeerRole.Chat -> Circle
            role == PeerRole.Repeater || role == PeerRole.Bridge -> Triangle
            else -> Hexagon
        }

        /** A peer's outline: its live advertisement's role and capabilities, else its stored role. */
        fun of(peer: PeerSummary): PeerAvatarShape =
            of(peer.role, peer.advertised?.let { Capabilities(it.capabilityBits) })

        /** The rounded triangle's corner radius, as a fraction of the size. */
        const val TRIANGLE_CORNER_RATIO = 0.16f

        /** Vertex to base relative to the frame: the frame plus how far the rounded apex sits below the vertex. */
        const val TRIANGLE_HEIGHT_RATIO = 1f + TRIANGLE_CORNER_RATIO

        /** The rounded hexagon's corner radius, as a fraction of the size. */
        const val HEXAGON_CORNER_RATIO = 0.2f
    }
}
