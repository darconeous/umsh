package com.voria.umsh.app

import androidx.navigation3.runtime.NavKey
import kotlinx.serialization.Serializable

/**
 * Every page the shell's back stacks hold. Serializable, so the stacks
 * survive process death; R8 keeps them (`proguard-rules.pro`).
 */
@Serializable
sealed interface UmshKey : NavKey {
    @Serializable
    data object ConversationsRoot : UmshKey

    /** A conversation, by its address (a peer's, or a channel conversation's). */
    @Serializable
    data class Thread(val address: String) : UmshKey

    /** One message's details (`bubbles.svg` 6–7), from its thread. */
    @Serializable
    data class MessageDetails(val address: String, val sessionId: String, val handle: Long) : UmshKey

    @Serializable
    data object PeersRoot : UmshKey

    @Serializable
    data object MapRoot : UmshKey

    @Serializable
    data object SettingsRoot : UmshKey

    @Serializable
    data object YourIdentity : UmshKey

    /**
     * The companion radio's page: above the shell on the app-level stack,
     * or in the Settings stack as Companion radio.
     */
    @Serializable
    data object RadioDetail : UmshKey

    /** Choose a radio (`radio-picker.svg`): above the shell on the app-level stack. */
    @Serializable
    data object RadioPicker : UmshKey

    /** Settings › Notifications. */
    @Serializable
    data object Notifications : UmshKey

    /** The app-level stack's root: the shell itself, with its destinations. */
    @Serializable
    data object Shell : UmshKey
}
