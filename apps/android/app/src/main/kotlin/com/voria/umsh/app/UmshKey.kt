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

    @Serializable
    data object PeersRoot : UmshKey

    @Serializable
    data object MapRoot : UmshKey

    @Serializable
    data object SettingsRoot : UmshKey

    @Serializable
    data object YourIdentity : UmshKey
}
