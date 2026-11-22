package com.voria.umsh.features.conversations

import com.voria.umsh.services.radio.RadioControlState
import com.voria.umsh.services.radio.RadioSnapshot

/**
 * What the composer can do (`composer.svg`), from the radio's link alone.
 * The field is usable in every state: a draft is kept with or without a
 * radio. Whether the radio carries this phone decides only whether Send may
 * fire (design §3.9), not what the composer says.
 */
enum class ComposerState {
    /** The link is up. */
    Ready,

    /** The link is on its way up or back, or not read yet: Send waits, dimmed. */
    Transient,

    /** No radio, or the link is down: a line above the field says why. */
    Blocked,
    ;

    companion object {
        /** [known] false: the radio has not been read yet, so a null [radio] is not "none". */
        fun from(radio: RadioSnapshot?, known: Boolean): ComposerState =
            when (RadioControlState.from(radio, known).link) {
                RadioControlState.Link.Connected -> Ready
                RadioControlState.Link.Unknown,
                RadioControlState.Link.Connecting,
                RadioControlState.Link.Reconnecting,
                -> Transient
                RadioControlState.Link.None,
                RadioControlState.Link.Disconnected,
                RadioControlState.Link.Failed,
                -> Blocked
            }
    }
}
