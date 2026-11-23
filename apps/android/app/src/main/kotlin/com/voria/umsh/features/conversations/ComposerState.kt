package com.voria.umsh.features.conversations

import com.voria.umsh.services.radio.RadioControlState
import com.voria.umsh.services.radio.RadioSnapshot

/**
 * What the composer can do (`composer.svg`). The field is usable in every
 * state: a draft is kept with or without a radio. Send fires only while the
 * radio carries this phone (design §3.6); a link on its way up or back, or
 * attached but not yet carrying this phone, waits with Send dimmed.
 */
enum class ComposerState {
    /** The radio carries this phone: Send goes. */
    Ready,

    /** On its way up or back, attached but not carrying this phone, or not read yet: Send waits, dimmed. */
    Transient,

    /** No radio, or the link is down: a line above the field says why. Nothing is queued. */
    Blocked,
    ;

    companion object {
        /** [known] false: the radio has not been read yet, so a null [radio] is not "none". */
        fun from(radio: RadioSnapshot?, known: Boolean): ComposerState =
            when (RadioControlState.from(radio, known).link) {
                RadioControlState.Link.Connected -> if (radio?.carriesThisPhone == true) Ready else Transient
                RadioControlState.Link.Unknown,
                RadioControlState.Link.Connecting,
                RadioControlState.Link.Reconnecting,
                -> Transient
                RadioControlState.Link.None,
                RadioControlState.Link.Waiting,
                RadioControlState.Link.Disconnected,
                RadioControlState.Link.Failed,
                -> Blocked
            }
    }
}
