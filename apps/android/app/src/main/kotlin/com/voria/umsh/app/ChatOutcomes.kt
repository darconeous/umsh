package com.voria.umsh.app

import com.voria.umsh.core.MobileAppException
import com.voria.umsh.models.ResendMode

/**
 * How a chat command ended, as the thread words it. The core keeps the
 * order of refusals and what a kept message means; this only sorts its
 * answer.
 */
sealed interface SendOutcome {
    /** Taken by the radio session. */
    data object Sent : SendOutcome

    /**
     * Kept but could not go out (the core's `MessageNotQueued`): the
     * composer lets go of it either way. [recorded], it is stored as not
     * delivered; otherwise it may read as sending until UMSH restarts.
     */
    data class Kept(val recorded: Boolean) : SendOutcome

    /** Refused before anything was kept; the words stay where they were. */
    data class Refused(val error: Throwable) : SendOutcome {
        /** `EMERGENCY`'s warning is wanted first. */
        val needsEmergencyAgreement: Boolean get() = error is MobileAppException.EmergencyNotCertified
    }

    companion object {
        /** What [error], thrown by a chat command, means. */
        fun of(error: Throwable): SendOutcome = when (error) {
            is MobileAppException.MessageNotQueued -> Kept(error.recorded)
            else -> Refused(error)
        }
    }
}

/** How a resend ended. */
sealed interface ResendOutcome {
    /** Gone out again: in place, or as a new message replacing the failed one. */
    data class Resent(val mode: ResendMode) : ResendOutcome

    /** Kept as a new message, but not sent; see [SendOutcome.Kept]. */
    data class Kept(val recorded: Boolean) : ResendOutcome

    data class Refused(val error: Throwable) : ResendOutcome {
        val needsEmergencyAgreement: Boolean get() = error is MobileAppException.EmergencyNotCertified
    }
}

/** How a reply typed into a notification ended. */
sealed interface ReplyOutcome {
    data object Sent : ReplyOutcome

    /**
     * It did not go out. [savedAsDraft]: its words wait under the
     * conversation's draft; not when the core kept the message itself, or
     * the conversation is not stored.
     */
    data class Failed(val savedAsDraft: Boolean) : ReplyOutcome
}

/** Words added to [address]'s stored draft from outside its thread; see [AppRuntime.draftAdditions]. */
data class DraftAddition(val address: String, val text: String) {
    /** [draft] with these words added, as the core adds them to a stored draft: on a line of their own, unless it is empty. */
    fun addedTo(draft: String): String = if (draft.isEmpty()) text else "$draft\n$text"
}
