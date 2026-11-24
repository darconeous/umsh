package com.voria.umsh.features.peers

import androidx.compose.runtime.staticCompositionLocalOf
import com.voria.umsh.app.AppRuntime
import com.voria.umsh.models.MeetState
import com.voria.umsh.services.mobilecore.AppLog
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.map

/**
 * Add peer's contact exchange (UEP-0022) as the pages see it: where it
 * stands, and what they can do about it. Every step is the core's; the
 * pages only show its state and pass on the holder's taps, each sent in
 * the runtime's scope, so leaving a page or rotating never cancels one.
 */
interface ExchangeHost {
    /** Where the exchange stands; null while it is closed. */
    val meet: StateFlow<MeetState?>

    /** The radio carries this phone, so Nearby can list devices; with [carriesThisPhoneNow] as its first value. */
    val carriesThisPhone: Flow<Boolean>

    fun carriesThisPhoneNow(): Boolean

    /** This phone's model (`platforms.json`), which its Hellos carry: its own glyph beside You. */
    val ownModel: Int

    /** Whether the exchange is wanted open: only [com.voria.umsh.app.MeetPresence] says. */
    suspend fun setWanted(wanted: Boolean)

    /** Ask Nearby's device [device]. */
    fun ask(device: Long)

    /** Exchange ([accept]) or Not now, while a device asks; nothing once none does. */
    fun answer(accept: Boolean)

    /** Same ([same]) or Different. */
    fun confirm(same: Boolean)

    /** Leave the attempt under way, or ended, under a fresh key; nothing when none is. */
    fun backOut(): Deferred<Unit>
}

/** [ExchangeHost] over the runtime. */
class RuntimeExchangeHost(private val runtime: AppRuntime) : ExchangeHost {
    override val ownModel: Int = runtime.platformModel.toInt()

    override val meet: StateFlow<MeetState?> get() = runtime.meet

    override val carriesThisPhone: Flow<Boolean> = runtime.radio.map { it?.carriesThisPhone == true }.distinctUntilChanged()

    override fun carriesThisPhoneNow(): Boolean = runtime.radio.value?.carriesThisPhone == true

    override suspend fun setWanted(wanted: Boolean) = runtime.setMeetWanted(wanted).await()

    override fun ask(device: Long) {
        runtime.askToExchange(device).logged("ask")
    }

    override fun answer(accept: Boolean) {
        runtime.answerExchange(accept).logged("answer")
    }

    override fun confirm(same: Boolean) {
        runtime.confirmCode(same).logged("confirm")
    }

    override fun backOut(): Deferred<Unit> = runtime.backOutOfExchange().logged("back out")

    /**
     * A step that did not go out leaves the state where it was, so the page
     * still offers it; the core ends an attempt that lost its radio itself.
     */
    private fun <T> Deferred<T>.logged(step: String): Deferred<T> = apply {
        invokeOnCompletion { error -> if (error != null) AppLog.w(TAG, "$step not taken: ${error.javaClass.simpleName}") }
    }

    private companion object {
        const val TAG = "umsh.meet"
    }
}

/**
 * The exchange the shell's pages show: the runtime's, unless a test or a
 * shot provides its own.
 */
val LocalExchangeHost = staticCompositionLocalOf<ExchangeHost?> { null }
