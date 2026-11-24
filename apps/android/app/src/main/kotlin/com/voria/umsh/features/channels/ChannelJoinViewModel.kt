package com.voria.umsh.features.channels

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.voria.umsh.app.AppRuntime
import com.voria.umsh.core.MobileAppException
import com.voria.umsh.core.MobileException
import com.voria.umsh.models.ChannelPreview
import com.voria.umsh.models.JoinedChannel
import com.voria.umsh.services.mobilecore.AppLog
import kotlin.coroutines.cancellation.CancellationException
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.launch

/** Why the field's text was not looked up, shown under it. */
enum class ChannelInputProblem {
    /** A name with characters no channel can be named with. */
    NotAscii,

    /** A name longer than a channel's can be. */
    TooLong,

    /** Neither a channel name nor a channel invitation. */
    NotChannel,
}

/** A command that failed, for its dialog. */
sealed interface ChannelJoinFailure {
    val error: Throwable

    /** The store could not be read. */
    data class NotLookedUp(override val error: Throwable) : ChannelJoinFailure

    data class NotJoined(override val error: Throwable) : ChannelJoinFailure
}

/** What looking up and joining need of the app. */
interface ChannelJoinHost {
    suspend fun preview(input: String): ChannelPreview

    fun join(input: String, alias: String?, clearAlias: Boolean, openConversation: Boolean): Deferred<JoinedChannel>

    fun rejoin(id: String): Deferred<Unit>
}

/** [ChannelJoinHost] over the runtime. */
class RuntimeChannelJoinHost(private val runtime: AppRuntime) : ChannelJoinHost {
    override suspend fun preview(input: String) = runtime.previewChannel(input)

    override fun join(input: String, alias: String?, clearAlias: Boolean, openConversation: Boolean) =
        runtime.joinChannel(input, alias, openConversation, clearAlias)

    override fun rejoin(id: String) = runtime.rejoinChannel(id)
}

/**
 * Join channel's lookup and join (`channels.svg` 5–9, `qr-scanner.svg` 4).
 * Look up reads the text here and now, storing and sending nothing; Join
 * hands the core the text that was looked up, which it reads again, so an
 * edit afterward cannot join something else. The join runs in the
 * runtime's scope, so a rotation does not cancel it; after process death
 * the preview is not restored.
 */
class ChannelJoinViewModel(private val host: ChannelJoinHost) : ViewModel() {
    private val _preview = MutableStateFlow<ChannelPreview?>(null)
    private val _problem = MutableStateFlow<ChannelInputProblem?>(null)
    private val _joining = MutableStateFlow(false)
    private val _failure = MutableStateFlow<ChannelJoinFailure?>(null)
    private val _joined = Channel<JoinedChannel>(Channel.BUFFERED)
    private var lookups = 0

    /** What the last Look up found; null before one, or after the field changed. */
    val preview: StateFlow<ChannelPreview?> = _preview.asStateFlow()
    val problem: StateFlow<ChannelInputProblem?> = _problem.asStateFlow()
    val joining: StateFlow<Boolean> = _joining.asStateFlow()
    val failure: StateFlow<ChannelJoinFailure?> = _failure.asStateFlow()

    /** Each join done, once: the screen leaves. */
    val joined: Flow<JoinedChannel> = _joined.receiveAsFlow()

    /** The field changed: neither its line nor the preview describe it now. */
    fun edited() {
        lookups++
        _problem.value = null
        _preview.value = null
    }

    /** Look up: what [input] names. */
    fun lookUp(input: String) {
        if (input.isBlank()) return
        val lookup = ++lookups
        viewModelScope.launch {
            val outcome = try {
                Result.success(host.preview(input.trim()))
            } catch (error: CancellationException) {
                throw error
            } catch (error: Exception) {
                Result.failure(error)
            }
            // A newer lookup or an edit since: this one no longer describes the field.
            if (lookup != lookups) return@launch
            outcome.onSuccess {
                _problem.value = null
                _preview.value = it
            }.onFailure { error ->
                _preview.value = null
                val problem = problem(error)
                if (problem != null) {
                    _problem.value = problem
                } else {
                    AppLog.w(TAG, "channel not looked up: ${error.javaClass.simpleName}")
                    _failure.value = ChannelJoinFailure.NotLookedUp(error)
                }
            }
        }
    }

    /**
     * Join what was looked up, named [alias] here; with [openConversation]
     * its chat opens too. An empty [alias] leaves a new channel unnamed, and
     * clears the alias of a held one (the field showed it, and was cleared).
     */
    fun join(alias: String, openConversation: Boolean) {
        val shown = _preview.value ?: return
        val named = alias.trim().ifEmpty { null }
        val clearing = named == null && shown.existing?.alias != null
        run({ host.join(shown.input, named, clearing, openConversation) }) { it }
    }

    /** A suggested channel (a built-in one this phone left): joined again. */
    fun rejoin(id: String) {
        run({ host.rejoin(id) }) { JoinedChannel(id, null) }
    }

    fun dismissFailure() {
        _failure.value = null
    }

    /** One join at a time: a second tap while one runs sends nothing. */
    private fun <T> run(start: () -> Deferred<T>, joined: (T) -> JoinedChannel) {
        if (_joining.value) return
        _joining.value = true
        val command = start()
        viewModelScope.launch {
            try {
                _joined.send(joined(command.await()))
            } catch (error: CancellationException) {
                throw error
            } catch (error: Exception) {
                AppLog.w(TAG, "channel not joined: ${error.javaClass.simpleName}")
                _failure.value = ChannelJoinFailure.NotJoined(error)
            } finally {
                _joining.value = false
            }
        }
    }

    companion object {
        private const val TAG = "umsh.channels"

        /** What the field's line says for [error], or null when the text was fine and something else failed. */
        fun problem(error: Throwable): ChannelInputProblem? {
            val input = (error as? MobileAppException.InvalidInput)?.error ?: return null
            return when (input) {
                is MobileException.ChannelNameNotAscii -> ChannelInputProblem.NotAscii
                is MobileException.ChannelNameTooLong -> ChannelInputProblem.TooLong
                else -> ChannelInputProblem.NotChannel
            }
        }
    }
}
