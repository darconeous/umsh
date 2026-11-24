package com.voria.umsh.features.peers

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.voria.umsh.app.AppRuntime
import com.voria.umsh.models.ImportPreview
import com.voria.umsh.models.PeerSummary
import kotlin.coroutines.cancellation.CancellationException
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.launch

/** Why the field's text was not previewed (`add-peer.svg` 2), shown under it. */
enum class AddPeerProblem {
    /** Not a node link, an address or a key. */
    NotPeer,
}

/**
 * A channel link entered or scanned where a peer was looked for: the
 * channel's join preview opens for it (`qr-scanner.svg` 4). [opening]
 * tells one opening from the next, so the same link entered twice starts
 * afresh.
 */
data class ChannelOpening(val input: String, val opening: Long)

/** Where Add peer leaves for once the field or the preview is done. */
sealed interface AddPeerExit {
    /** The node's page: saved here, or already saved before. */
    data class Page(val address: String) : AddPeerExit

    /** The node's conversation, saved and started here. */
    data class Conversation(val address: String) : AddPeerExit

    /** This phone's own identity was entered: Your identity, as a link to it opens. */
    data object OwnIdentity : AddPeerExit
}

/** What the preview's save is doing. */
sealed interface ImportSave {
    data object Idle : ImportSave

    /** Under way; [message] when it starts the conversation too. */
    data class Saving(val message: Boolean) : ImportSave

    /** It failed, [message] when it was Message: the failure dialog's error. The preview stays open. */
    data class Failed(val error: Throwable, val message: Boolean) : ImportSave
}

/** What Add peer needs of the app: who this phone is, what is stored, and the save. */
interface PeerImportHost {
    val ownAddress: String

    fun stored(address: String): PeerSummary?

    fun save(input: String, alias: String?, startConversation: Boolean): Deferred<String>
}

/** [PeerImportHost] over the runtime. */
class RuntimeImportHost(private val runtime: AppRuntime) : PeerImportHost {
    override val ownAddress: String get() = runtime.identity.value.address

    override fun stored(address: String): PeerSummary? = runtime.appState.value?.peers?.firstOrNull { it.address == address }

    override fun save(input: String, alias: String?, startConversation: Boolean) = runtime.savePeer(input, alias, startConversation)
}

/**
 * Add peer's identity field and its import preview (`add-peer.svg` 1–4).
 * Preview reads the text locally: a channel link opens the channel's join
 * preview; anything that names no node is a line under the field; a node
 * already saved, or this phone
 * itself, opens its page instead; any other node opens the preview, and
 * nothing is stored or sent until Save peer or Message. The save runs in
 * the runtime's scope, so a rotation does not cancel it; after process
 * death the preview does not reopen.
 */
class AddPeerViewModel(
    private val host: PeerImportHost,
    private val check: (String) -> ImportCheck = PeerImport::check,
) : ViewModel() {
    private val _problem = MutableStateFlow<AddPeerProblem?>(null)
    private val _preview = MutableStateFlow<ImportPreview?>(null)
    private val _save = MutableStateFlow<ImportSave>(ImportSave.Idle)
    private val _exits = Channel<AddPeerExit>(Channel.BUFFERED)
    private val _codeShown = MutableStateFlow(false)
    private val _channel = MutableStateFlow<ChannelOpening?>(null)
    private var openings = 0L

    val problem: StateFlow<AddPeerProblem?> = _problem.asStateFlow()
    val preview: StateFlow<ImportPreview?> = _preview.asStateFlow()
    val save: StateFlow<ImportSave> = _save.asStateFlow()

    /** A channel link's join preview, open over the page; null when none is. */
    val channel: StateFlow<ChannelOpening?> = _channel.asStateFlow()

    /** Your identity's QR sheet is open: kept across a rotation, not after process death. */
    val codeShown: StateFlow<Boolean> = _codeShown.asStateFlow()

    /** Where to go, once each; the screen navigates. */
    val exits: Flow<AddPeerExit> = _exits.receiveAsFlow()

    fun showCode(shown: Boolean) {
        _codeShown.value = shown
    }

    /** The field changed: its line no longer describes it. */
    fun edited() {
        _problem.value = null
    }

    /** Preview: what [input] names, read here and now. */
    fun preview(input: String) {
        if (input.isBlank()) return
        when (val checked = check(input)) {
            ImportCheck.ChannelLink -> {
                _problem.value = null
                _channel.value = ChannelOpening(input.trim(), ++openings)
            }
            ImportCheck.NotPeer -> _problem.value = AddPeerProblem.NotPeer
            is ImportCheck.Node -> {
                _problem.value = null
                val address = checked.preview.address
                val stored = host.stored(address)
                when {
                    address == host.ownAddress -> _exits.trySend(AddPeerExit.OwnIdentity)
                    stored != null && (stored.isSaved || stored.isCompanionRadio) -> _exits.trySend(AddPeerExit.Page(address))
                    else -> {
                        _save.value = ImportSave.Idle
                        _preview.value = checked.preview
                    }
                }
            }
        }
    }

    /** The channel's preview closed: dismissed, or joined. */
    fun closeChannel() {
        _channel.value = null
    }

    /** The sheet was dismissed: back to Add peer, nothing saved. Not while a save is under way. */
    fun dismissPreview() {
        if (_save.value is ImportSave.Saving) return
        _preview.value = null
        _save.value = ImportSave.Idle
    }

    /** Save peer ([message] false) or Message: saved with [alias], then its page or its conversation. */
    fun importPeer(alias: String, message: Boolean) {
        val shown = _preview.value ?: return
        if (_save.value is ImportSave.Saving) return
        _save.value = ImportSave.Saving(message)
        val saving = host.save(shown.input, alias.trim().ifEmpty { null }, message)
        viewModelScope.launch {
            try {
                val address = saving.await()
                _preview.value = null
                _save.value = ImportSave.Idle
                _exits.send(if (message) AddPeerExit.Conversation(address) else AddPeerExit.Page(address))
            } catch (error: CancellationException) {
                throw error
            } catch (error: Exception) {
                _save.value = ImportSave.Failed(error, message)
            }
        }
    }

    /** The failure dialog closed: the preview is still open to try another choice. */
    fun dismissFailure() {
        if (_save.value is ImportSave.Failed) _save.value = ImportSave.Idle
    }
}
