package com.voria.umsh.app

import com.voria.umsh.core.MobileAppLifecycle
import com.voria.umsh.core.MobileStagingAirException
import com.voria.umsh.models.AppStateSnapshot
import com.voria.umsh.models.ChatMessage
import com.voria.umsh.services.preferences.AppPreferences
import java.io.File
import java.time.Clock
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withTimeout

/**
 * A host running the staging core over the real core (JNA), whose staged
 * radio carries this phone: the staged mesh to send into.
 */
class StagedHost(root: File) {
    val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    val paths = AppPaths(File(root, "files").apply { mkdirs() }, File(root, "cache").apply { mkdirs() })
    val preferences = AppPreferences(paths.preferences, scope)
    val host = AppCoreHost(paths, MemoryVaults(VaultLog()), preferences, { 65026u }, Clock.systemUTC(), MutableSharedFlow(), true, scope)

    lateinit var runtime: AppRuntime
        private set

    /** Staging up, running, and its radio carrying this phone. */
    suspend fun start(): AppRuntime {
        host.ensureRuntime(staging = true)
        val ready = withTimeout(TIMEOUT) { host.state.first { it is HostState.Ready && it.runtime.kind == CoreKind.Staging } }
        runtime = (ready as HostState.Ready).runtime
        withTimeout(TIMEOUT) { runtime.lifecycle.first { it is MobileAppLifecycle.Running } }
        carrying(true)
        return runtime
    }

    val air get() = host.stagingRadio.value!!

    suspend fun carrying(carries: Boolean) {
        withTimeout(TIMEOUT) { runtime.radio.first { (it?.carriesThisPhone == true) == carries } }
    }

    /** The staged peer says [body], once it has learned the phone. */
    suspend fun peerSays(body: String) {
        withTimeout(TIMEOUT) {
            while (true) {
                try {
                    air.air.peerSays(body, false)
                    break
                } catch (_: MobileStagingAirException.NoPhone) {
                    delay(POLL_MS)
                }
            }
        }
    }

    suspend fun stateWhere(predicate: (AppStateSnapshot) -> Boolean): AppStateSnapshot =
        withTimeout(TIMEOUT) { runtime.appState.first { it != null && predicate(it) }!! }

    /** The newest messages of [address], read until [predicate] holds of them. */
    suspend fun messagesWhere(address: String, predicate: (List<ChatMessage>) -> Boolean): List<ChatMessage> =
        withTimeout(TIMEOUT) {
            while (true) {
                val messages = runtime.transcriptNewest(address, 50).messages
                if (predicate(messages)) return@withTimeout messages
                delay(POLL_MS)
            }
            @Suppress("UNREACHABLE_CODE")
            emptyList()
        }

    /** The stored draft, as the core reads it. */
    fun storedDraft(address: String): String? {
        val state = runtime.core.state(true)
        return state.directConversations.firstOrNull { it.peer.identity.canonicalAddress == address }?.draftText
            ?: state.channelConversations.firstOrNull { it.conversationAddress == address }?.draftText
    }

    /** `EMERGENCY`'s conversation, opened. */
    suspend fun emergency(): String {
        val channel = stateWhere { state -> state.channels.any { it.canonicalName == "emergency" } }
            .channels.first { it.canonicalName == "emergency" }
        return runtime.openChannelConversation(channel.id).await()
    }

    suspend fun close() {
        withTimeout(TIMEOUT) { host.shutdown() }
        scope.cancel()
    }

    companion object {
        const val TIMEOUT = 30_000L
        const val POLL_MS = 25L
    }
}
