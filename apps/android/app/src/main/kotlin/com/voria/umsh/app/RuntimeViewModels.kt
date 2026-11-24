package com.voria.umsh.app

import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.lifecycle.HasDefaultViewModelProviderFactory
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelStore
import androidx.lifecycle.ViewModelStoreOwner
import androidx.lifecycle.viewmodel.CreationExtras
import androidx.lifecycle.viewmodel.MutableCreationExtras
import androidx.lifecycle.viewmodel.compose.LocalViewModelStoreOwner
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.lifecycle.viewmodel.initializer
import androidx.lifecycle.viewmodel.viewModelFactory
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update

/** The runtime the shell is drawn over; provided inside the shell's keyed block. */
val LocalAppRuntime = staticCompositionLocalOf<AppRuntime> { error("no runtime: outside the shell") }

/** The process's host, for the few screens that act on it (the debug Developer section). */
val LocalAppCoreHost = staticCompositionLocalOf<AppCoreHost> { error("no host: outside the app") }

/** A page a notification, a shortcut or a link asked to open. */
sealed interface OpenRequest {
    /** A conversation, by address. */
    data class Conversation(val address: String) : OpenRequest

    /** Radio Detail: the radio notification's tap. */
    data object RadioDetail : OpenRequest

    /**
     * A notification about a node (a Next time heard notice): its
     * conversation when it sends text, else its page on Peers.
     */
    data class Peer(val address: String) : OpenRequest

    /** A `umsh:` link, opened from [origin] ([LinkRoute]). */
    data class Link(val uri: String, val origin: LinkOrigin) : OpenRequest
}

/**
 * What notifications, shortcuts and links asked to open, in the order they
 * arrived, until the shell opens each. At most one link and one other
 * request wait: a newer one of either kind replaces the older. Held by the
 * activity, so a link that arrives during onboarding waits for the shell
 * (and, through the activity's saved state, across process death).
 */
class OpenRequests {
    private val _pending = MutableStateFlow<List<OpenRequest>>(emptyList())

    val pending: StateFlow<List<OpenRequest>> = _pending.asStateFlow()

    /** The link waiting, if any. */
    val link: OpenRequest.Link? get() = _pending.value.firstNotNullOfOrNull { it as? OpenRequest.Link }

    /**
     * [request] waits to be opened. One equal to a request already waiting
     * (the same link tapped twice) is that request: requests are compared
     * by value throughout, as the [pending] flow compares its lists, so a
     * repeat is never held unseen behind one the shell is opening.
     */
    fun offer(request: OpenRequest) {
        _pending.update { waiting ->
            if (request in waiting) waiting else waiting.filterNot { (it is OpenRequest.Link) == (request is OpenRequest.Link) } + request
        }
    }

    /** [request] was opened: no longer waiting, nor any repeat of it. */
    fun done(request: OpenRequest) {
        _pending.update { waiting -> waiting - request }
    }
}

/**
 * What notifications, shortcuts and links asked to open; the shell opens
 * each and clears it. None outside the activity.
 */
val LocalOpenRequests = staticCompositionLocalOf { OpenRequests() }

/**
 * The shell's own ViewModel store: for a page drawn in two places, such as
 * Your identity as the Settings detail placeholder and as its own entry,
 * so both share one ViewModel rather than each entry having its own.
 */
val LocalShellViewModelStoreOwner = staticCompositionLocalOf<ViewModelStoreOwner> { error("no shell store: outside the shell") }

/** How a ViewModel's factory receives the runtime: never a global read inside the ViewModel. */
object RuntimeExtras {
    val Runtime = object : CreationExtras.Key<AppRuntime> {}
}

/**
 * A ViewModel of the current store owner (the shell's, or a back-stack
 * entry's), made by [create] from the runtime handed in through its
 * creation extras.
 */
@Composable
inline fun <reified VM : ViewModel> runtimeViewModel(
    key: String? = null,
    owner: ViewModelStoreOwner = checkNotNull(LocalViewModelStoreOwner.current) { "no ViewModelStoreOwner" },
    crossinline create: (AppRuntime) -> VM,
): VM {
    val runtime = LocalAppRuntime.current
    val defaults = (owner as? HasDefaultViewModelProviderFactory)?.defaultViewModelCreationExtras
        ?: CreationExtras.Empty
    val extras = MutableCreationExtras(defaults).apply { set(RuntimeExtras.Runtime, runtime) }
    val factory = remember { viewModelFactory { initializer { create(this[RuntimeExtras.Runtime]!!) } } }
    return viewModel(viewModelStoreOwner = owner, key = key, factory = factory, extras = extras)
}

/**
 * The ViewModel stores of each shell: the shell's own, and, beneath it,
 * every back-stack entry's. Held by the activity, so they survive a
 * configuration change. The shell releases its store when it goes for any
 * other reason (a mode switch, a new identity, a host that is no longer
 * ready), so no ViewModel outlives the runtime it was made over.
 */
class ShellStores : ViewModel() {
    private val stores = HashMap<String, ViewModelStore>()

    /** The store for [key], made on first use. Safe to call from composition. */
    fun owner(key: String): ViewModelStoreOwner {
        val store = stores.getOrPut(key) { ViewModelStore() }
        return object : ViewModelStoreOwner {
            override val viewModelStore = store
        }
    }

    /** The keys of the stores held: for the tests. */
    internal val keys: Set<String> get() = stores.keys.toSet()

    /** Clear every store but [key]'s: ones a shell left behind across a recreation. */
    fun retainOnly(key: String) {
        stores.keys.filter { it != key }.forEach(::release)
    }

    /** Clear [key]'s store and its ViewModels. */
    fun release(key: String) {
        stores.remove(key)?.clear()
    }

    override fun onCleared() {
        stores.values.forEach { it.clear() }
        stores.clear()
    }
}
