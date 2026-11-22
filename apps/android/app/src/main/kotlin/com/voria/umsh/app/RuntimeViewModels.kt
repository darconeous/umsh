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

/** The runtime the shell is drawn over; provided inside the shell's keyed block. */
val LocalAppRuntime = staticCompositionLocalOf<AppRuntime> { error("no runtime: outside the shell") }

/** The process's host, for the few screens that act on it (the debug Developer section). */
val LocalAppCoreHost = staticCompositionLocalOf<AppCoreHost> { error("no host: outside the app") }

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
