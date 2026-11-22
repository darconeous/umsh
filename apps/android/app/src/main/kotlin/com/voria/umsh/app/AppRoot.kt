package com.voria.umsh.app

import androidx.activity.compose.LocalActivity
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.key
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.LocalViewModelStoreOwner
import androidx.lifecycle.viewmodel.compose.viewModel
import com.voria.umsh.BuildConfig
import com.voria.umsh.app.debug.StagingStoreActions
import com.voria.umsh.designsystem.EraseFailureDialog
import com.voria.umsh.designsystem.NoticeHost
import com.voria.umsh.designsystem.UmshTheme
import com.voria.umsh.features.onboarding.WelcomeScreen
import com.voria.umsh.features.settings.IdentityLostScreen
import com.voria.umsh.features.settings.IdentityUnavailableScreen
import com.voria.umsh.services.preferences.OnboardingStep
import java.util.UUID
import kotlinx.coroutines.flow.flowOf

/** What the activity draws: the shell over the running core, or why there is none. */
@Composable
fun AppRoot(host: AppCoreHost) {
    // Debug builds: the Developer switch draws with the fallback scheme,
    // for screenshot runs beside the drawings.
    val fallback by remember(host) {
        if (BuildConfig.DEBUG) host.preferences.fallbackScheme else flowOf(false)
    }.collectAsStateWithLifecycle(initialValue = false)
    UmshTheme(fallbackScheme = fallback) {
        val state by host.state.collectAsStateWithLifecycle()
        Surface(Modifier.fillMaxSize().testTag(Tags.APP_ROOT)) {
            if (state !is HostState.Ready) {
                // No shell, so no shell store: one kept across a recreation
                // made as the runtime went is let go here, not when the next
                // runtime is shown.
                val stores: ShellStores = viewModel()
                SideEffect { stores.retainOnly("") }
            }
            when (val shown = state) {
                is HostState.Ready -> RuntimeShell(host, shown.runtime)
                // These replace the shell: nothing that looks like the app
                // while its data or identity cannot be reached.
                is HostState.StoreUnavailable -> NoticeHost {
                    StorageUnavailableScreen(shown.detail.render()) {
                        // Debug builds: staging's own store is reset from here,
                        // since the Developer section is out of reach.
                        if (shown.kind == CoreKind.Staging) StagingStoreActions(host)
                    }
                }
                HostState.IdentityUnavailable -> NoticeHost { IdentityUnavailableScreen() }
                is HostState.IdentityLost -> NoticeHost {
                    // Staging never erases the live identity (D16).
                    IdentityLostScreen(
                        shown.detail,
                        onErase = if (shown.erasable) {
                            { host.erase(EraseMode.IdentityOnly, thenMint = true) }
                        } else {
                            null
                        },
                    )
                }
                // Starting keeps the splash screen up; NeedsFirstLaunch is
                // brought up by the activity as soon as it is shown.
                HostState.Starting, HostState.NeedsFirstLaunch -> Unit
            }
            val eraseFailure by host.eraseFailure.collectAsStateWithLifecycle()
            eraseFailure?.let { outcome -> EraseFailureDialog(outcome, onDismiss = host::dismissEraseFailure) }
        }
    }
}

/**
 * The shell, keyed on the runtime it is drawn over. A new runtime (a mode
 * switch, or a new identity) is a new shell: its back stacks, saved UI state
 * and ViewModels are deliberately discarded. The key is saveable, so the
 * same shell comes back after a configuration change or process death and
 * its back stacks with it.
 */
@Composable
private fun RuntimeShell(host: AppCoreHost, runtime: AppRuntime) {
    val saved = rememberSaveable { mutableStateOf<String?>(null) }
    val firstRuntime = remember { arrayOfNulls<AppRuntime>(1) }
    val shellKey = remember(runtime) {
        // The first runtime this activity sees takes back the shell it last
        // showed (same kind and identity): a recreated activity, or a
        // restored process.
        // Any later runtime is a new shell.
        // The key names the identity as well as the kind: a new identity
        // minted while the activity was away is never handed the erased
        // one's back stacks.
        val prefix = "${runtime.kind}/${runtime.ownerAddress}/"
        val restoring = firstRuntime[0] == null && saved.value?.startsWith(prefix) == true
        if (firstRuntime[0] == null) firstRuntime[0] = runtime
        if (restoring) saved.value!! else "$prefix${UUID.randomUUID()}"
    }
    SideEffect { saved.value = shellKey }

    // The stores belong to the runtime, not only the key: a store never
    // hands a ViewModel made over one runtime to the next.
    val stores: ShellStores = viewModel()
    val storeKey = "$shellKey#${runtime.generation}"
    val owner = remember(storeKey) { stores.owner(storeKey) }
    val activity = LocalActivity.current
    DisposableEffect(stores, storeKey) {
        stores.retainOnly(storeKey)
        onDispose {
            // A recreated activity takes the same store back; anything else
            // (a new runtime, a host no longer ready) ends this shell.
            if (activity?.isChangingConfigurations != true) stores.release(storeKey)
        }
    }
    key(shellKey) {
        CompositionLocalProvider(
            LocalAppRuntime provides runtime,
            LocalAppCoreHost provides host,
            LocalViewModelStoreOwner provides owner,
        ) {
            // First launch replaces the shell until Welcome is done. The
            // Connect a radio step waits for Phase 2's radio search, so a
            // stored ConnectRadio shows the shell too (D6).
            val onboarding by runtime.onboarding.collectAsStateWithLifecycle()
            if (onboarding == OnboardingStep.Welcome) {
                NoticeHost { WelcomeScreen() }
            } else {
                UmshShell()
            }
        }
    }
}
