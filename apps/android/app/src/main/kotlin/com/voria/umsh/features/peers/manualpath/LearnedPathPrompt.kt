package com.voria.umsh.features.peers.manualpath

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.repeatOnLifecycle
import androidx.lifecycle.viewModelScope
import com.voria.umsh.R
import com.voria.umsh.app.AppRuntime
import com.voria.umsh.app.LocalAppRuntime
import com.voria.umsh.app.Tags
import com.voria.umsh.app.runtimeViewModel
import com.voria.umsh.designsystem.FailureDialog
import com.voria.umsh.designsystem.UmshColors
import com.voria.umsh.designsystem.isolated
import com.voria.umsh.designsystem.rememberDisplayNames
import com.voria.umsh.designsystem.userIsolated
import com.voria.umsh.features.peers.NamedHops
import com.voria.umsh.models.DirectConversationSummary
import com.voria.umsh.models.RepeaterHint
import com.voria.umsh.models.RouteSummary
import com.voria.umsh.services.mobilecore.AppLog
import kotlin.coroutines.cancellation.CancellationException
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch

/**
 * Whether a direct thread offers the learned path in place of a held one
 * (`manual-path.svg` 7): asked of the core each time the transcript
 * changes while the thread is shown and started, since a send's ack, or
 * the flood's, is what the core counts; asked once more on coming back.
 * The core asks for the phone's position when it matters, and offers once
 * per saved path: Keep manual path, or dismissing, settles it; Use learned
 * path drops the hold.
 */
class LearnedPathViewModel(private val runtime: AppRuntime, val address: String) : ViewModel() {
    private val _offer = MutableStateFlow<RouteSummary?>(null)

    /** The held route, carrying its learned rival, while it is offered. */
    val offer: StateFlow<RouteSummary?> = _offer.asStateFlow()

    private val _switching = MutableStateFlow(false)
    val switching: StateFlow<Boolean> = _switching.asStateFlow()

    private val _failure = MutableStateFlow<Throwable?>(null)
    val failure: StateFlow<Throwable?> = _failure.asStateFlow()

    /**
     * Ask on every transcript change until canceled; the prompt runs this
     * only while it is shown and its screen started, so a hidden thread
     * neither asks the core nor reads the phone's position.
     */
    suspend fun watch() {
        combine(
            runtime.appState.map { state -> state?.conversations?.any { it is DirectConversationSummary && it.address == address } == true }
                .distinctUntilChanged(),
            runtime.transcriptRevisions.map { it[address] ?: 0L }.distinctUntilChanged(),
        ) { direct, revision -> direct to revision }.collect { (direct, _) -> if (direct) check() }
    }

    private suspend fun check() {
        // One offer at a time: the one shown waits for its answer.
        if (_offer.value != null) return
        _offer.value = try {
            runtime.learnedPathOffer(address).await()
        } catch (error: CancellationException) {
            throw error
        } catch (error: Exception) {
            AppLog.d(TAG, "learned path unchecked: ${error.javaClass.simpleName}")
            null
        }
    }

    /** Use learned path: the hold goes, and the learned route is the one sent on. */
    fun useLearned() {
        if (_switching.value) return
        _switching.value = true
        val sent = runtime.adoptLearnedPath(address)
        viewModelScope.launch {
            try {
                sent.await()
                _offer.value = null
            } catch (error: CancellationException) {
                throw error
            } catch (error: Exception) {
                AppLog.w(TAG, "learned path not adopted: ${error.javaClass.simpleName}")
                _failure.value = error
            } finally {
                _switching.value = false
            }
        }
    }

    /** Keep manual path, or the sheet dismissed: the question is settled for this path. */
    fun keepManual() {
        if (_offer.value == null || _switching.value) return
        _offer.value = null
        runtime.keepManualPath(address)
    }

    fun dismissFailure() {
        _failure.value = null
    }

    private companion object {
        const val TAG = "umsh.learnedpath"
    }
}

/** The prompt in a direct thread, when the core offers it. */
@Composable
fun LearnedPathPrompt(address: String) {
    val viewModel = runtimeViewModel(key = "learned_path") { LearnedPathViewModel(it, address) }
    val lifecycle = LocalLifecycleOwner.current.lifecycle
    LaunchedEffect(viewModel, lifecycle) {
        lifecycle.repeatOnLifecycle(Lifecycle.State.STARTED) { viewModel.watch() }
    }
    val offer by viewModel.offer.collectAsStateWithLifecycle()
    val switching by viewModel.switching.collectAsStateWithLifecycle()
    val failure by viewModel.failure.collectAsStateWithLifecycle()
    offer?.let { route ->
        LearnedPathSheet(route, switching, onUse = viewModel::useLearned, onKeep = viewModel::keepManual)
    }
    failure?.let { error ->
        FailureDialog(stringResource(R.string.learned_path_not_switched_title), stringResource(R.string.peer_failure_body), error, viewModel::dismissFailure)
    }
}

@OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)
@Composable
private fun LearnedPathSheet(route: RouteSummary, switching: Boolean, onUse: () -> Unit, onKeep: () -> Unit) {
    val sheet = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    ModalBottomSheet(onDismissRequest = onKeep, sheetState = sheet, modifier = Modifier.testTag(Tags.LEARNED_PATH_SHEET)) {
        Column(Modifier.verticalScroll(rememberScrollState()).padding(horizontal = 16.dp).navigationBarsPadding()) {
            Text(
                stringResource(R.string.learned_path_title),
                style = MaterialTheme.typography.titleLarge,
                modifier = Modifier.padding(bottom = 16.dp).semantics { heading() },
            )
            val manualHops = route.heldFloodFromStart ?: route.hopCount
            PathCard(
                label = stringResource(R.string.learned_path_manual),
                hops = manualHops,
                hints = route.hints,
                emptyText = stringResource(if (route.heldFloodFromStart != null) R.string.route_brief_flood else R.string.route_brief_direct),
                verdict = pluralStringResource(R.plurals.learned_path_no_ack, route.fallbackAcks, route.fallbackAcks),
                good = false,
                tag = Tags.LEARNED_PATH_MANUAL,
            )
            route.candidate?.let { candidate ->
                PathCard(
                    label = stringResource(R.string.learned_path_learned),
                    hops = candidate.hopCount,
                    hints = candidate.hints,
                    emptyText = stringResource(R.string.route_brief_direct),
                    verdict = stringResource(R.string.learned_path_carried),
                    good = true,
                    tag = Tags.LEARNED_PATH_LEARNED,
                )
            }
            Button(
                onClick = onUse,
                enabled = !switching,
                modifier = Modifier.fillMaxWidth().padding(top = 8.dp).heightIn(min = 48.dp).testTag(Tags.LEARNED_PATH_USE),
            ) {
                if (switching) {
                    val description = stringResource(R.string.learned_path_switching)
                    CircularProgressIndicator(Modifier.size(20.dp).semantics { stateDescription = description }, strokeWidth = 2.dp)
                } else {
                    Text(stringResource(R.string.learned_path_use))
                }
            }
            TextButton(
                onClick = onKeep,
                enabled = !switching,
                modifier = Modifier.fillMaxWidth().padding(bottom = 16.dp).heightIn(min = 48.dp).testTag(Tags.LEARNED_PATH_KEEP),
            ) {
                Text(stringResource(R.string.learned_path_keep))
            }
        }
    }
}

/** One path compared: its label and length, its repeaters as chips, and how it fared. */
@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun PathCard(label: String, hops: Int?, hints: List<RepeaterHint>, emptyText: String, verdict: String, good: Boolean, tag: String) {
    val runtime = LocalAppRuntime.current
    val names = rememberDisplayNames()
    val octets = hints.map { it.octets }
    val namedFlow = remember(octets) { runtime.hopNames.peers(octets, runtime.appState) }
    val named by namedFlow.collectAsState(NamedHops.NONE)
    val nodes = named.forHints(octets)
    val locale = LocalConfiguration.current.locales[0]
    Surface(
        color = MaterialTheme.colorScheme.surfaceContainerHigh,
        shape = RoundedCornerShape(16.dp),
        modifier = Modifier.fillMaxWidth().padding(bottom = 12.dp).semantics(mergeDescendants = true) {}.testTag(tag),
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    label.uppercase(locale),
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.weight(1f),
                )
                hops?.let { Text(pluralStringResource(R.plurals.route_hops, it, it), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant) }
            }
            if (hints.isEmpty()) {
                Text(emptyText, style = MaterialTheme.typography.bodyMedium)
            } else {
                FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    hints.forEachIndexed { index, hint ->
                        val name = nodes.getOrNull(index)?.let { userIsolated(names.peer(it)) } ?: isolated(hint.text)
                        Box(
                            Modifier.background(MaterialTheme.colorScheme.surfaceContainerHighest, RoundedCornerShape(8.dp)).padding(horizontal = 12.dp, vertical = 6.dp),
                        ) {
                            Text(name, style = MaterialTheme.typography.labelLarge)
                        }
                    }
                }
            }
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(Modifier.size(10.dp).background(if (good) UmshColors.fixed.connected else MaterialTheme.colorScheme.error, CircleShape))
                Text(verdict, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.padding(start = 8.dp))
            }
        }
    }
}
