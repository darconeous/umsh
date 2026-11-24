package com.voria.umsh.features.channels

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextField
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.unit.dp
import androidx.lifecycle.ViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewModelScope
import com.voria.umsh.R
import com.voria.umsh.app.Tags
import com.voria.umsh.app.runtimeViewModel
import com.voria.umsh.designsystem.DialogAction
import com.voria.umsh.designsystem.FailureDialog
import com.voria.umsh.designsystem.FullScreenDialogScaffold
import com.voria.umsh.designsystem.SectionHeader
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

/**
 * New private channel's create: one at a time, in the runtime's scope, so
 * a rotation does not cancel it. [created] gives the new channel's ID once.
 */
class ChannelCreateViewModel(private val create: (String) -> Deferred<String>) : ViewModel() {
    private val _creating = MutableStateFlow(false)
    private val _failure = MutableStateFlow<Throwable?>(null)
    private val _created = Channel<String>(Channel.BUFFERED)

    val creating: StateFlow<Boolean> = _creating.asStateFlow()
    val failure: StateFlow<Throwable?> = _failure.asStateFlow()
    val created: Flow<String> = _created.receiveAsFlow()

    fun create(name: String) {
        if (name.isBlank() || _creating.value) return
        _creating.value = true
        val creating = create.invoke(name.trim())
        viewModelScope.launch {
            try {
                _created.send(creating.await())
            } catch (error: CancellationException) {
                throw error
            } catch (error: Exception) {
                AppLog.w("umsh.channels", "channel not created: ${error.javaClass.simpleName}")
                _failure.value = error
            } finally {
                _creating.value = false
            }
        }
    }

    fun dismissFailure() {
        _failure.value = null
    }
}

/**
 * New private channel (`channels.svg` 4): a full-screen dialog with the
 * name, which is local and suggested to invitees, and the two facts a
 * creator must know before inviting anyone. Create makes the channel under
 * a new key and [onCreated] opens its page. A failure (the phone holds as
 * many channels as it can, or storage) opens a failure dialog with the
 * reason.
 */
@Composable
fun ChannelCreateScreen(onClose: () -> Unit, onCreated: (String) -> Unit) {
    val viewModel = runtimeViewModel { runtime -> ChannelCreateViewModel(runtime::createPrivateChannel) }
    val creating by viewModel.creating.collectAsStateWithLifecycle()
    val failure by viewModel.failure.collectAsStateWithLifecycle()
    val created by rememberUpdatedState(onCreated)
    LaunchedEffect(viewModel) { viewModel.created.collect { created(it) } }
    // Kept across process death; nothing is made until Create.
    var name by rememberSaveable { mutableStateOf("") }
    val focus = remember { FocusRequester() }
    LaunchedEffect(Unit) { runCatching { focus.requestFocus() } }

    FullScreenDialogScaffold(
        title = stringResource(R.string.channel_create_title),
        navigationIcon = R.drawable.ic_close,
        navigationDescription = stringResource(R.string.action_close),
        onNavigate = onClose,
        action = DialogAction(
            label = stringResource(R.string.channel_create),
            enabled = name.isNotBlank(),
            tag = Tags.CHANNEL_CREATE_ACTION,
            busy = creating,
            busyDescription = stringResource(R.string.channel_creating),
            onClick = { viewModel.create(name) },
        ),
        modifier = Modifier.testTag(Tags.CHANNEL_CREATE),
    ) { padding ->
        Column(
            Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(bottom = 24.dp),
        ) {
            TextField(
                value = name,
                onValueChange = { name = it },
                label = { Text(stringResource(R.string.channel_name)) },
                supportingText = { Text(stringResource(R.string.channel_name_supporting)) },
                singleLine = true,
                keyboardOptions = KeyboardOptions(capitalization = KeyboardCapitalization.Words, imeAction = ImeAction.Done),
                keyboardActions = KeyboardActions(onDone = { viewModel.create(name) }),
                modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp).focusRequester(focus).testTag(Tags.CHANNEL_CREATE_NAME),
            )
            SectionHeader(stringResource(R.string.channel_create_section), Modifier.padding(top = 8.dp))
            Text(
                stringResource(R.string.channel_create_members),
                style = MaterialTheme.typography.bodyMedium,
                modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp),
            )
            Text(
                stringResource(R.string.channel_create_removing),
                style = MaterialTheme.typography.bodyMedium,
                modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
            )
        }
    }

    failure?.let { error ->
        FailureDialog(
            stringResource(R.string.channel_not_created_title),
            stringResource(R.string.channel_not_created_body),
            error,
            viewModel::dismissFailure,
        )
    }
}
