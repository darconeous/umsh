package com.voria.umsh.features.onboarding

import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import androidx.browser.customtabs.CustomTabsIntent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.platform.LocalSoftwareKeyboardController
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.TextRange
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.TextFieldValue
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.core.net.toUri
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.voria.umsh.R
import com.voria.umsh.app.AppCoreHost
import com.voria.umsh.app.LocalAppCoreHost
import com.voria.umsh.app.Tags
import com.voria.umsh.app.runtimeViewModel
import com.voria.umsh.designsystem.AvatarSize
import com.voria.umsh.designsystem.FailureDialog
import com.voria.umsh.designsystem.PeerAvatar
import com.voria.umsh.designsystem.PeerAvatarShape
import com.voria.umsh.models.NodeHint
import java.io.IOException

/** Where Learn more goes. A URL, not text. */
private const val LEARN_MORE_URL = "https://umsh.dev"

/**
 * Welcome (`onboarding.svg` boards 1–3): replaces the shell on first
 * launch. The identity exists already; the page asks only for a name.
 */
@Composable
fun WelcomeScreen() {
    val host = LocalAppCoreHost.current
    val viewModel = runtimeViewModel {
        OnboardingViewModel(it, radioSetUp = { radioSetUp(host) })
    }
    val identity by viewModel.identity.collectAsStateWithLifecycle()
    val saving by viewModel.saving.collectAsStateWithLifecycle()
    val failure by viewModel.failure.collectAsStateWithLifecycle()
    WelcomeContent(
        hint = identity.hint,
        initialName = identity.advertisedName,
        saving = saving,
        failure = failure,
        onContinue = viewModel::continueWith,
        onDismissFailure = viewModel::dismissFailure,
    )
}

/** Welcome's content, apart from where its state lives: the UI tests draw it with a failure in hand. */
@Composable
fun WelcomeContent(
    hint: NodeHint,
    initialName: String,
    saving: Boolean,
    failure: WelcomeFailure?,
    onContinue: (String) -> Unit,
    onDismissFailure: () -> Unit,
) {
    val context = LocalContext.current
    var name by rememberSaveable(stateSaver = TextFieldValue.Saver) { mutableStateOf(atEnd(initialName)) }
    // The stored name arrives with the start's first read, after the page
    // is drawn: it is taken up until the field is typed in, so Continue
    // never clears a name that was already saved.
    var edited by rememberSaveable { mutableStateOf(false) }
    LaunchedEffect(initialName) { if (!edited) name = atEnd(initialName) }
    val focus = remember { FocusRequester() }
    LaunchedEffect(Unit) { focus.requestFocus() }
    val focusManager = LocalFocusManager.current
    val keyboard = LocalSoftwareKeyboardController.current
    // The keyboard goes before the page does: one left up as Connect a
    // radio comes in keeps its Back callback, and the first Back there is lost.
    val continueWith = {
        keyboard?.hide()
        focusManager.clearFocus()
        onContinue(name.text)
    }

    Box(
        Modifier
            .fillMaxSize()
            .safeDrawingPadding()
            .imePadding()
            .testTag(Tags.WELCOME),
        contentAlignment = Alignment.TopCenter,
    ) {
        Column(
            Modifier.widthIn(max = 560.dp).fillMaxSize().padding(horizontal = 24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Column(
                Modifier.weight(1f).fillMaxWidth().verticalScroll(rememberScrollState()),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                Spacer(Modifier.height(40.dp))
                PeerAvatar(hint, PeerAvatarShape.Circle, size = AvatarSize.Page)
                Spacer(Modifier.height(4.dp))
                Text(
                    stringResource(R.string.welcome_title),
                    style = MaterialTheme.typography.headlineSmall,
                    textAlign = TextAlign.Center,
                )
                Text(
                    stringResource(R.string.welcome_body),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    textAlign = TextAlign.Center,
                )
                TextButton(
                    onClick = { openLearnMore(context) },
                    modifier = Modifier.testTag(Tags.WELCOME_LEARN_MORE),
                ) {
                    Text(stringResource(R.string.welcome_learn_more))
                }
                Spacer(Modifier.height(8.dp))
                OutlinedTextField(
                    value = name,
                    onValueChange = {
                        // A selection or composition change is not an edit.
                        if (it.text != name.text) edited = true
                        name = it
                    },
                    label = { Text(stringResource(R.string.name_label)) },
                    supportingText = { Text(stringResource(R.string.name_supporting)) },
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(
                        capitalization = KeyboardCapitalization.Words,
                        autoCorrectEnabled = false,
                        imeAction = ImeAction.Done,
                    ),
                    keyboardActions = KeyboardActions(onDone = { continueWith() }),
                    modifier = Modifier.fillMaxWidth().focusRequester(focus).testTag(Tags.WELCOME_NAME),
                )
            }
            // Rides above the keyboard: the page keeps its layout.
            Button(
                onClick = continueWith,
                enabled = !saving,
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(vertical = 16.dp)
                    .testTag(Tags.WELCOME_CONTINUE),
            ) {
                Text(stringResource(R.string.action_continue))
            }
        }
    }

    failure?.let { shown ->
        FailureDialog(
            title = stringResource(
                when (shown) {
                    is WelcomeFailure.NameNotSaved -> R.string.name_save_failed_title
                    is WelcomeFailure.StepNotSaved -> R.string.setup_step_failed_title
                },
            ),
            body = stringResource(
                when (shown) {
                    is WelcomeFailure.NameNotSaved -> R.string.name_save_failed_body
                    is WelcomeFailure.StepNotSaved -> R.string.setup_step_failed_body
                },
            ),
            error = shown.error,
            onDismiss = onDismissFailure,
        )
    }
}

/** [text] with the cursor after it, as if typed. */
private fun atEnd(text: String) = TextFieldValue(text, TextRange(text.length))

/** umsh.dev in a Custom Tab; failing that, any browser; failing that, nothing. */
private fun openLearnMore(context: Context) {
    val uri = LEARN_MORE_URL.toUri()
    try {
        CustomTabsIntent.Builder().build().launchUrl(context, uri)
    } catch (_: ActivityNotFoundException) {
        try {
            context.startActivity(Intent(Intent.ACTION_VIEW, uri))
        } catch (_: ActivityNotFoundException) {
            // No browser: the page stays as it is.
        }
    }
}

/** A radio is set up already; a registry that will not read counts as none, so the step is offered. */
private suspend fun radioSetUp(host: AppCoreHost): Boolean = try {
    host.preferences.radioRegistry.bound() != null
} catch (_: IOException) {
    false
}
