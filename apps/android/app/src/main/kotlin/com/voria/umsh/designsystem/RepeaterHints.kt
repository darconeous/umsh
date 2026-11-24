package com.voria.umsh.designsystem

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.size
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.ListItemDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import com.voria.umsh.R
import com.voria.umsh.app.Tags
import com.voria.umsh.models.DisplayNames
import com.voria.umsh.models.NodeHint
import com.voria.umsh.models.Octets
import com.voria.umsh.models.PeerSummary
import com.voria.umsh.services.mobilecore.AppLog
import kotlin.coroutines.cancellation.CancellationException
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/**
 * A two-byte repeater hint as a badge: the named node's own avatar when
 * one is known, else the hint (`9v*` two over one) in a gray hexagon, since
 * two bytes carry no color of their own.
 */
@Composable
fun RepeaterHintBadge(hint: Octets, text: String, named: PeerSummary?, size: Dp = AvatarSize.List) {
    if (named != null) {
        PeerAvatar(named, size = size, favorite = named.isFavorite, describe = false)
    } else {
        PeerAvatar(NodeHint(hint, text), PeerAvatarShape.Hexagon, size = size, describe = false)
    }
}

/**
 * One repeater (`bubbles.svg` 6–7): a named node is titled by its name,
 * with the hint under it, and opens its page through [onOpen]; a hint that
 * names no known node is titled by the hint and offers [lookUp].
 */
@Composable
fun RepeaterHintRow(
    hint: Octets,
    text: String,
    named: PeerSummary?,
    names: DisplayNames,
    onOpen: ((PeerSummary) -> Unit)?,
    lookUp: (() -> Deferred<Unit>)?,
    modifier: Modifier = Modifier,
) {
    val hintLine = stringResource(R.string.repeater_hint_row, isolated(text))
    val open = named?.let { peer -> onOpen?.let { { it(peer) } } }
    ListItem(
        headlineContent = { Text(named?.let(names::peer) ?: hintLine, maxLines = 1, overflow = TextOverflow.Ellipsis) },
        supportingContent = if (named != null) ({ Text(hintLine) }) else null,
        leadingContent = { RepeaterHintBadge(hint, text, named) },
        trailingContent = if (named == null && lookUp != null) ({ HintLookupButton(lookUp, Modifier.testTag(Tags.hintLookup(hint.hex()))) }) else null,
        colors = ListItemDefaults.colors(containerColor = Color.Transparent),
        modifier = modifier
            .then(if (open != null) Modifier.clickable(onClickLabel = stringResource(R.string.open_peer_page), onClick = open) else Modifier)
            .semantics(mergeDescendants = true) {},
    )
}

/**
 * Ask the node behind a hint who it is (iOS `HintDiscoveryButton`): shown
 * as outstanding for [waitMs] once the radio took the ask, so a lost answer
 * does not claim one is still coming. A failure to send is its dialog.
 */
@Composable
fun HintLookupButton(ask: () -> Deferred<Unit>, modifier: Modifier = Modifier, waitMs: Long = LOOKUP_WAIT_MS) {
    var askedAt by rememberSaveable { mutableStateOf<Long?>(null) }
    var sending by remember { mutableStateOf(false) }
    var failure by remember { mutableStateOf<Throwable?>(null) }
    val scope = rememberCoroutineScope()
    val waiting = stringResource(R.string.waiting_for_reply)
    LaunchedEffect(askedAt) {
        val at = askedAt ?: return@LaunchedEffect
        delay((at + waitMs - System.currentTimeMillis()).coerceAtLeast(0))
        askedAt = null
    }
    Box(modifier.size(48.dp), contentAlignment = Alignment.Center) {
        if (askedAt != null) {
            CircularProgressIndicator(Modifier.size(24.dp).semantics { stateDescription = waiting }, strokeWidth = 2.dp)
        } else {
            IconButton(
                enabled = !sending,
                onClick = {
                    sending = true
                    val sent = ask()
                    scope.launch {
                        try {
                            sent.await()
                            askedAt = System.currentTimeMillis()
                        } catch (error: CancellationException) {
                            throw error
                        } catch (error: Exception) {
                            AppLog.w("umsh.peers", "hint lookup not sent: ${error.javaClass.simpleName}")
                            failure = error
                        } finally {
                            sending = false
                        }
                    }
                },
            ) {
                Icon(
                    painterResource(R.drawable.ic_search),
                    contentDescription = stringResource(R.string.look_up_hint),
                    tint = MaterialTheme.colorScheme.primary,
                )
            }
        }
    }
    failure?.let { error ->
        FailureDialog(
            stringResource(R.string.identity_not_asked_title),
            stringResource(R.string.request_failure_body),
            error,
            onDismiss = { failure = null },
        )
    }
}

/** How long a hint lookup shows as outstanding (iOS `HintDiscoveryButton.wait`). */
const val LOOKUP_WAIT_MS = 15_000L
