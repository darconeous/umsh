package com.voria.umsh.features.conversations

import androidx.compose.animation.core.Animatable
import androidx.compose.foundation.gestures.detectHorizontalDragGestures
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.Stable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.CustomAccessibilityAction
import androidx.compose.ui.semantics.customActions
import androidx.compose.ui.semantics.onLongClick
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import com.voria.umsh.R
import com.voria.umsh.models.ChatMessage
import com.voria.umsh.models.MessageRef
import kotlin.math.abs
import kotlinx.coroutines.launch

/** What a transcript row can ask of its thread. */
@Stable
internal class MessageHandlers(
    val onOpenQuote: (MessageRef) -> Unit,
    /** Long press: the message menu, with its reactions. */
    val onMenu: (ChatMessage) -> Unit,
    /** The retry button beside a failed message of mine. */
    val onRetry: (ChatMessage) -> Unit,
    /** Swiped toward the middle. */
    val onReply: (ChatMessage) -> Unit,
    val onChip: (ChatMessage, ReactionChip) -> Unit,
    /** A gap tapped: its placeholders. */
    val onGap: (List<ChatMessage>) -> Unit,
    /** A menu item chosen without the menu: TalkBack's custom actions. */
    val onMenuItem: (ChatMessage, MenuItem) -> Unit,
    /** A `umsh:` link in a message's body, tapped. */
    val onOpenLink: (String) -> Unit = {},
    /** A channel sender's avatar, tapped: their member sheet. Null in a direct chat. */
    val onMember: ((ChatMessage) -> Unit)? = null,
) {
    /** Whether [message]'s sender has a member sheet: received in a channel, with a hint. */
    fun hasMember(message: ChatMessage): Boolean = onMember != null && !message.isOutbound && message.senderHint != null
}

/**
 * Long press opens the message's menu; TalkBack gets the same as a long
 * click, and every menu item (and React) as a custom action, on the one
 * merged node the message reads as.
 */
@Composable
internal fun Modifier.messageGestures(message: ChatMessage, handlers: MessageHandlers): Modifier {
    // TalkBack reaches the sender's sheet from any of their messages, not only the run's last.
    val memberLabel = stringResource(R.string.member_show)
    val member = handlers.hasMember(message)
    if (!MessageMenu.hasMenu(message)) {
        return semantics(mergeDescendants = true) {
            if (member) customActions = listOf(CustomAccessibilityAction(memberLabel) { handlers.onMember?.invoke(message); true })
        }
    }
    val haptics = LocalHapticFeedback.current
    val current by rememberUpdatedState(message)
    // Keyed on nothing: a new handlers object must not restart a press in progress.
    val currentHandlers by rememberUpdatedState(handlers)
    val longLabel = stringResource(R.string.message_actions)
    val reactLabel = stringResource(R.string.menu_react)
    val items = MessageMenu.items(message)
    val labels = items.map { stringResource(it.label) }
    val reacts = MessageMenu.reactions(message)
    return this
        .pointerInput(Unit) {
            detectTapGestures(
                onLongPress = {
                    haptics.performHapticFeedback(HapticFeedbackType.LongPress)
                    currentHandlers.onMenu(current)
                },
            )
        }
        .semantics(mergeDescendants = true) {
            onLongClick(label = longLabel) {
                handlers.onMenu(current)
                true
            }
            customActions = buildList {
                if (reacts) add(CustomAccessibilityAction(reactLabel) { handlers.onMenu(current); true })
                items.forEachIndexed { index, item ->
                    add(CustomAccessibilityAction(labels[index]) { handlers.onMenuItem(current, item); true })
                }
                if (member) add(CustomAccessibilityAction(memberLabel) { handlers.onMember?.invoke(current); true })
            }
        }
}

/**
 * Swipe a bubble toward the middle of the screen to reply
 * (`replies-reactions.svg` 1): the reply glyph shows from under it, a
 * haptic tick past the threshold arms it, and letting go starts the reply.
 * Swipes from the screen edge never reach here: the system takes them for
 * Back.
 */
@Composable
internal fun SwipeToReply(message: ChatMessage, handlers: MessageHandlers, content: @Composable () -> Unit) {
    if (!message.actions.reply) {
        content()
        return
    }
    val density = LocalDensity.current
    val thresholdPx = with(density) { SWIPE_THRESHOLD.toPx() }
    val maxPx = with(density) { SWIPE_MAX.toPx() }
    val rtl = LocalLayoutDirection.current == LayoutDirection.Rtl
    // Toward the middle: a received bubble moves toward the end, mine toward the start.
    val sign = (if (message.isOutbound) -1f else 1f) * (if (rtl) -1f else 1f)
    val offset = remember { Animatable(0f) }
    var armed by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()
    val haptics = LocalHapticFeedback.current
    val current by rememberUpdatedState(message)
    Box(
        Modifier
            .fillMaxWidth()
            .pointerInput(sign) {
                detectHorizontalDragGestures(
                    onDragEnd = {
                        if (armed) handlers.onReply(current)
                        armed = false
                        scope.launch { offset.animateTo(0f) }
                    },
                    onDragCancel = {
                        armed = false
                        scope.launch { offset.animateTo(0f) }
                    },
                ) { change, amount ->
                    val toward = (offset.value * sign + amount * sign).coerceIn(0f, maxPx)
                    if (toward > 0f) change.consume()
                    scope.launch { offset.snapTo(toward * sign) }
                    val nowArmed = toward >= thresholdPx
                    if (nowArmed && !armed) haptics.performHapticFeedback(HapticFeedbackType.SegmentTick)
                    armed = nowArmed
                }
            },
    ) {
        val progress = (abs(offset.value) / thresholdPx).coerceIn(0f, 1f)
        if (progress > 0f) {
            Icon(
                painterResource(R.drawable.ic_reply),
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier
                    .align(if (message.isOutbound) Alignment.CenterEnd else Alignment.CenterStart)
                    .padding(horizontal = 4.dp)
                    .size(24.dp)
                    .alpha(progress),
            )
        }
        Box(Modifier.graphicsLayer { translationX = offset.value }) { content() }
    }
}

private val SWIPE_THRESHOLD = 64.dp
private val SWIPE_MAX = 96.dp
