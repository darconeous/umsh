package com.voria.umsh.features.conversations

import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.IntrinsicSize
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.layout.HorizontalAlignmentLine
import androidx.compose.ui.layout.Layout
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.font.FontStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import com.voria.umsh.R
import com.voria.umsh.app.Tags
import com.voria.umsh.designsystem.LocalFixedColors
import com.voria.umsh.designsystem.PeerAvatar
import com.voria.umsh.designsystem.annotatedStringResource
import com.voria.umsh.designsystem.dateLineText
import com.voria.umsh.designsystem.isolated
import com.voria.umsh.models.ChatMessage
import com.voria.umsh.models.MessageRef
import com.voria.umsh.models.Presence
import com.voria.umsh.models.PreviewText.Sender
import com.voria.umsh.models.Quote
import com.voria.umsh.models.TranscriptRow
import java.time.Instant
import kotlinx.coroutines.delay
import com.voria.umsh.designsystem.userIsolated

/** How wide a bubble may grow, and the gutter a channel's member avatars take. */
internal data class BubbleLayout(val maxBubbleWidth: Dp, val memberGutter: Dp)

/** A row of the transcript (`threads.svg`, `bubbles.svg`, `replies-reactions.svg` 3 and 5). */
@Composable
internal fun TranscriptRowItem(
    row: TranscriptRow,
    context: ThreadContext,
    layout: BubbleLayout,
    lastOutboundKey: String?,
    now: Instant,
    highlighted: Boolean,
    onOpenQuote: (MessageRef) -> Unit,
) {
    when (row) {
        is TranscriptRow.DateLine -> DateLineRow(row, now)
        is TranscriptRow.Gap -> GapRow(row, context, layout)
        is TranscriptRow.Message -> {
            val wash by animateFloatAsState(
                if (highlighted) HIGHLIGHT_ALPHA else 0f,
                animationSpec = tween(if (highlighted) 0 else HIGHLIGHT_FADE_MS),
                label = "quote wash",
            )
            val color = LocalFixedColors.current.sent(context.security)
            Box(
                Modifier
                    .fillMaxWidth()
                    .padding(top = row.presentation.topSpacingDp.dp)
                    .drawBehind { if (wash > 0f) drawRect(color.copy(alpha = wash)) }
                    .padding(horizontal = 16.dp),
            ) {
                MessageRow(row, context, layout, row.message.ref.key == lastOutboundKey, onOpenQuote)
            }
        }
    }
}

/** "Today 9:40": the day set apart from the time, above the first message and after every lull of an hour. */
@Composable
private fun DateLineRow(row: TranscriptRow.DateLine, now: Instant) {
    Text(
        dateLineText(Instant.ofEpochMilli(row.atMs), now, dayStyle = SpanStyle(fontWeight = FontWeight.SemiBold)),
        style = MaterialTheme.typography.labelMedium,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        textAlign = TextAlign.Center,
        modifier = Modifier.fillMaxWidth().padding(top = 12.dp, bottom = 8.dp).testTag(Tags.DATE_LINE),
    )
}

@Composable
private fun MessageRow(
    row: TranscriptRow.Message,
    context: ThreadContext,
    layout: BubbleLayout,
    isMostRecentOutbound: Boolean,
    onOpenQuote: (MessageRef) -> Unit,
) {
    val message = row.message
    val tag = Modifier.testTag(Tags.message(message.ref.key))
    when {
        message.isDeleted -> DeletedLine(message.isOutbound, tag)
        message.presence == Presence.Unavailable -> SideLine(
            stringResource(R.string.message_unavailable),
            outbound = false,
            modifier = tag,
            inset = if (context.isChannel) layout.memberGutter else 0.dp,
        )
        message.isStatus -> StatusLine(message, context, tag, inset = if (context.isChannel) layout.memberGutter else 0.dp)
        else -> Bubble(row, context, layout, isMostRecentOutbound, onOpenQuote, tag)
    }
}

/** A deletion is an italic line on its sender's side, not a bubble. */
@Composable
private fun DeletedLine(outbound: Boolean, modifier: Modifier) = SideLine(
    stringResource(if (outbound) R.string.message_you_deleted else R.string.message_deleted),
    outbound,
    modifier,
)

@Composable
private fun SideLine(text: String, outbound: Boolean, modifier: Modifier, inset: Dp = 0.dp) {
    Text(
        text,
        style = MaterialTheme.typography.bodyMedium,
        fontStyle = FontStyle.Italic,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        textAlign = if (outbound) TextAlign.End else TextAlign.Start,
        modifier = modifier.fillMaxWidth().padding(start = inset + 8.dp, end = 8.dp),
    )
}

/** Status text ("/me"): no bubble, the name in bold. */
@Composable
private fun StatusLine(message: ChatMessage, context: ThreadContext, modifier: Modifier, inset: Dp) {
    val name = senderText(context.statusName(message))
    val bold = buildAnnotatedString { withStyle(SpanStyle(fontWeight = FontWeight.Bold)) { append(name) } }
    Text(
        annotatedStringResource(R.string.status_line, userIsolated(bold), AnnotatedString(userIsolated(message.body))),
        style = MaterialTheme.typography.bodyLarge,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = modifier.fillMaxWidth().padding(start = inset).semantics(mergeDescendants = true) {},
    )
}

@Composable
private fun Bubble(
    row: TranscriptRow.Message,
    context: ThreadContext,
    layout: BubbleLayout,
    isMostRecentOutbound: Boolean,
    onOpenQuote: (MessageRef) -> Unit,
    modifier: Modifier,
) {
    val message = row.message
    val presentation = row.presentation
    val outbound = message.isOutbound
    val colors = MaterialTheme.colorScheme
    val fixed = LocalFixedColors.current
    val security = context.security(message)
    val fill = if (outbound) fixed.sent(security) else colors.surfaceContainerHighest
    val ink = if (outbound) fixed.onSent else colors.onSurface
    val chips = remember(message.reactions) { ReactionChip.of(message.reactions) }
    val label = if (presentation.isFirstInRun) context.runLabel(message) else null
    val avatar = context.memberAvatar(message)
    val gutter = if (context.isChannel && !outbound) layout.memberGutter else 0.dp

    Column(
        modifier.fillMaxWidth().semantics(mergeDescendants = true) {},
        horizontalAlignment = if (outbound) Alignment.End else Alignment.Start,
    ) {
        label?.let {
            Text(
                senderText(it),
                style = MaterialTheme.typography.labelMedium,
                fontWeight = FontWeight.Medium,
                color = colors.onSurfaceVariant,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
                modifier = Modifier.padding(start = gutter + 12.dp, bottom = 2.dp).testTag(Tags.RUN_LABEL),
            )
        }
        Row(verticalAlignment = Alignment.Bottom) {
            if (gutter > 0.dp) {
                // Level with the bubble's bottom, not the chips hanging below it.
                Box(Modifier.width(gutter).alignBy { it.measuredHeight }) {
                    if (presentation.isLastInRun && avatar != null) {
                        PeerAvatar(avatar.first, avatar.second, Modifier.testTag(Tags.MEMBER_AVATAR), size = MEMBER_AVATAR, describe = false)
                    }
                }
            }
            BubbleWithChips(
                outbound,
                Modifier.alignBy(BubbleBottom),
                bubble = {
                    Column(
                        Modifier
                            .widthIn(max = layout.maxBubbleWidth)
                            .width(IntrinsicSize.Max)
                            .background(fill, bubbleShape(outbound, presentation.isFirstInRun, presentation.isLastInRun))
                            .testTag(Tags.BUBBLE),
                    ) {
                        message.quote?.let { quote ->
                            QuoteBlock(quote, context, outbound, onOpenQuote)
                        }
                        Text(
                            remember(message.body) { linkified(message.body) },
                            style = MaterialTheme.typography.bodyLarge,
                            color = ink,
                            modifier = Modifier.padding(horizontal = 14.dp, vertical = 8.dp),
                        )
                    }
                },
                chips = if (chips.isEmpty()) {
                    null
                } else {
                    { ReactionChipRow(chips, context.security, Modifier.padding(horizontal = 8.dp)) }
                },
            )
        }
        CaptionLine(message, context, isMostRecentOutbound, Modifier.padding(start = gutter + 4.dp, end = 4.dp, top = 2.dp))
    }
}

/** Joined, not tailed: tight corners on the run's side between bubbles of one run. */
private fun bubbleShape(outbound: Boolean, first: Boolean, last: Boolean): RoundedCornerShape {
    val top = if (first) BUBBLE_RADIUS else JOINED_RADIUS
    val bottom = if (last) BUBBLE_RADIUS else JOINED_RADIUS
    return if (outbound) {
        RoundedCornerShape(topStart = BUBBLE_RADIUS, topEnd = top, bottomEnd = bottom, bottomStart = BUBBLE_RADIUS)
    } else {
        RoundedCornerShape(topStart = top, topEnd = BUBBLE_RADIUS, bottomEnd = BUBBLE_RADIUS, bottomStart = bottom)
    }
}

/** A reply's quote inside its bubble: the name, then one line; tapping it shows the original. */
@Composable
private fun QuoteBlock(
    quote: Quote,
    context: ThreadContext,
    outbound: Boolean,
    onOpenQuote: (MessageRef) -> Unit,
) {
    val colors = MaterialTheme.colorScheme
    val accent = if (outbound) LocalFixedColors.current.onSent else LocalFixedColors.current.sent(context.security)
    val wash = if (outbound) Color.White.copy(alpha = 0.2f) else colors.onSurface.copy(alpha = 0.06f)
    val lineColor = if (outbound) LocalFixedColors.current.onSent.copy(alpha = 0.85f) else colors.onSurfaceVariant
    val original = quote as? Quote.Original
    val name = context.quoteName(quote)
    val line: String
    val italic: Boolean
    when {
        original == null -> {
            line = stringResource(R.string.quote_unknown)
            italic = true
        }
        original.isDeleted -> {
            line = stringResource(R.string.message_deleted)
            italic = true
        }
        else -> {
            line = original.body
            italic = false
        }
    }
    val open = original?.let { { onOpenQuote(it.target) } }
    Row(
        Modifier
            .padding(start = 6.dp, end = 6.dp, top = 6.dp)
            // The bar spans the block, whatever the text size.
            .height(IntrinsicSize.Min)
            .fillMaxWidth()
            .background(wash, RoundedCornerShape(12.dp))
            .then(if (open != null) Modifier.clickable(onClickLabel = stringResource(R.string.quote_show_original), onClick = open) else Modifier)
            // A one-line block (a deleted original) still makes a 48 dp target.
            .heightIn(min = 48.dp)
            .padding(7.dp)
            .testTag(Tags.QUOTE),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Box(Modifier.width(3.dp).fillMaxHeight().background(accent, RoundedCornerShape(1.5.dp)))
        Column(Modifier.weight(1f)) {
            // The name only for an original this phone holds, not deleted: a
            // deleted or unknown one reads as one italic line.
            if (name != null && original?.isDeleted == false) {
                Text(
                    if (name is Sender.Me) AnnotatedString(stringResource(R.string.quote_you)) else senderText(name),
                    style = MaterialTheme.typography.labelLarge.copy(fontSize = MaterialTheme.typography.bodyMedium.fontSize),
                    fontWeight = FontWeight.SemiBold,
                    color = accent,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
            Text(
                line,
                style = MaterialTheme.typography.bodyMedium,
                fontStyle = if (italic) FontStyle.Italic else FontStyle.Normal,
                color = lineColor,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        }
    }
}

/** The line under a message: Edited, Received late, or how mine is getting on. */
@Composable
private fun CaptionLine(message: ChatMessage, context: ThreadContext, isMostRecentOutbound: Boolean, modifier: Modifier) {
    val expectsAcknowledgment = !context.isChannel
    // A direct message names its repeaters for a moment, then settles into
    // waiting: the caption changes by itself once, at that moment.
    var nowMs by remember { mutableLongStateOf(System.currentTimeMillis()) }
    val settlesAt = DeliveryCaption.settlesAtMs(message, expectsAcknowledgment)
    LaunchedEffect(settlesAt) {
        if (settlesAt == null) return@LaunchedEffect
        val wait = settlesAt - System.currentTimeMillis()
        if (wait > 0) delay(wait)
        nowMs = System.currentTimeMillis()
    }
    val caption = DeliveryCaption.of(message, isMostRecentOutbound, expectsAcknowledgment, nowMs, context::repeaterName) ?: return
    val failure = caption.state?.isFailure == true
    Text(
        captionText(caption),
        style = MaterialTheme.typography.labelMedium,
        fontWeight = if (failure) FontWeight.SemiBold else FontWeight.Normal,
        color = if (failure) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = modifier.testTag(Tags.CAPTION),
    )
}

/** [caption] in the reader's language: one string per sequence. */
@Composable
internal fun captionText(caption: DeliveryCaption): String {
    val state = caption.state?.let { stateText(it) }
    return when {
        caption.edited && state != null -> stringResource(R.string.caption_edited_pair, state)
        caption.edited -> stringResource(R.string.caption_edited)
        else -> state.orEmpty()
    }
}

@Composable
private fun stateText(state: DeliveryCaption.State): String = when (state) {
    DeliveryCaption.State.ReceivedLate -> stringResource(R.string.caption_received_late)
    DeliveryCaption.State.EditOfUnknown -> stringResource(R.string.caption_edit_of_unknown)
    DeliveryCaption.State.Sending -> stringResource(R.string.caption_sending)
    DeliveryCaption.State.Confirming -> stringResource(R.string.caption_confirming)
    DeliveryCaption.State.Delivered -> stringResource(R.string.caption_delivered)
    DeliveryCaption.State.DeliveredLate -> stringResource(R.string.caption_delivered_late)
    DeliveryCaption.State.DeliveredFlooded -> stringResource(R.string.caption_delivered_flooded)
    DeliveryCaption.State.Unconfirmed -> stringResource(R.string.caption_unconfirmed)
    DeliveryCaption.State.NotDelivered -> stringResource(R.string.caption_not_delivered)
    DeliveryCaption.State.Sent -> stringResource(R.string.caption_sent)
    is DeliveryCaption.State.HeardRepeats -> pluralStringResource(R.plurals.caption_heard_repeats, state.count, state.count)
    is DeliveryCaption.State.SentVia -> {
        val lead = when (val name = state.lead) {
            is DeliveryCaption.RepeaterName.Named -> name.name
            is DeliveryCaption.RepeaterName.Hint -> isolated(name.text)
        }
        if (state.others == 0) {
            stringResource(R.string.caption_sent_via_one, lead)
        } else {
            pluralStringResource(R.plurals.caption_sent_via_others, state.others, lead, state.others)
        }
    }
}

/**
 * Missing messages: an empty bubble with a down arrow while they wait to be
 * asked for, a spinner while they are. Asking is Phase 2's, so it has no action.
 */
@Composable
private fun GapRow(row: TranscriptRow.Gap, context: ThreadContext, layout: BubbleLayout) {
    val description = pluralStringResource(R.plurals.gap_missing, row.messages.size, row.messages.size)
    Box(
        Modifier
            .fillMaxWidth()
            .padding(top = 10.dp, start = 16.dp + if (context.isChannel) layout.memberGutter else 0.dp)
            .testTag(Tags.GAP),
    ) {
        Box(
            Modifier
                .size(width = 64.dp, height = 40.dp)
                .background(MaterialTheme.colorScheme.surfaceContainerHighest, RoundedCornerShape(BUBBLE_RADIUS))
                .clearAndSetSemantics { contentDescription = description },
            contentAlignment = Alignment.Center,
        ) {
            if (row.isIdle) {
                Icon(
                    painterResource(R.drawable.ic_arrow_downward),
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.size(20.dp),
                )
            } else {
                CircularProgressIndicator(Modifier.size(16.dp), strokeWidth = 2.4.dp)
            }
        }
    }
}

private val BUBBLE_RADIUS = 20.dp
private val JOINED_RADIUS = 6.dp
private val MEMBER_AVATAR = 28.dp

/** How much of a bubble's bottom its reaction chips cover; the rest of their height hangs below it. */
private val CHIP_TUCK = 8.dp

/** A bubble's bottom edge, which the member avatar is level with whatever hangs below it. */
private val BubbleBottom = HorizontalAlignmentLine(::minOf)

/**
 * A bubble and its reaction chips, if any: the chips over the bubble's
 * bottom [CHIP_TUCK], toward the middle of the screen, hanging below by
 * whatever their measured height leaves (it grows with the text size).
 */
@Composable
private fun BubbleWithChips(
    outbound: Boolean,
    modifier: Modifier,
    bubble: @Composable () -> Unit,
    chips: (@Composable () -> Unit)?,
) {
    Layout(
        content = {
            bubble()
            chips?.invoke()
        },
        modifier = modifier,
    ) { measurables, constraints ->
        val loose = constraints.copy(minWidth = 0, minHeight = 0)
        val body = measurables[0].measure(loose)
        val row = measurables.getOrNull(1)?.measure(loose)
        val chipTop = body.height - CHIP_TUCK.roundToPx()
        val width = maxOf(body.width, row?.width ?: 0)
        val height = if (row == null) body.height else maxOf(body.height, chipTop + row.height)
        layout(width, height, mapOf(BubbleBottom to body.height)) {
            body.placeRelative(if (outbound) width - body.width else 0, 0)
            row?.placeRelative(if (outbound) 0 else width - row.width, chipTop)
        }
    }
}
private const val HIGHLIGHT_ALPHA = 0.14f
private const val HIGHLIGHT_FADE_MS = 800
