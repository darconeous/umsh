package com.voria.umsh.features.conversations

import android.icu.text.DateFormat
import android.icu.text.NumberFormat
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ListItem
import androidx.compose.material3.ListItemDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.layout.Layout
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.unit.Constraints
import androidx.compose.ui.unit.dp
import androidx.lifecycle.ViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewModelScope
import com.voria.umsh.R
import com.voria.umsh.app.AppRuntime
import com.voria.umsh.app.LocalAppRuntime
import com.voria.umsh.app.Tags
import com.voria.umsh.app.UmshKey
import com.voria.umsh.app.runtimeViewModel
import com.voria.umsh.core.renderRepeaterHint
import com.voria.umsh.designsystem.DetailPane
import com.voria.umsh.designsystem.EmptyState
import com.voria.umsh.designsystem.RepeaterHintRow
import com.voria.umsh.designsystem.SectionHeader
import com.voria.umsh.designsystem.UmshScaffold
import com.voria.umsh.designsystem.UmshTopAppBar
import com.voria.umsh.designsystem.identifierAnnotated
import com.voria.umsh.designsystem.rememberCopier
import com.voria.umsh.designsystem.rememberDisplayNames
import com.voria.umsh.features.peers.NamedHops
import com.voria.umsh.models.ChatMessage
import com.voria.umsh.models.MessageRef
import com.voria.umsh.models.Octets
import com.voria.umsh.services.mobilecore.AppLog
import java.util.Locale
import kotlin.coroutines.cancellation.CancellationException
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

/** What the details page has of its message. */
sealed interface DetailsRead {
    data object Reading : DetailsRead

    data class Shown(val message: ChatMessage) : DetailsRead

    /** No longer stored, or never readable. */
    data object Gone : DetailsRead
}

/** One message, read from the store and read again whenever its transcript changes. */
class MessageDetailsViewModel(private val runtime: AppRuntime, private val key: UmshKey.MessageDetails) : ViewModel() {
    private val _message = MutableStateFlow<DetailsRead>(DetailsRead.Reading)

    val message: StateFlow<DetailsRead> = _message.asStateFlow()

    /** A received message's route hops, named (entry for entry with its route hints), with the hints they answer. */
    @OptIn(ExperimentalCoroutinesApi::class)
    val routeNames: StateFlow<NamedHops> = _message.map { read ->
        (read as? DetailsRead.Shown)?.message?.reception?.routeHints.orEmpty()
    }.distinctUntilChanged().flatMapLatest { hints ->
        runtime.hopNames.peers(hints, runtime.appState)
    }.stateIn(viewModelScope, SharingStarted.Eagerly, NamedHops.NONE)

    init {
        val ref = MessageRef(key.sessionId, key.handle)
        viewModelScope.launch {
            runtime.transcriptRevisions.map { it[key.address] ?: 0L }.distinctUntilChanged().collect {
                try {
                    val read = runtime.transcriptAround(key.address, ref, radius = 0)?.messages?.firstOrNull { it.ref == ref }
                    _message.value = read?.let(DetailsRead::Shown) ?: DetailsRead.Gone
                } catch (error: CancellationException) {
                    throw error
                } catch (error: Exception) {
                    AppLog.w("umsh.thread", "message details unread: ${error.javaClass.simpleName}")
                    // What was shown stands; a first read that fails has nothing to show.
                    if (_message.value == DetailsRead.Reading) _message.value = DetailsRead.Gone
                }
            }
        }
    }
}

/**
 * A message's details (`bubbles.svg` 6–7), with iOS's sections: the
 * message; for mine, the repeaters heard carrying it; for a received one,
 * its sender, its reception and its route, from the sender toward this
 * phone. Read from the stored message. A repeater the core named, or a
 * route hop [com.voria.umsh.features.peers.HopNames] names, opens its page
 * through [onOpenPeer]; one that names no node offers a lookup.
 */
@Composable
fun MessageDetailsScreen(key: UmshKey.MessageDetails, onBack: (() -> Unit)?, onOpenPeer: (String) -> Unit) {
    val viewModel = runtimeViewModel { MessageDetailsViewModel(it, key) }
    val read by viewModel.message.collectAsStateWithLifecycle()
    val routeNames by viewModel.routeNames.collectAsStateWithLifecycle()
    val runtime = LocalAppRuntime.current
    val appState by runtime.appState.collectAsStateWithLifecycle()
    val names = rememberDisplayNames()
    val locale = LocalConfiguration.current.locales[0]
    DetailPane {
        UmshScaffold(
            topBar = { UmshTopAppBar(stringResource(R.string.message_details_title), onBack = onBack) },
            modifier = Modifier.testTag(Tags.MESSAGE_DETAILS),
        ) { padding ->
            val shown = when (val current = read) {
                DetailsRead.Reading -> {
                    Box(Modifier.padding(padding).fillMaxSize(), contentAlignment = Alignment.Center) { CircularProgressIndicator() }
                    return@UmshScaffold
                }
                DetailsRead.Gone -> {
                    EmptyState(
                        R.drawable.ic_forum_outlined,
                        stringResource(R.string.message_unavailable),
                        Modifier.padding(padding).testTag(Tags.MESSAGE_DETAILS_GONE),
                    )
                    return@UmshScaffold
                }
                is DetailsRead.Shown -> current.message
            }
            val copier = rememberCopier()
            val peers = appState?.peers.orEmpty().associateBy { it.address }
            Box(Modifier.padding(padding).fillMaxWidth(), contentAlignment = Alignment.TopCenter) {
                Column(
                    Modifier.widthIn(max = 600.dp).fillMaxWidth().verticalScroll(rememberScrollState()).padding(bottom = 24.dp),
                ) {
                    SectionHeader(stringResource(R.string.details_section_message))
                    DetailRow(
                        stringResource(R.string.details_direction),
                        stringResource(if (shown.isOutbound) R.string.details_sent else R.string.details_received),
                    )
                    DetailRow(stringResource(R.string.details_time), dateTime(shown.createdAtMs, locale))
                    shown.wireId?.let { DetailRow(stringResource(R.string.details_wire_id), identifier(it.toLong(), locale)) }

                    val repeats = shown.repeats
                    if (shown.isOutbound && repeats != null) {
                        SectionHeader(stringResource(R.string.details_section_repeated_by))
                        var named = false
                        // Each was heard forwarding this phone's own frame, so it is
                        // in range: asked with no repeater before it.
                        repeats.repeaters.forEach { repeater ->
                            val peer = repeater.peerAddress?.let(peers::get)
                            if (peer != null) named = true
                            RepeaterHintRow(
                                hint = repeater.hint,
                                text = repeater.text,
                                named = peer,
                                names = names,
                                onOpen = { onOpenPeer(it.address) },
                                lookUp = { runtime.lookUpRepeaterHint(repeater.hint, emptyList()) },
                                modifier = Modifier.testTag(Tags.detailsRepeater(repeater.hint.hex())),
                            )
                        }
                        if (repeats.anonymous > 0) {
                            DetailRow(stringResource(R.string.repeater_unidentified), integer(repeats.anonymous, locale))
                        }
                        if (repeats.repeaters.isEmpty() && repeats.anonymous <= 0) {
                            Note(stringResource(R.string.details_none_heard))
                        }
                        if (named) Note(stringResource(R.string.repeater_hint_footer))
                    }

                    val hint = shown.senderNodeHint
                    if (!shown.isOutbound && hint != null) {
                        SectionHeader(stringResource(R.string.details_section_sender))
                        val copyHint = stringResource(R.string.action_copy_hint)
                        DetailRow(
                            stringResource(R.string.details_hint),
                            identifierAnnotated(hint.text),
                            copy = copyHint to { copier.copy(hint.text, R.string.copied_hint) },
                        )
                        val copyAddress = stringResource(R.string.action_copy_address)
                        shown.senderAddress?.let { address ->
                            DetailRow(
                                stringResource(R.string.details_address),
                                identifierAnnotated(address),
                                stacked = true,
                                copy = copyAddress to { copier.copy(address, R.string.copied_address) },
                            )
                        }
                    }

                    val reception = shown.reception
                    if (reception != null) {
                        SectionHeader(stringResource(R.string.details_section_reception))
                        DetailRow(
                            stringResource(R.string.details_hop_count),
                            when (val hops = reception.hopCount) {
                                null -> stringResource(R.string.details_hops_unknown)
                                1 -> stringResource(R.string.details_hops_direct, integer(1, locale))
                                else -> integer(hops.toLong(), locale)
                            },
                        )
                        reception.rssiDbm?.let { DetailRow(stringResource(R.string.details_signal), stringResource(R.string.details_dbm, integer(it.toLong(), locale))) }
                        reception.snrCentibels?.let { DetailRow(stringResource(R.string.details_snr), stringResource(R.string.details_db, decibels(it, locale))) }
                        reception.lqi?.let { DetailRow(stringResource(R.string.details_link_quality), integer(it.toLong(), locale)) }
                        DetailRow(
                            stringResource(R.string.details_source),
                            stringResource(if (reception.sourceAuthenticated) R.string.details_authenticated else R.string.details_unauthenticated),
                        )
                        if (reception.routeHints.isNotEmpty()) {
                            SectionHeader(stringResource(R.string.details_section_route))
                            val hopNodes = routeNames.forHints(reception.routeHints)
                            RouteHop.listed(reception.routeHints).forEach { hop ->
                                RepeaterHintRow(
                                    hint = hop.hint,
                                    text = repeaterHintText(hop.hint),
                                    // The hops before it are its index in the route.
                                    named = hopNodes.getOrNull(hop.preceding.size),
                                    names = names,
                                    onOpen = { onOpenPeer(it.address) },
                                    lookUp = { runtime.lookUpRepeaterHint(hop.hint, hop.preceding) },
                                    modifier = Modifier.testTag(Tags.detailsRepeater(hop.hint.hex())),
                                )
                            }
                            if (hopNodes.any { it != null }) Note(stringResource(R.string.repeater_hint_footer))
                        }
                    } else if (!shown.isOutbound) {
                        Note(stringResource(R.string.details_no_reception))
                    }
                }
            }
        }
    }
}

@Composable
private fun DetailRow(label: String, value: String) = DetailRow(label, AnnotatedString(value))

/**
 * The value sits beside its label when both fit on one line, and under it
 * otherwise, so neither is squeezed: a long date in a long language, or a
 * large font, would wrap the label a letter at a time beside it. [stacked]
 * puts it under the label always, as for an address. [copy], its action's
 * label and the copy, makes the row copy on a tap, as an address does
 * elsewhere.
 */
@Composable
private fun DetailRow(label: String, value: AnnotatedString, stacked: Boolean = false, copy: Pair<String, () -> Unit>? = null) {
    val valueColor = MaterialTheme.colorScheme.onSurfaceVariant
    ListItem(
        headlineContent = {
            LabelAndValue(
                label = { Text(label) },
                value = { Text(value, style = MaterialTheme.typography.bodyMedium, color = valueColor) },
                stacked = stacked,
            )
        },
        colors = ListItemDefaults.colors(containerColor = Color.Transparent),
        modifier = if (copy != null) {
            Modifier.clickable(onClickLabel = copy.first, onClick = copy.second)
        } else {
            Modifier.semantics(mergeDescendants = true) {}
        },
    )
}

/** [label] at the start with [value] at the end when both fit their widest, else [value] under [label]. */
@Composable
private fun LabelAndValue(label: @Composable () -> Unit, value: @Composable () -> Unit, stacked: Boolean) {
    Layout(contents = listOf(label, value)) { (labels, values), constraints ->
        val labelPart = labels.single()
        val valuePart = values.single()
        val gap = 16.dp.roundToPx()
        val width = constraints.maxWidth
        val besideEachOther = !stacked && constraints.hasBoundedWidth &&
            labelPart.maxIntrinsicWidth(Constraints.Infinity) + gap + valuePart.maxIntrinsicWidth(Constraints.Infinity) <= width
        val loose = constraints.copy(minWidth = 0, minHeight = 0)
        if (besideEachOther) {
            val shownValue = valuePart.measure(loose)
            val shownLabel = labelPart.measure(loose.copy(maxWidth = width - shownValue.width - gap))
            val height = maxOf(shownLabel.height, shownValue.height)
            layout(width, height) {
                shownLabel.placeRelative(0, (height - shownLabel.height) / 2)
                shownValue.placeRelative(width - shownValue.width, (height - shownValue.height) / 2)
            }
        } else {
            val shownLabel = labelPart.measure(loose)
            val shownValue = valuePart.measure(loose)
            val layoutWidth = if (constraints.hasBoundedWidth) width else maxOf(shownLabel.width, shownValue.width)
            layout(layoutWidth, shownLabel.height + shownValue.height) {
                shownLabel.placeRelative(0, 0)
                shownValue.placeRelative(0, shownLabel.height)
            }
        }
    }
}

@Composable
private fun Note(text: String) {
    Text(
        text,
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
    )
}

private fun dateTime(atMs: Long, locale: Locale): String =
    DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.MEDIUM, locale).format(java.util.Date(atMs))

private fun integer(value: Long, locale: Locale): String = NumberFormat.getIntegerInstance(locale).format(value)

/** An identifier such as a wire ID: the locale's digits, never grouped. */
private fun identifier(value: Long, locale: Locale): String =
    NumberFormat.getIntegerInstance(locale).apply { isGroupingUsed = false }.format(value)

private fun decibels(centibels: Int, locale: Locale): String =
    NumberFormat.getNumberInstance(locale).apply {
        minimumFractionDigits = 1
        maximumFractionDigits = 1
    }.format(centibels / 10.0)

/** One hop of a received message's route, and the hops a lookup of it is steered through. */
data class RouteHop(
    val hint: Octets,
    /** The hops between it and this phone, nearest this phone first, as the core keeps a route. */
    val preceding: List<Octets>,
) {
    companion object {
        /**
         * [route] as the core records it (nearest this phone first), listed
         * the way the message traveled: sender first. Each hop is asked by
         * way of the ones nearer this phone, as iOS's `route[..<index]`.
         */
        fun listed(route: List<Octets>): List<RouteHop> =
            route.indices.reversed().map { index -> RouteHop(route[index], route.take(index)) }
    }
}

/** A two-byte repeater hint as the core renders it; its hex if the core refuses it. */
private fun repeaterHintText(hint: Octets): String =
    runCatching { renderRepeaterHint(hint.toByteArray()).text }.getOrElse { hint.hex() }
