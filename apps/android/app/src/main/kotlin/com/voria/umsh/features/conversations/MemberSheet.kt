package com.voria.umsh.features.conversations

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.ListItem
import androidx.compose.material3.ListItemDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Text
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.voria.umsh.R
import com.voria.umsh.app.Tags
import com.voria.umsh.designsystem.AvatarSize
import com.voria.umsh.designsystem.CanonicalAddress
import com.voria.umsh.designsystem.IdentifierText
import com.voria.umsh.designsystem.IdentifierTextStyle
import com.voria.umsh.designsystem.PeerAvatar
import com.voria.umsh.designsystem.SectionHeader
import com.voria.umsh.designsystem.label
import com.voria.umsh.designsystem.rememberDisplayNames
import com.voria.umsh.models.PeerRole
import com.voria.umsh.models.PeerSummary

/**
 * What this phone knows about one channel member (`conversation-info.svg`
 * 6), from their avatar: what the thread calls them, the name they call
 * themselves when that differs, their hint, and the address once known. A
 * saved node leads to its page; anyone else gets Request identity, which
 * reads Identity requested once it has gone ([requested]).
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun MemberSheet(
    member: ChannelMember,
    requested: Boolean,
    onRequestIdentity: () -> Unit,
    onOpenPeer: (String) -> Unit,
    onDismiss: () -> Unit,
) {
    val name = senderText(member.name)
    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true),
        modifier = Modifier.testTag(Tags.MEMBER_SHEET),
    ) {
        Column(Modifier.fillMaxWidth().verticalScroll(rememberScrollState()).navigationBarsPadding().padding(bottom = 24.dp)) {
            Text(
                name,
                style = MaterialTheme.typography.titleMedium,
                textAlign = TextAlign.Center,
                modifier = Modifier.fillMaxWidth().padding(horizontal = 24.dp, vertical = 8.dp).semantics { heading() }.testTag(Tags.MEMBER_TITLE),
            )
            member.savedPeer?.let { peer -> PeerHeader(peer) { onOpenPeer(peer.address) } }
            SectionHeader(stringResource(R.string.member_section))
            ValueRow(R.string.member_name, Tags.MEMBER_NAME) { Text(name, style = MaterialTheme.typography.bodyLarge, color = MaterialTheme.colorScheme.onSurfaceVariant) }
            member.distinctHandle?.let { handle ->
                ValueRow(R.string.member_calls_themselves, Tags.MEMBER_HANDLE) { Text(handle, style = MaterialTheme.typography.bodyLarge, color = MaterialTheme.colorScheme.onSurfaceVariant) }
            }
            member.nodeHint?.let { hint ->
                ValueRow(R.string.member_hint_label, Tags.MEMBER_HINT) {
                    IdentifierText(hint.text, style = valueIdentifierStyle(), color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
            member.address?.let { address ->
                ListItem(
                    headlineContent = { Text(stringResource(R.string.details_address)) },
                    supportingContent = {
                        CanonicalAddress(address, textAlign = TextAlign.Start, modifier = Modifier.testTag(Tags.MEMBER_ADDRESS))
                    },
                    colors = ListItemDefaults.colors(containerColor = Color.Transparent),
                )
            }
            if (member.savedPeer == null) {
                Button(
                    onClick = onRequestIdentity,
                    enabled = !requested,
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp)
                        .padding(top = 16.dp)
                        .heightIn(min = 48.dp)
                        .testTag(Tags.MEMBER_REQUEST_IDENTITY),
                ) {
                    Text(stringResource(if (requested) R.string.member_identity_requested else R.string.member_request_identity))
                }
                Text(
                    stringResource(R.string.member_request_footer),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
                )
            }
        }
    }
}

/** A saved member's node: its avatar, name and role, leading to its page. */
@Composable
private fun PeerHeader(peer: PeerSummary, onOpen: () -> Unit) {
    val names = rememberDisplayNames()
    ListItem(
        leadingContent = { PeerAvatar(peer, size = AvatarSize.List, describe = false) },
        headlineContent = { Text(names.peer(peer)) },
        supportingContent = when {
            peer.isCompanionRadio -> ({ Text(stringResource(R.string.companion_radio)) })
            peer.role != PeerRole.Unknown -> ({ Text(peer.role.label()) })
            else -> null
        },
        trailingContent = { Icon(painterResource(R.drawable.ic_chevron_right), contentDescription = null) },
        colors = ListItemDefaults.colors(containerColor = Color.Transparent),
        modifier = Modifier
            .clickable(role = Role.Button, onClickLabel = stringResource(R.string.open_peer_page), onClick = onOpen)
            .testTag(Tags.MEMBER_PEER),
    )
}

/** A label, with its value at the row's end; one node for TalkBack. */
@Composable
private fun ValueRow(label: Int, tag: String, value: @Composable () -> Unit) {
    ListItem(
        headlineContent = { Text(stringResource(label)) },
        trailingContent = value,
        colors = ListItemDefaults.colors(containerColor = Color.Transparent),
        modifier = Modifier.semantics(mergeDescendants = true) {}.testTag(tag),
    )
}

/** An identifier at the size of the row values beside it (the boards' "3f9a", "BtC5"). */
@Composable
internal fun valueIdentifierStyle() = IdentifierTextStyle.merge(fontSize = MaterialTheme.typography.bodyLarge.fontSize)
