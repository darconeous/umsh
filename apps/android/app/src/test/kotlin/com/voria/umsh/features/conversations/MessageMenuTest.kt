package com.voria.umsh.features.conversations

import com.voria.umsh.features.conversations.ThreadFixtures.message
import com.voria.umsh.models.DeliveryState
import com.voria.umsh.models.MessageActions
import com.voria.umsh.models.Presence
import com.voria.umsh.models.ResendMode
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** What the long-press menu offers (`bubbles.svg` 3), from the row's `actions`. */
class MessageMenuTest {
    @Test
    fun aReceivedMessageGetsReactionsReplyCopyAndDetails() {
        val received = message(1, actions = MessageActions(react = true, reply = true))
        assertTrue(MessageMenu.reactions(received))
        assertEquals(listOf(MenuItem.Reply, MenuItem.Copy, MenuItem.Details), MessageMenu.items(received))
    }

    @Test
    fun mineWithinItsWindowCanBeEditedAndDeleted() {
        val mine = message(1, outbound = true, actions = MessageActions(edit = true, delete = true, react = true, reply = true))
        assertEquals(
            listOf(MenuItem.Reply, MenuItem.Copy, MenuItem.Edit, MenuItem.Details, MenuItem.Delete),
            MessageMenu.items(mine),
        )
    }

    @Test
    fun aFailedMessageOfMineOffersTryAgainOrResend() {
        val inPlace = message(1, outbound = true, delivery = DeliveryState.Failed, actions = MessageActions(resend = ResendMode.InPlace))
        val asNew = message(2, outbound = true, delivery = DeliveryState.Undelivered, actions = MessageActions(resend = ResendMode.AsNew))
        assertEquals(listOf(MenuItem.Copy, MenuItem.TryAgain, MenuItem.Details), MessageMenu.items(inPlace))
        assertEquals(listOf(MenuItem.Copy, MenuItem.Resend, MenuItem.Details), MessageMenu.items(asNew))
    }

    @Test
    fun onlyMyEditedMessageOffersItsOriginal() {
        val edited = message(1, outbound = true, edited = true, originalBody = "South gate.")
        assertEquals(listOf(MenuItem.Copy, MenuItem.ViewOriginal, MenuItem.Details), MessageMenu.items(edited))
        val theirs = message(2, edited = true, originalBody = "South gate.")
        assertEquals(listOf(MenuItem.Copy, MenuItem.Details), MessageMenu.items(theirs))
    }

    @Test
    fun nothingThatIsNotThereHasAMenu() {
        val all = MessageActions(edit = true, delete = true, react = true, reply = true)
        assertFalse(MessageMenu.hasMenu(message(1, deleted = true, actions = all)))
        assertFalse(MessageMenu.hasMenu(message(2, presence = Presence.GapIdle, actions = all)))
        assertFalse(MessageMenu.hasMenu(message(3, presence = Presence.Unavailable, actions = all)))
        assertEquals(emptyList<MenuItem>(), MessageMenu.items(message(4, deleted = true, actions = all)))
        assertFalse(MessageMenu.reactions(message(5, deleted = true, actions = all)))
    }

    @Test
    fun theResendDialogOffersPlainSendingOnlyForAForwardSecretOne() {
        val secret = message(1, outbound = true, forwardSecret = true, actions = MessageActions(resend = ResendMode.InPlace))
        assertTrue(ResendPrompt(secret, ResendMode.InPlace).offersWithoutForwardSecrecy)
        assertFalse(ResendPrompt(message(2, outbound = true), ResendMode.AsNew).offersWithoutForwardSecrecy)
    }
}
