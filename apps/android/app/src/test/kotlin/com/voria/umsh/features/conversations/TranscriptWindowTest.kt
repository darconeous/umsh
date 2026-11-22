package com.voria.umsh.features.conversations

import com.voria.umsh.features.conversations.ThreadFixtures.MINUTE
import com.voria.umsh.features.conversations.ThreadFixtures.message
import com.voria.umsh.models.MessagePresentation.Companion.LOOSE_SPACING_DP
import com.voria.umsh.models.MessagePresentation.Companion.TIGHT_SPACING_DP
import com.voria.umsh.models.Presence
import com.voria.umsh.models.TranscriptPage
import com.voria.umsh.models.TranscriptRow
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** `threads.svg` boards 1–3: runs, date lines, gaps, and the window's edges and capacity. */
class TranscriptWindowTest {
    private fun messages(rows: List<TranscriptRow>) = rows.filterIsInstance<TranscriptRow.Message>()

    @Test
    fun runsJoinOneSendersConsecutiveMessages() {
        val rows = TranscriptWindow.rows(
            listOf(
                message(1),
                message(2),
                message(3, outbound = true),
                message(4, outbound = true),
                message(5, senderAddress = "peerB"),
            ),
            hasOlder = false,
        )
        assertTrue(rows.first() is TranscriptRow.DateLine)
        val shown = messages(rows).map { it.presentation }
        assertEquals(listOf(true, false, true, false, true), shown.map { it.isFirstInRun })
        assertEquals(listOf(false, true, false, true, true), shown.map { it.isLastInRun })
        // The date line brings its own space; then tight within a run, loose between runs.
        assertEquals(listOf(0, TIGHT_SPACING_DP, LOOSE_SPACING_DP, TIGHT_SPACING_DP, LOOSE_SPACING_DP), shown.map { it.topSpacingDp })
    }

    @Test
    fun deletionsStatusLinesAndUnavailableMarkersBreakRuns() {
        val rows = TranscriptWindow.rows(
            listOf(
                message(1),
                message(2, deleted = true),
                message(3),
                message(4, status = true),
                message(5),
                message(6, presence = Presence.Unavailable),
                message(7),
            ),
            hasOlder = true,
        )
        assertTrue(messages(rows).all { it.presentation.isFirstInRun && it.presentation.isLastInRun })
    }

    @Test
    fun hintsSeparateUnresolvedChannelMembers() {
        val rows = TranscriptWindow.rows(
            listOf(
                message(1, senderAddress = null, senderHint = byteArrayOf(1, 2, 3)),
                message(2, senderAddress = null, senderHint = byteArrayOf(1, 2, 3)),
                message(3, senderAddress = null, senderHint = byteArrayOf(4, 5, 6)),
            ),
            hasOlder = true,
        )
        assertEquals(listOf(true, false, true), messages(rows).map { it.presentation.isFirstInRun })
    }

    @Test
    fun anHourLullStartsADateLineAndARun() {
        val rows = TranscriptWindow.rows(
            listOf(message(1, at = 0), message(2, at = 59 * MINUTE), message(3, at = 119 * MINUTE)),
            hasOlder = false,
        )
        assertEquals(
            listOf("date:s/1", "s/1", "s/2", "date:s/3", "s/3"),
            rows.map { it.key },
        )
        assertTrue(messages(rows)[2].presentation.isFirstInRun)
        assertFalse(messages(rows)[1].presentation.isFirstInRun)
    }

    @Test
    fun theFirstMessageHasADateLineOnlyWhenNothingIsOlder() {
        val shown = listOf(message(1), message(2))
        assertTrue(TranscriptWindow.rows(shown, hasOlder = false).first() is TranscriptRow.DateLine)
        assertTrue(TranscriptWindow.rows(shown, hasOlder = true).none { it is TranscriptRow.DateLine })
    }

    @Test
    fun gapsCollapseByStateAndAreKeyedByTheirNewest() {
        val rows = TranscriptWindow.rows(
            listOf(
                message(1),
                message(2, presence = Presence.GapIdle),
                message(3, presence = Presence.GapIdle),
                message(4, presence = Presence.GapPending),
                message(5, presence = Presence.GapPending, deleted = true),
                message(6),
            ),
            hasOlder = true,
        )
        val gaps = rows.filterIsInstance<TranscriptRow.Gap>()
        assertEquals(listOf("gap:s/3", "gap:s/4"), gaps.map { it.key })
        assertEquals(listOf(true, false), gaps.map { it.isIdle })
        assertEquals(listOf(2, 1), gaps.map { it.messages.size })
        // A gap interrupts the run around it.
        assertTrue(messages(rows).last().presentation.isFirstInRun)
    }

    @Test
    fun onlyTheNewestOfMineAtTheLiveEdgeIsMostRecent() {
        val page = TranscriptPage(
            listOf(message(1, outbound = true), message(2, outbound = true), message(3, outbound = true, deleted = true), message(4)),
            hasOlder = false,
            hasNewer = false,
        )
        val window = TranscriptWindow().replacedBy(page, revision = 3)
        assertEquals("s/2", window.lastOutboundKey)
        assertEquals(3L, window.loadedRevision)
        assertTrue(window.hasLoadedOnce)
        assertNull(window.replacedBy(page.copy(hasNewer = true), revision = 3).lastOutboundKey)
    }

    @Test
    fun theWindowHoldsAtMostItsCapacity() {
        fun page(from: Long, count: Int, older: Boolean, newer: Boolean) =
            TranscriptPage((from until from + count).map { message(it) }, older, newer)

        var window = TranscriptWindow().replacedBy(page(1_000, TranscriptWindow.PAGE_SIZE, older = true, newer = false), 1)
        repeat(4) {
            val oldest = window.messages.first().ref.handle
            window = window.prepending(page(oldest - TranscriptWindow.PAGE_SIZE, TranscriptWindow.PAGE_SIZE, older = true, newer = false))
        }
        assertTrue(window.exceedsCapacity)
        // Reading history gives up the newest edge, which is now beyond the window.
        val trimmed = window.trimmedToCapacity()
        assertEquals(TranscriptWindow.CAPACITY, trimmed.messages.size)
        assertEquals(window.messages.first(), trimmed.messages.first())
        assertTrue(trimmed.hasNewer)
        assertNull(trimmed.lastOutboundKey)

        // Paging forward gives up the oldest edge instead.
        val newest = trimmed.messages.last().ref.handle
        val forward = trimmed.appending(page(newest + 1, TranscriptWindow.PAGE_SIZE, older = false, newer = false))
        assertEquals(TranscriptWindow.CAPACITY, forward.messages.size)
        assertEquals(newest + TranscriptWindow.PAGE_SIZE, forward.messages.last().ref.handle)
        assertTrue(forward.hasOlder)
        assertFalse(forward.hasNewer)
    }
}
