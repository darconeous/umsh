package com.voria.umsh.services.notifications

import com.voria.umsh.core.MobileNotificationEventRecord
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** The whole suppression rule (§6.2): the conversation on screen, with the app in front. */
class NotificationSuppressionTest {
    private val message = MobileNotificationEventRecord.Message("ridge", null, "ridge", null, null, "hi", false, null)
    private val summary = MobileNotificationEventRecord.Summary("ridge", null, 3u)
    private val failure = MobileNotificationEventRecord.DeliveryFailure("ridge", null, "hi", true)
    private val heard = MobileNotificationEventRecord.PeerHeard("ridge")

    @Test
    fun theConversationOnScreenInFrontIsLeftAlone() {
        assertTrue(NotificationSuppression.suppressed(message, foreground = true, visible = "ridge"))
        assertTrue(NotificationSuppression.suppressed(summary, foreground = true, visible = "ridge"))
        assertTrue(NotificationSuppression.suppressed(failure, foreground = true, visible = "ridge"))
    }

    @Test
    fun anotherConversationOrNoneIsTold() {
        assertFalse(NotificationSuppression.suppressed(message, foreground = true, visible = "kestrel"))
        assertFalse(NotificationSuppression.suppressed(message, foreground = true, visible = null))
    }

    @Test
    fun aThreadLeftOpenInTheBackgroundIsTold() {
        assertFalse(NotificationSuppression.suppressed(message, foreground = false, visible = "ridge"))
    }

    @Test
    fun aWatchedNodeIsAlwaysTold() {
        assertFalse(NotificationSuppression.suppressed(heard, foreground = true, visible = "ridge"))
    }
}
