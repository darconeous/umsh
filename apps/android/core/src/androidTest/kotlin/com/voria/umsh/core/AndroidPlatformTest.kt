package com.voria.umsh.core

import org.junit.Assert.assertEquals
import org.junit.Test

/** What only a device can show: the core reads Android's own zone data. */
class AndroidPlatformTest {
    @Test
    fun zoneRuleReadsPackedTzdata() {
        // Null here means the packed record lacks the TZif footer that
        // carries the rule.
        assertEquals("PST8PDT,M3.2.0,M11.1.0", zoneRule("America/Los_Angeles"))
        assertEquals(330.toShort(), zoneRule("Asia/Kolkata")?.let { ruleOffsetMin(it, 0) })
    }
}
