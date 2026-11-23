package com.voria.umsh.services.radio

import com.voria.umsh.R
import com.voria.umsh.core.ulcpStatusName
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** A device's status is worded by its code, never by the core's Debug name. */
class UlcpStatusTextTest {
    /** Each named code is the status the core names it. */
    @Test
    fun theCodesAreTheCoresStatuses() {
        UlcpStatusText::class.java.declaredFields
            .filter { it.type == Int::class.javaPrimitiveType && java.lang.reflect.Modifier.isStatic(it.modifiers) && !it.name.startsWith("$") }
            .forEach { field ->
                val code = (field.get(null) as Int).toUInt()
                val name = ulcpStatusName(code)
                assertTrue("$code is $name, not ${field.name}", name.endsWith(field.name))
            }
    }

    @Test
    fun anUnknownCodeIsWordedByNumber() {
        assertEquals(R.string.ulcp_status_code, UlcpStatusText.text(250u))
        assertEquals(250L, UlcpStatusText.of(250u).code)
    }
}
