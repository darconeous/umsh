package com.voria.umsh.features.peers.manualpath

import com.voria.umsh.R
import com.voria.umsh.core.MobileIdentity
import com.voria.umsh.core.inspectPublicIdentity
import com.voria.umsh.models.Octets
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Typed repeater hints through the core, and each problem to its line (`manual-path.svg` 4–5). */
class HintEntryTest {
    @Test
    fun eachProblemHasItsLine() {
        assertEquals(R.string.hint_entry_base58_help, RepeaterHints.footer(HintForm.Base58Prefix, null))
        assertEquals(R.string.hint_entry_base58_help, RepeaterHints.footer(HintForm.Base58Prefix, HintProblem.TooShort))
        assertEquals(R.string.hint_entry_base58_too_long, RepeaterHints.footer(HintForm.Base58Prefix, HintProblem.TooLong))
        assertEquals(R.string.hint_entry_base58_invalid, RepeaterHints.footer(HintForm.Base58Prefix, HintProblem.InvalidCharacter))
        assertEquals(R.string.hint_entry_base58_out_of_range, RepeaterHints.footer(HintForm.Base58Prefix, HintProblem.OutOfRange))
        assertEquals(R.string.hint_entry_hex_help, RepeaterHints.footer(HintForm.Hex, null))
        assertEquals(R.string.hint_entry_hex_help, RepeaterHints.footer(HintForm.Hex, HintProblem.TooShort))
        assertEquals(R.string.hint_entry_hex_help, RepeaterHints.footer(HintForm.Hex, HintProblem.TooLong))
        assertEquals(R.string.hint_entry_hex_invalid, RepeaterHints.footer(HintForm.Hex, HintProblem.InvalidCharacter))
    }

    @Test
    fun theCoreParsesWhatIsTyped() {
        assertEquals(HintInput.EMPTY, RepeaterHints.parse("  ", HintForm.Hex))
        val hex = RepeaterHints.parse("5ebd", HintForm.Hex)
        assertNull(hex.problem)
        assertEquals(listOf(Octets(byteArrayOf(0x5e, 0xbd.toByte()))), hex.candidates.map { it.octets })
        assertEquals("5EBD", RepeaterHints.hexText(hex.candidates.single()))
        assertEquals(HintProblem.InvalidCharacter, RepeaterHints.parse("5EBG", HintForm.Hex).problem)
        assertTrue(RepeaterHints.parse("5EB", HintForm.Hex).candidates.isEmpty())
        assertEquals(HintProblem.InvalidCharacter, RepeaterHints.parse("0OIl", HintForm.Base58Prefix).problem)
        assertEquals(HintProblem.TooShort, RepeaterHints.parse("7Nq", HintForm.Base58Prefix).problem)

        // A real address's first characters name its own two bytes.
        val address = MobileIdentity.unlock(ByteArray(32) { 0x77 }).use { it.publicIdentity().canonicalAddress }
        val own = inspectPublicIdentity(address).hint.bytes.copyOf(2)
        val typed = RepeaterHints.parse(address.take(6), HintForm.Base58Prefix)
        assertNull(typed.problem)
        assertEquals(listOf(Octets(own)), typed.candidates.map { it.octets })
    }

    @Test
    fun aNodeHintIsCutToTheRepeaterHint() {
        val hint = RepeaterHints.of(Octets(byteArrayOf(0x5e, 0xbd.toByte(), 0x11)))
        assertEquals(Octets(byteArrayOf(0x5e, 0xbd.toByte())), hint.octets)
        assertTrue(hint.text.isNotEmpty())
    }
}
