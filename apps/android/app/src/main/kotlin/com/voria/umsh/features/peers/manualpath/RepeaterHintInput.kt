package com.voria.umsh.features.peers.manualpath

import androidx.annotation.StringRes
import com.voria.umsh.R
import com.voria.umsh.core.RepeaterHintInputFormat
import com.voria.umsh.core.RepeaterHintInputProblem
import com.voria.umsh.core.parseRepeaterHintInput
import com.voria.umsh.core.renderRepeaterHint
import com.voria.umsh.models.Octets
import com.voria.umsh.models.RepeaterHint
import com.voria.umsh.services.mobilecore.RecordMapping

/** How a repeater hint is typed: chosen, not guessed, since `a1b2` reads in both alphabets. */
enum class HintForm { Base58Prefix, Hex }

/** Why typed text does not yet name a repeater hint (the core's `RepeaterHintInputProblem`). */
enum class HintProblem { TooShort, TooLong, InvalidCharacter, OutOfRange }

/** What typed text names: one hint, two when a Base58 prefix straddles a boundary, or none and why. */
data class HintInput(val candidates: List<RepeaterHint>, val problem: HintProblem?) {
    companion object {
        val EMPTY = HintInput(emptyList(), null)
    }
}

/** Repeater hints typed, parsed and rendered by the core, which owns the alphabet and the rules. */
object RepeaterHints {
    /** A node's or neighbor's hint cut to the two bytes a path carries, as the core renders it. */
    fun of(hint: Octets): RepeaterHint {
        val bytes = octetsOf(hint).toByteArray()
        return try {
            RecordMapping.repeaterHint(renderRepeaterHint(bytes))
        } catch (error: Exception) {
            RepeaterHint(Octets(bytes), Octets(bytes).hex().uppercase())
        }
    }

    /** A node's or neighbor's hint cut to the two bytes a path carries, without rendering it (no core call). */
    fun octetsOf(hint: Octets): Octets = Octets(hint.toByteArray().copyOf(REPEATER_HINT_LEN))

    /** What [text] names in [form]; blank text names nothing and has no problem. */
    fun parse(text: String, form: HintForm): HintInput {
        val trimmed = text.trim()
        if (trimmed.isEmpty()) return HintInput.EMPTY
        val record = parseRepeaterHintInput(
            trimmed,
            when (form) {
                HintForm.Base58Prefix -> RepeaterHintInputFormat.BASE58_PREFIX
                HintForm.Hex -> RepeaterHintInputFormat.HEX
            },
        )
        return HintInput(
            record.candidates.map(RecordMapping::repeaterHint),
            when (record.problem) {
                null -> null
                RepeaterHintInputProblem.TOO_SHORT -> HintProblem.TooShort
                RepeaterHintInputProblem.TOO_LONG -> HintProblem.TooLong
                RepeaterHintInputProblem.INVALID_CHARACTER -> HintProblem.InvalidCharacter
                RepeaterHintInputProblem.OUT_OF_RANGE -> HintProblem.OutOfRange
            },
        )
    }

    /**
     * The line under the field (`manual-path.svg` 4): what is wrong with
     * the text, or, with nothing wrong or nothing typed, what to type.
     */
    @StringRes
    fun footer(form: HintForm, problem: HintProblem?): Int = when (form) {
        HintForm.Base58Prefix -> when (problem) {
            HintProblem.InvalidCharacter -> R.string.hint_entry_base58_invalid
            HintProblem.OutOfRange -> R.string.hint_entry_base58_out_of_range
            HintProblem.TooLong -> R.string.hint_entry_base58_too_long
            HintProblem.TooShort, null -> R.string.hint_entry_base58_help
        }
        HintForm.Hex -> when (problem) {
            HintProblem.InvalidCharacter -> R.string.hint_entry_hex_invalid
            else -> R.string.hint_entry_hex_help
        }
    }

    /** The two bytes as four uppercase hex digits, the form a hint is typed in. */
    fun hexText(hint: RepeaterHint): String = hint.octets.hex().uppercase()

    private const val REPEATER_HINT_LEN = 2
}
