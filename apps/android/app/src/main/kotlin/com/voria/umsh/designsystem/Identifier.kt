package com.voria.umsh.designsystem

import androidx.annotation.StringRes
import androidx.compose.material3.LocalContentColor
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.VerbatimTtsAnnotation
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.withAnnotation
import androidx.compose.ui.text.withStyle

/*
 * Identifiers (addresses, hints, hex, `umsh:` links, error detail) are never
 * string resources. Wherever one is shown it sits in a left-to-right isolate,
 * so right-to-left text around it cannot reorder its characters, and carries
 * a verbatim TTS span, so TalkBack spells it rather than reading it as words.
 */

private const val LRI = '⁦'
private const val PDI = '⁩'

/** [text] in a left-to-right isolate. */
fun isolated(text: String): String = "$LRI$text$PDI"

private const val FSI = '\u2068'

/**
 * Someone's own text (a name, a message body) placed into a translated
 * template: in a first-strong isolate, so it takes its own direction and
 * never reorders the words around it.
 */
fun userIsolated(text: String): String = "$FSI$text$PDI"

/** [text] in a first-strong isolate, its styles and annotations kept. */
fun userIsolated(text: AnnotatedString): AnnotatedString = buildAnnotatedString {
    append(FSI)
    append(text)
    append(PDI)
}

/** [text] isolated, spoken character by character, and in the monospace when [monospace]. */
fun identifierAnnotated(text: String, monospace: Boolean = true): AnnotatedString = buildAnnotatedString {
    appendIdentifier(text, monospace)
}

private fun AnnotatedString.Builder.appendIdentifier(text: String, monospace: Boolean) {
    withAnnotation(VerbatimTtsAnnotation(text)) {
        if (monospace) {
            withStyle(SpanStyle(fontFamily = FontFamily.Monospace)) { append(isolated(text)) }
        } else {
            append(isolated(text))
        }
    }
}

/** An identifier on its own: the system monospace at 13/20 unless [style] says otherwise. */
@Composable
fun IdentifierText(
    text: String,
    modifier: Modifier = Modifier,
    style: TextStyle = IdentifierTextStyle,
    color: Color = LocalContentColor.current,
    textAlign: TextAlign? = null,
) {
    Text(
        text = identifierAnnotated(text, monospace = false),
        modifier = modifier,
        style = style,
        color = color,
        textAlign = textAlign,
    )
}

/**
 * A string resource whose arguments are identifiers, such as "Node hint
 * %1$s": each argument isolated and spoken verbatim, in the sentence's own
 * font unless [monospace].
 */
@Composable
fun identifierStringResource(
    @StringRes id: Int,
    vararg identifiers: String,
    monospace: Boolean = false,
): AnnotatedString {
    val markers = identifiers.indices.map { "$MARK_OPEN$it$MARK_CLOSE" }
    val formatted = stringResource(id, *markers.toTypedArray())
    return withIdentifiers(formatted, identifiers.toList(), monospace)
}

/**
 * A string resource whose first argument is a word and whose second is an
 * identifier, such as "Private · 9c41": the identifier isolated and spoken
 * verbatim.
 */
@Composable
fun wordAndIdentifierStringResource(@StringRes id: Int, word: String, identifier: String): AnnotatedString =
    withIdentifiers(stringResource(id, word, "${MARK_OPEN}0$MARK_CLOSE"), listOf(identifier), monospace = false)

/** [formatted] with each `MARK_OPEN i MARK_CLOSE` replaced by identifier `i`. Pure, for tests. */
internal fun withIdentifiers(formatted: String, identifiers: List<String>, monospace: Boolean): AnnotatedString =
    buildAnnotatedString {
        var index = 0
        while (index < formatted.length) {
            val open = formatted.indexOf(MARK_OPEN, index)
            val close = if (open < 0) -1 else formatted.indexOf(MARK_CLOSE, open)
            if (open < 0 || close < 0) {
                append(formatted.substring(index))
                break
            }
            append(formatted.substring(index, open))
            val which = formatted.substring(open + 1, close).toIntOrNull()
            if (which != null && which in identifiers.indices) {
                appendIdentifier(identifiers[which], monospace)
            }
            index = close + 1
        }
    }

/* Private-use characters: never in a translation, so safe as placeholders. */
private const val MARK_OPEN = ''
private const val MARK_CLOSE = ''
