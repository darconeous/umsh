package com.voria.umsh.designsystem

import android.text.Annotation
import android.text.Spanned
import androidx.annotation.StringRes
import androidx.compose.runtime.Composable
import androidx.compose.ui.platform.LocalResources
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString

/**
 * A format string whose arguments keep their own styling and annotations
 * (an identifier's isolate and verbatim speech), and whose own
 * `<annotation type="…">` spans take the style [styles] gives that type:
 * a translator marks what is styled, so the style follows the words in any
 * language. Arguments are positional, `%1$s` to `%9$s`.
 */
@Composable
fun annotatedStringResource(
    @StringRes id: Int,
    vararg args: AnnotatedString,
    styles: Map<String, SpanStyle> = emptyMap(),
): AnnotatedString {
    val text = LocalResources.current.getText(id)
    return format(text, args.toList(), styles)
}

/** [text] with its annotation spans styled and its `%n$s` placeholders replaced. Pure but for the span types. */
internal fun format(text: CharSequence, args: List<AnnotatedString>, styles: Map<String, SpanStyle>): AnnotatedString {
    val template = buildAnnotatedString {
        append(text.toString())
        if (text is Spanned) {
            text.getSpans(0, text.length, Annotation::class.java).forEach { span ->
                if (span.key == ANNOTATION_TYPE) {
                    styles[span.value]?.let { addStyle(it, text.getSpanStart(span), text.getSpanEnd(span)) }
                }
            }
        }
    }
    return buildAnnotatedString {
        var index = 0
        val source = template.text
        while (index < source.length) {
            val match = PLACEHOLDER.find(source, index)
            if (match == null) {
                append(template.subSequence(index, source.length))
                break
            }
            append(template.subSequence(index, match.range.first))
            val which = match.groupValues[1].toInt() - 1
            args.getOrNull(which)?.let { append(it) }
            index = match.range.last + 1
        }
    }
}

private const val ANNOTATION_TYPE = "type"
private val PLACEHOLDER = Regex("%([1-9])\\\$s")
