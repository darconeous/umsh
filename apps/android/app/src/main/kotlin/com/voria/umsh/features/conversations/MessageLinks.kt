package com.voria.umsh.features.conversations

import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.LinkAnnotation
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.TextLinkStyles
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.style.TextDecoration
import androidx.compose.ui.text.withStyle
import androidx.core.util.PatternsCompat

/** A link found in a message body: its place, and what it opens. */
data class MessageLink(val start: Int, val end: Int, val target: Target) {
    sealed interface Target {
        /** A web address, with a scheme added when the body gave none. */
        data class Web(val url: String) : Target

        /** An `umsh:` link, which opens in the app once its pages exist (Phase 3). */
        data class Umsh(val uri: String) : Target
    }

    companion object {
        /** The links in [body], in order and never overlapping; `umsh:` links win over anything inside them. */
        fun find(body: String): List<MessageLink> {
            val found = ArrayList<MessageLink>()
            UMSH.findAll(body).forEach { match ->
                val end = match.range.first + match.value.trimEnd(*TRAILING).length
                if (end > match.range.first + UMSH_PREFIX_LENGTH) {
                    found += MessageLink(match.range.first, end, Target.Umsh(body.substring(match.range.first, end)))
                }
            }
            val web = PatternsCompat.WEB_URL.matcher(body)
            while (web.find()) {
                val start = web.start()
                val end = start + web.group().trimEnd(*TRAILING).length
                if (end <= start) continue
                if (found.any { start < it.end && end > it.start }) continue
                val text = body.substring(start, end)
                val url = if (SCHEME.containsMatchIn(text)) text else "https://$text"
                found += MessageLink(start, end, Target.Web(url))
            }
            return found.sortedBy { it.start }
        }

        private val UMSH = Regex("(?i)(?<![\\w.+-])umsh:[^\\s<>\"]+")
        private const val UMSH_PREFIX_LENGTH = 5
        private val SCHEME = Regex("^[a-zA-Z][a-zA-Z0-9+.-]*://")
        private val TRAILING = charArrayOf('.', ',', ';', ':', '!', '?', ')', ']', '\'', '"', '…', '”', '’')
    }
}

/**
 * [body] with its links underlined in the body's own color: web links open
 * in the browser, `umsh:` links are underlined with no action until their
 * pages exist.
 */
fun linkified(body: String, links: List<MessageLink> = MessageLink.find(body)): AnnotatedString = buildAnnotatedString {
    var index = 0
    val underline = SpanStyle(textDecoration = TextDecoration.Underline)
    for (link in links) {
        append(body.substring(index, link.start))
        val text = body.substring(link.start, link.end)
        when (val target = link.target) {
            is MessageLink.Target.Web -> {
                pushLink(LinkAnnotation.Url(target.url, TextLinkStyles(style = underline)))
                append(text)
                pop()
            }
            is MessageLink.Target.Umsh -> withStyle(underline) { append(text) }
        }
        index = link.end
    }
    append(body.substring(index))
}
