package com.voria.umsh.services.format

import android.icu.text.Collator
import java.text.Normalizer
import java.util.Locale

/**
 * How names sort, in the reader's language, at ICU's secondary strength:
 * accents break ties and case is ignored, so "émile" sits beside "Emile". The app's
 * implementation is ICU's ([AndroidCollation]); JVM tests use `java.text`'s.
 */
fun interface Collation : Comparator<String>

/** [Collation] through ICU's `Collator`, at secondary strength. */
class AndroidCollation(locale: Locale) : Collation {
    private val collator = Collator.getInstance(locale).apply { strength = Collator.SECONDARY }

    // An ICU Collator is not thread-safe; a sort may run on any thread.
    override fun compare(a: String, b: String): Int = synchronized(collator) { collator.compare(a, b) }
}

/**
 * Text as search compares it: case and accents folded away, so "jose"
 * finds "José". Pure (`java.text.Normalizer` is the same on a phone and the
 * JVM).
 */
object SearchFolding {
    private val marks = Regex("\\p{Mn}+")

    fun fold(text: String): String =
        marks.replace(Normalizer.normalize(text, Normalizer.Form.NFD), "").lowercase(Locale.ROOT)

    /** Whether [text] holds [query], folded. An empty query is in everything. */
    fun contains(text: String?, query: SearchQuery): Boolean =
        text != null && fold(text).contains(query.folded)
}

/** A query as typed, and folded once for every candidate it is compared with. */
class SearchQuery(val text: String) {
    val folded: String = SearchFolding.fold(text)
}
