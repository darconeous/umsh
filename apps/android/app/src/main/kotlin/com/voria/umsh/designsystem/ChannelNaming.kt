package com.voria.umsh.designsystem

import com.voria.umsh.models.ChannelSummary
import java.util.Locale

/**
 * What a channel's badge spells and what its title says, by the rules in
 * `docs/ux/src/apps/channel-badges.md`. Pure Kotlin; the Compose side
 * ([ChannelBadge], [channelTitle]) only resolves the strings.
 */
object ChannelNaming {
    const val PUBLIC = "public"
    const val EMERGENCY = "emergency"

    /** The name the user sees for [channel] before the title rules: their alias, else its name. */
    private fun shownName(channel: ChannelSummary): String? =
        channel.alias?.takeIf { it.isNotBlank() } ?: channel.name?.takeIf { it.isNotBlank() }

    /**
     * The title beside a badge. The standard channels keep their fixed
     * titles unless the user named them; a channel never named is a
     * private channel.
     */
    fun title(channel: ChannelSummary): ChannelTitle {
        val alias = channel.alias?.takeIf { it.isNotBlank() }
        if (alias == null) {
            when (channel.canonicalName) {
                PUBLIC -> return ChannelTitle.Public
                EMERGENCY -> return ChannelTitle.Emergency
            }
        }
        val name = shownName(channel) ?: return ChannelTitle.Private
        return ChannelTitle.Text(titleFor(name))
    }

    /**
     * A name as a title: a leading emoji is what the badge shows, so it and
     * the whitespace after it are dropped. A name that is that emoji alone
     * keeps a title: a flag's region code, else the name as written (CLDR
     * short names are not bundled yet).
     */
    fun titleFor(name: String): String {
        val clusters = Graphemes.split(name)
        val first = clusters.firstOrNull() ?: return name
        if (!Graphemes.isEmoji(first)) return name
        val rest = name.substring(first.length).trimStart()
        if (rest.isNotEmpty()) return rest
        return Graphemes.flagRegion(first) ?: name
    }

    /** The badge's lettering, as whole grapheme clusters: one to four. */
    fun lettering(channel: ChannelSummary): List<String> {
        val alias = channel.alias?.takeIf { it.isNotBlank() }
        if (alias == null) {
            when (channel.canonicalName) {
                PUBLIC -> return listOf("P")
                EMERGENCY -> return listOf("E")
            }
        }
        return lettering(shownName(channel), channel.channelIdHex)
    }

    /**
     * A name that starts with an emoji is lettered with it alone; any other
     * with the first cluster of each word (split at whitespace, hyphens and
     * underscores), uppercased, up to four. A channel never named shows its
     * identifier.
     */
    fun lettering(name: String?, identifierHex: String): List<String> {
        val clusters = name?.let(Graphemes::split).orEmpty()
        val first = clusters.firstOrNull()
        if (first != null && Graphemes.isEmoji(first)) return listOf(first)
        val initials = words(name.orEmpty())
            .take(4)
            .map { Graphemes.split(it).first().uppercase(Locale.ROOT) }
        return initials.ifEmpty { Graphemes.split(identifierHex.uppercase(Locale.ROOT)) }
    }

    /** The fixed fill a standard channel takes, or null for a derived one. */
    fun builtin(channel: ChannelSummary): Builtin? = when (channel.canonicalName) {
        PUBLIC -> Builtin.Public
        EMERGENCY -> Builtin.Emergency
        else -> null
    }

    enum class Builtin { Public, Emergency }

    /**
     * [text]'s words, split at whitespace, hyphens and underscores. Kotlin's
     * `isWhitespace` is Unicode's on the JVM and on a phone alike (a regex
     * `\s` is ASCII-only on the JVM but not in Android's ICU engine), and
     * it takes the no-break and ideographic spaces as iOS does.
     */
    private fun words(text: String): List<String> = buildList {
        val word = StringBuilder()
        for (char in text) {
            if (char.isWhitespace() || char == '-' || char == '_') {
                if (word.isNotEmpty()) add(word.toString())
                word.clear()
            } else {
                word.append(char)
            }
        }
        if (word.isNotEmpty()) add(word.toString())
    }
}

/** A channel's title, before its strings are resolved. */
sealed interface ChannelTitle {
    data class Text(val text: String) : ChannelTitle
    data object Public : ChannelTitle
    data object Emergency : ChannelTitle

    /** Never named: "Private channel". The badge shows the identifier. */
    data object Private : ChannelTitle
}
