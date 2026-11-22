package com.voria.umsh.services.mobilecore

import com.voria.umsh.core.MobileAppConfigRecord
import com.voria.umsh.core.MobileAppCore
import com.voria.umsh.core.MobileAppStore
import com.voria.umsh.core.SecretVault
import com.voria.umsh.services.mobilecore.ParityFormat.bytewise
import com.voria.umsh.services.mobilecore.ParityFormat.neighbor
import com.voria.umsh.services.mobilecore.ParityFormat.opt
import com.voria.umsh.services.mobilecore.ParityFormat.stateLines
import java.io.File
import org.junit.Assert.fail
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * Renders what the app shows of the committed parity stores, read through a
 * radioless core and mapped by [RecordMapping], and holds it to the goldens.
 * The format is the contract in
 * `crates/umsh-mobile-core/src/app_core/parity/README.md`; the core's own
 * parity test owns the goldens, so nothing here writes them.
 */
class ReadMappingParityTest {
    @get:Rule val temp = TemporaryFolder()

    private val directory = ParityFormat.directory

    @Test
    fun seededMatches() = check("seeded", "owner")

    @Test
    fun augmentedMatches() = check("augmented", "alice")

    private fun check(name: String, owner: String) {
        val expected = File(directory, "$name.golden").readText()
        val rendered = render(name, owner, expected)
        if (rendered == expected) return
        val ours = rendered.split("\n")
        val theirs = expected.split("\n")
        val index = ours.indices.firstOrNull { it >= theirs.size || ours[it] != theirs[it] }
            ?: minOf(ours.size, theirs.size)
        fail(
            "$name.golden differs at line ${index + 1}:\n" +
                "  got:  ${ours.getOrElse(index) { "<end>" }}\n" +
                "  want: ${theirs.getOrElse(index) { "<end>" }}",
        )
    }

    private fun render(name: String, owner: String, golden: String): String {
        // Opening migrates in place, so only ever open a copy.
        val copy = File(temp.newFolder(), "$name.sqlite")
        File(directory, "$name.sqlite").copyTo(copy)
        val store = MobileAppStore.open(copy.path)
        val core = MobileAppCore(store, NoVault, MobileAppConfigRecord(temp.newFolder().path, 0u))
        try {
            core.setOwner(owner)
            val state = RecordMapping.state(core.state(false), emptyMap(), previous = null)
            val lines = mutableListOf("## state")
            lines += stateLines(state).sortedWith(ParityFormat::bytewise)

            // Every conversation in the state, and every transcript the
            // golden names (some belong to no conversation), that has messages.
            val addresses = (
                state.conversations.map { it.address } +
                    golden.lineSequence().filter { it.startsWith(TRANSCRIPT) }.map { it.removePrefix(TRANSCRIPT) }
                ).toSortedSet(ParityFormat::bytewise).filter { core.messageCount(it) > 0 }
            for (address in addresses) {
                val page = RecordMapping.page(core.transcriptNewest(address, 500u), state.peers)
                lines += "$TRANSCRIPT$address"
                lines += "page has_older=${page.hasOlder} has_newer=${page.hasNewer}"
                lines += page.messages.map(ParityFormat::messageLine)
            }

            val listings = state.peers.mapNotNull { peer ->
                core.peerRepeaters(peer.address)?.let { peer.address to RecordMapping.listing(it) }
            }.sortedWith { a, b -> bytewise(a.first, b.first) }
            for ((address, listing) in listings) {
                lines += "## repeaters $address"
                lines += "listing total=${opt(listing.total) { it.toString() }}" +
                    " next_cursor=${opt(listing.nextCursor, ParityFormat::bytes)} as_of=${listing.asOfMs}"
                lines += listing.entries.map { "entry " + neighbor(it, state) }
            }
            return lines.joinToString("\n") + "\n"
        } finally {
            core.close()
            store.close()
        }
    }

    /** Nothing here reads a channel key. */
    private object NoVault : SecretVault {
        override fun load(account: String): ByteArray? = null
        override fun store(account: String, secret: ByteArray) = Unit
        override fun delete(account: String) = Unit
        override fun deleteAll() = Unit
    }

    private companion object {
        const val TRANSCRIPT = "## transcript "
    }
}
