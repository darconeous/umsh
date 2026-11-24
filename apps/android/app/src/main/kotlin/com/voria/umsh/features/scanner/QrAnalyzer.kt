package com.voria.umsh.features.scanner

import com.voria.umsh.core.MobileLinkKind
import com.voria.umsh.core.MobileException
import com.voria.umsh.core.classifyUmshLink
import com.voria.umsh.core.inspectChannelUri
import com.voria.umsh.features.peers.ImportCheck
import com.voria.umsh.features.peers.PeerImport
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/** What the scanner makes of a code's text (`qr-scanner.svg` 2–4). */
sealed interface ScanVerdict {
    /** A `umsh:` node or channel code: the scanner closes and its origin previews [text]. */
    data class Accepted(val text: String) : ScanVerdict

    /** Anything else, a bare address or key included: only `umsh:` codes are accepted. */
    data object NotUmsh : ScanVerdict
}

/**
 * Which codes the scanner takes: the core sorts the link
 * (`classify_umsh_link`), and a node link must read as a node
 * (`inspect_peer_identity`), a channel link as a channel
 * (`inspect_channel_uri`), to close the scanner. Pure and local.
 */
object ScanCheck {
    fun check(text: String): ScanVerdict {
        val trimmed = text.trim()
        val readable = when (classifyUmshLink(trimmed)) {
            MobileLinkKind.NODE -> PeerImport.check(trimmed) is ImportCheck.Node
            MobileLinkKind.CHANNEL -> isChannel(trimmed)
            MobileLinkKind.NOT_LINK -> false
        }
        return if (readable) ScanVerdict.Accepted(trimmed) else ScanVerdict.NotUmsh
    }

    private fun isChannel(link: String): Boolean = try {
        inspectChannelUri(link)
        true
    } catch (_: MobileException) {
        false
    }
}

/**
 * The scanner's frame analysis: decodes each frame, latches the first
 * accepted code ([accepted], set once and never again, however many
 * frames still hold it), and reports a refused code as [refusal] until
 * the code has been out of the frame for [clearAfterFrames] frames in a
 * row, so a frame or two of blur does not flicker the pill. Frames arrive
 * on one background thread; the flows are read anywhere.
 */
class QrAnalyzer(
    private val check: (String) -> ScanVerdict = ScanCheck::check,
    private val clearAfterFrames: Int = CLEAR_AFTER_FRAMES,
) {
    private val decoder = QrDecoder()
    private val latched = AtomicBoolean(false)
    private val _accepted = MutableStateFlow<String?>(null)
    private val _refusal = MutableStateFlow<ScanVerdict?>(null)
    private var lastText: String? = null
    private var lastVerdict: ScanVerdict? = null
    private var framesWithout = 0

    /** The first accepted code's text; null until one is seen. */
    val accepted: StateFlow<String?> = _accepted.asStateFlow()

    /** The refused code in the frame ([ScanVerdict.NotUmsh]); null with none. */
    val refusal: StateFlow<ScanVerdict?> = _refusal.asStateFlow()

    /** The camera stopped handing frames over: no code is in a frame that is not there. */
    fun forgetRefusal() {
        _refusal.value = null
    }

    fun analyze(frame: LuminanceFrame) {
        if (latched.get()) return
        val text = decoder.decode(frame)
        if (text == null) {
            framesWithout++
            if (framesWithout >= clearAfterFrames) _refusal.value = null
            return
        }
        framesWithout = 0
        // The same code frame after frame is checked once.
        val verdict = if (text == lastText) lastVerdict!! else check(text).also {
            lastText = text
            lastVerdict = it
        }
        when (verdict) {
            is ScanVerdict.Accepted -> if (latched.compareAndSet(false, true)) {
                _refusal.value = null
                _accepted.value = verdict.text
            }
            else -> _refusal.value = verdict
        }
    }

    private companion object {
        /** About a third of a second at the analysis rate. */
        const val CLEAR_AFTER_FRAMES = 10
    }
}
