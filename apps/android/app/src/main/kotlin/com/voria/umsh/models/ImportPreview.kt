package com.voria.umsh.models

/**
 * A node's identity as typed, pasted or scanned (`add-peer.svg` 3–4):
 * nothing stored or sent yet. [input] is the text the core parsed, which
 * saving parses again, so the core decides whether its identity replaces
 * a stored one.
 */
data class ImportPreview(
    val input: String,
    val address: String,
    val hint: NodeHint,
    /** The link carried identity details, whether or not they could be read. */
    val hasIdentityData: Boolean,
    /** Those details, when they parse; their signature may still fail. */
    val identity: AdvertisedIdentity?,
)
