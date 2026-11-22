package com.voria.umsh.models

/**
 * Bytes compared by content.
 *
 * The core's records hold `ByteArray`s, whose `equals` is identity, so two
 * reads of the same row never compare equal and every `StateFlow` write
 * would publish. Models hold these instead.
 */
class Octets(bytes: ByteArray) {
    private val bytes = bytes.copyOf()

    val size: Int get() = bytes.size

    operator fun get(index: Int): Byte = bytes[index]

    fun toByteArray(): ByteArray = bytes.copyOf()

    /** Lowercase hex, two digits a byte. */
    fun hex(): String = bytes.joinToString("") { "%02x".format(it.toInt() and 0xFF) }

    override fun equals(other: Any?): Boolean = other is Octets && bytes.contentEquals(other.bytes)

    override fun hashCode(): Int = bytes.contentHashCode()

    override fun toString(): String = "x" + hex()
}

internal fun ByteArray.octets() = Octets(this)
