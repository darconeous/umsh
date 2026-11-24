package com.voria.umsh.features

import com.voria.umsh.core.MobileIdentity
import com.voria.umsh.core.NodeIdentityProfileRecord
import com.voria.umsh.core.nodeUriWithIdentity
import com.voria.umsh.core.publicIdentityBytes
import com.voria.umsh.core.signNodeIdentityBundle
import kotlinx.coroutines.runBlocking

/**
 * Node links for import tests (a copy of the JVM tests' own), made by the core: a fixed key per [seed],
 * and identity bundles signed by it, unsigned, tampered, or unreadable.
 */
object ImportFixtures {
    // Seeds that are multiples of 0x11 are the staged air's own nodes; these tests use others.
    const val REPORTED = 1_761_666_120L

    fun secret(seed: Int) = ByteArray(32) { seed.toByte() }

    fun address(seed: Int): String = MobileIdentity.unlock(secret(seed)).use { it.publicIdentity().canonicalAddress }

    fun hex(address: String): String = publicIdentityBytes(address).joinToString("") { "%02x".format(it) }

    class Signed(val address: String, val bundle: ByteArray, val link: String)

    fun signedLink(seed: Int, name: String = "Marmot"): Signed = runBlocking {
        val address = address(seed)
        val bundle = signNodeIdentityBundle(
            secret(seed),
            NodeIdentityProfileRecord(
                roleCode = 2u,
                capabilityBits = 0x06u,
                name = name,
                latitude = 44.0521,
                longitude = -123.0868,
                locationPrecision = 5u,
                altitudeM = null,
                timestamp = REPORTED.toUInt(),
            ),
        )
        Signed(address, bundle, nodeUriWithIdentity(address, bundle))
    }

    /** The same claims with the 64-byte signature cut off. */
    fun unsignedLink(seed: Int): String {
        val signed = signedLink(seed)
        return nodeUriWithIdentity(signed.address, signed.bundle.copyOf(signed.bundle.size - 64))
    }

    /** The signed claims with one signature byte changed. */
    fun tamperedLink(seed: Int): String {
        val signed = signedLink(seed)
        val bundle = signed.bundle.copyOf().also { it[it.lastIndex] = (it.last().toInt() xor 0x01).toByte() }
        return nodeUriWithIdentity(signed.address, bundle)
    }

    /** Identity bytes that do not parse. */
    fun unreadableLink(seed: Int): String = nodeUriWithIdentity(address(seed), byteArrayOf(0x7F, 0x7F, 0x7F))
}
