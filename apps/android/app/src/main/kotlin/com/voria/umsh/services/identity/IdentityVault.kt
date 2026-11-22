package com.voria.umsh.services.identity

import com.voria.umsh.models.KeyProtection
import com.voria.umsh.services.mobilecore.AppLog

/** Why this phone's identity secret could not be used. */
sealed class IdentityVaultException(message: String) : Exception(message) {
    /** The Keystore is not ready; it may be later. Nothing is lost. */
    class Unavailable(val kind: String) : IdentityVaultException("identity unavailable: $kind")

    /** A secret is stored and can never be opened again. [detail] is diagnostic. */
    class Lost(val detail: String) : IdentityVaultException("identity lost: $detail")
}

/**
 * Where this phone's identity secret is kept: one secret, never more.
 *
 * Every call does file and Keystore I/O; make them off the main thread.
 * Failures come back only as [IdentityVaultException].
 */
interface IdentityVault {
    /** The stored secret, or null when there is none. */
    fun load(): ByteArray?

    fun store(secret: ByteArray)

    /**
     * Forget the secret, and the key that wrapped it. Throws only when the
     * secret is still stored. Nothing happens when there is none.
     */
    fun delete()

    /** Where the wrapping key is held. */
    fun protection(): KeyProtection
}

/** The identity secret in its own Keystore-wrapped vault. */
class KeystoreIdentityVault(private val vault: KeystoreSecretVault) : IdentityVault {
    override fun load(): ByteArray? = guarded("load") { vault.load(ACCOUNT) }

    override fun store(secret: ByteArray) = guarded("store") { vault.store(ACCOUNT, secret) }

    override fun delete() = guarded("delete") { vault.deleteAll() }

    override fun protection(): KeyProtection = try {
        when (vault.protection) {
            KeystoreSecretVault.Protection.StrongBox -> KeyProtection.StrongBox
            KeystoreSecretVault.Protection.TrustedEnvironment -> KeyProtection.TrustedEnvironment
            KeystoreSecretVault.Protection.Software -> KeyProtection.Software
            KeystoreSecretVault.Protection.Unknown -> KeyProtection.Unknown
        }
    } catch (error: Exception) {
        AppLog.w(TAG, "key protection unreadable: ${error.javaClass.name}")
        KeyProtection.Unknown
    }

    private inline fun <T> guarded(operation: String, body: () -> T): T = try {
        body()
    } catch (error: Exception) {
        val kind = error.javaClass.name
        AppLog.e(TAG, "identity $operation failed: $kind")
        throw when (SecretFailures.classify(error)) {
            SecretFailures.Kind.Transient -> IdentityVaultException.Unavailable(kind)
            SecretFailures.Kind.Permanent -> IdentityVaultException.Lost(kind)
        }
    }

    private companion object {
        const val TAG = "umsh.identity"
        const val ACCOUNT = "identity"
    }
}
