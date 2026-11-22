package com.voria.umsh.services.identity

import com.voria.umsh.core.SecretVault
import com.voria.umsh.core.SecretVaultException
import com.voria.umsh.services.mobilecore.AppLog

/**
 * One core's channel keys, as the core's [SecretVault].
 *
 * The core calls it on its worker thread. Every failure comes back as a
 * [SecretVaultException]: [SecretVaultException.Unavailable] when it may
 * pass, [SecretVaultException.Failed] when the key is gone. A key that is
 * stored but will not open is never answered as none.
 */
class CoreSecretVault(private val vault: KeystoreSecretVault) : SecretVault {
    override fun load(account: String): ByteArray? = guarded("load") { vault.load(account) }

    override fun store(account: String, secret: ByteArray) = guarded("store") { vault.store(account, secret) }

    override fun delete(account: String) = guarded("delete") { vault.delete(account) }

    override fun deleteAll() = guarded("deleteAll") { vault.deleteAll() }

    private inline fun <T> guarded(operation: String, body: () -> T): T = try {
        body()
    } catch (error: Exception) {
        AppLog.e(TAG, "channel key $operation failed: ${error.javaClass.name}")
        throw when (SecretFailures.classify(error)) {
            SecretFailures.Kind.Transient -> SecretVaultException.Unavailable()
            SecretFailures.Kind.Permanent -> SecretVaultException.Failed()
        }
    }

    private companion object {
        const val TAG = "umsh.vault"
    }
}
