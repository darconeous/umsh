package com.voria.umsh.services.identity

import com.voria.umsh.core.MobileException
import com.voria.umsh.core.MobileIdentity
import com.voria.umsh.core.PublicIdentityRecord
import com.voria.umsh.core.generateIdentitySecret

/**
 * Decides which identity this phone runs as. Never mints over a secret that
 * exists: a stored secret that cannot be used is reported, not replaced.
 */
class IdentityOperations(
    private val vault: IdentityVault,
    private val generate: () -> ByteArray = ::generateIdentitySecret,
) {
    sealed interface Loaded {
        /** [minted]: there was none, and this one was just made. */
        data class Ready(val identity: PublicIdentityRecord, val minted: Boolean) : Loaded

        data class Unavailable(val error: IdentityVaultException.Unavailable) : Loaded

        data class Lost(val detail: String) : Loaded
    }

    /**
     * Read the stored identity, or mint one when there is none.
     * [beforeMint] runs before a new secret is stored, so a launch killed
     * between the two still finds the first-run step recorded.
     */
    suspend fun load(beforeMint: suspend () -> Unit): Loaded = try {
        val stored = vault.load()
        if (stored != null) {
            Loaded.Ready(publicIdentity(stored), minted = false)
        } else {
            beforeMint()
            val secret = generate()
            val identity = publicIdentity(secret.copyOf())
            try {
                vault.store(secret)
            } finally {
                secret.fill(0)
            }
            Loaded.Ready(identity, minted = true)
        }
    } catch (error: IdentityVaultException.Unavailable) {
        Loaded.Unavailable(error)
    } catch (error: IdentityVaultException.Lost) {
        Loaded.Lost(error.detail)
    } catch (error: MobileException) {
        Loaded.Lost("unlock: ${error.javaClass.simpleName}")
    }

    /**
     * The stored identity's public half, never minting one: for Manage
     * space, which names the identity at stake and starts nothing. Null
     * when there is none, or it cannot be read.
     */
    fun peek(): PublicIdentityRecord? = try {
        vault.load()?.let(::publicIdentity)
    } catch (_: IdentityVaultException) {
        null
    } catch (_: MobileException) {
        null
    }

    /** Whether a secret is stored at all, readable or not. */
    fun stored(): Boolean = try {
        vault.load()?.also { it.fill(0) } != null
    } catch (_: IdentityVaultException.Lost) {
        true
    } catch (_: IdentityVaultException.Unavailable) {
        true
    }

    /**
     * The stored identity, unlocked for one start: a start consumes it.
     * Throws [IdentityVaultException], or `MobileException` for a secret of
     * the wrong length.
     */
    fun unlock(): MobileIdentity {
        val secret = vault.load() ?: throw IdentityVaultException.Lost("secret missing")
        return unlockAndZero(secret)
    }

    private fun publicIdentity(secret: ByteArray): PublicIdentityRecord =
        unlockAndZero(secret).use { it.publicIdentity() }

    /** The core zeroes its copy; this zeroes ours. */
    private fun unlockAndZero(secret: ByteArray): MobileIdentity = try {
        MobileIdentity.unlock(secret)
    } finally {
        secret.fill(0)
    }
}
