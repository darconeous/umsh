package com.voria.umsh.app

import com.voria.umsh.core.SecretVault
import com.voria.umsh.models.KeyProtection
import com.voria.umsh.services.identity.IdentityVault
import com.voria.umsh.services.identity.IdentityVaultException
import java.util.Collections
import java.util.concurrent.atomic.AtomicInteger

/** What the fake vaults were asked, in order, across all of them. */
class VaultLog {
    val events: MutableList<String> = Collections.synchronizedList(mutableListOf())

    fun snapshot(): List<String> = synchronized(events) { events.toList() }
}

class MemoryIdentityVault(private val log: VaultLog) : IdentityVault {
    @Volatile var secret: ByteArray? = null

    @Volatile var failLoad: IdentityVaultException? = null

    @Volatile var failDelete: IdentityVaultException? = null

    /** With [failDelete]: the secret goes before the delete throws. */
    @Volatile var failDeleteAfterForgetting = false

    /** Fails only the loads with these 1-based call numbers. */
    @Volatile var failLoadCalls: Map<Int, IdentityVaultException> = emptyMap()

    private val loads = AtomicInteger()

    val loadCount: Int get() = loads.get()

    override fun load(): ByteArray? {
        failLoadCalls[loads.incrementAndGet()]?.let { throw it }
        failLoad?.let { throw it }
        return secret?.copyOf()
    }

    override fun store(secret: ByteArray) {
        log.events += "identity.store"
        this.secret = secret.copyOf()
    }

    override fun delete() {
        failDelete?.let {
            if (failDeleteAfterForgetting) secret = null
            throw it
        }
        log.events += "identity.delete"
        secret = null
    }

    override fun protection() = KeyProtection.Software
}

class MemorySecretVault(private val name: String, private val log: VaultLog) : SecretVault {
    val secrets: MutableMap<String, ByteArray> = Collections.synchronizedMap(mutableMapOf())

    /** Makes [deleteAll] throw, as a Keystore that is not ready does. */
    @Volatile var failDeleteAll: Exception? = null

    override fun load(account: String): ByteArray? = secrets[account]?.copyOf()

    override fun store(account: String, secret: ByteArray) {
        secrets[account] = secret.copyOf()
    }

    override fun delete(account: String) {
        secrets.remove(account)
    }

    override fun deleteAll() {
        failDeleteAll?.let { throw it }
        log.events += "$name.deleteAll"
        secrets.clear()
    }
}

class MemoryVaults(log: VaultLog) : VaultFactory {
    override val identity = MemoryIdentityVault(log)
    val live = MemorySecretVault("live", log)
    val staging = MemorySecretVault("staging", log)

    override fun channelKeys(kind: CoreKind) = when (kind) {
        CoreKind.Live -> live
        CoreKind.Staging -> staging
    }
}
