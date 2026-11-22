package com.voria.umsh.services.identity

import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.UserNotAuthenticatedException
import androidx.test.platform.app.InstrumentationRegistry
import com.voria.umsh.core.SecretVaultException
import com.voria.umsh.models.KeyProtection
import java.io.File
import java.security.KeyStore
import java.security.KeyStoreException
import java.security.ProviderException
import java.security.UnrecoverableKeyException
import java.util.UUID
import javax.crypto.AEADBadTagException
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Before
import org.junit.Test

/**
 * The vaults' failures reach the core and the host as their own types, a
 * stored secret that will not open is never read as none, and what may pass
 * is told apart from what is gone.
 */
class VaultErrorMappingTest {
    private val run = UUID.randomUUID().toString()
    private val identityAlias = "com.voria.umsh.test.$run.identity"
    private val channelAlias = "com.voria.umsh.test.$run.channel-keys"
    private lateinit var root: File
    private lateinit var identity: KeystoreIdentityVault
    private lateinit var channels: CoreSecretVault

    @Before
    fun setUp() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        root = File(context.cacheDir, "vault-mapping-$run")
        identity = KeystoreIdentityVault(KeystoreSecretVault(File(root, "identity"), identityAlias))
        channels = CoreSecretVault(KeystoreSecretVault(File(root, "channel-keys"), channelAlias))
    }

    @After
    fun tearDown() {
        root.deleteRecursively()
        KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.run {
            deleteEntry(identityAlias)
            deleteEntry(channelAlias)
        }
    }

    private fun onlyFile(directory: String) = File(root, directory).listFiles()!!.single()

    @Test
    fun anIdentityRoundTripsAndDeletesWithItsKey() {
        assertNull(identity.load())
        val secret = ByteArray(32) { it.toByte() }
        identity.store(secret)
        assertArrayEquals(secret, identity.load())
        assertNotEquals(KeyProtection.Unknown, identity.protection())
        identity.delete()
        assertNull(identity.load())
        assertFalse(KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.containsAlias(identityAlias))
        identity.delete()
    }

    @Test
    fun aDamagedIdentityIsLost() {
        identity.store(ByteArray(32) { 1 })
        val file = onlyFile("identity")
        val bytes = file.readBytes()
        bytes[bytes.size - 1] = (bytes[bytes.size - 1].toInt() xor 1).toByte()
        file.writeBytes(bytes)
        assertThrows(IdentityVaultException.Lost::class.java) { identity.load() }
    }

    @Test
    fun aTruncatedIdentityIsLost() {
        identity.store(ByteArray(32) { 2 })
        onlyFile("identity").writeBytes(byteArrayOf(1, 2, 3))
        assertThrows(IdentityVaultException.Lost::class.java) { identity.load() }
    }

    /** The key went (a reset Keystore) while the file stayed: never answered as none, never re-keyed. */
    @Test
    fun anIdentityWhoseKeyIsGoneIsLost() {
        identity.store(ByteArray(32) { 3 })
        KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.deleteEntry(identityAlias)
        val lost = assertThrows(IdentityVaultException.Lost::class.java) { identity.load() }
        assertEquals(WrappingKeyMissingException::class.java.name, lost.detail)
        assertFalse(KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.containsAlias(identityAlias))
    }

    @Test
    fun channelKeysFailAsTheCoreExpects() {
        val account = "8D3F1A2B-0000-4000-8000-00000000ABCD"
        assertNull(channels.load(account))
        channels.store(account, ByteArray(32) { 4 })
        val file = onlyFile("channel-keys")
        val bytes = file.readBytes()
        bytes[bytes.size - 1] = (bytes[bytes.size - 1].toInt() xor 1).toByte()
        file.writeBytes(bytes)
        assertThrows(SecretVaultException.Failed::class.java) { channels.load(account) }
        channels.deleteAll()
        assertNull(channels.load(account))
        assertFalse(File(root, "channel-keys").exists())
    }

    @Test
    fun failuresAreToldApartByClass() {
        val transient = listOf(
            KeyStoreException(),
            ProviderException(),
            UserNotAuthenticatedException(),
            java.io.IOException(),
            IllegalStateException("unrecognized"),
            // keystore2 wraps a busy or not-ready lookup this way.
            UnrecoverableKeyException("Failed to obtain information about key").apply {
                initCause(KeyStoreException())
            },
            UnrecoverableKeyException(),
        )
        val permanent = listOf(
            KeyPermanentlyInvalidatedException(),
            AEADBadTagException(),
            IllegalArgumentException(),
            WrappingKeyMissingException(),
            RuntimeException(AEADBadTagException()),
            UnrecoverableKeyException().apply { initCause(KeyPermanentlyInvalidatedException()) },
        )
        transient.forEach { assertEquals(it.toString(), SecretFailures.Kind.Transient, SecretFailures.classify(it)) }
        permanent.forEach { assertEquals(it.toString(), SecretFailures.Kind.Permanent, SecretFailures.classify(it)) }
    }
}
