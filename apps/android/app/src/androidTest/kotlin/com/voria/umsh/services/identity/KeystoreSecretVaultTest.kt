package com.voria.umsh.services.identity

import android.util.Log
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import java.security.KeyStore
import javax.crypto.AEADBadTagException
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Before
import org.junit.Test

class KeystoreSecretVaultTest {
    private val alias = "com.voria.umsh.secret-vault.test"
    private lateinit var directory: File
    private lateinit var vault: KeystoreSecretVault

    @Before
    fun setUp() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        directory = File(context.noBackupFilesDir, "vault-test").apply { deleteRecursively() }
        vault = KeystoreSecretVault(directory, alias)
    }

    @After
    fun tearDown() {
        directory.deleteRecursively()
        KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.deleteEntry(alias)
    }

    @Test
    fun storesLoadsReplacesAndDeletes() {
        val account = "8D3F1A2B-0000-4000-8000-00000000ABCD"
        assertNull(vault.load(account))
        val first = ByteArray(32) { it.toByte() }
        vault.store(account, first)
        assertArrayEquals(first, vault.load(account))
        val second = ByteArray(32) { (31 - it).toByte() }
        vault.store(account, second)
        assertArrayEquals(second, vault.load(account))
        vault.delete(account)
        assertNull(vault.load(account))
        vault.delete(account)
    }

    @Test
    fun theFileHoldsNoPlaintext() {
        val secret = ByteArray(32) { 0x5A }
        vault.store("identity", secret)
        val sealed = directory.listFiles()!!.single().readBytes()
        val plain = sealed.toList().windowed(secret.size).any { it == secret.toList() }
        assert(!plain) { "plaintext secret found in the file" }
    }

    @Test
    fun aFileMovedToAnotherAccountDoesNotOpen() {
        vault.store("alice", ByteArray(32) { 1 })
        vault.store("bob", ByteArray(32) { 2 })
        val alice = File(directory, "alice".toByteArray().joinToString("") { "%02x".format(it) })
        val bob = File(directory, "bob".toByteArray().joinToString("") { "%02x".format(it) })
        alice.copyTo(bob, overwrite = true)
        assertThrows(AEADBadTagException::class.java) { vault.load("bob") }
    }

    @Test
    fun aDamagedFileDoesNotOpen() {
        vault.store("identity", ByteArray(32) { 3 })
        val file = directory.listFiles()!!.single()
        val bytes = file.readBytes()
        bytes[bytes.size - 1] = (bytes[bytes.size - 1].toInt() xor 1).toByte()
        file.writeBytes(bytes)
        assertThrows(AEADBadTagException::class.java) { vault.load("identity") }
    }

    @Test
    fun reportsWhereTheKeyIsHeld() {
        val protection = vault.protection
        Log.i("KeystoreSecretVaultTest", "wrapping key protection: $protection")
        assertNotEquals(KeystoreSecretVault.Protection.Unknown, protection)
    }
}
