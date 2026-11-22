package com.voria.umsh.services.identity

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.util.AtomicFile
import com.voria.umsh.services.mobilecore.AppLog
import java.io.File
import java.io.FileNotFoundException
import java.io.IOException
import java.security.GeneralSecurityException
import java.security.KeyStore
import java.security.ProviderException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec

/**
 * Secrets at rest, one kind per instance: the identity's private key in one
 * vault, each core's channel keys in another. Each has its own [directory]
 * and [keyAlias], so erasing one kind (the core's `deleteAll`) never touches
 * another.
 *
 * Each secret is a file under [directory], AES-256-GCM encrypted under one
 * non-exportable Android Keystore key, held in StrongBox when the device has
 * one and in the TEE otherwise. The ciphertext is useless off this device.
 * The account name is bound in as associated data, so a file moved to
 * another account's name fails to open instead of answering for it.
 *
 * The key needs no user authentication, matching iOS's
 * `AfterFirstUnlockThisDeviceOnly`: [directory] is in credential-encrypted
 * storage, which is unavailable before the first unlock anyway.
 *
 * Calls do file and Keystore I/O; make them off the main thread.
 */
class KeystoreSecretVault(
    private val directory: File,
    private val keyAlias: String,
) {
    /** Where the wrapping key lives, as the Keystore reports it. */
    enum class Protection { StrongBox, TrustedEnvironment, Software, Unknown }

    /**
     * The stored secret for [account], or null when there is none.
     *
     * Throws when a secret is stored but cannot be opened: a damaged or
     * moved file (`AEADBadTagException`, `IllegalArgumentException`), a
     * wrapping key that is gone ([WrappingKeyMissingException]), or a
     * Keystore that is not ready. Never answers null for those.
     */
    fun load(account: String): ByteArray? {
        val sealed = try {
            file(account).readFully()
        } catch (_: FileNotFoundException) {
            return null
        }
        require(sealed.size > HEADER_LEN && sealed[0] == FORMAT) { "Unreadable secret" }
        // Never a fresh key here: one made now could only fail the tag.
        val key = existingKey() ?: throw WrappingKeyMissingException()
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(
            Cipher.DECRYPT_MODE,
            key,
            GCMParameterSpec(TAG_BITS, sealed, 1, IV_LEN),
        )
        cipher.updateAAD(account.toByteArray(Charsets.UTF_8))
        return cipher.doFinal(sealed, HEADER_LEN, sealed.size - HEADER_LEN)
    }

    /** Store [secret] for [account], replacing any secret it had. */
    fun store(account: String, secret: ByteArray) {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        // The Keystore chooses the IV; a caller-chosen one is refused.
        cipher.init(Cipher.ENCRYPT_MODE, key())
        cipher.updateAAD(account.toByteArray(Charsets.UTF_8))
        val sealed = byteArrayOf(FORMAT) + cipher.iv + cipher.doFinal(secret)
        directory.mkdirs()
        val file = file(account)
        val out = file.startWrite()
        try {
            out.write(sealed)
            file.finishWrite(out)
        } catch (error: Throwable) {
            file.failWrite(out)
            throw error
        }
    }

    /** Forget [account]'s secret. Nothing happens when it has none. */
    fun delete(account: String) {
        file(account).delete()
        check(!file(account).baseFile.exists()) { "Secret not deleted" }
    }

    /**
     * Forget every secret, and the wrapping key with them. Done when the
     * files are gone, an atomic write's leftovers included: a key left
     * behind wraps nothing and is reused by the next [store], and an empty
     * directory holds nothing, so failing to delete either is not thrown.
     */
    @Synchronized
    fun deleteAll() {
        directory.listFiles()?.forEach { it.deleteRecursively() }
        // listFiles answers null for an unreadable directory, too: only an
        // empty listing, or no directory, is done.
        check(!directory.exists() || directory.listFiles()?.isEmpty() == true) { "Secrets not deleted" }
        if (directory.exists() && !directory.delete()) AppLog.w(TAG, "empty secrets directory kept")
        try {
            KeyStore.getInstance(KEYSTORE).apply { load(null) }.deleteEntry(keyAlias)
        } catch (error: GeneralSecurityException) {
            AppLog.w(TAG, "wrapping key kept: ${error.javaClass.name}")
        } catch (error: IOException) {
            AppLog.w(TAG, "wrapping key kept: ${error.javaClass.name}")
        } catch (error: ProviderException) {
            AppLog.w(TAG, "wrapping key kept: ${error.javaClass.name}")
        }
    }

    /** Where the wrapping key is held; creates the key if there is none. */
    val protection: Protection
        get() {
            val key = key()
            val info = SecretKeyFactory.getInstance(key.algorithm, KEYSTORE)
                .getKeySpec(key, KeyInfo::class.java) as KeyInfo
            return when (info.securityLevel) {
                KeyProperties.SECURITY_LEVEL_STRONGBOX -> Protection.StrongBox
                KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> Protection.TrustedEnvironment
                KeyProperties.SECURITY_LEVEL_SOFTWARE -> Protection.Software
                else -> Protection.Unknown
            }
        }

    /** Account names are identifiers chosen by the core; hex keeps any of them a safe file name. */
    private fun file(account: String) = AtomicFile(
        File(directory, account.toByteArray(Charsets.UTF_8).joinToString("") { "%02x".format(it) }),
    )

    @Synchronized
    private fun existingKey(): SecretKey? =
        KeyStore.getInstance(KEYSTORE).apply { load(null) }.getKey(keyAlias, null) as SecretKey?

    @Synchronized
    private fun key(): SecretKey {
        existingKey()?.let { return it }
        return try {
            generate(strongBox = true)
        } catch (_: StrongBoxUnavailableException) {
            generate(strongBox = false)
        }
    }

    private fun generate(strongBox: Boolean): SecretKey {
        val spec = KeyGenParameterSpec.Builder(
            keyAlias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setIsStrongBoxBacked(strongBox)
            .build()
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE)
            .apply { init(spec) }
            .generateKey()
    }

    private companion object {
        const val TAG = "umsh.vault"
        const val KEYSTORE = "AndroidKeyStore"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val FORMAT: Byte = 1
        const val IV_LEN = 12
        const val TAG_BITS = 128
        const val HEADER_LEN = 1 + IV_LEN
    }
}

/** A secret is stored, but the Keystore key that wrapped it is gone. */
class WrappingKeyMissingException : GeneralSecurityException("Wrapping key missing")
