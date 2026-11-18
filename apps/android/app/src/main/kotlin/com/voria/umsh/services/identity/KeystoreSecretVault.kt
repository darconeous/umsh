package com.voria.umsh.services.identity

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.util.AtomicFile
import java.io.File
import java.io.FileNotFoundException
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec

/**
 * Secrets at rest: the identity's private key and channel keys.
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
    private val keyAlias: String = DEFAULT_KEY_ALIAS,
) {
    /** Where the wrapping key lives, as the Keystore reports it. */
    enum class Protection { StrongBox, TrustedEnvironment, Software, Unknown }

    /** The stored secret for [account], or null when there is none. */
    fun load(account: String): ByteArray? {
        val sealed = try {
            file(account).readFully()
        } catch (_: FileNotFoundException) {
            return null
        }
        require(sealed.size > HEADER_LEN && sealed[0] == FORMAT) { "Unreadable secret" }
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(
            Cipher.DECRYPT_MODE,
            key(),
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
    private fun key(): SecretKey {
        val keyStore = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        (keyStore.getKey(keyAlias, null) as SecretKey?)?.let { return it }
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
        const val DEFAULT_KEY_ALIAS = "com.voria.umsh.secret-vault"
        const val KEYSTORE = "AndroidKeyStore"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val FORMAT: Byte = 1
        const val IV_LEN = 12
        const val TAG_BITS = 128
        const val HEADER_LEN = 1 + IV_LEN
    }
}
