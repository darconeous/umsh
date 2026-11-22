package com.voria.umsh.services.identity

import android.os.Build
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.UserNotAuthenticatedException
import java.io.IOException
import java.security.KeyStoreException
import java.security.ProviderException
import javax.crypto.AEADBadTagException

/**
 * Whether a failure to open a stored secret may pass, or means the secret
 * is gone for good.
 *
 * Decided by exception class, nearest first along the cause chain.
 * Anything not recognized counts as transient: a permanent answer invites
 * the person to erase, and an unrecognized failure is not evidence enough
 * for that.
 */
internal object SecretFailures {
    enum class Kind { Transient, Permanent }

    fun classify(error: Throwable): Kind {
        var cause: Throwable? = error
        val seen = HashSet<Throwable>()
        while (cause != null && seen.add(cause)) {
            kindOf(cause)?.let { return it }
            cause = cause.cause
        }
        return Kind.Transient
    }

    private fun kindOf(error: Throwable): Kind? = when {
        // Subclasses of `InvalidKeyException`, so before anything broader.
        error is KeyPermanentlyInvalidatedException -> Kind.Permanent
        error is UserNotAuthenticatedException -> Kind.Transient
        error is WrappingKeyMissingException -> Kind.Permanent
        error is AEADBadTagException -> Kind.Permanent
        // `UnrecoverableKeyException` is no class of its own here: keystore2
        // wraps every key-lookup failure in it, busy and not-ready ones too,
        // so its cause decides, and without one it is unrecognized.
        // The file is not one this vault wrote: too short, or another format.
        error is IllegalArgumentException -> Kind.Permanent
        Build.VERSION.SDK_INT >= 33 && error is android.security.KeyStoreException ->
            if (error.isTransientFailure || error.isSystemError) Kind.Transient else null
        error is KeyStoreException -> Kind.Transient
        error is ProviderException -> Kind.Transient
        error is IOException -> Kind.Transient
        else -> null
    }
}
