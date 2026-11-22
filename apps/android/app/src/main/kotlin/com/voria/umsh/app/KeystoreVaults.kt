package com.voria.umsh.app

import com.voria.umsh.core.SecretVault
import com.voria.umsh.services.identity.CoreSecretVault
import com.voria.umsh.services.identity.IdentityVault
import com.voria.umsh.services.identity.KeystoreIdentityVault
import com.voria.umsh.services.identity.KeystoreSecretVault

/**
 * The Keystore-wrapped vaults, each with its own directory and alias: the
 * identity, the live core's channel keys, and staging's, so staged seeds
 * never land among the live keys and erasing one never touches another.
 */
class KeystoreVaults(paths: AppPaths) : VaultFactory {
    override val identity: IdentityVault =
        KeystoreIdentityVault(KeystoreSecretVault(paths.identity, paths.identityAlias))

    private val channelKeys = CoreKind.entries.associateWith { kind ->
        CoreSecretVault(KeystoreSecretVault(paths.channelKeys(kind), paths.channelKeyAlias(kind)))
    }

    override fun channelKeys(kind: CoreKind): SecretVault = channelKeys.getValue(kind)
}
