import Foundation
import Security
import Synchronization
import UMSHMobileCore

/// Keychain custody for channel keys.
///
/// A channel key is group membership: whoever holds it can read the channel
/// and send as any member. It gets the same protection class as the identity
/// secret and never enters the SQLite store, which holds public records only.
/// Keys are filed under the channel's ID, uppercase, so a record and its key
/// are removed together.
///
/// The core calls it synchronously, on its own thread, so every call answers
/// on the thread that made it.
final class KeychainChannelKeyVault: SecretVault {
    private static let service = "com.voria.umsh.channel-keys"
    private static let legacyService = "com.umsh.channel-keys"

    private let legacyServiceMoved = Atomic<Bool>(false)

    /// Until the keys under the old service name have moved, none can be
    /// read with certainty, so every call answers unavailable rather than
    /// "not found". Tried again on each call until it succeeds once.
    private func moveLegacyServiceIfNeeded() throws(SecretVaultError) {
        guard !legacyServiceMoved.load(ordering: .acquiring) else { return }
        guard renameKeychainService(from: Self.legacyService, to: Self.service) == errSecSuccess else {
            throw .Unavailable
        }
        legacyServiceMoved.store(true, ordering: .releasing)
    }

    private static func query(account: String) -> [CFString: Any] {
        [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account.uppercased(),
            kSecAttrSynchronizable: kCFBooleanFalse as Any,
        ]
    }

    func load(account: String) throws(SecretVaultError) -> Data? {
        try moveLegacyServiceIfNeeded()
        var query = Self.query(account: account)
        query[kSecReturnData] = kCFBooleanTrue
        query[kSecMatchLimit] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound {
            return nil
        }
        guard status == errSecSuccess, let secret = result as? Data else {
            throw Self.error(status)
        }
        return secret
    }

    func store(account: String, secret: Data) throws(SecretVaultError) {
        try moveLegacyServiceIfNeeded()
        // Matches the identity secret: a locked-phone background relaunch
        // has to rebuild the mesh session with these channels registered.
        let protection: [CFString: Any] = [
            kSecAttrAccessible: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            kSecValueData: secret,
        ]
        let item = Self.query(account: account).merging(protection) { _, new in new }
        let status = SecItemAdd(item as CFDictionary, nil)
        if status == errSecDuplicateItem {
            // Re-storing a key already on file restates what is there;
            // joining is idempotent at every other layer too.
            let updateStatus = SecItemUpdate(
                Self.query(account: account) as CFDictionary,
                protection as CFDictionary
            )
            guard updateStatus == errSecSuccess else { throw Self.error(updateStatus) }
            return
        }
        guard status == errSecSuccess else { throw Self.error(status) }
    }

    func delete(account: String) throws(SecretVaultError) {
        try moveLegacyServiceIfNeeded()
        let status = SecItemDelete(Self.query(account: account) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw Self.error(status)
        }
    }

    /// Erasing the identity is what calls this: channel keys are group
    /// membership held by *this* phone, and a phone that is no longer the
    /// node those groups admitted has no business keeping them. Deletes by
    /// service rather than by walking the channel table, so a key whose
    /// SQLite row was already lost goes with the rest.
    func deleteAll() throws(SecretVaultError) {
        try moveLegacyServiceIfNeeded()
        // No account: on iOS a delete matching only class and service takes
        // every item under it.
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: Self.service,
        ]
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw Self.error(status)
        }
    }

    private static func error(_ status: OSStatus) -> SecretVaultError {
        switch status {
        case errSecInteractionNotAllowed, errSecNotAvailable: .Unavailable
        default: .Failed
        }
    }
}

extension SecretVault {
    func storeKey(_ key: Data, channelID: UUID) throws {
        guard key.count == 32 else { throw SecretVaultError.Failed }
        try store(account: channelID.uuidString, secret: key)
    }

    func loadKey(channelID: UUID) throws -> Data? {
        try load(account: channelID.uuidString)
    }

    func deleteKey(channelID: UUID) throws {
        try delete(account: channelID.uuidString)
    }
}

/// Channel keys held in memory, for previews, which must never reach the
/// Keychain.
final class MemorySecretVault: SecretVault, @unchecked Sendable {
    private let secrets = Mutex<[String: Data]>([:])

    func load(account: String) throws -> Data? {
        secrets.withLock { $0[account.uppercased()] }
    }

    func store(account: String, secret: Data) throws {
        secrets.withLock { $0[account.uppercased()] = secret }
    }

    func delete(account: String) throws {
        _ = secrets.withLock { $0.removeValue(forKey: account.uppercased()) }
    }

    func deleteAll() throws {
        secrets.withLock { $0.removeAll() }
    }
}
