import Foundation
import Security

/// Keychain custody for channel keys.
///
/// A channel key is group membership: whoever holds it can read the channel
/// and send as any member. It gets the same protection class as the identity
/// secret and never enters the SQLite store, which holds public records only.
/// Keys are filed under the channel's local identifier so a record and its key
/// are removed together.
protocol ChannelKeyVault: Actor {
    func storeKey(_ key: Data, channelID: UUID) async throws
    func loadKey(channelID: UUID) async throws -> Data?
    func deleteKey(channelID: UUID) async throws
    /// Forget every channel key this phone holds.
    ///
    /// Erasing the identity is what calls this: channel keys are group
    /// membership held by *this* phone, and a phone that is no longer the
    /// node those groups admitted has no business keeping them. Deletes by
    /// service rather than by walking the channel table, so a key whose
    /// SQLite row was already lost goes with the rest.
    func deleteAllKeys() async throws
}

actor KeychainChannelKeyVault: ChannelKeyVault {
    private static let service = "com.umsh.channel-keys"

    func storeKey(_ key: Data, channelID: UUID) throws {
        guard key.count == 32 else {
            throw IdentityVaultError.coreFailure
        }
        let item: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: Self.service,
            kSecAttrAccount: channelID.uuidString,
            kSecAttrSynchronizable: kCFBooleanFalse as Any,
            // Matches the identity secret: a locked-phone background relaunch
            // has to rebuild the mesh session with these channels registered.
            kSecAttrAccessible: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            kSecValueData: key,
        ]
        let status = SecItemAdd(item as CFDictionary, nil)
        if status == errSecDuplicateItem {
            // Re-storing the key for a channel already on file restates what
            // is there; joining is idempotent at every other layer too.
            let query: [CFString: Any] = [
                kSecClass: kSecClassGenericPassword,
                kSecAttrService: Self.service,
                kSecAttrAccount: channelID.uuidString,
                kSecAttrSynchronizable: kCFBooleanFalse as Any,
            ]
            let update: [CFString: Any] = [
                kSecAttrAccessible: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
                kSecValueData: key,
            ]
            let updateStatus = SecItemUpdate(query as CFDictionary, update as CFDictionary)
            guard updateStatus == errSecSuccess else {
                throw mapKeychainStatus(updateStatus)
            }
            return
        }
        guard status == errSecSuccess else {
            throw mapKeychainStatus(status)
        }
    }

    func loadKey(channelID: UUID) throws -> Data? {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: Self.service,
            kSecAttrAccount: channelID.uuidString,
            kSecAttrSynchronizable: kCFBooleanFalse as Any,
            kSecReturnData: kCFBooleanTrue as Any,
            kSecMatchLimit: kSecMatchLimitOne,
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound {
            return nil
        }
        guard status == errSecSuccess, let key = result as? Data else {
            throw mapKeychainStatus(status)
        }
        return key
    }

    func deleteKey(channelID: UUID) throws {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: Self.service,
            kSecAttrAccount: channelID.uuidString,
            kSecAttrSynchronizable: kCFBooleanFalse as Any,
        ]
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw mapKeychainStatus(status)
        }
    }

    func deleteAllKeys() throws {
        // No account: on iOS a delete matching only class and service takes
        // every item under it, which is the point — this must not depend on
        // a channel list that may itself be gone.
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: Self.service,
        ]
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw mapKeychainStatus(status)
        }
    }

    private func mapKeychainStatus(_ status: OSStatus) -> IdentityVaultError {
        switch status {
        case errSecInteractionNotAllowed, errSecNotAvailable:
            .protectedDataUnavailable
        default:
            .keychainFailure
        }
    }
}
