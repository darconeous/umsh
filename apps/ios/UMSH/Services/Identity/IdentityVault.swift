import Foundation
import Security

struct LocalIdentitySnapshot: Equatable, Sendable {
    let id: String
    let publicIdentity: MeshPublicIdentity
}

enum IdentityVaultError: Error, Equatable, Sendable {
    case identityAlreadyExists
    case protectedDataUnavailable
    case randomGenerationFailed
    case keychainFailure
    case coreFailure
}

protocol IdentityVault: Actor {
    func loadIdentity() async throws -> LocalIdentitySnapshot?
    func createIdentity() async throws -> LocalIdentitySnapshot
}

actor KeychainIdentityVault: IdentityVault {
    private static let service = "com.umsh.identity-secret"
    private static let account = "primary"

    private let meshEngine: any MeshEngine

    init(meshEngine: any MeshEngine) {
        self.meshEngine = meshEngine
    }

    func loadIdentity() async throws -> LocalIdentitySnapshot? {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: Self.service,
            kSecAttrAccount: Self.account,
            kSecAttrSynchronizable: kCFBooleanFalse as Any,
            kSecReturnData: kCFBooleanTrue as Any,
            kSecReturnAttributes: kCFBooleanTrue as Any,
            kSecMatchLimit: kSecMatchLimitOne,
        ]

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound {
            return nil
        }
        guard status == errSecSuccess,
              let item = result as? [CFString: Any],
              let secret = item[kSecValueData] as? Data
        else {
            throw mapKeychainStatus(status)
        }

        migrateAccessibilityIfNeeded(item: item, secret: secret)
        return try await snapshot(secretKey: secret)
    }

    /// Items written before background support used WhenUnlocked, which a
    /// locked-phone background relaunch cannot read. Rewrite them as
    /// AfterFirstUnlock (still device-only, non-synchronizing). Best-effort:
    /// the secret is already in hand, so a failed migration only means the
    /// next locked-phone relaunch cannot attach — same as before.
    private func migrateAccessibilityIfNeeded(item: [CFString: Any], secret: Data) {
        let accessible = item[kSecAttrAccessible] as? String
        guard accessible != (kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly as String) else {
            return
        }
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: Self.service,
            kSecAttrAccount: Self.account,
            kSecAttrSynchronizable: kCFBooleanFalse as Any,
        ]
        let update: [CFString: Any] = [
            kSecAttrAccessible: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            kSecValueData: secret,
        ]
        _ = SecItemUpdate(query as CFDictionary, update as CFDictionary)
    }

    func createIdentity() async throws -> LocalIdentitySnapshot {
        var secret = Data(count: 32)

        let randomStatus = secret.withUnsafeMutableBytes { bytes in
            SecRandomCopyBytes(kSecRandomDefault, bytes.count, bytes.baseAddress!)
        }
        guard randomStatus == errSecSuccess else {
            throw IdentityVaultError.randomGenerationFailed
        }

        let item: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: Self.service,
            kSecAttrAccount: Self.account,
            kSecAttrSynchronizable: kCFBooleanFalse as Any,
            // AfterFirstUnlock (not WhenUnlocked): a background BLE relaunch
            // while the phone is locked must still be able to rebuild the
            // mesh session. Device-only and non-synchronizing are unchanged.
            kSecAttrAccessible: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            kSecValueData: secret,
        ]
        let status = SecItemAdd(item as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw mapKeychainStatus(status)
        }
        do {
            return try await snapshot(secretKey: secret)
        } catch {
            SecItemDelete([
                kSecClass: kSecClassGenericPassword,
                kSecAttrService: Self.service,
                kSecAttrAccount: Self.account,
            ] as CFDictionary)
            throw error
        }
    }

    private func snapshot(secretKey: Data) async throws -> LocalIdentitySnapshot {
        do {
            return LocalIdentitySnapshot(
                publicIdentity: try await meshEngine.unlockIdentity(secretKey: secretKey)
            )
        } catch {
            throw IdentityVaultError.coreFailure
        }
    }

    private func mapKeychainStatus(_ status: OSStatus) -> IdentityVaultError {
        switch status {
        case errSecDuplicateItem:
            .identityAlreadyExists
        case errSecInteractionNotAllowed, errSecNotAvailable:
            .protectedDataUnavailable
        default:
            .keychainFailure
        }
    }
}

private extension LocalIdentitySnapshot {
    init(publicIdentity: MeshPublicIdentity) {
        self.init(id: publicIdentity.canonicalAddress, publicIdentity: publicIdentity)
    }
}
