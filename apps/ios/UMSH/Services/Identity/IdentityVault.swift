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
            kSecMatchLimit: kSecMatchLimitOne,
        ]

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound {
            return nil
        }
        guard status == errSecSuccess, let secret = result as? Data else {
            throw mapKeychainStatus(status)
        }

        return try await snapshot(secretKey: secret)
    }

    func createIdentity() async throws -> LocalIdentitySnapshot {
        if try await loadIdentity() != nil {
            throw IdentityVaultError.identityAlreadyExists
        }

        var secret = Data(count: 32)
        defer { secret.resetBytes(in: secret.startIndex..<secret.endIndex) }

        let randomStatus = secret.withUnsafeMutableBytes { bytes in
            SecRandomCopyBytes(kSecRandomDefault, bytes.count, bytes.baseAddress!)
        }
        guard randomStatus == errSecSuccess else {
            throw IdentityVaultError.randomGenerationFailed
        }

        let identity = try await snapshot(secretKey: secret)
        let item: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: Self.service,
            kSecAttrAccount: Self.account,
            kSecAttrSynchronizable: kCFBooleanFalse as Any,
            kSecAttrAccessible: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecValueData: secret,
        ]
        let status = SecItemAdd(item as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw mapKeychainStatus(status)
        }
        return identity
    }

    private func snapshot(secretKey: Data) async throws -> LocalIdentitySnapshot {
        do {
            return LocalIdentitySnapshot(
                id: Self.account,
                publicIdentity: try await meshEngine.derivePublicIdentity(secretKey: secretKey)
            )
        } catch {
            throw IdentityVaultError.coreFailure
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
