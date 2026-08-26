import Foundation
import Security

/// `Identifiable` by the canonical address it already keys everything else
/// by, so a presentation can be driven by "which identity" rather than by a
/// separate flag that could disagree with it.
struct LocalIdentitySnapshot: Equatable, Identifiable, Sendable {
    let id: String
    let publicIdentity: MeshPublicIdentity
}

/// What the Keychain holds, and whether this install has any claim to it.
///
/// The third case is the one that needs a name. Deleting an app removes its
/// container; it does not remove its Keychain items. A reinstall therefore
/// finds the previous install's node key sitting on top of an empty
/// database — the same identity to everyone on the mesh, with none of the
/// conversations, peers, or channels that were keyed to it.
enum StoredIdentity: Equatable, Sendable {
    /// Nothing on file: a genuinely new phone.
    case none
    /// This install's identity, anchored to this container.
    case present(LocalIdentitySnapshot)
    /// A key left behind by an install that is gone. Whether to keep it is
    /// the operator's decision, not the app's: the key is still what peers
    /// recognize, and the data it belonged to is not coming back either way.
    case orphaned(LocalIdentitySnapshot)
}

enum IdentityVaultError: Error, Equatable, Sendable {
    case identityAlreadyExists
    case protectedDataUnavailable
    case randomGenerationFailed
    case keychainFailure
    case coreFailure
}

protocol IdentityVault: Actor {
    /// What is on file, and whether this install put it there.
    func storedIdentity() async throws -> StoredIdentity
    func createIdentity() async throws -> LocalIdentitySnapshot
    /// Keep an orphaned identity: anchor it to this container so the next
    /// launch reads it as this install's own.
    func adoptStoredIdentity() async throws -> LocalIdentitySnapshot
    /// Destroy the private key. Irreversible: nothing else holds a copy.
    func eraseIdentity() async throws
}

extension IdentityVault {
    /// The identity to run as, or `nil` when there is none to run as yet.
    ///
    /// An orphan counts as none: it is not this install's until somebody
    /// says so, and starting the app on top of one would settle a question
    /// that belongs to whoever is holding the phone.
    func loadIdentity() async throws -> LocalIdentitySnapshot? {
        if case let .present(snapshot) = try await storedIdentity() { return snapshot }
        return nil
    }
}

actor KeychainIdentityVault: IdentityVault {
    private static let service = "com.umsh.identity-secret"
    private static let account = "primary"

    private let meshEngine: any MeshEngine
    private let anchor: IdentityAnchor

    init(meshEngine: any MeshEngine, anchor: IdentityAnchor = IdentityAnchor()) {
        self.meshEngine = meshEngine
        self.anchor = anchor
    }

    func storedIdentity() async throws -> StoredIdentity {
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
            // Nothing on file, so nothing for the anchor to point at. Drop a
            // stale one rather than leave it to vouch for the next key.
            anchor.clear()
            return .none
        }
        guard status == errSecSuccess,
              let item = result as? [CFString: Any],
              let secret = item[kSecValueData] as? Data
        else {
            throw mapKeychainStatus(status)
        }

        migrateAccessibilityIfNeeded(item: item, secret: secret)
        let snapshot = try await snapshot(secretKey: secret)
        return anchor.matches(snapshot.id) ? .present(snapshot) : .orphaned(snapshot)
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
            let snapshot = try await snapshot(secretKey: secret)
            anchor.write(snapshot.id)
            return snapshot
        } catch {
            deleteSecret()
            anchor.clear()
            throw error
        }
    }

    func adoptStoredIdentity() async throws -> LocalIdentitySnapshot {
        guard case let .orphaned(snapshot) = try await storedIdentity() else {
            throw IdentityVaultError.identityAlreadyExists
        }
        anchor.write(snapshot.id)
        return snapshot
    }

    func eraseIdentity() throws {
        anchor.clear()
        let status = deleteSecret()
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw mapKeychainStatus(status)
        }
    }

    /// Remove the secret by class and service, no account: this has to take
    /// any item filed under the service, including one an older build wrote
    /// under a different account name.
    @discardableResult
    private func deleteSecret() -> OSStatus {
        SecItemDelete([
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: Self.service,
        ] as CFDictionary)
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

/// A file in the app container naming the identity this install owns.
///
/// The Keychain is the wrong place to record this and so is anything else
/// that outlives the app: the whole point is to hold something iOS *does*
/// destroy on delete, so that a key with no anchor beside it is a key from
/// an install that is gone. A file in Application Support is exactly that,
/// and it survives the things that should not count as a reinstall — an
/// upgrade, a restore, a device migration.
///
/// Every operation is best-effort. An anchor that cannot be written leaves
/// the identity looking orphaned on the next launch, which asks a question
/// that has a right answer, rather than failing a mint that worked.
struct IdentityAnchor: Sendable {
    private let url: URL?

    init(fileManager: FileManager = .default) {
        url = try? fileManager.url(
            for: .applicationSupportDirectory,
            in: .userDomainMask,
            appropriateFor: nil,
            create: true
        )
        .appendingPathComponent("UMSH", isDirectory: true)
        .appendingPathComponent("identity-anchor", isDirectory: false)
    }

    /// Whether this container claims the given identity.
    func matches(_ identityID: String) -> Bool {
        guard let url, let recorded = try? String(contentsOf: url, encoding: .utf8) else {
            return false
        }
        return recorded.trimmingCharacters(in: .whitespacesAndNewlines) == identityID
    }

    func write(_ identityID: String) {
        guard let url else { return }
        try? FileManager.default.createDirectory(
            at: url.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        try? identityID.write(to: url, atomically: true, encoding: .utf8)
    }

    func clear() {
        guard let url else { return }
        try? FileManager.default.removeItem(at: url)
    }
}

private extension LocalIdentitySnapshot {
    init(publicIdentity: MeshPublicIdentity) {
        self.init(id: publicIdentity.canonicalAddress, publicIdentity: publicIdentity)
    }
}
