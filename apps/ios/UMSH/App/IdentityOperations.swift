import Foundation

/// Decides which identity may be used. The runtime owns bootstrap and the
/// transport; this collaborator owns vault and persistence decisions.
struct IdentityOperations: Sendable {
    enum Resolution: Equatable, Sendable {
        case ready(LocalIdentitySnapshot, minted: Bool)
        case needsAdoption(LocalIdentitySnapshot)
    }

    let vault: any IdentityVault
    let knowsIdentity: @Sendable (LocalIdentitySnapshot) async throws -> Bool
    let persistName: @Sendable (String, String?) async throws -> Void

    func load() async throws -> Resolution {
        try Task.checkCancellation()
        switch try await vault.storedIdentity() {
        case let .present(identity):
            return .ready(identity, minted: false)
        case .none:
            try Task.checkCancellation()
            return .ready(try await vault.createIdentity(), minted: true)
        case let .orphaned(identity):
            // A failed database read is not evidence of an empty installation.
            guard try await knowsIdentity(identity) else { return .needsAdoption(identity) }
            try Task.checkCancellation()
            return .ready(try await vault.adoptStoredIdentity(), minted: false)
        }
    }

    func saveName(_ name: String, owner: String) async throws -> String {
        try Task.checkCancellation()
        let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
        do { try await persistName(owner, trimmed.isEmpty ? nil : trimmed) }
        catch { throw AppOperationError.storage(error) }
        return trimmed
    }
}
