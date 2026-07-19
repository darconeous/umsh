import Foundation
import UMSHMobileCore

actor RustMeshEngine: MeshEngine {
    func renderNodeHint(_ bytes: Data) throws -> MeshNodeHint {
        do {
            let record = try UMSHMobileCore.renderNodeHint(bytes: bytes)
            return MeshNodeHint(bytes: record.bytes, text: record.text)
        } catch MobileError.InvalidNodeHintLength {
            throw MeshEngineError.invalidNodeHint
        } catch {
            throw MeshEngineError.coreFailure
        }
    }

    func inspectPublicIdentity(_ address: String) throws -> MeshPublicIdentity {
        do {
            let record = try UMSHMobileCore.inspectPublicIdentity(address: address)
            return MeshPublicIdentity(
                canonicalAddress: record.canonicalAddress,
                hint: MeshNodeHint(bytes: record.hint.bytes, text: record.hint.text)
            )
        } catch is MobileError {
            throw MeshEngineError.invalidAddress
        } catch {
            throw MeshEngineError.coreFailure
        }
    }

    func derivePublicIdentity(secretKey: Data) throws -> MeshPublicIdentity {
        do {
            let record = try UMSHMobileCore.derivePublicIdentity(secretKey: secretKey)
            return MeshPublicIdentity(
                canonicalAddress: record.canonicalAddress,
                hint: MeshNodeHint(bytes: record.hint.bytes, text: record.hint.text)
            )
        } catch is MobileError {
            throw MeshEngineError.invalidAddress
        } catch {
            throw MeshEngineError.coreFailure
        }
    }
}
