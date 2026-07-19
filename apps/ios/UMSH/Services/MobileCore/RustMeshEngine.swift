import Foundation
import UMSHMobileCore

actor RustMeshEngine: MeshEngine {
    private var localIdentity: MobileIdentity?
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

    func inspectNodeURI(_ uri: String) throws -> MeshNodeURIPreview {
        do {
            let record = try UMSHMobileCore.inspectNodeUri(uri: uri)
            return MeshNodeURIPreview(
                publicIdentity: MeshPublicIdentity(
                    canonicalAddress: record.canonicalAddress,
                    hint: MeshNodeHint(bytes: record.hint.bytes, text: record.hint.text)
                ),
                hasIdentityData: record.hasIdentityData
            )
        } catch is MobileError {
            throw MeshEngineError.invalidAddress
        } catch {
            throw MeshEngineError.coreFailure
        }
    }

    func unlockIdentity(secretKey: Data) throws -> MeshPublicIdentity {
        do {
            let identity = try MobileIdentity.unlock(secretKey: secretKey)
            let record = identity.publicIdentity()
            localIdentity = identity
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
