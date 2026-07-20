import Foundation
import UMSHMobileCore

actor RustMeshEngine: MeshEngine {
    private var localIdentity: MobileIdentity?
    private var mobileMeshSession: MobileMeshSession?
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
            return Self.preview(from: try UMSHMobileCore.inspectNodeUri(uri: uri))
        } catch is MobileError {
            throw MeshEngineError.invalidAddress
        } catch {
            throw MeshEngineError.coreFailure
        }
    }

    func inspectPeerIdentity(_ input: String) throws -> MeshNodeURIPreview {
        do {
            return Self.preview(from: try UMSHMobileCore.inspectPeerIdentity(input: input))
        } catch is MobileError {
            throw MeshEngineError.invalidAddress
        } catch {
            throw MeshEngineError.coreFailure
        }
    }

    func decodeNodeIdentity(address: String, payload: Data) throws -> MeshNodeIdentity {
        do {
            let record = try UMSHMobileCore.decodeNodeIdentity(address: address, payload: payload)
            return Self.identity(from: record)
        } catch MobileError.InvalidIdentityData {
            throw MeshEngineError.invalidIdentityData
        } catch is MobileError {
            throw MeshEngineError.invalidAddress
        } catch {
            throw MeshEngineError.coreFailure
        }
    }

    private static func preview(from record: NodeUriPreviewRecord) -> MeshNodeURIPreview {
        MeshNodeURIPreview(
            publicIdentity: MeshPublicIdentity(
                canonicalAddress: record.canonicalAddress,
                hint: MeshNodeHint(bytes: record.hint.bytes, text: record.hint.text)
            ),
            hasIdentityData: record.hasIdentityData,
            identity: record.identity.map(identity(from:)),
            identityPayload: record.identityPayload
        )
    }

    private static func identity(from record: NodeIdentityRecord) -> MeshNodeIdentity {
        MeshNodeIdentity(
            roleCode: record.roleCode,
            roleLabel: record.roleLabel,
            capabilities: record.capabilities,
            name: record.name,
            latitude: record.latitude,
            longitude: record.longitude,
            locationPrecision: record.locationPrecision,
            altitudeMeters: record.altitudeM,
            timestamp: record.timestamp,
            signature: {
                switch record.signature {
                case .unsigned: .unsigned
                case .valid: .valid
                case .invalid: .invalid
                }
            }()
        )
    }

    func unlockIdentity(secretKey: Data) throws -> MeshPublicIdentity {
        do {
            let identity = try MobileIdentity.unlock(secretKey: secretKey)
            let record = identity.publicIdentity()
            localIdentity = identity
            mobileMeshSession = nil
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

    func meshSession(fileManager: FileManager = .default) async throws -> MobileMeshSession? {
        guard let localIdentity else { return nil }
        if let mobileMeshSession { return mobileMeshSession }
        guard let applicationSupport = fileManager.urls(
            for: .applicationSupportDirectory,
            in: .userDomainMask
        ).first else {
            throw MeshEngineError.coreFailure
        }
        let root = applicationSupport
            .appendingPathComponent("UMSH", isDirectory: true)
            .appendingPathComponent("CounterReservations", isDirectory: true)
        do {
            let store = try MobileCounterStore(rootDirectory: root.path)
            let session = try await MobileMeshSession(identity: localIdentity, counterStore: store)
            mobileMeshSession = session
            return session
        } catch {
            throw MeshEngineError.coreFailure
        }
    }
}
