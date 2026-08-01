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

    func renderRouterHint(_ bytes: Data) throws -> MeshRouterHint {
        do {
            let record = try UMSHMobileCore.renderRouterHint(bytes: bytes)
            return MeshRouterHint(bytes: record.bytes, text: record.text)
        } catch MobileError.InvalidRouterHintLength {
            throw MeshEngineError.invalidRouterHint
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

    func inspectChannelURI(_ uri: String) throws -> MeshChannelPreview {
        do {
            return Self.channelPreview(from: try UMSHMobileCore.inspectChannelUri(uri: uri))
        } catch is MobileError {
            throw MeshEngineError.invalidChannelURI
        } catch {
            throw MeshEngineError.coreFailure
        }
    }

    func inspectChannelName(_ name: String) throws -> MeshChannelPreview {
        do {
            return Self.channelPreview(from: try UMSHMobileCore.inspectChannelName(name: name))
        } catch MobileError.ChannelNameNotAscii {
            throw MeshEngineError.channelNameNotASCII
        } catch MobileError.ChannelNameTooLong {
            throw MeshEngineError.channelNameTooLong
        } catch {
            throw MeshEngineError.coreFailure
        }
    }

    func generateChannelKey() -> Data {
        UMSHMobileCore.generateChannelKey()
    }

    func deriveChannelID(key: Data) throws -> Data {
        do {
            return try UMSHMobileCore.deriveChannelId(key: key)
        } catch {
            throw MeshEngineError.coreFailure
        }
    }

    func channelConversationAddress(key: Data) throws -> String {
        do {
            return try UMSHMobileCore.channelConversationAddress(key: key)
        } catch {
            throw MeshEngineError.coreFailure
        }
    }

    func deriveChannelTint(key: Data) throws -> Data {
        do {
            return try UMSHMobileCore.deriveChannelTint(key: key)
        } catch {
            throw MeshEngineError.coreFailure
        }
    }

    func formatChannelInvitation(
        key: Data,
        name: String?,
        displayName: String?,
        maxFloodHops: UInt8?,
        regionCode: Data?
    ) throws -> String {
        do {
            return try UMSHMobileCore.formatChannelInvitation(
                key: key,
                name: name,
                displayName: displayName,
                maxFloodHops: maxFloodHops,
                region: regionCode
            )
        } catch {
            throw MeshEngineError.coreFailure
        }
    }

    func regionCode(from text: String) throws -> Data {
        do {
            return try UMSHMobileCore.regionCodeFromString(text: text)
        } catch {
            throw MeshEngineError.invalidRegion
        }
    }

    func regionDescription(_ code: Data) throws -> String {
        do {
            return try UMSHMobileCore.regionCodeDescription(code: code)
        } catch {
            throw MeshEngineError.invalidRegion
        }
    }

    private static func channelPreview(from record: ChannelPreviewRecord) -> MeshChannelPreview {
        MeshChannelPreview(
            kind: {
                switch record.kind {
                case .namedPublic: .namedPublic
                case .privateKey: .privateKey
                }
            }(),
            canonicalName: record.canonicalName,
            key: record.key,
            channelID: record.channelId,
            tint: record.tint,
            displayName: record.displayName,
            maxFloodHops: record.maxFloodHops,
            regionCode: record.region
        )
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
