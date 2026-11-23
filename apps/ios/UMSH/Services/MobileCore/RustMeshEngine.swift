import Foundation
import UMSHMobileCore

actor RustMeshEngine: MeshEngine {
    /// The identity last unlocked, until the app core takes it to start.
    private var localIdentity: MobileIdentity?

    func renderRepeaterHint(_ bytes: Data) throws -> MeshRepeaterHint {
        do {
            let record = try UMSHMobileCore.renderRepeaterHint(bytes: bytes)
            return MeshRepeaterHint(bytes: record.bytes, text: record.text)
        } catch MobileError.InvalidRepeaterHintLength {
            throw MeshEngineError.invalidRepeaterHint
        } catch {
            throw MeshEngineError.coreFailure
        }
    }

    func parseRepeaterHintInput(_ text: String, format: RepeaterHintFormat) -> RepeaterHintInput {
        let coreFormat: UMSHMobileCore.RepeaterHintInputFormat = switch format {
        case .base58Prefix: .base58Prefix
        case .hex: .hex
        }
        let record = UMSHMobileCore.parseRepeaterHintInput(text: text, format: coreFormat)
        return RepeaterHintInput(
            candidates: record.candidates.map { MeshRepeaterHint(bytes: $0.bytes, text: $0.text) },
            problem: record.problem.map {
                switch $0 {
                case .tooShort: .tooShort
                case .tooLong: .tooLong
                case .invalidCharacter: .invalidCharacter
                case .outOfRange: .outOfRange
                }
            }
        )
    }

    func inspectPublicIdentity(_ address: String) throws -> MeshPublicIdentity {
        do {
            let record = try UMSHMobileCore.inspectPublicIdentity(address: address)
            return MeshPublicIdentity(
                canonicalAddress: record.canonicalAddress,
                hint: MeshNodeHint(bytes: record.hint.bytes, text: record.hint.text)
            )
        } catch let error as MobileError {
            throw Self.inputError(error)
        } catch {
            throw MeshEngineError.coreFailure
        }
    }

    func inspectPeerIdentity(_ input: String) throws -> MeshNodeURIPreview {
        do {
            return Self.preview(from: try UMSHMobileCore.inspectPeerIdentity(input: input), input: input)
        } catch let error as MobileError {
            throw Self.inputError(error)
        } catch {
            throw MeshEngineError.coreFailure
        }
    }

    func generateIdentitySecret() -> Data {
        UMSHMobileCore.generateIdentitySecret()
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

    /// Classify UniFFI's typed errors without treating every core failure as
    /// invalid user input. New Rust cases require an explicit Swift decision.
    static func inputError(_ error: MobileError, invalidURI: MeshEngineError = .invalidAddress) -> MeshEngineError {
        switch error {
        case .InvalidAddressLength, .InvalidAddressCharacter, .AddressOverflow,
             .InvalidPublicKeyLength: .invalidAddress
        case .InvalidUri: invalidURI
        case .InvalidIdentityData: .invalidIdentityData
        case .InvalidNodeHintLength: .invalidNodeHint
        case .InvalidRepeaterHintLength: .invalidRepeaterHint
        case .InvalidRegionCode: .invalidRegion
        case .ChannelNameNotAscii: .channelNameNotASCII
        case .ChannelNameTooLong: .channelNameTooLong
        case .InvalidSecretKeyLength, .InvalidChannelKeyLength, .InvalidUlcpFrame,
             .GattSegmentRunt, .GattSegmentReservedBits, .GattSegmentOrphan,
             .GattSegmentTooLong, .GattMtuTooSmall, .UlcpFrameUnparsable,
             .UlcpUnexpectedCommand, .UlcpMalformedPayload, .UlcpUnexpectedFrame,
             .UlcpMismatchedResponse, .AdministrativeSession, .UnsupportedCapability:
            .coreFailure
        }
    }

    static func channelPreview(from record: ChannelPreviewRecord) -> MeshChannelPreview {
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

    private static func preview(from record: NodeUriPreviewRecord, input: String) -> MeshNodeURIPreview {
        MeshNodeURIPreview(
            input: input,
            publicIdentity: MeshPublicIdentity(
                canonicalAddress: record.canonicalAddress,
                hint: MeshNodeHint(bytes: record.hint.bytes, text: record.hint.text)
            ),
            hasIdentityData: record.hasIdentityData,
            identity: record.identity.map(identity(from:)),
            identityPayload: record.identityPayload
        )
    }

    static func identity(from record: NodeIdentityRecord) -> MeshNodeIdentity {
        MeshNodeIdentity(
            roleCode: record.roleCode,
            capabilityBits: MeshNodeCapabilities(rawValue: record.capabilityBits),
            forwards: record.forwards,
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
            return MeshPublicIdentity(
                canonicalAddress: record.canonicalAddress,
                hint: MeshNodeHint(bytes: record.hint.bytes, text: record.hint.text)
            )
        } catch let error as MobileError {
            throw Self.inputError(error)
        } catch {
            throw MeshEngineError.coreFailure
        }
    }

    func lockIdentity() {
        localIdentity = nil
    }

    /// The identity last unlocked, handed out once: starting the app core
    /// consumes it, so each start unlocks again.
    func takeIdentity() -> MobileIdentity? {
        defer { localIdentity = nil }
        return localIdentity
    }
}
