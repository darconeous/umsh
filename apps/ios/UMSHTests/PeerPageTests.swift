import Foundation
import Testing
import UMSHMobileCore
@testable import UMSH

private let english = Locale(identifier: "en_US")
private let german = Locale(identifier: "de_DE")

private func node(
    capabilities: MeshNodeCapabilities? = nil,
    role: PeerRole = .chat,
    systemRole: MobileStoredSystemRole? = nil
) -> PeerSummary {
    PeerSummary(
        id: 1,
        identity: MeshPublicIdentity(
            canonicalAddress: "Rm7qHU2XmNkfXVGRHxTmN4PkLhoRQMVqktxmuQWY8Jfy",
            hint: MeshNodeHint(bytes: Data([1, 2, 3]), text: "Rm7")
        ),
        alias: nil,
        advertisedName: nil,
        systemRole: systemRole,
        storedRole: role,
        advertisedIdentity: capabilities.map {
            MeshNodeIdentity(
                roleCode: role.roleCode ?? 0,
                capabilityBits: $0,
                forwards: $0.contains(.repeater),
                name: nil,
                latitude: nil,
                longitude: nil,
                locationPrecision: nil,
                altitudeMeters: nil,
                timestamp: nil,
                signature: .valid
            )
        }
    )
}

private let everything = PeerVerb.Availability(identify: true, message: true, ping: true, neighbors: true, manage: true)

private func hint(_ text: String, _ bytes: UInt8...) -> MeshRouterHint {
    MeshRouterHint(bytes: Data(bytes), text: text)
}

@Suite
struct PeerVerbTests {
    @Test func capabilitiesDecideTheVerbsNotTheRole() {
        // A chat device that also repeats gets Neighbors.
        #expect(
            PeerVerb.offered(for: node(capabilities: [.textMessages, .repeater], role: .chat), availability: everything)
                == [.message, .ping, .neighbors, .manage]
        )
        // A repeater that says nothing of text gets no Message.
        #expect(
            PeerVerb.offered(for: node(capabilities: [.repeater, .telemetry], role: .repeater), availability: everything)
                == [.ping, .neighbors, .manage]
        )
        #expect(
            PeerVerb.offered(for: node(capabilities: [.mobile, .textMessages]), availability: everything)
                == [.message, .ping, .manage]
        )
    }

    @Test func aNodeWithNoAdvertisementKeepsEveryVerbAndLeadsWithIdentify() {
        #expect(
            PeerVerb.offered(for: node(role: .unknown), availability: everything)
                == [.identify, .message, .ping, .neighbors, .manage]
        )
    }

    @Test func anAdvertisementNamingNoCapabilitiesRulesOutTheirVerbs() {
        #expect(
            PeerVerb.offered(for: node(capabilities: []), availability: everything)
                == [.ping, .manage]
        )
    }

    @Test func theCompanionRadioOffersPingAndManageAlone() {
        #expect(
            PeerVerb.offered(for: node(systemRole: .companionRadio), availability: everything)
                == [.ping, .manage]
        )
    }

    @Test func nothingWiredMeansNoTiles() {
        #expect(PeerVerb.offered(for: node(), availability: PeerVerb.Availability()).isEmpty)
    }
}

@Suite
struct PingPathTests {
    private func reply(
        hopCount: UInt8?,
        unnamed: UInt8?,
        hints: [MeshRouterHint] = [],
        trace: [MeshLegSignal] = [],
        rssi: Int16? = -97,
        snr: Int16? = 65
    ) -> PeerPingReply {
        PeerPingReply(
            roundTripMilliseconds: 1_400,
            hopCount: hopCount,
            routeHints: hints,
            traceSignal: trace,
            rssiDBm: rssi,
            signalToNoiseCentibels: snr,
            linkQuality: nil,
            viaRouteRetry: false,
            unnamedHops: unnamed
        )
    }

    @Test func aDirectReplyIsOneLegWithThePhonesReading() {
        let path = PingPath(reply: reply(hopCount: 1, unnamed: 0))
        #expect(path.stops == [.phone, .peer])
        #expect(path.legs == [.reading(MeshLegSignal(rssiDBm: -97, signalToNoiseCentibels: 65))])
    }

    @Test func eachLegAfterTheFirstIsTheNearRepeatersReading() {
        let near = hint("BtC", 0x01, 0x02)
        let far = hint("7N*", 0x03, 0x04)
        let first = MeshLegSignal(rssiDBm: -108, signalToNoiseCentibels: -25)
        let second = MeshLegSignal(rssiDBm: -92, signalToNoiseCentibels: 80)
        let path = PingPath(reply: reply(hopCount: 3, unnamed: 0, hints: [near, far], trace: [first, second]))
        #expect(path.stops == [.phone, .repeater(near, preceding: []), .repeater(far, preceding: [near]), .peer])
        #expect(path.legs == [
            .reading(MeshLegSignal(rssiDBm: -97, signalToNoiseCentibels: 65)),
            .reading(first),
            .reading(second),
        ])
    }

    @Test func aBridgedHopKeepsItsEmptyReading() {
        let bridge = hint("Br1", 0x05, 0x06)
        let bridged = MeshLegSignal(rssiDBm: nil, signalToNoiseCentibels: nil)
        let path = PingPath(reply: reply(hopCount: 2, unnamed: 0, hints: [bridge], trace: [bridged]))
        #expect(path.legs.last == .reading(bridged))
    }

    @Test func repeatersCountedButNotNamedAreOneDashedStretch() {
        let path = PingPath(reply: reply(hopCount: 3, unnamed: 2))
        #expect(path.stops == [.phone, .peer])
        #expect(path.legs == [.unnamed(count: 2)])
    }

    @Test func aReplyWithNoHopCountEndsInAnUnknownStretch() {
        let path = PingPath(reply: reply(hopCount: nil, unnamed: nil))
        #expect(path.stops == [.phone, .peer])
        #expect(path.legs == [.unknown])

        let near = hint("BtC", 0x01, 0x02)
        let first = MeshLegSignal(rssiDBm: -108, signalToNoiseCentibels: -25)
        let partial = PingPath(reply: reply(hopCount: nil, unnamed: nil, hints: [near], trace: [first]))
        #expect(partial.stops == [.phone, .repeater(near, preceding: []), .peer])
        #expect(partial.legs == [
            .reading(MeshLegSignal(rssiDBm: -97, signalToNoiseCentibels: 65)),
            .unknown,
        ])
    }

    @Test func noAnswerBreaksTheLine() {
        #expect(PingPath(unanswered: true).legs == [.broken])
        #expect(PingPath(unanswered: false).legs == [.pending])
    }
}

@Suite
struct RouteLegTests {
    @Test func aSourceRouteNumbersItsLegs() {
        let route = PeerRoute(
            kind: .source,
            hints: [hint("BtC", 1, 2), hint("7N*", 3, 4)],
            hopCount: 3,
            floodHops: nil,
            floodRegions: []
        )
        #expect(RouteScreen.legs(for: route) == [.numbered(1), .numbered(2), .numbered(3)])
    }

    @Test func aFloodRouteIsOneDashedStretch() {
        let route = PeerRoute(kind: .flood, hints: [], hopCount: 3, floodHops: 2, floodRegions: [])
        #expect(RouteScreen.legs(for: route) == [.unnamed(count: 2)])
        #expect(RouteScreen.legs(for: .unknown) == [.pending])
    }
}

@Suite
struct SolicitVantageTests {
    /// The route's one repeater.
    private let routeHint = RouterHintRecord(bytes: Data([5, 6]), text: "BtC")
    /// The peer's router hint: the first two bytes of its key, as the core
    /// derives it.
    private let peerHint = RouterHintRecord(bytes: Data([1, 2]), text: "Rm7")

    private func route(_ vantage: MobileAppDiscoveryVantageRecord?) -> PeerRoute {
        PeerRoute(MobileAppRouteRecord(
            kind: .source,
            hints: [routeHint],
            hopCount: 2,
            floodHops: nil,
            floodRegions: [],
            holdRemainingMs: nil,
            holdFloodHops: nil,
            fallbackAcks: 0,
            confirmedAgeMs: nil,
            candidate: nil,
            discoveryVantage: vantage
        ))
    }

    @Test func anAskThatStopsShortNamesWhereItLands() throws {
        // The core sends the route's hints alone when the peer is not known
        // to repeat.
        let stops = route(MobileAppDiscoveryVantageRecord(
            repeaters: [routeHint],
            landsAtPeer: false,
            evidence: .unknown
        ))
        let vantage = try #require(SolicitVantage(peer: node(), vantage: stops.discoveryVantage))
        #expect(vantage.repeaters == [Data([5, 6])])
        #expect(vantage.landingRepeater == hint("BtC", 5, 6))
        #expect(!vantage.landsAtPeer)
        #expect(vantage.evidence == .unknown)
        #expect(vantage.peerAddress == node().identity.canonicalAddress)
    }

    @Test func anAskAimedAtThePeerHasNoLandingRepeater() throws {
        // The core sends the route's hints and then the peer's own.
        let lands = route(MobileAppDiscoveryVantageRecord(
            repeaters: [routeHint, peerHint],
            landsAtPeer: true,
            evidence: .yes
        ))
        let vantage = try #require(SolicitVantage(peer: node(), vantage: lands.discoveryVantage))
        #expect(vantage.repeaters == [Data([5, 6]), node().identity.hint.bytes.prefix(2)])
        #expect(vantage.landingRepeater == nil)
        #expect(vantage.landsAtPeer)
        #expect(vantage.evidence == .yes)
    }

    @Test func aRepeaterAtTheEndOfAFullPathStopsOneShort() throws {
        // A peer known to repeat whose route already holds 15 hints: the
        // core cannot add the peer's own, so the ask lands one short.
        let hints = (0..<15).map { RouterHintRecord(bytes: Data([0x10, UInt8($0)]), text: "h\($0)") }
        let full = route(MobileAppDiscoveryVantageRecord(
            repeaters: hints,
            landsAtPeer: false,
            evidence: .yes
        ))
        let vantage = try #require(SolicitVantage(peer: node(), vantage: full.discoveryVantage))
        #expect(vantage.repeaters.count == 15)
        #expect(vantage.landingRepeater == hint("h14", 0x10, 14))
        #expect(!vantage.landsAtPeer)
        #expect(vantage.evidence == .yes)
    }

    @Test func noVantageFromTheCoreOffersNoAsk() {
        #expect(SolicitVantage(peer: node(), vantage: route(nil).discoveryVantage) == nil)
        #expect(SolicitVantage(peer: node(), vantage: PeerRoute.unknown.discoveryVantage) == nil)
    }
}

@Suite
struct PresentationTests {
    @Test func addressesAreGroupedInFours() {
        let grouped = CanonicalAddressView.grouped("Rm7qHU2XmNkfXVGRHxTmN4PkLhoRQMVqktxmuQWY8Jfy")
        #expect(grouped == "Rm7q HU2X mNkf XVGR HxTm N4Pk LhoR QMVq ktxm uQWY 8Jfy")
        #expect(grouped.replacingOccurrences(of: " ", with: "") == "Rm7qHU2XmNkfXVGRHxTmN4PkLhoRQMVqktxmuQWY8Jfy")
    }

    @Test func signalReadingsFollowTheLocale() {
        #expect(
            SignalPresentation.readingText(rssiDBm: -97, snrCentibels: 65, locale: english)
                == "-97 dBm · SNR 6.5 dB"
        )
        #expect(SignalPresentation.snrText(6.5, locale: german) == "SNR 6,5 dB")
        #expect(SignalPresentation.readingText(rssiDBm: nil, snrCentibels: nil, locale: english) == nil)
    }

    @Test func signalBarsFollowSignalToNoise() {
        #expect(SignalPresentation.bars(rssiDBm: -97, snrDecibels: 6.5) == 3)
        #expect(SignalPresentation.bars(rssiDBm: -108, snrDecibels: -2.5) == 1)
        #expect(SignalPresentation.bars(rssiDBm: -85, snrDecibels: nil) == 4)
        #expect(SignalPresentation.bars(rssiDBm: nil, snrDecibels: nil) == nil)
    }

    @Test func hopCountsArePluralized() {
        #expect(RoutePresentation.hopsText(1, locale: english) == "1 hop")
        #expect(RoutePresentation.hopsText(3, locale: english) == "3 hops")
        #expect(RoutePresentation.replyHopsText(1, locale: english) == "Direct")
        #expect(RoutePresentation.replyHopsText(nil, locale: english) == nil)
    }

    @Test func routeBriefsStayShort() {
        let source = PeerRoute(kind: .source, hints: [hint("BtC", 1, 2)], hopCount: 2, floodHops: nil, floodRegions: [])
        #expect(RoutePresentation.briefText(source, locale: english) == "2 hops")
        #expect(RoutePresentation.briefText(.unknown, locale: english) == "Flood")
        #expect(RoutePresentation.briefText(.unavailable, locale: english) == "—")
        var held = source
        held.holdUntil = .now.addingTimeInterval(60)
        #expect(RoutePresentation.briefText(held, locale: english) == "Manual")
    }

    @Test func discoverWaitsRoundUpToWholeSeconds() {
        func footer(_ wait: Duration, askedHere: Bool = false) -> String? {
            DiscoverPeersView.waitFooter(wait: wait, askedHere: askedHere, locale: english)
        }
        #expect(footer(.zero) == nil)
        #expect(footer(.milliseconds(200)) == "Ask again in 1 sec.")
        #expect(footer(.seconds(40)) == "Ask again in 40 sec.")
        #expect(footer(.milliseconds(39_001)) == "Ask again in 40 sec.")
        #expect(footer(.seconds(40), askedHere: true) == "Asked—replies appear below. Ask again in 40 sec.")
    }

    @Test func cellSizesUseTheLocalesNumbers() {
        #expect(LocationPresentation.cellSizeText(meters: 611, locale: english) == "611 m")
        #expect(LocationPresentation.cellSizeText(meters: 4.5, locale: german) == "4,5 m")
        #expect(LocationPresentation.cellSizeText(meters: 9_800, locale: english) == "9.8 km")
        #expect(LocationPresentation.cellSizeText(meters: 2_505_000, locale: english) == "2,505 km")
        #expect(LocationPresentation.cellSizeText(meters: 0.15, locale: english) == "15 cm")
    }

    @Test func agesSayJustNowThenWholeUnits() {
        let since = Date(timeIntervalSinceReferenceDate: 0)
        func age(_ seconds: TimeInterval) -> String {
            AgePresentation.text(since: since, now: since.addingTimeInterval(seconds), locale: english)
        }
        #expect(age(3) == "just now")
        #expect(age(59) == "just now")
        // The system words the units, and its wording differs between iOS
        // releases, so what is checked is that an age rounds down to a
        // whole unit.
        #expect(age(179) == age(120))
        #expect(age(179) != age(180))
        #expect(age(3 * 3_600 + 59 * 60) == age(3 * 3_600))
        #expect(age(3 * 3_600 + 59 * 60) != age(4 * 3_600))
        // A clock a little behind the node's still reads as now.
        #expect(age(-5) == "just now")
    }

    @Test func compactAgesSayNowThenNarrowWholeUnits() {
        let since = Date(timeIntervalSinceReferenceDate: 0)
        func age(_ seconds: TimeInterval, _ style: AgeStyle = .compact) -> String {
            AgePresentation.text(since: since, now: since.addingTimeInterval(seconds), style: style, locale: english)
        }
        #expect(age(0) == "now")
        #expect(age(59) == "now")
        // A stamp a hair ahead of this phone's clock: never "in 0s".
        #expect(age(-0.4) == "now")
        #expect(age(-30) == "now")
        #expect(age(3_600) == "1h ago")
        #expect(age(3_600 + 59 * 60) == age(3_600))
        #expect(age(3_600) != age(3_600, .standard))
    }

    @Test func agesRedrawOnlyWhenTheirWordsChange() {
        let since = Date(timeIntervalSinceReferenceDate: 0)
        func next(_ seconds: TimeInterval) -> TimeInterval {
            AgePresentation.nextChange(since: since, after: since.addingTimeInterval(seconds))
                .timeIntervalSince(since)
        }
        #expect(next(3) == 60)
        #expect(next(60) == 120)
        #expect(next(150) == 180)
        #expect(next(3_600) == 7_200)
        #expect(next(90_000) == 172_800)
    }

    @Test func bearingsRunClockwiseFromNorth() {
        let east = LocationPresentation.bearingDegrees(fromLatitude: 0, longitude: 0, toLatitude: 0, longitude: 1)
        let north = LocationPresentation.bearingDegrees(fromLatitude: 0, longitude: 0, toLatitude: 1, longitude: 0)
        let southwest = LocationPresentation.bearingDegrees(fromLatitude: 1, longitude: 1, toLatitude: 0, longitude: 0)
        #expect(abs(east - 90) < 0.01)
        #expect(abs(north) < 0.01)
        #expect(abs(southwest - 225) < 0.1)
        #expect(LocationPresentation.compassText(degrees: 44, locale: english) == "northeast")
        #expect(LocationPresentation.compassText(degrees: 350, locale: english) == "north")
    }
}

@Suite
struct CoreLimitsTests {
    @Test func settingsNeverStoredStartAtTheCoresValues() {
        let limits = mobileLimits()
        #expect(CoreLimits.current == limits)
        #expect(CoreLimits.floodHops(stored: nil) == limits.recommendedFloodHops)
        #expect(CoreLimits.beaconFloodHops(stored: nil) == limits.recommendedBeaconFloodHops)
        #expect(CoreLimits.locationPrecision(stored: nil) == limits.defaultLocationPrecision)
    }

    @Test func storedSettingsAreKeptAndUnusableOnesStartOver() {
        let limits = mobileLimits()
        #expect(CoreLimits.floodHops(stored: 12) == 12)
        #expect(CoreLimits.beaconFloodHops(stored: 0) == 0)
        #expect(CoreLimits.locationPrecision(stored: 3) == 3)
        #expect(CoreLimits.floodHops(stored: -1) == limits.recommendedFloodHops)
        #expect(CoreLimits.beaconFloodHops(stored: 256) == limits.recommendedBeaconFloodHops)
    }

    @Test func intervalPickersOfferTheCoresChoicesInsideItsRange() {
        let limits = mobileLimits()
        #expect(advertisementIntervalChoices == limits.advertIntervalChoicesS)
        #expect(beaconIntervalChoices == limits.beaconIntervalChoicesS)
        for seconds in advertisementIntervalChoices + beaconIntervalChoices where seconds != 0 {
            #expect((limits.minAnnounceIntervalS...limits.maxAnnounceIntervalS).contains(seconds))
        }
        #expect(formattedAnnouncementInterval(0, locale: english) == "Off")
        #expect(formattedAnnouncementInterval(4 * 3_600, locale: english) == "Every 4 hours")
        #expect(formattedAnnouncementInterval(1_200, locale: english) == "Every 20 minutes")
    }
}
