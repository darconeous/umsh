import Foundation

/// How a route is put into words, wherever one is shown: the peer page's
/// strip, the Route screen, the Ping sheet, and the manual path editor.
enum RoutePresentation {
    /// A distance in hops: "1 hop", "3 hops". One transmission per leg, so
    /// one more than the repeaters a path names.
    static func hopsText(_ hops: Int, locale: Locale = .current) -> String {
        String(
            localized: "\(hops) hops",
            locale: locale,
            comment: "A route's length, counted in radio hops. Has plural variants."
        )
    }

    /// Repeaters a reply counted but did not name: "2 unnamed repeaters".
    static func unnamedRepeatersText(_ count: Int, locale: Locale = .current) -> String {
        String(
            localized: "\(count) unnamed repeaters",
            locale: locale,
            comment: "Repeaters a ping reply counted without identifying them. Has plural variants."
        )
    }

    /// A flood allowance as a row value: off, or how many hops.
    static func floodText(_ hops: UInt8, locale: Locale = .current) -> String {
        hops == 0
            ? String(localized: "Off", locale: locale, comment: "Flood allowance: the frame does not flood.")
            : hopsText(Int(hops), locale: locale)
    }

    /// The route in a word or two, for the peer page's strip: "Direct",
    /// "3 hops", "Flood", "Manual". `nil` is the moment before the first
    /// read resolves.
    static func briefText(_ route: PeerRoute?, locale: Locale = .current) -> String {
        guard let route else { return "…" }
        if route.isHeld {
            return String(localized: "Manual", locale: locale, comment: "Route kind: a path chosen by hand.")
        }
        switch route.kind {
        case .unavailable:
            return "—"
        case .unknown, .flood:
            return floodWord(locale)
        case .direct:
            return directWord(locale)
        case .source:
            if route.isDirect { return directWord(locale) }
            return hopsText(Int(route.hopCount ?? UInt8(route.hints.count + 1)), locale: locale)
        }
    }

    /// What kind of route the next frame takes, for the Route screen's
    /// Next send row.
    static func kindText(_ route: PeerRoute, locale: Locale = .current) -> String {
        if route.isHeld {
            if let flood = route.heldFloodFromStart {
                let hops = hopsText(Int(flood), locale: locale)
                return String(
                    localized: "Manual · Flood \(hops)",
                    locale: locale,
                    comment: "Route kind: a hand-chosen route that floods from the start. The placeholder is a hop count."
                )
            }
            return String(localized: "Manual", locale: locale, comment: "Route kind: a path chosen by hand.")
        }
        return switch route.kind {
        case .unavailable:
            String(localized: "Unavailable", locale: locale, comment: "Route kind: there is no radio to ask.")
        case .unknown:
            String(localized: "Not learned yet", locale: locale, comment: "Route kind: nothing learned, so the next send floods.")
        case .direct:
            directWord(locale)
        case .source:
            route.isDirect
                ? directWord(locale)
                : String(localized: "Source route", locale: locale, comment: "Route kind: the sender names each repeater.")
        case .flood:
            floodWord(locale)
        }
    }

    /// The hops a ping reply crossed: "Direct", "3 hops". `nil` when the
    /// reply did not say.
    static func replyHopsText(_ hopCount: UInt8?, locale: Locale = .current) -> String? {
        guard let hopCount else { return nil }
        return hopCount == 1 ? directWord(locale) : hopsText(Int(hopCount), locale: locale)
    }

    private static func directWord(_ locale: Locale) -> String {
        String(localized: "Direct", locale: locale, comment: "Route kind: in radio range, no repeaters.")
    }

    private static func floodWord(_ locale: Locale) -> String {
        String(localized: "Flood", locale: locale, comment: "Route kind: every repeater rebroadcasts the frame. A routing term, not water.")
    }
}
