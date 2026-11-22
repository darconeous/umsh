import SwiftUI

/// How an age is worded: in full for a label that has the room, or narrow
/// for a list's time column.
enum AgeStyle: Sendable {
    /// "just now", then "2 min. ago", "3 hr. ago", "4 days ago".
    case standard
    /// "now", then "2m ago", "3h ago", "4d ago".
    case compact
}

/// How long ago something happened, in the fewest words that stay true:
/// a word for the first minute, then whole minutes, hours, or days.
///
/// Seconds are never shown. A label that counts them is either wrong a
/// moment later or redrawing every second, and nobody acts on the
/// difference between three seconds and forty. An age a little below zero,
/// a stamp from a clock running ahead of this one, reads as the first
/// minute too, never as "in 0s".
enum AgePresentation {
    static func text(
        since: Date,
        now: Date = .now,
        style: AgeStyle = .standard,
        locale: Locale = .current
    ) -> String {
        let age = now.timeIntervalSince(since)
        guard age >= 60 else {
            return switch style {
            case .standard:
                String(localized: "just now", locale: locale, comment: "An age under a minute, such as when a node was last heard.")
            case .compact:
                String(localized: "now", locale: locale, comment: "An age under a minute in a list's time column.")
            }
        }
        // Whole units only, so the label reads the same however far into
        // the unit the moment is.
        let unit = unit(for: age)
        let floored = (age / unit).rounded(.down) * unit
        let format = Date.AnchoredRelativeFormatStyle(
            anchor: since,
            presentation: .numeric,
            unitsStyle: style == .compact ? .narrow : .abbreviated,
            locale: locale
        )
        return format.format(since.addingTimeInterval(floored))
    }

    /// When `text` next reads differently: the end of the first minute,
    /// then each new minute, hour, or day.
    static func nextChange(since: Date, after now: Date) -> Date {
        let age = now.timeIntervalSince(since)
        guard age >= 60 else { return since.addingTimeInterval(60) }
        let unit = unit(for: age)
        return since.addingTimeInterval(((age / unit).rounded(.down) + 1) * unit)
    }

    private static func unit(for age: TimeInterval) -> TimeInterval {
        switch age {
        case ..<3_600: 60
        case ..<86_400: 3_600
        default: 86_400
        }
    }
}

/// An age that keeps itself current, redrawing only when its words change.
struct AgeText: View {
    let since: Date
    var style: AgeStyle = .standard

    var body: some View {
        TimelineView(AgeSchedule(since: since)) { context in
            Text(verbatim: AgePresentation.text(since: since, now: context.date, style: style))
        }
    }
}

/// An age inside a sentence, on the same schedule as `AgeText`: the
/// sentence is the caller's format string, `AgeLabel(since: date) { age in
/// Text("heard \(age)") }`, so a translator sees it whole.
struct AgeLabel<Content: View>: View {
    let since: Date
    var style: AgeStyle = .standard
    @ViewBuilder let content: (String) -> Content

    var body: some View {
        TimelineView(AgeSchedule(since: since)) { context in
            content(AgePresentation.text(since: since, now: context.date, style: style))
        }
    }
}

/// The moments an age label changes, and no others.
private struct AgeSchedule: TimelineSchedule {
    let since: Date

    func entries(from startDate: Date, mode: TimelineScheduleMode) -> some Sequence<Date> {
        sequence(first: startDate) { AgePresentation.nextChange(since: since, after: $0) }
    }
}
