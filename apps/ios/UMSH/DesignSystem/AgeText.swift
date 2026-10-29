import SwiftUI

/// How long ago something happened, in the fewest words that stay true:
/// "just now" for the first minute, then "2 min. ago", "3 hr. ago",
/// "4 days ago".
///
/// Seconds are never shown. A label that counts them is either wrong a
/// moment later or redrawing every second, and nobody acts on the
/// difference between three seconds and forty.
enum AgePresentation {
    static func text(since: Date, now: Date = .now, locale: Locale = .current) -> String {
        let age = now.timeIntervalSince(since)
        guard age >= 60 else {
            return String(localized: "just now", locale: locale, comment: "An age under a minute, such as when a node was last heard.")
        }
        let formatter = RelativeDateTimeFormatter()
        formatter.locale = locale
        formatter.unitsStyle = .abbreviated
        formatter.dateTimeStyle = .numeric
        // Whole units only, so the label reads the same however far into
        // the unit the moment is.
        let unit = unit(for: age)
        return formatter.localizedString(fromTimeInterval: -(age / unit).rounded(.down) * unit)
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

    var body: some View {
        TimelineView(AgeSchedule(since: since)) { context in
            Text(verbatim: AgePresentation.text(since: since, now: context.date))
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
