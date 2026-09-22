import SwiftUI

/// What a screen is showing and how old it is.
///
/// Every category screen carries one: values prefilled from the cache are
/// the device as it was last seen, and presenting that as current is the
/// one thing a design built on caching must not do.
struct RemoteReadingFooter: View {
    let asOf: Date?
    let isFresh: Bool
    let isBusy: Bool
    /// What is being asked, as the sentences name it.
    var subject = "the device"

    init(reading: RemoteCategoryReading?, isBusy: Bool) {
        asOf = reading?.asOf
        isFresh = reading?.isFresh == true
        self.isBusy = isBusy
    }

    /// The same footer for a reading that is not a property category—a
    /// router's neighbor listing, say—so every cached screen dates itself
    /// in the same words.
    init(asOf: Date?, isFresh: Bool, isBusy: Bool, subject: String) {
        self.asOf = asOf
        self.isFresh = isFresh
        self.isBusy = isBusy
        self.subject = subject
    }

    var body: some View {
        if isBusy {
            Text("Asking \(subject)…")
        } else if let asOf {
            Text(
                isFresh
                    ? "Read from \(subject) just now."
                    : "Last read \(asOf.formatted(.relative(presentation: .named)))."
            )
        } else {
            Text("Nothing read yet. Tap Refresh to ask \(subject).")
        }
    }
}

/// The last failure, where every category screen puts it.
struct RemoteProblemSection: View {
    let model: ManageDeviceModel

    var body: some View {
        if let problem = model.problem {
            Section { Text(problem).foregroundStyle(.red) }
        }
    }
}
