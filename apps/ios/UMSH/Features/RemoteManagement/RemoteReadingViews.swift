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

/// What the device is being asked, or what went wrong last, pinned above
/// every management screen's content.
///
/// Above rather than in the form: a form's last section is below the fold
/// on any screen worth managing, and a failure there goes unseen.
struct ManagementStatusBar: View {
    let model: ManageDeviceModel

    var body: some View {
        if model.isBusy {
            bar {
                ProgressView()
                Text("Waiting for the device…", comment: "Managing a node: a request is outstanding.")
                    .frame(maxWidth: .infinity, alignment: .leading)
                Button {
                    model.cancel()
                } label: {
                    Text("Cancel", comment: "Stops waiting on a request to a managed node.")
                }
                .accessibilityIdentifier("manage.cancel")
            }
        } else if let problem = model.problem {
            bar {
                Image(systemName: "exclamationmark.triangle.fill")
                    .foregroundStyle(.red)
                Text(verbatim: problem)
                    .frame(maxWidth: .infinity, alignment: .leading)
                Button {
                    model.problem = nil
                } label: {
                    Image(systemName: "xmark")
                }
                .accessibilityLabel(Text("Dismiss", comment: "VoiceOver label: hides a management error."))
                .accessibilityIdentifier("manage.dismissProblem")
            }
        }
    }

    private func bar(@ViewBuilder _ content: () -> some View) -> some View {
        HStack(spacing: 12) { content() }
            .font(.callout)
            .padding(.horizontal)
            .padding(.vertical, 10)
            .background(.bar)
    }
}

extension View {
    /// Pin the device's status above this screen.
    func managementStatus(_ model: ManageDeviceModel) -> some View {
        safeAreaInset(edge: .top, spacing: 0) {
            ManagementStatusBar(model: model)
        }
    }
}
