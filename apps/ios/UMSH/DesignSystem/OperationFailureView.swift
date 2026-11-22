import SwiftUI
import UMSHMobileCore

/// A failure the person is told about once, with what failed and why.
struct FailureNotice: Equatable, Sendable {
    let title: String
    let message: String
}

extension FailureNotice {
    /// A command that did not happen: what was asked, then the core's reason.
    init(_ title: String, _ error: any Error) {
        self.init(title: title, message: MobileAppError.message(for: error))
    }
}

extension Binding where Value == FailureNotice? {
    /// Run `command`, setting a notice that says why when it does not
    /// happen. Reports whether it did.
    @MainActor
    @discardableResult
    func attempt(_ title: String, _ command: () async throws -> Void) async -> Bool {
        do {
            try await command()
            return true
        } catch {
            wrappedValue = FailureNotice(title, error)
            return false
        }
    }
}

extension View {
    /// Say `notice` in a dialog while it is set.
    func failureAlert(_ notice: Binding<FailureNotice?>) -> some View {
        alert(
            notice.wrappedValue?.title ?? "",
            isPresented: Binding(
                get: { notice.wrappedValue != nil },
                set: { if !$0 { notice.wrappedValue = nil } }
            ),
            presenting: notice.wrappedValue
        ) { _ in
            Button(role: .cancel) {} label: { Text("OK", comment: "Dismisses an alert.") }
        } message: { notice in
            Text(verbatim: notice.message)
        }
    }
}

/// Recovery stays next to the failed action. Callers supply the retry policy.
struct OperationFailureView: View {
    let error: AppOperationError
    let retry: () async -> Void
    @State private var isRetrying = false

    var body: some View {
        if error != .cancelled {
            VStack(alignment: .leading, spacing: 8) {
                Text(error.localizedDescription)
                    .foregroundStyle(Color(uiColor: .secondaryLabel))
                Button("Try Again") {
                    isRetrying = true
                }
                .disabled(isRetrying)
                .task(id: isRetrying) {
                    guard isRetrying else { return }
                    defer { isRetrying = false }
                    await retry()
                }
            }
            .font(.callout)
        }
    }
}
