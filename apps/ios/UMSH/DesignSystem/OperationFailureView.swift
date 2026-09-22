import SwiftUI

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
