import Foundation

@main
struct RadioHostStateSmokeTest {
    static func main() {
        let phone = Data(repeating: 1, count: 32)
        let other = Data(repeating: 2, count: 32)

        precondition(RadioHostState.classify(radioKey: Data(), selectedHostKey: phone) == .unclaimed)
        precondition(RadioHostState.classify(radioKey: phone, selectedHostKey: phone) == .matchesCurrentIdentity)
        precondition(RadioHostState.classify(radioKey: other, selectedHostKey: phone) == .belongsToAnotherIdentity)
        precondition(RadioHostState.classify(radioKey: phone, selectedHostKey: nil) == .localIdentityUnavailable)

        print("Radio host ownership classifier passed")
    }
}
