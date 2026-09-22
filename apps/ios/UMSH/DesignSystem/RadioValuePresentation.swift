import Foundation

enum RadioValuePresentation {
    static func bandwidth(_ hertz: UInt32) -> String {
        let kilohertz = Double(hertz) / 1_000
        return "\(kilohertz.formatted(.number.precision(.fractionLength(0...2)))) kHz"
    }
}
