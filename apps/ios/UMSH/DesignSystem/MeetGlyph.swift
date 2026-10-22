import SwiftUI

/// A device on Add Peer's Nearby, before anything is exchanged: its color
/// for this visit and the outline of what kind of device it is, never an
/// avatar, since nothing yet says whose it is.
struct MeetGlyph: View {
    /// The session color, as `0xRRGGBB`.
    let color: UInt32
    /// Its model id (`boards.json`, `platforms.json`).
    let model: UInt16
    var diameter: CGFloat = 44

    var body: some View {
        Circle()
            .fill(Color(rgb: color))
            .frame(width: diameter, height: diameter)
            .overlay {
                Image(systemName: MeetModels.bundled.symbol(model: model))
                    .font(.system(size: diameter * 0.46, weight: .semibold))
                    .foregroundStyle(.black.opacity(0.78))
            }
            .accessibilityHidden(true)
    }
}

/// How near a device seems, as the arcs of a signal lit from the inside
/// out: `nearness` of three.
struct MeetNearness: View {
    let nearness: UInt8

    var body: some View {
        Image(systemName: "wifi", variableValue: Double(nearness) / 3)
            .foregroundStyle(.tint)
            .accessibilityLabel(Text("Nearness \(nearness) of 3"))
    }
}

/// What devices call themselves by model id: the boards in `boards.json`
/// and the host platforms in `platforms.json`.
struct MeetModels: Sendable {
    private struct Platform: Decodable, Sendable {
        let modelID: UInt16
        let name: String
        let symbol: String

        enum CodingKeys: String, CodingKey {
            case modelID = "model_id", name, symbol
        }
    }

    private struct File: Decodable { let platforms: [Platform] }
    private let platforms: [UInt16: Platform]
    private let boards: RadioBoardCatalog

    init(platforms json: Data?, boards: RadioBoardCatalog) {
        let file = json.flatMap { try? JSONDecoder().decode(File.self, from: $0) }
        platforms = Dictionary(
            (file?.platforms ?? []).map { ($0.modelID, $0) },
            uniquingKeysWith: { first, _ in first }
        )
        self.boards = boards
    }

    /// What the interface calls `model`.
    func name(model: UInt16) -> String {
        platforms[model]?.name ?? boards.board(modelID: model)?.name ?? "Device"
    }

    /// The symbol a device of `model` is drawn with: its platform's, or a
    /// handheld radio's.
    func symbol(model: UInt16) -> String {
        platforms[model]?.symbol ?? "flipphone"
    }

    static let bundled: MeetModels = {
        let url = Bundle.main.url(forResource: "platforms", withExtension: "json")
        assert(url != nil, "platforms.json is missing from the bundle")
        return MeetModels(platforms: url.flatMap { try? Data(contentsOf: $0) }, boards: .bundled)
    }()
}

extension Color {
    /// A color given as `0xRRGGBB`.
    init(rgb: UInt32) {
        self.init(
            red: Double((rgb >> 16) & 0xFF) / 255,
            green: Double((rgb >> 8) & 0xFF) / 255,
            blue: Double(rgb & 0xFF) / 255
        )
    }
}
