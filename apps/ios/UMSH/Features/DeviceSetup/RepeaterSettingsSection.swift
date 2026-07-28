import SwiftUI
import UMSHMobileCore

/// Presentation for a 2-byte routing-domain region code.
///
/// A code that decodes to three letters came from an airport code and is
/// shown as such; anything else has no recoverable text form and is shown
/// as its raw hex. Both forms carry the hex, because the hex is what the
/// operator will see in a packet capture or on another node.
enum RegionCodeText {
    /// `SJC (0x7853)`, or `0xDF6F` for a derived code.
    static func label(_ code: Data) -> String {
        let hex = self.hex(code)
        guard let description = try? regionCodeDescription(code: code),
              description != hex else { return hex }
        return "\(description) (\(hex))"
    }

    static func hex(_ code: Data) -> String {
        "0x" + code.map { String(format: "%02X", $0) }.joined()
    }
}

/// The repeater forwarding policy for one device.
///
/// Routing regions are not RF settings. A region scopes which floods this
/// device is willing to relay; the frequency and modulation live in the
/// radio section and are a separate question entirely. The wording here
/// keeps that line visible, because conflating them produces a repeater
/// that is silent for reasons nobody can find.
struct RepeaterSettingsSection: View {
    @Binding var enabled: Bool
    @Binding var regions: [Data]
    @Binding var defaultRegion: Data?
    @Binding var minRssiDBm: Int16?
    @Binding var minSnrDB: Int8?

    @State private var regionInput = ""
    @State private var regionProblem: String?

    var body: some View {
        Section {
            Toggle("Forward other nodes' traffic", isOn: $enabled)
        } header: {
            Text("Repeater")
        } footer: {
            Text(enabled
                 ? "This device relays floods it hears, subject to the limits below."
                 : "This device carries only its own traffic and advertises no forwarding role.")
        }

        if enabled {
            Section {
                ForEach(regions, id: \.self) { region in
                    Text(RegionCodeText.label(region))
                        .font(.body.monospaced())
                }
                .onDelete { offsets in
                    let removed = offsets.map { regions[$0] }
                    regions.remove(atOffsets: offsets)
                    if let defaultRegion, removed.contains(defaultRegion) {
                        self.defaultRegion = nil
                    }
                }
                HStack {
                    TextField("Airport code, name, or 0x1234", text: $regionInput)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .onSubmit { addRegion() }
                    Button("Add", action: addRegion)
                        .disabled(regionInput.trimmingCharacters(in: .whitespaces).isEmpty)
                }
            } header: {
                Text("Routing regions")
            } footer: {
                if let regionProblem {
                    Text(regionProblem).foregroundStyle(.red)
                } else if regions.isEmpty {
                    Text("With no regions listed, this device forwards traffic from every region. Add regions to relay only for a named area — a three-letter airport code such as SJC, a region name your mesh has agreed on, or a raw code. This is a routing domain, not a radio band.")
                } else {
                    Text("Only floods tagged with one of these regions, or carrying no region at all, are relayed. This is a routing domain, not a radio band.")
                }
            }

            Section {
                Picker("Tag untagged traffic", selection: defaultRegionSelection) {
                    Text("None — don't tag").tag(Data?.none)
                    ForEach(regions, id: \.self) { region in
                        Text(RegionCodeText.label(region)).tag(Data?.some(region))
                    }
                }
                .disabled(regions.isEmpty)
            } footer: {
                Text(regions.isEmpty
                     ? "Add a routing region to be able to tag traffic that arrives without one."
                     : "Floods that arrive with no region are relayed carrying this one, which scopes how much further they travel. Traffic that already carries a region keeps it.")
            }

            Section {
                Picker("Minimum signal", selection: $minRssiDBm) {
                    Text("Off").tag(Int16?.none)
                    ForEach(rssiChoices, id: \.self) { value in
                        Text("\(value) dBm").tag(Int16?.some(value))
                    }
                }
                Picker("Minimum quality", selection: $minSnrDB) {
                    Text("Off").tag(Int8?.none)
                    ForEach(snrChoices, id: \.self) { value in
                        Text("\(value) dB").tag(Int8?.some(value))
                    }
                }
            } header: {
                Text("Forwarding thresholds")
            } footer: {
                Text("Frames heard below a threshold are not relayed. Raising them keeps a repeater from amplifying signals too weak to be worth repeating; leaving them off relays everything it can decode.")
            }
        }
    }

    private var defaultRegionSelection: Binding<Data?> {
        Binding(
            get: {
                // A default outside the list would be written verbatim and
                // is a configuration the device does not cross-check, so
                // the picker refuses to show a selection it cannot offer.
                guard let defaultRegion, regions.contains(defaultRegion) else { return nil }
                return defaultRegion
            },
            set: { defaultRegion = $0 }
        )
    }

    private var rssiChoices: [Int16] {
        stride(from: Int16(-130), through: Int16(-60), by: 5).map { $0 }
    }

    private var snrChoices: [Int8] {
        stride(from: Int8(-20), through: Int8(10), by: 2).map { $0 }
    }

    private func addRegion() {
        let text = regionInput.trimmingCharacters(in: .whitespaces)
        guard !text.isEmpty else { return }
        guard let code = try? regionCodeFromString(text: text) else {
            regionProblem = "That is not a region code. Use a three-letter airport code, a region name, or 0x followed by up to four hex digits."
            return
        }
        regionProblem = nil
        regionInput = ""
        guard !regions.contains(code) else { return }
        regions.append(code)
    }
}
