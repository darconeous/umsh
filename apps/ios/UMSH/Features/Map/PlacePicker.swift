import CoreLocation
import MapKit
import SwiftUI

/// Choose a place by moving the map under a fixed crosshair.
///
/// The map moves and the crosshair does not: the point being chosen stays in
/// the middle of the screen where no finger covers it, and the gesture that
/// picks it is the same one that got the reader to the right part of the
/// world. A dragged pin has neither property.
///
/// Nothing here is written anywhere. The answer goes back to whichever editor
/// opened this, which keeps its own Apply as the only path to a device.
struct PlacePicker: View {
    /// Where to open. Absent opens on this phone, and failing that on a view
    /// of the whole world.
    var initial: CLLocationCoordinate2D?
    /// The grid this place will be reported on, drawn as the cell a node
    /// would actually advertise and adjustable here. Absent where the
    /// coordinate is taken exactly and there is no cell to draw.
    var precision: UInt8?
    /// Hand back the crosshair, unrounded, and the grid chosen for it —
    /// which is nil exactly where none was offered. What quantizes the point
    /// is the location encoding, where the value is written rather than
    /// here, so nothing on this screen has committed to anything.
    let choose: (CLLocationCoordinate2D, UInt8?) -> Void

    @Environment(\.dismiss) private var dismiss
    @Environment(\.readPhonePosition) private var readPhonePosition

    @State private var camera: MapCameraPosition = .automatic
    /// Where the crosshair is, which is wherever the map's center is.
    @State private var center: CLLocationCoordinate2D?
    /// The grid on screen, which starts as the one handed in. Held rather
    /// than bound, so a precision tried out and then cancelled leaves
    /// nothing behind.
    @State private var chosenPrecision: UInt8?
    @State private var isReadingPhone = false
    @State private var phoneUnavailable = false

    var body: some View {
        NavigationStack {
            Map(position: $camera) {
                UserAnnotation()
                if let corners = cellCorners {
                    MapPolygon(coordinates: corners)
                        .foregroundStyle(Color.accentColor.opacity(0.15))
                        .stroke(Color.accentColor, lineWidth: 1.5)
                }
            }
            .onMapCameraChange(frequency: .continuous) { context in
                center = context.region.center
            }
            .overlay {
                Image(systemName: "scope")
                    .font(.system(size: 32, weight: .light))
                    .foregroundStyle(Color.accentColor)
                    .shadow(color: .black.opacity(0.35), radius: 2)
                    // The crosshair marks the map; it must never take a pan
                    // meant for the map under it.
                    .allowsHitTesting(false)
            }
            .safeAreaInset(edge: .bottom) { footer }
            .navigationTitle("Choose a Place")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .topBarTrailing) {
                    Button {
                        Task { await centerOnPhone() }
                    } label: {
                        if isReadingPhone {
                            ProgressView()
                        } else {
                            Image(systemName: "location")
                        }
                    }
                    .disabled(isReadingPhone || readPhonePosition == nil)
                    .accessibilityLabel("Center on This Phone")
                }
            }
            .task { await frame() }
        }
    }

    private var footer: some View {
        VStack(spacing: 8) {
            HStack {
                Text(readout)
                    .font(.callout.monospacedDigit())
                Spacer(minLength: 12)
                // Beside the place rather than behind it, because the cell
                // is drawn on the map: coarsening it is a box growing under
                // the crosshair, which is the whole argument for choosing it
                // here instead of in a form.
                if precision != nil {
                    Picker("Cell", selection: $chosenPrecision) {
                        ForEach(LocationPresentation.precisions, id: \.self) { precision in
                            Text(LocationPresentation.precisionLabel(precisionBytes: precision))
                                .tag(UInt8?.some(precision))
                        }
                    }
                    .pickerStyle(.menu)
                }
            }
            if let note {
                Text(note)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
            }
            Button {
                guard let center else { return }
                choose(center, chosenPrecision)
                dismiss()
            } label: {
                Text("Use This Place").frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .disabled(center == nil)
        }
        .padding()
        .background(.bar)
    }

    private var readout: String {
        guard let center else { return "Finding a place to start…" }
        return LocationPresentation.coordinateText(
            latitude: center.latitude,
            longitude: center.longitude,
            cellMeters: cellMeters
        )
    }

    private var note: String? {
        phoneUnavailable ? "This phone could not find where it is. Move the map by hand." : nil
    }

    private var cellMeters: Double? {
        chosenPrecision.flatMap { LocationPresentation.cellMeters(precisionBytes: $0) }
    }

    /// The cell the crosshair falls in, as the four corners of the box a
    /// node reporting from here would disclose.
    ///
    /// Latitude and longitude are each cut into 16ⁿ equal parts and the point
    /// lands in one of them — that is the encoding's own definition, so the
    /// box follows from the precision alone. Derived here rather than by
    /// encoding and decoding through the core because it is redrawn on every
    /// frame of a pan.
    private var cellCorners: [CLLocationCoordinate2D]? {
        guard let precision = chosenPrecision, let center,
              // The core owns which precisions exist; a cell size coming
              // back at all is what says this one does.
              LocationPresentation.cellMeters(precisionBytes: precision) != nil
        else { return nil }
        let cells = pow(16.0, Double(precision))
        let latitudeSpan = 180.0 / cells
        let longitudeSpan = 360.0 / cells
        let south = ((center.latitude + 90) / latitudeSpan).rounded(.down) * latitudeSpan - 90
        let west = ((center.longitude + 180) / longitudeSpan).rounded(.down) * longitudeSpan - 180
        return [
            CLLocationCoordinate2D(latitude: south, longitude: west),
            CLLocationCoordinate2D(latitude: south, longitude: west + longitudeSpan),
            CLLocationCoordinate2D(
                latitude: south + latitudeSpan,
                longitude: west + longitudeSpan
            ),
            CLLocationCoordinate2D(latitude: south + latitudeSpan, longitude: west),
        ]
    }

    /// How much ground to open on: enough of it to see where the place sits,
    /// which for a graded position is a multiple of the cell being chosen.
    private var openingMeters: CLLocationDistance {
        max((cellMeters ?? 0) * 12, 800)
    }

    private func frame() async {
        chosenPrecision = precision
        if let initial {
            center = initial
            camera = .region(
                MKCoordinateRegion(
                    center: initial,
                    latitudinalMeters: openingMeters,
                    longitudinalMeters: openingMeters
                )
            )
            return
        }
        // Framed on the world before CoreLocation is asked anything. A phone
        // that will not say where it is — refused, or never asked — must
        // still leave a map somebody can move and a place they can take;
        // waiting on the fix to frame anything at all is how a denied
        // permission turns into a picker that cannot pick.
        center = Self.unplaced.center
        camera = .region(Self.unplaced)
        await centerOnPhone()
    }

    /// What a picker opens on when it is given nothing and told nothing.
    private static let unplaced = MKCoordinateRegion(
        center: CLLocationCoordinate2D(latitude: 20, longitude: 0),
        span: MKCoordinateSpan(latitudeDelta: 120, longitudeDelta: 120)
    )

    private func centerOnPhone() async {
        guard let readPhonePosition, !isReadingPhone else { return }
        isReadingPhone = true
        phoneUnavailable = false
        defer { isReadingPhone = false }
        guard let reading = await readPhonePosition() else {
            phoneUnavailable = true
            return
        }
        center = reading.coordinate
        withAnimation {
            camera = .region(
                MKCoordinateRegion(
                    center: reading.coordinate,
                    latitudinalMeters: openingMeters,
                    longitudinalMeters: openingMeters
                )
            )
        }
    }
}
