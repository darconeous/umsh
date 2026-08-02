import SwiftUI

/// Where the mesh is, as opposed to who is in it.
///
/// Deliberately separate from the peer list rather than a second presentation
/// of it. What belongs here is every node that has reported a location —
/// mostly nodes heard over the air and never saved — so the peer list is not
/// the set being drawn, and a toggle above the peer list would say it was.
struct NodeMapView: View {
    var body: some View {
        ContentUnavailableView {
            Label("No reported locations", systemImage: "map")
        } description: {
            Text("Locations reported by observed nodes will appear here with their precision and age.")
        }
        .navigationTitle("Map")
    }
}
