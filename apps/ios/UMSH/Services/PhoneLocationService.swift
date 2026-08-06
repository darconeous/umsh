import CoreLocation

/// The phone's own position, read only while its owner has chosen to put
/// it in the identity this phone announces.
///
/// A seam over CoreLocation rather than a location layer: the app starts
/// readings while sharing is on and stops them when it is off, and
/// everything about *what* is disclosed — the cell, the precision — is
/// decided past the seam, where the identity is built. Nothing here
/// stores a coordinate.
///
/// When-in-use authorization only, and honestly so: the announcement
/// schedules this feeds already run only while the app is open, so
/// background location would buy a permission prompt and nothing else.
@MainActor
final class PhoneLocationService: NSObject {
    private let manager = CLLocationManager()
    /// Called on the main actor for each reading while running.
    private var onReading: ((CLLocation) -> Void)?
    /// Called on the main actor if location access is revoked while
    /// running: no reading will follow, and whatever the last one
    /// disclosed must not outlive the permission.
    private var onAuthorizationLost: (() -> Void)?

    override init() {
        super.init()
        manager.delegate = self
    }

    /// Begin readings sized to the disclosure: `cellMeters` is the cell
    /// the identity will name, so the fix only needs to be good to about
    /// that, and a phone that has not moved most of a cell has nothing
    /// new to report. Asking for more accuracy than the cell keeps any
    /// of would only spend battery refining digits that are thrown away.
    func start(
        cellMeters: Double,
        onReading: @escaping (CLLocation) -> Void,
        onAuthorizationLost: @escaping () -> Void
    ) {
        self.onReading = onReading
        self.onAuthorizationLost = onAuthorizationLost
        manager.desiredAccuracy = cellMeters <= 150
            ? kCLLocationAccuracyNearestTenMeters
            : kCLLocationAccuracyHundredMeters
        manager.distanceFilter = max(cellMeters / 2, 10)
        if manager.authorizationStatus == .notDetermined {
            manager.requestWhenInUseAuthorization()
        }
        manager.startUpdatingLocation()
    }

    func stop() {
        manager.stopUpdatingLocation()
        onReading = nil
        onAuthorizationLost = nil
    }

    private func deliver(_ reading: CLLocation) {
        onReading?(reading)
    }

    private func handleAuthorizationChange() {
        guard onReading != nil else { return }
        switch manager.authorizationStatus {
        case .authorizedWhenInUse, .authorizedAlways:
            // A grant that arrives after `start` — the first run, where
            // the permission sheet sat between asking and answering.
            manager.startUpdatingLocation()
        case .denied, .restricted:
            // Revoked mid-run. The manager is left running so a
            // re-grant resumes on its own; the owner is told because
            // the disclosure it made from the last reading now has no
            // permission behind it.
            onAuthorizationLost?()
        default:
            break
        }
    }
}

extension PhoneLocationService: CLLocationManagerDelegate {
    nonisolated func locationManager(
        _ manager: CLLocationManager,
        didUpdateLocations locations: [CLLocation]
    ) {
        guard let last = locations.last else { return }
        Task { @MainActor in self.deliver(last) }
    }

    nonisolated func locationManager(
        _ manager: CLLocationManager,
        didFailWithError error: Error
    ) {
        // Transient by design: a reading comes later or does not, and the
        // last cell pushed into the identity stands until one does.
    }

    nonisolated func locationManagerDidChangeAuthorization(_ manager: CLLocationManager) {
        Task { @MainActor in self.handleAuthorizationChange() }
    }
}
