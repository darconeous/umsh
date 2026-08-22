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

    /// One reading, for a screen that needs to know where the phone is
    /// rather than to disclose it — the region lookup behind "Update based
    /// on location".
    ///
    /// Nothing is stored and nothing is shared: the answer goes to the
    /// screen that asked, is turned into a list of regions, and is gone.
    /// It runs on its own manager so that asking cannot displace the
    /// sharing schedule's callbacks, which want a different accuracy and
    /// have a different lifetime. Nil means access was refused, or no fix
    /// arrived in time.
    func readOnce() async -> CLLocation? {
        await OneShotLocationReader().read()
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

/// A single fix, asked for and answered once.
///
/// `requestLocation` delivers exactly one reading or one failure, so this is
/// a continuation with a manager attached rather than a stream. It holds
/// itself alive until it answers, because the caller holds only the task —
/// and it answers exactly once however the attempt ends, including the case
/// nobody covers otherwise: a permission sheet left standing.
@MainActor
private final class OneShotLocationReader: NSObject, CLLocationManagerDelegate {
    /// How long to wait before giving up. Long enough for a cold start
    /// indoors, short enough that a sheet is not stuck behind it.
    private static let limit = Duration.seconds(20)

    private let manager = CLLocationManager()
    private var answer: CheckedContinuation<CLLocation?, Never>?
    private var expiry: Task<Void, Never>?
    /// Kept alive by itself until it answers. Nothing else has a reason to
    /// hold it, and a reader deallocated mid-request would strand the
    /// continuation.
    private var retained: OneShotLocationReader?

    func read() async -> CLLocation? {
        await withCheckedContinuation { (continuation: CheckedContinuation<CLLocation?, Never>) in
            answer = continuation
            retained = self
            manager.delegate = self
            // A region is a routing domain tens of kilometers across, so a
            // coarse fix answers the question this is asked for and costs
            // the least battery and the least time to acquire.
            manager.desiredAccuracy = kCLLocationAccuracyHundredMeters
            expiry = Task { [weak self] in
                try? await Task.sleep(for: Self.limit)
                self?.finish(nil)
            }
            switch manager.authorizationStatus {
            case .notDetermined:
                // Asking for a location before the grant lands fails
                // outright, so the request waits for the answer.
                manager.requestWhenInUseAuthorization()
            case .denied, .restricted:
                finish(nil)
            default:
                manager.requestLocation()
            }
        }
    }

    private func finish(_ reading: CLLocation?) {
        guard let answer else { return }
        self.answer = nil
        expiry?.cancel()
        expiry = nil
        retained = nil
        answer.resume(returning: reading)
    }

    private func authorizationSettled() {
        guard answer != nil else { return }
        switch manager.authorizationStatus {
        case .authorizedWhenInUse, .authorizedAlways: manager.requestLocation()
        case .denied, .restricted: finish(nil)
        default: break
        }
    }

    nonisolated func locationManager(
        _ manager: CLLocationManager,
        didUpdateLocations locations: [CLLocation]
    ) {
        Task { @MainActor in self.finish(locations.last) }
    }

    nonisolated func locationManager(
        _ manager: CLLocationManager,
        didFailWithError error: Error
    ) {
        Task { @MainActor in self.finish(nil) }
    }

    nonisolated func locationManagerDidChangeAuthorization(_ manager: CLLocationManager) {
        Task { @MainActor in self.authorizationSettled() }
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
