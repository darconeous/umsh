# MAC Commands

A MAC command payload consists of:

- **1 byte**: command identifier
- **optional bytes**: command-specific payload

Support for MAC commands is optional.

## Defined MAC Commands

### Beacon Request
Requests that the destination send back a beacon.

This request may include a 4-byte nonce. If included, that nonce must be copied into the response beacon.

Beacon requests may be used for:

- presence detection
- frame-counter synchronization

### Identity Request
Requests that the destination provide node identity information.

### Signal Report Request
Requests signal information from the destination.

### Signal Report Response
Carries a signal report in response to a prior request.

### Echo Request
Requests that the destination respond with an Echo Response.

This request may include an arbitrary payload. If included, the payload must be copied into the Echo Response.

Echo requests may be used for:

- round-trip latency measurement
- reachability testing
- frame-counter synchronization (by observing the frame counter in the response's SECINFO)

### Echo Response
Carries a response to a prior Echo Request, including any payload from the request.
