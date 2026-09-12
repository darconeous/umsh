# Embedded bridge client

`no_std` TLS identity provider and bounded tunnel queues shared by the embedded
client and host interoperability tests. External dependencies are managed by
Cargo; no dependency sources are vendored here.

The provider signs TLS 1.3 client authentication with the device's boot identity
seed and verifies the server's handshake signature against its configured pin.
Its generated certificate is an identity container, not a PKI trust anchor.
Callers must check `authenticated()` after opening a fresh TLS connection.

The T-Beam task supplies Embassy IPv4 networking, cancellation, timeouts, and
PSRAM storage. Runtime configuration defaults to disabled. Host attachment and
the device's repeater setting have independent lifetimes.

## Validation

The production rustls bridge server is exercised by
`cargo test -p umsh-bridge --test embedded_client`. This tests the same provider
used in firmware, including client identity, server pin, authorization, and
incompatible ALPN rejection by the server. Tunnel and mux tests cover bounded
queues, age limits, node-only ingress, and handoffs during physical transmission.

## Upstream TLS behavior

`embedded-tls` 0.19 offers `umsh-bridge/1` in ClientHello, but discards the
server's EncryptedExtensions and exposes no selected-ALPN accessor. The existing
bridge server rejects incompatible offers. A server that omits ALPN altogether
cannot currently be distinguished by the client. The bridge specification
recommends offering this identifier; it does not require checking the server's
selection. The client makes that offer and independently verifies the pinned
server identity. The implementation retains the unmodified upstream dependency.

The library also collapses post-handshake fatal alerts into `InternalError`, so
a server refusal received after client Finished can be reported as a TLS failure
without its authentication-specific reason. The refusal still closes the
connection; the limitation affects diagnostic classification.

KeyUpdate returns an unimplemented error and causes the client to reconnect.
Unexpected parsed handshake messages in the application-data phase reach a
library `unimplemented!()` branch. This source finding has not been reproduced
in normal bridge operation and remains a robustness investigation for upstream.
