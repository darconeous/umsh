# Bridge Client

An integrated [internet bridge](internet-bridging.md) client connects the device's
node to a bridge server over IP. Configuration belongs to the device domain and
is independent of the attached host. Enabling the client does not enable Wi-Fi,
change IP configuration, or change `PROP_MAC_REPEATER_ENABLED`.

## Capabilities

`CAP_BRIDGE_CLIENT` (58) requires `CAP_REPEATER` and at least one implemented IP
family. It requires all five properties below. The IP-family requirement is an
alternative expressed here in prose, not an AND-list of capability codes.

## PROP_BRIDGE_ENABLED

Property 4928; Get/Set; BOOL. Defaults to false. A write changes the desired
state immediately; it does not wait for a connection. When enabled without a
host or server key, the client reports Unconfigured and makes no connection.

## PROP_BRIDGE_HOST

Property 4929; Get/Set; STRING. A DNS A-label hostname or unbracketed IP literal,
without a scheme, path, or port. Maximum 253 octets before the terminating NUL.
Empty clears the host. A client uses the IP families its platform implements;
an unsupported literal reports a connection failure rather than falling back
to another destination. The hostname supplies TLS SNI where applicable; it
does not establish trust in the server.

## PROP_BRIDGE_PORT

Property 4930; Get/Set; UINT16. Defaults to 21837. Zero is invalid. Like other
ULCP scalars, the value is little-endian.

## PROP_BRIDGE_SERVER_KEY

Property 4931; Get/Set; a canonical 32-octet Ed25519 public key, or empty to clear
the pin. Invalid or weak public keys are refused. The client authenticates the
TLS 1.3 `CertificateVerify` signature against this key. Certificate claims,
names, validity dates, and public certificate authorities do not establish trust.

The client's authentication identity **MUST** be the device identity exposed by
`PROP_DEV_KEY`. No additional client key is provisioned or exposed through ULCP.
If that identity ceases to match the running node and TLS credential, the client
stops until identity initialization completes.

## PROP_BRIDGE_LINK

Property 4932; Get/Is; two octets: STATE followed by REASON. Read-only. Changes
are announced to the attached host. Enablement and connection state are distinct.

STATE | Meaning
------|--------
0 | Disabled
1 | Unconfigured
2 | Waiting for network
3 | Connecting
4 | Connected
5 | Retrying

REASON | Meaning
-------|--------
0 | None
1 | DNS failure or unsupported address family
2 | TCP connection or I/O failure
3 | TLS protocol failure
4 | Authentication failure
5 | Receive idle timeout
6 | Device identity unavailable

Connected describes the tunnel, not whether the node repeats. A client whose
repeater is disabled is a valid leaf; hosts should display the repeater state
alongside the link state.

## Persistence and lifecycle

The four configuration properties are saved by `CMD_SAVE` in the device snapshot.
`CMD_CLEAR` erases saved configuration without changing live configuration;
`CMD_RST` follows the normal saved-state restore rules. Defaults are disabled,
empty host, port 21837, and no server key. Attach/detach does not change these
properties or interrupt the bridge. Authorized mesh administrators may write
them through the existing device-management binding.

Changing configuration or losing the network closes the current connection and
discards queued frames. Each connection starts with empty queues and decoder
state. Invalid writes leave the old value intact. Connection failures are
reported through `PROP_BRIDGE_LINK`, not by delaying a configuration response.
