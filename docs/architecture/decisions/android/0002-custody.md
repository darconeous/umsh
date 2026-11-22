# ADR 0002: Keystore-wrapped identity custody

- Status: Accepted; StrongBox and TEE unverified on hardware
- Phase: 1

## Decision

The identity's private key is hardware-protected at rest, but not
hardware-resident while in use: the same posture as iOS ADR 0002.

### At rest

- Each secret is a file, AES-256-GCM encrypted under a non-exportable Android
  Keystore key. The key is created in StrongBox when the device has one and
  in the TEE otherwise; `KeyInfo.securityLevel` says which, and Your identity
  shows it (Security chip, Secure area, Software only).
- The key needs no user authentication. The files are in credential-encrypted
  storage, so they are unreadable before the first unlock anyway; this
  matches iOS's `AfterFirstUnlockThisDeviceOnly`. The app is not direct-boot
  aware.
- The account name is bound in as associated data, so a file copied to
  another account's name fails to open.
- Secrets live under `noBackupFilesDir`, one vault per kind of secret, each
  with its own directory and Keystore alias:
  - `identity/` (alias `…identity`): the identity's 32-byte secret, one account;
  - `channel-keys/` (alias `…channel-keys`): the live core's channel keys;
  - `channel-keys-staging/` (alias `…channel-keys-staging`): the debug staging
    core's, so staged seeds never land among the live keys.

  The core's `erase` calls `deleteAll()` on the vault it was given, so the
  identity never shares a vault with channel keys.
- Secrets never enter SQLite, preferences, logs, or backups.

### In use

Unlocking decrypts the secret into process memory once per start and passes
it to `MobileIdentity.unlock`; the Kotlin copy is zeroed after, and Rust
zeroizes its own. Rust then signs and derives keys in software.

The key cannot stay in hardware. UMSH uses one Ed25519 key for signatures
and, converted to X25519, for key agreement. Keystore cannot do agreement
with an Ed25519 key or convert one, and its Ed25519 support (API 33+) is
signing-only. Keeping the key in hardware would need a crypto back end that
delegates agreement, which is the pluggable-crypto work.

### Failures

A secret that is stored but cannot be opened is never read as none, and the
app never mints over it. Failures are classified by exception class:

- **Transient** (`KeyStoreException`, `ProviderException`,
  `UserNotAuthenticatedException`, I/O, an Android `KeyStoreException`
  marked transient, and anything unrecognized): channel keys answer
  `SecretVaultException.Unavailable`; the identity shows Identity unavailable
  and is retried on the next foreground. No erase is offered.
- **Permanent** (`KeyPermanentlyInvalidatedException`, `AEADBadTagException`,
  a malformed file, or a wrapping key that is gone while the file remains):
  channel keys answer `Failed`; the identity shows Identity lost, with its
  diagnostic and Erase identity.

The cause chain is read nearest first. `UnrecoverableKeyException` decides
nothing by itself: keystore2 wraps every failed key lookup in it, busy and
not-ready ones included, so its cause decides.

An unrecognized failure counts as transient because a permanent answer
invites the person to erase.

### Erasure

One entry point erases, for in-app Erase identity, Manage space, and Start
over. The running core stops first. The identity secret goes next; if it
will not, nothing else is touched and the core comes back. Success is the
secret file being gone: a wrapping key left behind wraps nothing, so failing
to delete it is logged, not reported. Then the
live store's channel keys, counter reservations and, for Start over, content
go through a radioless core, or by deleting the files when the store will not
open; the other kind's counters go with them, since the identity is shared.
Start over also deletes the staging store, the staged air's state, the
staging vault, and clears the preferences.

### No recovery

Uninstalling the app, or the system's Clear storage, deletes the Keystore
keys and the files: the identity is gone for good. There is no anchor and no
"recovered identity" flow, since nothing outlives the app's data on Android.
`android:manageSpaceActivity` replaces Clear storage with a screen offering
Erase identity and Start over through the same entry point. The public
Android release waits for an implemented identity export
(`docs/protocol/src/identity-export.md`).

## Consequences

Emulators report software-backed keys only; StrongBox and TEE behavior,
including invalidation after a lock-screen change, is verified on hardware
before release.

A process killed after the secret is deleted and before the store is erased
leaves rows owned by the old address. The next launch mints a new identity;
the old rows stay unreachable under a dead owner, as on iOS.
