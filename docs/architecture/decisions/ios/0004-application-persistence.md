# ADR 0004: Prototype application state with SQLite

- Status: Accepted for the application schema foundation
- Phase: 0

## Decision

Use SQLite directly for the Phase 0 transaction and migration prototype. The
prototype must demonstrate identity-scoped uniqueness, explicit transactions,
rollback, indexed search, foreign keys, and deterministic migrations. Security
state and optimistic message/application state may use separate stores and are
reconciled by durable logical identifiers; raw secrets never enter SQLite.

SwiftData remains an option only if a competing prototype proves equivalent
control for the minimum deployment target. A higher-level SQLite library may
be adopted later, but the schema and transaction tests must not depend on its
object-graph behavior.

## Consequences

No durable feature schema lands until the prototype and migration tests pass.
This record chooses the spike substrate, not a public data-model API.

## Prototype evidence

`SQLiteApplicationStore` now provides deterministic `PRAGMA user_version`
migration, foreign-key enforcement, explicit immediate transactions with
rollback, and an application-support database location. Its first prototype
tables contain only public local-identity and identity-owned node records; raw
secret material is not accepted by the API.

The executable `scripts/ios/verify-ios-persistence.sh` check demonstrates:

- repeatable migration to schema version 1 and reopening at the same version;
- the same peer public address under two local identities, but no duplicate
  within one identity;
- whole-batch rollback when a later statement violates uniqueness;
- rejection of a node whose owning local identity does not exist; and
- locale-independent alias-prefix search whose query plan uses the composite
  owner/search index.

This accepts direct SQLite as the initial application persistence layer. It
does not freeze the complete feature schema; later tables still require their
own migrations and transaction tests.
