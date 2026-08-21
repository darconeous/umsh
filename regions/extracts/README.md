# Extracts

Machine-written. Do not hand-edit.

Each file is produced by `regiondb-build update` from the pinned downloads in
`regions/vendor/`, and carries a header naming the source, its URL, its
SHA-256, and when it was retrieved. The pass is idempotent: the same vendor
bytes produce the same extract bytes, so re-running it against unchanged
upstream data produces no diff at all.

An edit here survives exactly until the next update, which is why corrections
belong in `../classifications/` and `../overrides/` instead. Those are applied
on top of the extracts by the build, and are committed for the same reason
these are: so that the geographic policy in a release is reviewable.

`regiondb-build update --check` re-derives everything and fails if what is
committed differs.

The global country boundary layer is deliberately absent — it is written to
`../build/boundaries/country/` instead. See the note in `../README.md`.
