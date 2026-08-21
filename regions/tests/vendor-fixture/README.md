# Synthetic vendor fixture

Stand-ins for the real upstream downloads, small enough to commit and shaped to
exercise the normalization rules in `regiondb-build update` rather than to
describe the world. Every row here is deliberate:

- `SFO`, `SQL`, `PAO`, `SJC` — ordinary records; `SQL` carries
  `scheduled_service=yes`, which is what makes it a commercial *candidate* that
  the committed classification then excludes.
- `CLS` — a `closed` facility, which must be dropped.
- the `NOIATA` row — no IATA code, dropped.
- `BAD` — latitude 99, out of range, dropped with a note.
- `DUP` — the same IATA code at two idents. The positions agree, so this one
  collapses silently; move either coordinate and the update pass must refuse to
  guess.
- `WRP` — longitude 190, which normalizes into `[-180, 180)`.

`citycodes.csv` carries two real metro codes and one too-short code that the
metro seed pass must ignore.
