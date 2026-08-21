# Third-party code in the region map

The map ships with no build step, so its dependencies are committed here as
prebuilt distribution files rather than pulled from a CDN or a package
manager. Vendoring keeps the page's Content-Security-Policy tight, keeps the
published tree reproducible, and lets `make site-preview` work offline.

UMSH itself is dual-licensed Apache-2.0 / MIT (see `LICENSE-APACHE` and
`LICENSE-MIT` at the repository root). Everything below is compatible with
both.

## Vendored files

| Path | Package | Version | License | Upstream |
|---|---|---|---|---|
| `sqlite-wasm/sqlite3.mjs` | `@sqlite.org/sqlite-wasm` | 3.53.0-build1 | Public Domain (Apache-2.0 packaging) | <https://sqlite.org/wasm> |
| `sqlite-wasm/sqlite3.wasm` | `@sqlite.org/sqlite-wasm` | 3.53.0-build1 | Public Domain | <https://sqlite.org/wasm> |

Each directory carries its license alongside the code.

## Why the SQLite project's own build, and not sql.js

sql.js is the better-known WebAssembly SQLite and it **cannot open a
`.regiondb` at all**. Its stock build omits the R-tree extension, so the
`effective_rtree` virtual table fails to load and the file is rejected with
`no such module: rtree` before a single lookup runs. This was checked against
the real fixture rather than assumed:

    no such module: rtree

The SQLite project's own WebAssembly distribution includes R-tree, and opens
the same fixture cleanly. Anything replacing it must be checked the same way —
a build without R-tree is not a candidate, whatever else it offers.

## Content-Security-Policy notes

`sqlite3.mjs` fetches `sqlite3.wasm` from its own directory, so `connect-src
'self'` is sufficient; nothing reaches another origin. Instantiating
WebAssembly does require `wasm-unsafe-eval` in a strict policy — that is the
standard directive for running WASM at all and does not permit `eval` of
JavaScript.

The file was checked before committing for `eval`, `new Function`, and
`importScripts`: it uses none of them. It does reference `fetch` and
`XMLHttpRequest`, both only for loading its own `.wasm` payload.
