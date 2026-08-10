# Third-party code in the web flasher

The flasher ships with no build step, so its dependencies are committed here as
prebuilt distribution files rather than pulled from a CDN or a package manager.
Vendoring keeps the page's Content-Security-Policy at `script-src 'self'`, keeps
the published tree reproducible, and lets `make site-preview` work offline.

UMSH itself is dual-licensed Apache-2.0 / MIT (see `LICENSE-APACHE` and
`LICENSE-MIT` at the repository root). Everything below is compatible with both.

## Vendored files

| Path | Package | Version | License | Upstream |
|---|---|---|---|---|
| `vendor/esptool-js/esptool.js` | `esptool-js` | 0.6.1 | Apache-2.0 | <https://github.com/espressif/esptool-js> |
| `vendor/fflate/fflate.js` | `fflate` | 0.8.3 | MIT | <https://github.com/101arrowz/fflate> |

Each directory carries the upstream `LICENSE` verbatim alongside the code.

`esptool.js` is the package's prebuilt browser bundle (`bundle.js` in the npm
tarball), renamed for clarity. It is a self-contained ES module exporting
`ESPLoader` and `Transport`; the flash stubs for every supported chip are inlined
in it, so nothing is fetched at runtime. It was checked before committing for
`eval`, `new Function`, dynamic `import()`, and `fetch`/`XMLHttpRequest` — it uses
none of them, which is what lets the page keep a CSP with no `unsafe-eval` and
`connect-src 'self'`.

`fflate.js` is the package's browser ES-module build (`esm/browser.js`). The
flasher uses only `unzipSync`, to open an nRF52 DFU package in memory.

SHA-256 of the files as taken from the npm tarballs:

```
ef7d5a237d3f273ecf546bcee65dddad90bd82cf02f22a980d1537e0cd79a152  esptool-js 0.6.1  bundle.js
b7ca4450b19559a1d50eb381adcee94b82449674be4cd17789d9beba7e6122a1  fflate 0.8.3      esm/browser.js
```

### Updating

```bash
curl -LO https://registry.npmjs.org/esptool-js/-/esptool-js-<version>.tgz
tar xzf esptool-js-<version>.tgz
cp package/bundle.js site/static/flasher/vendor/esptool-js/esptool.js
cp package/LICENSE   site/static/flasher/vendor/esptool-js/LICENSE

curl -LO https://registry.npmjs.org/fflate/-/fflate-<version>.tgz
tar xzf fflate-<version>.tgz
cp package/esm/browser.js site/static/flasher/vendor/fflate/fflate.js
cp package/LICENSE        site/static/flasher/vendor/fflate/LICENSE
```

Re-run the `eval`/`fetch` check on any new esptool-js bundle, update the version
and hashes above, and bench-test a Heltec V3 flash before committing.

## Derived code (not vendored, but owed attribution)

`../nrf-dfu.js` implements the legacy Nordic serial DFU protocol that the
Adafruit nRF52 bootloader speaks. It is adapted from `lib/dfu.js` in
[meshcore-dev/flasher.meshcore.io](https://github.com/meshcore-dev/flasher.meshcore.io),
MIT, Copyright (c) 2025 Rastislav Vysoky. That file carries no per-file header
upstream, so the notice lives in the header of `nrf-dfu.js` and the full license
text is in `vendor/meshcore-flasher/LICENSE`.

That implementation is in turn a port of `dfu/dfu_transport_serial.py` from
[adafruit-nrfutil](https://github.com/adafruit/Adafruit_nRF52_nrfutil),
BSD-3-Clause, Copyright (c) 2015 Nordic Semiconductor — the tool the Makefile's
`flash-*-serial` targets shell out to, and the origin of the protocol constants
(SLIP/HCI framing, packet types, and the nRF52840 flash timing figures). Its
license text is in `vendor/adafruit-nrfutil/LICENSE`.

No code was taken from [meshtastic/web-flasher](https://github.com/meshtastic/web-flasher):
it is GPL-3.0, which is incompatible with this repository's licensing.

`../serial.js` is adapted from `tools/ulcp-web-debugger/www/transports/serial.js`
in this repository — same project, no third-party licensing involved. It is a
copy rather than an import so that the published site never depends on the
unpublished debugger tree.
