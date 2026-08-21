#!/usr/bin/env python3
"""Drive the region map in a real browser.

The lookup logic is covered without a browser by `site/tests/regions/`. What
this checks is the half those tests cannot reach: that the page boots at all —
that its imports resolve, the WebAssembly SQLite loads, MapLibre initializes,
the database opens, and a lookup reaches the result panel with no console
error along the way.

That is not a hypothetical concern. The first version of the viewer failed on
its very first import, because MapLibre 6 exports no default binding, and
every syntax check in the world passed it.

Needs Chromium and Playwright, which CI does not carry:

    uv run --project tools/regiondb-build python tools/regiondb-build/smoke_map.py
"""

from __future__ import annotations

import http.server
import shutil
import socketserver
import sys
import tempfile
import threading
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
STATIC = REPO / "site" / "static"
HARNESS = REPO / "site" / "tests" / "regions" / "harness.html"
FIXTURE = REPO / "regions" / "tests" / "fixture" / "fixture.regiondb"

# Where the page looks for a published database. The fixture stands in for one.
PUBLISHED_NAME = "world.regiondb"


def _serve(root: Path):
    handler = lambda *args, **kwargs: http.server.SimpleHTTPRequestHandler(  # noqa: E731
        *args, directory=str(root), **kwargs
    )
    server = socketserver.TCPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, server.server_address[1]


def main() -> int:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("playwright is not installed; skipping the browser smoke test", file=sys.stderr)
        return 0

    with tempfile.TemporaryDirectory() as work:
        root = Path(work)
        shutil.copytree(STATIC, root, dirs_exist_ok=True)
        shutil.copy(HARNESS, root / "regions" / "map" / "harness.html")
        shutil.copy(FIXTURE, root / "regions" / PUBLISHED_NAME)

        server, port = _serve(root)
        try:
            failures = _drive(sync_playwright, port)
        finally:
            server.shutdown()

    for failure in failures:
        print(f"  {failure}", file=sys.stderr)
    if failures:
        print(f"{len(failures)} map smoke failures", file=sys.stderr)
        return 1
    print("map smoke test passed")
    return 0


def _drive(sync_playwright, port: int) -> list[str]:
    failures: list[str] = []
    chromium = next(
        (path for path in Path("/opt/pw-browsers").glob("chromium-*/chrome-linux/chrome")),
        None,
    )

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(
            executable_path=str(chromium) if chromium else None,
            args=["--no-sandbox", "--use-gl=swiftshader", "--enable-unsafe-swiftshader"],
        )
        page = browser.new_page(viewport={"width": 1280, "height": 800})
        page.on(
            "console",
            lambda message: (
                failures.append(f"console error: {message.text}")
                if message.type == "error"
                else None
            ),
        )
        page.on("pageerror", lambda error: failures.append(f"page error: {error}"))
        page.on("requestfailed", lambda request: failures.append(f"request failed: {request.url}"))

        page.goto(f"http://127.0.0.1:{port}/regions/map/harness.html", wait_until="load")
        try:
            page.wait_for_function(
                "document.querySelector('#database-meta').textContent.includes('Dataset')",
                timeout=45_000,
            )
        except Exception:
            failures.append("the database panel never rendered; the page did not open a database")
            browser.close()
            return failures

        # San Carlos, the standing regression: a positioned location whose
        # commercial airport is somewhere else entirely.
        page.fill("input[name=lat]", "37.5119")
        page.fill("input[name=lon]", "-122.2495")
        page.click("#coordinate-form button")
        page.wait_for_function("!document.querySelector('#lookup-result').hidden", timeout=20_000)
        result = page.inner_text("#lookup-result")

        for expected in ("iata-location:SQL", "iata-airport:SFO", "country:US"):
            if expected not in result:
                failures.append(f"lookup result is missing {expected}")
        if "iata-airport:SQL" in result:
            failures.append("lookup result claims San Carlos is a commercial airport")

        toggles = page.eval_on_selector_all("#layer-toggles input", "elements => elements.length")
        if toggles == 0:
            failures.append("no layer toggles were built")

        browser.close()
    return failures


if __name__ == "__main__":
    raise SystemExit(main())
