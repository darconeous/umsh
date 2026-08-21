"""Downloading and pinning upstream data.

This is the only part of the builder that touches the network, and it is a
separate command for that reason: `build` must work on a clean checkout with no
network at all. What `fetch` produces is a directory of raw files under
`regions/vendor/` plus a lock recording exactly what was retrieved.

The lock's `retrieved_at` is only refreshed when the content hash actually
changes. Re-fetching unchanged upstream data therefore leaves both the lock and
every derived extract byte-identical, which is what makes an update pass with
nothing to report produce no diff at all.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import httpx
import yaml


class FetchError(RuntimeError):
    """A source could not be retrieved, or did not match its pin."""


@dataclass(frozen=True)
class Source:
    identifier: str
    url: str
    filename: str
    license: str
    attribution: str
    notes: str
    pin: str
    sha256: str | None = None


def load_sources(path: Path) -> list[Source]:
    document = yaml.safe_load(path.read_text())
    return [
        Source(
            identifier=entry["id"],
            url=entry["url"],
            filename=entry["filename"],
            license=entry.get("license", "unknown"),
            attribution=entry.get("attribution", ""),
            notes=entry.get("notes", ""),
            pin=entry.get("pin", "none"),
            sha256=entry.get("sha256"),
        )
        for entry in document.get("sources", [])
    ]


def load_lock(path: Path) -> dict:
    if not path.exists():
        return {"version": 1, "sources": {}}
    return json.loads(path.read_text())


def write_lock(path: Path, lock: dict) -> None:
    path.write_text(json.dumps(lock, indent=2, sort_keys=True) + "\n")


def fetch(
    sources_path: Path,
    lock_path: Path,
    vendor_dir: Path,
    *,
    only: str | None = None,
    timeout: float = 300.0,
) -> list[str]:
    """Download every configured source, returning a line per source."""
    sources = load_sources(sources_path)
    lock = load_lock(lock_path)
    vendor_dir.mkdir(parents=True, exist_ok=True)
    report: list[str] = []

    with httpx.Client(follow_redirects=True, timeout=timeout) as client:
        for source in sources:
            if only and source.identifier != only:
                continue
            destination = vendor_dir / source.filename
            digest = hashlib.sha256()
            size = 0
            temporary = destination.with_suffix(destination.suffix + ".partial")
            with client.stream("GET", source.url) as response:
                if response.status_code != 200:
                    raise FetchError(
                        f"{source.identifier}: {source.url} returned {response.status_code}"
                    )
                with temporary.open("wb") as handle:
                    for chunk in response.iter_bytes():
                        handle.write(chunk)
                        digest.update(chunk)
                        size += len(chunk)

            actual = digest.hexdigest()
            if source.sha256 and source.sha256 != actual:
                temporary.unlink()
                raise FetchError(
                    f"{source.identifier}: expected sha256 {source.sha256}, got {actual}. "
                    "Refusing to use a source that does not match its pin."
                )
            temporary.replace(destination)

            previous = lock["sources"].get(source.identifier, {})
            unchanged = previous.get("sha256") == actual
            lock["sources"][source.identifier] = {
                "url": source.url,
                "sha256": actual,
                "size": size,
                "license": source.license,
                "attribution": source.attribution,
                "retrieved_at": (
                    previous["retrieved_at"]
                    if unchanged and previous.get("retrieved_at")
                    else datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
                ),
            }
            report.append(
                f"{source.identifier}: {size / 1_048_576:.1f} MiB "
                f"{'unchanged' if unchanged else 'updated'} ({actual[:12]})"
            )

    write_lock(lock_path, lock)
    return report
