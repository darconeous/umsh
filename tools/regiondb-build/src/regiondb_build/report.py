"""Build reports.

A region release is a geographic policy change, and the numbers here are what
makes reviewing one possible: how many sites went in, how much geometry came
out, how often the lookup cache has to fall back, and what the build was unsure
about. `changes.json` answers the other half — what moved since the last
release.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def write(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")


def summarize(report: dict[str, Any]) -> str:
    counts = report.get("counts", {})
    geometry = report.get("geometry", {})
    cache = report.get("cache", {})
    database = report.get("database", {})

    lines = [
        f"dataset {report.get('dataset_version', 'unknown')} "
        f"(format {report.get('format_version')}, content {report.get('content_hash', '')[:12]})",
        "  regions: "
        + ", ".join(f"{name} {count}" for name, count in sorted(counts.items()) if count),
        f"  geometry: {geometry.get('parts', 0)} parts, "
        f"{geometry.get('vertices', 0)} vertices",
        f"  cache: {cache.get('ranges', 0)} ranges from {cache.get('leaves', 0)} leaves, "
        f"{cache.get('boundary_leaves', 0)} needing fallback, "
        f"at most {cache.get('max_candidates', 0)} candidates",
        f"  database: {database.get('size_bytes', 0) / 1_048_576:.2f} MiB in "
        f"{report.get('duration_s', 0):.1f}s",
    ]
    warnings = report.get("warnings", [])
    if warnings:
        lines.append(f"  warnings: {len(warnings)}")
        for warning in warnings[:20]:
            lines.append(f"    - {warning}")
        if len(warnings) > 20:
            lines.append(f"    ... and {len(warnings) - 20} more, see the build report")
    return "\n".join(lines)


def diff(old: dict[str, Any], new: dict[str, Any]) -> dict[str, Any]:
    """Compare two builds' region inventories."""
    old_regions = set(old.get("region_keys", []))
    new_regions = set(new.get("region_keys", []))
    return {
        "added_regions": sorted(new_regions - old_regions),
        "removed_regions": sorted(old_regions - new_regions),
        "dataset_version": {"old": old.get("dataset_version"), "new": new.get("dataset_version")},
        "size_bytes": {
            "old": old.get("database", {}).get("size_bytes"),
            "new": new.get("database", {}).get("size_bytes"),
            "delta": (new.get("database", {}).get("size_bytes", 0))
            - (old.get("database", {}).get("size_bytes", 0)),
        },
        "content_hash": {"old": old.get("content_hash"), "new": new.get("content_hash")},
    }
