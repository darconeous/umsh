"""Checking a compiled database.

Two kinds of check live here. Known points are the human-readable fixtures: a
position, and the semantic regions a person expects it to be in or out of.
Sampling is the machine check: for a large number of positions, the cached
lookup path and an exhaustive scan of the same file must return exactly the
same set, which is what proves the cache is an optimization and not a second
source of truth.

Sampling is weighted toward boundaries, because that is where the cache stops
being able to answer on its own and where an error would actually hide.
"""

from __future__ import annotations

import random
from pathlib import Path

import yaml

from .lookup import RegionDb


def run(
    database: Path,
    *,
    points: Path | None = None,
    sample: int = 0,
    seed: int = 20260821,
) -> list[str]:
    failures: list[str] = []
    with RegionDb(database) as db:
        if points:
            failures.extend(check_points(db, points))
        if sample:
            failures.extend(check_sampling(db, sample, seed))
    return failures


def check_points(db: RegionDb, path: Path) -> list[str]:
    document = yaml.safe_load(path.read_text()) or {}
    failures: list[str] = []
    for case in document.get("points", []):
        result = db.lookup(case["lat"], case["lon"])
        keys = {match.region_key for match in result.matches}
        names = [item.name for item in result.radio_regions]
        expect = case.get("expect", {})
        label = case.get("name", f"{case['lat']},{case['lon']}")

        for required in expect.get("include_semantic", []):
            if required not in keys:
                failures.append(f"{label}: expected {required}, got {sorted(keys)}")
        for forbidden in expect.get("exclude_semantic", []):
            if forbidden in keys:
                failures.append(f"{label}: did not expect {forbidden}, but it matched")
        for required in expect.get("radio_regions", []):
            if required not in names:
                failures.append(f"{label}: expected radio region {required}, got {names}")
        expected_default = expect.get("suggested_default_region")
        if expected_default is not None:
            actual = (
                result.suggested_default_region.name if result.suggested_default_region else None
            )
            if actual != expected_default:
                failures.append(
                    f"{label}: expected suggested default {expected_default!r}, got {actual!r}"
                )
        if expect.get("no_regions") and result.matches:
            failures.append(f"{label}: expected no regions, got {sorted(keys)}")
    return failures


def check_sampling(db: RegionDb, count: int, seed: int) -> list[str]:
    """Compare the cached path against an exhaustive scan.

    Half the positions are uniform over the sphere, half are jittered off the
    vertices of stored geometry so that the boundary cases — the only ones the
    cache cannot answer by itself — are densely covered.
    """
    generator = random.Random(seed)
    failures: list[str] = []
    positions = list(_uniform_positions(generator, count // 2))
    positions.extend(_boundary_positions(db, generator, count - count // 2))

    for latitude, longitude in positions:
        cached = [match.region_key for match in db.lookup(latitude, longitude).matches]
        exact = [
            match.region_key for match in db.lookup(latitude, longitude, exhaustive=True).matches
        ]
        if cached != exact:
            failures.append(
                f"{latitude:.6f},{longitude:.6f}: cache returned {cached}, exact scan {exact}"
            )
            if len(failures) > 50:
                failures.append("... stopping after 50 mismatches")
                break
    return failures


def _uniform_positions(generator: random.Random, count: int):
    import math

    for _ in range(count):
        # Uniform on the sphere rather than uniform in latitude, so the poles
        # are not oversampled into meaninglessness.
        yield (
            math.degrees(math.asin(generator.uniform(-1.0, 1.0))),
            generator.uniform(-180.0, 180.0),
        )


def _boundary_positions(db: RegionDb, generator: random.Random, count: int):
    from . import blob

    vertices: list[tuple[float, float]] = []
    for row in db._connection.execute(  # noqa: SLF001 - the reader is ours
        "SELECT geometry FROM geometry_parts ORDER BY id"
    ):
        for ring in blob.decode(row[0]):
            for lon_e6, lat_e6 in ring.points:
                vertices.append((blob.from_e6(lat_e6), blob.from_e6(lon_e6)))
    if not vertices:
        return

    for _ in range(count):
        latitude, longitude = generator.choice(vertices)
        # Jitter across a range that straddles the grid: some positions land
        # exactly on an edge, some just inside, some just outside.
        scale = generator.choice((0.0, 1e-6, 1e-5, 1e-4, 1e-3))
        yield (
            max(-90.0, min(90.0, latitude + generator.uniform(-scale, scale))),
            longitude + generator.uniform(-scale, scale),
        )
