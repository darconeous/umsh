"""Reading a compiled `.regiondb`.

This is the Python side of the runtime contract. It exists for two reasons: the
builder's own validation compares the compiled cache against an exhaustive scan
of the same file, and the cross-implementation conformance fixture is generated
from here and replayed by the Rust reader. The two must agree exactly, so the
algorithm is written to be transcribed rather than to be clever.
"""

from __future__ import annotations

import math
import sqlite3
from dataclasses import dataclass
from pathlib import Path

from . import blob, morton
from .emit import FORMAT_VERSION, decode_region_ids
from .model import MEMBERSHIP_CORE, MEMBERSHIP_EXPANDED, ROLE_CORE, ROLE_EFFECTIVE


class RegionDbError(RuntimeError):
    """The database cannot be read, or was written by a newer builder."""


@dataclass(frozen=True)
class RegionMatch:
    region_id: int
    region_key: str
    namespace: str
    code: str
    display_name: str
    radio_name: str
    wire_code: int
    kind: str
    layer: str
    priority: int
    default_rank: int | None
    membership: int
    site: tuple[float, float] | None


@dataclass(frozen=True)
class RadioRegion:
    name: str
    code: int


@dataclass(frozen=True)
class Lookup:
    latitude: float
    longitude: float
    matches: tuple[RegionMatch, ...]
    radio_regions: tuple[RadioRegion, ...]
    suggested_default_region: RadioRegion | None
    dataset_version: str


@dataclass(frozen=True)
class _RegionRow:
    region_id: int
    region_key: str
    namespace: str
    code: str
    display_name: str
    radio_name: str
    wire_code: int
    kind: str
    layer: str
    priority: int
    default_rank: int | None
    site: tuple[float, float] | None


class RegionDb:
    """An opened region database."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self._connection = sqlite3.connect(f"file:{self.path}?mode=ro", uri=True)
        version = self._connection.execute("PRAGMA user_version").fetchone()[0]
        if version > FORMAT_VERSION:
            raise RegionDbError(
                f"{self.path} declares format version {version}; this reader understands "
                f"{FORMAT_VERSION}"
            )
        if version < 1:
            raise RegionDbError(f"{self.path} is not a region database")
        self.format_version = version
        self.metadata = dict(self._connection.execute("SELECT key, value FROM metadata"))
        self._has_lookup_ranges = (
            self._connection.execute("SELECT 1 FROM lookup_ranges LIMIT 1").fetchone()
            is not None
        )
        self._has_core_parts = {
            row[0]
            for row in self._connection.execute(
                "SELECT DISTINCT region_id FROM geometry_parts WHERE role = ?", (ROLE_CORE,)
            )
        }
        self._regions = {
            row[0]: _RegionRow(
                region_id=row[0],
                region_key=row[1],
                namespace=row[2],
                code=row[3],
                display_name=row[4],
                radio_name=row[5],
                wire_code=row[6],
                kind=row[7],
                layer=row[8],
                priority=row[9],
                default_rank=row[10],
                site=(row[11], row[12]) if row[11] is not None else None,
            )
            for row in self._connection.execute(
                "SELECT id, region_key, namespace, code, display_name, radio_name, wire_code, "
                "kind, layer, priority, default_rank, site_lon, site_lat FROM regions"
            )
        }

    def close(self) -> None:
        self._connection.close()

    def __enter__(self) -> RegionDb:
        return self

    def __exit__(self, *_) -> None:
        self.close()

    @property
    def dataset_version(self) -> str:
        return self.metadata.get("dataset_version", "unknown")

    def region_keys(self) -> list[str]:
        return sorted(row.region_key for row in self._regions.values())

    def _parts(self, region_id: int, role: int) -> list[list[blob.Ring]]:
        return [
            blob.decode(row[0])
            for row in self._connection.execute(
                "SELECT geometry FROM geometry_parts WHERE region_id = ? AND role = ? ORDER BY id",
                (region_id, role),
            )
        ]

    def _covers(self, region_id: int, role: int, lon_e6: int, lat_e6: int) -> bool:
        for row in self._connection.execute(
            "SELECT geometry, min_lon, min_lat, max_lon, max_lat FROM geometry_parts "
            "WHERE region_id = ? AND role = ? ORDER BY id",
            (region_id, role),
        ):
            payload, min_lon, min_lat, max_lon, max_lat = row
            # The stored bounds are the part's own quantized extent, so a point
            # outside them cannot be on the boundary either.
            if not (
                blob.to_e6(min_lon) <= lon_e6 <= blob.to_e6(max_lon)
                and blob.to_e6(min_lat) <= lat_e6 <= blob.to_e6(max_lat)
            ):
                continue
            if blob.point_in_rings(blob.decode(payload), lon_e6, lat_e6):
                return True
        return False

    def _effective_members(self, latitude: float, longitude: float) -> list[int]:
        """The cached path: one range query plus whatever it could not decide.

        A database built without the cache has an empty lookup_ranges table,
        and the answer comes from the R-tree over the same effective polygons.
        A database built with it covers the whole key space, so a missing
        range means no coverage.
        """
        key = morton.key(latitude, longitude)
        row = self._connection.execute(
            "SELECT start_key, end_key, base_set_id, candidate_region_ids FROM lookup_ranges "
            "WHERE start_key <= ? ORDER BY start_key DESC LIMIT 1",
            (key,),
        ).fetchone()
        if row is None:
            if self._has_lookup_ranges:
                return []
            return self._rtree_members(latitude, longitude)
        _, end_key, base_set_id, candidates = row
        if key > end_key:
            return []

        payload = self._connection.execute(
            "SELECT region_ids FROM region_sets WHERE id = ?", (base_set_id,)
        ).fetchone()
        members = set(decode_region_ids(payload[0])) if payload else set()

        if candidates:
            lon_e6, lat_e6 = self._quantize(latitude, longitude)
            for region_id in decode_region_ids(candidates):
                if self._covers(region_id, ROLE_EFFECTIVE, lon_e6, lat_e6):
                    members.add(region_id)
        return sorted(members)

    def _rtree_members(self, latitude: float, longitude: float) -> list[int]:
        """Candidate regions whose effective bounding boxes cover the position."""
        lon_e6, lat_e6 = self._quantize(latitude, longitude)
        lon = blob.from_e6(lon_e6)
        lat = blob.from_e6(lat_e6)
        members: set[int] = set()
        for (region_id, payload) in self._connection.execute(
            "SELECT p.region_id, p.geometry FROM effective_rtree r "
            "JOIN geometry_parts p ON p.id = r.part_id "
            "WHERE r.min_lon <= ? AND r.max_lon >= ? AND r.min_lat <= ? AND r.max_lat >= ?",
            (lon, lon, lat, lat),
        ):
            if region_id in members:
                continue
            if blob.point_in_rings(blob.decode(payload), lon_e6, lat_e6):
                members.add(region_id)
        return sorted(members)

    def _exhaustive_members(self, latitude: float, longitude: float) -> list[int]:
        """The correctness path: test every region's effective geometry."""
        lon_e6, lat_e6 = self._quantize(latitude, longitude)
        return sorted(
            region_id
            for region_id in self._regions
            if self._covers(region_id, ROLE_EFFECTIVE, lon_e6, lat_e6)
        )

    @staticmethod
    def _quantize(latitude: float, longitude: float) -> tuple[int, int]:
        return (
            blob.to_e6(morton.normalize_longitude(longitude)),
            blob.to_e6(morton.check_latitude(latitude)),
        )

    def lookup(self, latitude: float, longitude: float, *, exhaustive: bool = False) -> Lookup:
        members = (
            self._exhaustive_members(latitude, longitude)
            if exhaustive
            else self._effective_members(latitude, longitude)
        )
        lon_e6, lat_e6 = self._quantize(latitude, longitude)

        matches: list[RegionMatch] = []
        for region_id in members:
            row = self._regions[region_id]
            # No stored core parts means the region was never expanded, so
            # its effective geometry is its core and membership here is
            # already established.
            membership = (
                MEMBERSHIP_CORE
                if region_id not in self._has_core_parts
                or self._covers(region_id, ROLE_CORE, lon_e6, lat_e6)
                else MEMBERSHIP_EXPANDED
            )
            matches.append(
                RegionMatch(
                    region_id=row.region_id,
                    region_key=row.region_key,
                    namespace=row.namespace,
                    code=row.code,
                    display_name=row.display_name,
                    radio_name=row.radio_name,
                    wire_code=row.wire_code,
                    kind=row.kind,
                    layer=row.layer,
                    priority=row.priority,
                    default_rank=row.default_rank,
                    membership=membership,
                    site=row.site,
                )
            )

        matches.sort(key=lambda item: (item.priority, item.membership, item.region_key))
        return Lookup(
            latitude=latitude,
            longitude=longitude,
            matches=tuple(matches),
            radio_regions=tuple(_radio_regions(matches)),
            suggested_default_region=_suggested_default(matches, latitude, longitude),
            dataset_version=self.dataset_version,
        )


def _radio_regions(matches: list[RegionMatch]) -> list[RadioRegion]:
    """Collapse semantic matches onto the list a radio would be given.

    Two matches that encode identically are one region as far as the radio is
    concerned — the airport and metro senses of `SFO`, for instance — so the
    first in policy order wins the slot and the rest drop out.
    """
    seen: set[int] = set()
    out: list[RadioRegion] = []
    for match in matches:
        if match.wire_code in seen:
            continue
        seen.add(match.wire_code)
        out.append(RadioRegion(name=match.radio_name, code=match.wire_code))
    return out


# Mean Earth radius, for the runtime tie-break below.
EARTH_RADIUS_M = 6_371_008.8


def site_distance(match: RegionMatch, latitude: float, longitude: float) -> float:
    """Great-circle distance from a position to a match's generating site.

    Deliberately spherical, and deliberately not the WGS84 model the build
    measures radius caps and buffers with. This distance is never a
    measurement — it only orders two candidates that are both already within a
    hundred kilometers — and making it spherical means a browser or a phone can
    reproduce the ordering with arithmetic instead of a geodesic library.

    The distinction matters more than it looks. Where two expansion buffers
    overlap, the two sites can be equidistant to within tens of meters, and
    there the ellipsoidal correction is large enough to pick the other winner.
    Two runtimes disagreeing about which region to suggest is exactly the kind
    of quiet inconsistency the conformance fixture exists to catch.
    """
    if match.site is None:
        return float("inf")
    site_longitude, site_latitude = match.site
    first = math.radians(latitude)
    second = math.radians(site_latitude)
    delta_longitude = math.radians(site_longitude - longitude)
    haversine = (
        math.sin((second - first) / 2.0) ** 2
        + math.cos(first) * math.cos(second) * math.sin(delta_longitude / 2.0) ** 2
    )
    return 2.0 * math.asin(math.sqrt(haversine)) * EARTH_RADIUS_M


def _suggested_default(
    matches: list[RegionMatch], latitude: float, longitude: float
) -> RadioRegion | None:
    """Pick the region to suggest as the packet default.

    Only the IATA-derived layers are eligible, and a core match beats an
    expanded one from the same layer. Ties among expanded matches — which
    happen wherever two expansion buffers overlap — go to the nearest site.
    """
    eligible = [match for match in matches if match.default_rank is not None]
    if not eligible:
        return None

    best = min(
        eligible,
        key=lambda item: (
            item.default_rank,
            item.membership,
            site_distance(item, latitude, longitude),
            item.region_key,
        ),
    )
    return RadioRegion(name=best.radio_name, code=best.wire_code)
