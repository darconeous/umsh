"""Writing the compiled `.regiondb`.

The container is an ordinary SQLite database with a defined UMSH schema, so
that any platform with SQLite can read it and any developer can open it with
standard tools. Geometry is stored in the project's own blob encoding rather
than as SpatiaLite geometry, because requiring a native SQLite extension on
iOS is exactly the dependency this design is avoiding.

Reproducibility is a content guarantee rather than a byte guarantee. Rows go in
in a fixed order, the page size is pinned, nothing carries a wall-clock
timestamp that was not supplied as a build input, and the file is vacuumed the
same way every time — but SQLite makes no promise that identical logical
content yields identical bytes across versions, so what the build actually
publishes and compares is `content_hash`, taken over the normalized logical
tables.
"""

from __future__ import annotations

import hashlib
import sqlite3
from dataclasses import dataclass
from pathlib import Path

from . import blob, geom
from .cells import Leaf
from .model import ROLE_CORE, ROLE_EFFECTIVE, Region, SourceRecord

FORMAT_VERSION = 1
PAGE_SIZE = 4096

SCHEMA = """
CREATE TABLE metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE sources (
    id INTEGER PRIMARY KEY,
    source_key TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    url TEXT,
    revision TEXT,
    sha256 TEXT,
    license TEXT,
    attribution TEXT
);

CREATE TABLE regions (
    id INTEGER PRIMARY KEY,
    region_key TEXT NOT NULL UNIQUE,
    namespace TEXT NOT NULL,
    code TEXT NOT NULL,
    display_name TEXT NOT NULL,
    radio_name TEXT NOT NULL,
    wire_code INTEGER NOT NULL,
    kind TEXT NOT NULL,
    layer TEXT NOT NULL,
    priority INTEGER NOT NULL,
    default_rank INTEGER,
    expansion_m INTEGER NOT NULL DEFAULT 0,
    site_lon REAL,
    site_lat REAL,
    source_id INTEGER,
    flags INTEGER NOT NULL DEFAULT 0,
    notes TEXT,
    FOREIGN KEY(source_id) REFERENCES sources(id)
);

CREATE TABLE geometry_parts (
    id INTEGER PRIMARY KEY,
    region_id INTEGER NOT NULL,
    role INTEGER NOT NULL,
    min_lon REAL NOT NULL,
    min_lat REAL NOT NULL,
    max_lon REAL NOT NULL,
    max_lat REAL NOT NULL,
    geometry BLOB NOT NULL,
    FOREIGN KEY(region_id) REFERENCES regions(id)
);

CREATE INDEX geometry_parts_region ON geometry_parts(region_id, role);

CREATE VIRTUAL TABLE effective_rtree USING rtree(
    part_id,
    min_lon, max_lon,
    min_lat, max_lat
);

CREATE TABLE region_sets (
    id INTEGER PRIMARY KEY,
    region_ids BLOB NOT NULL
);

CREATE TABLE lookup_ranges (
    start_key INTEGER PRIMARY KEY,
    end_key INTEGER NOT NULL,
    base_set_id INTEGER NOT NULL,
    candidate_region_ids BLOB,
    FOREIGN KEY(base_set_id) REFERENCES region_sets(id)
);

CREATE TABLE provenance (
    region_id INTEGER NOT NULL,
    source_id INTEGER,
    source_feature_id TEXT,
    detail TEXT,
    PRIMARY KEY(region_id, source_id, source_feature_id, detail)
);
"""


@dataclass
class EmitStats:
    regions: int
    parts: int
    core_vertices: int
    effective_vertices: int
    region_sets: int
    lookup_ranges: int
    size_bytes: int
    content_hash: str


def encode_region_ids(identifiers: tuple[int, ...] | list[int]) -> bytes:
    """Pack a sorted region-id set as varint gaps.

    Sets repeat heavily across the lookup ranges and are interned, so the
    encoding is chosen for compactness rather than random access; a reader
    walks the whole set anyway.
    """
    out = bytearray()
    previous = 0
    for identifier in sorted(identifiers):
        if identifier <= previous - 1:
            raise ValueError("region id set must be strictly increasing after sorting")
        gap = identifier - previous
        while True:
            byte = gap & 0x7F
            gap >>= 7
            if gap:
                out.append(byte | 0x80)
            else:
                out.append(byte)
                break
        previous = identifier
    return bytes(out)


def decode_region_ids(data: bytes) -> list[int]:
    identifiers: list[int] = []
    value = 0
    shift = 0
    current = 0
    for byte in data:
        value |= (byte & 0x7F) << shift
        if byte & 0x80:
            shift += 7
            continue
        current += value
        identifiers.append(current)
        value = 0
        shift = 0
    return identifiers


def write(
    path: Path,
    *,
    regions: list[Region],
    sources: list[SourceRecord],
    leaves: list[Leaf],
    metadata: dict[str, str],
) -> EmitStats:
    """Write the database, replacing anything already at `path`."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        path.unlink()

    connection = sqlite3.connect(path)
    try:
        connection.execute(f"PRAGMA page_size = {PAGE_SIZE}")
        connection.execute("PRAGMA journal_mode = DELETE")
        connection.executescript(SCHEMA)
        connection.execute(f"PRAGMA user_version = {FORMAT_VERSION}")

        source_ids = {}
        for index, source in enumerate(sorted(sources, key=lambda item: item.source_key), start=1):
            source_ids[source.source_key] = index
            connection.execute(
                "INSERT INTO sources (id, source_key, name, url, revision, sha256, license, "
                "attribution) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    index,
                    source.source_key,
                    source.name,
                    source.url,
                    source.revision,
                    source.sha256,
                    source.license,
                    source.attribution,
                ),
            )

        ordered = sorted(regions, key=lambda item: (item.priority, item.region_key))
        region_ids = {region.region_key: index for index, region in enumerate(ordered, start=1)}

        part_id = 0
        core_vertices = 0
        effective_vertices = 0
        for region in ordered:
            identifier = region_ids[region.region_key]
            connection.execute(
                "INSERT INTO regions (id, region_key, namespace, code, display_name, radio_name, "
                "wire_code, kind, layer, priority, default_rank, expansion_m, site_lon, site_lat, "
                "source_id, flags, notes) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    identifier,
                    region.region_key,
                    region.namespace,
                    region.code,
                    region.display_name,
                    region.radio_name,
                    region.wire_code,
                    region.kind,
                    region.layer,
                    region.priority,
                    region.default_rank,
                    region.expansion_m,
                    region.site.longitude if region.site else None,
                    region.site.latitude if region.site else None,
                    source_ids.get(region.source_key) if region.source_key else None,
                    region.flags,
                    region.notes,
                ),
            )

            for detail in region.provenance:
                connection.execute(
                    "INSERT OR IGNORE INTO provenance (region_id, source_id, source_feature_id, "
                    "detail) VALUES (?, ?, ?, ?)",
                    (
                        identifier,
                        source_ids.get(region.source_key) if region.source_key else None,
                        region.source_feature_id,
                        detail,
                    ),
                )

            # A region with no expansion has identical core and effective
            # geometry, and storing both would double the administrative
            # layers for nothing. Core parts are written only when expansion
            # actually moved the boundary; a reader that finds no core parts
            # for a region takes its effective geometry as the core.
            effective = region.effective if region.effective is not None else region.core
            roles = [(ROLE_EFFECTIVE, effective)]
            if region.expansion_m > 0:
                roles.insert(0, (ROLE_CORE, region.core))
            for role, geometry in roles:
                for rings in geom.to_parts(geometry):
                    payload = blob.encode(rings)
                    longitudes = [point[0] for ring in rings for point in ring.points]
                    latitudes = [point[1] for ring in rings for point in ring.points]
                    vertex_count = len(longitudes)
                    if role == ROLE_CORE:
                        core_vertices += vertex_count
                    else:
                        effective_vertices += vertex_count
                    part_id += 1
                    bounds = (
                        blob.from_e6(min(longitudes)),
                        blob.from_e6(min(latitudes)),
                        blob.from_e6(max(longitudes)),
                        blob.from_e6(max(latitudes)),
                    )
                    connection.execute(
                        "INSERT INTO geometry_parts (id, region_id, role, min_lon, min_lat, "
                        "max_lon, max_lat, geometry) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                        (part_id, identifier, role, *bounds, payload),
                    )
                    if role == ROLE_EFFECTIVE:
                        connection.execute(
                            "INSERT INTO effective_rtree (part_id, min_lon, max_lon, min_lat, "
                            "max_lat) VALUES (?, ?, ?, ?, ?)",
                            (part_id, bounds[0], bounds[2], bounds[1], bounds[3]),
                        )

        set_ids: dict[bytes, int] = {}
        for leaf in leaves:
            payload = encode_region_ids(leaf.base)
            if payload not in set_ids:
                set_ids[payload] = len(set_ids) + 1
                connection.execute(
                    "INSERT INTO region_sets (id, region_ids) VALUES (?, ?)",
                    (set_ids[payload], payload),
                )
            candidates = encode_region_ids(leaf.candidates) if leaf.candidates else None
            connection.execute(
                "INSERT INTO lookup_ranges (start_key, end_key, base_set_id, "
                "candidate_region_ids) VALUES (?, ?, ?, ?)",
                (leaf.start_key, leaf.end_key, set_ids[payload], candidates),
            )

        for key, value in sorted(metadata.items()):
            connection.execute("INSERT INTO metadata (key, value) VALUES (?, ?)", (key, str(value)))

        content_hash = compute_content_hash(connection)
        connection.execute(
            "INSERT INTO metadata (key, value) VALUES ('content_hash', ?)", (content_hash,)
        )
        connection.commit()
        connection.execute("VACUUM")
        connection.commit()
    finally:
        connection.close()

    return EmitStats(
        regions=len(regions),
        parts=part_id,
        core_vertices=core_vertices,
        effective_vertices=effective_vertices,
        region_sets=len(set_ids),
        lookup_ranges=len(leaves),
        size_bytes=path.stat().st_size,
        content_hash=content_hash,
    )


def compute_content_hash(connection: sqlite3.Connection) -> str:
    """Hash the logical content of the database, ignoring SQLite's layout.

    This is the reproducibility guarantee: two builds of the same inputs agree
    here even if their files differ byte for byte.
    """
    digest = hashlib.sha256()
    digest.update(f"format_version={FORMAT_VERSION}\n".encode())
    queries = (
        (
            "sources",
            "SELECT source_key, name, url, revision, sha256, license, attribution "
            "FROM sources ORDER BY source_key",
        ),
        (
            "regions",
            "SELECT region_key, namespace, code, display_name, radio_name, wire_code, "
            "kind, layer, priority, default_rank, expansion_m, site_lon, site_lat, flags, "
            "notes FROM regions ORDER BY region_key",
        ),
        (
            "parts",
            "SELECT r.region_key, p.role, p.geometry FROM geometry_parts p "
            "JOIN regions r ON r.id = p.region_id "
            "ORDER BY r.region_key, p.role, p.id",
        ),
        (
            "ranges",
            "SELECT start_key, end_key, base_set_id, candidate_region_ids "
            "FROM lookup_ranges ORDER BY start_key",
        ),
        ("sets", "SELECT id, region_ids FROM region_sets ORDER BY id"),
        (
            "provenance",
            "SELECT r.region_key, p.source_feature_id, p.detail FROM provenance p "
            "JOIN regions r ON r.id = p.region_id "
            "ORDER BY r.region_key, p.source_feature_id, p.detail",
        ),
        ("metadata", "SELECT key, value FROM metadata WHERE key <> 'content_hash' ORDER BY key"),
    )
    for label, query in queries:
        digest.update(f"[{label}]\n".encode())
        for row in connection.execute(query):
            for column in row:
                if isinstance(column, bytes):
                    digest.update(b"b:" + column.hex().encode())
                else:
                    digest.update(f"v:{column!r}".encode())
                digest.update(b"\x1f")
            digest.update(b"\x1e")
    return digest.hexdigest()
