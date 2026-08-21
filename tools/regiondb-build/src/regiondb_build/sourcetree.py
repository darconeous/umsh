"""Reading a committed source tree.

Both the global database and the test fixture are compiled from a directory
with this shape, so the fixture exercises the real loading code rather than a
simplified stand-in:

    <root>/policy.yaml
    <root>/extracts/iata-locations.csv
    <root>/extracts/commercial-airport-candidates.csv
    <root>/extracts/metro-codes.csv
    <root>/extracts/boundaries/country/<ISO2>.geojson
    <root>/extracts/boundaries/us-state/<USPS>.geojson
    <root>/classifications/commercial-airports.yaml
    <root>/metros/metros.yaml
    <root>/custom/regions.yaml
    <root>/overrides/overrides.yaml

Nothing here reads `<root>/vendor/`: the build consumes committed files only.
"""

from __future__ import annotations

import csv
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from shapely.geometry import shape
from shapely.geometry.base import BaseGeometry

from .model import Site

IATA_LOCATIONS_COLUMNS = [
    "iata",
    "ident",
    "type",
    "name",
    "latitude_deg",
    "longitude_deg",
    "iso_country",
    "iso_region",
    "municipality",
    "scheduled_service",
]

COMMERCIAL_CANDIDATE_COLUMNS = [
    "iata",
    "name",
    "latitude_deg",
    "longitude_deg",
    "iso_country",
    "municipality",
    "type",
    "scheduled_service",
]

METRO_CODE_COLUMNS = ["iata", "name", "iso_country"]


class SourceError(ValueError):
    """A source file is missing, malformed, or internally inconsistent."""


@dataclass
class ClassificationOverride:
    iata: str
    commercial: bool
    reason: str
    evidence: tuple[str, ...] = ()


@dataclass
class MetroDefinition:
    region_id: str
    iata: str
    name: str
    geometry: BaseGeometry
    expansion_m: int | None
    interpretation: str | None
    confidence: str | None
    source_name: str | None


@dataclass
class CustomDefinition:
    region_id: str
    name: str
    radio_name: str
    geometry: BaseGeometry
    expansion_m: int | None
    priority: int
    allow_short_code: bool
    notes: str | None


@dataclass
class OverrideDefinition:
    override_id: str
    layer: str
    operation: str
    target: str | None
    geometry: BaseGeometry
    priority: int
    reason: str


@dataclass
class BoundaryFeature:
    code: str
    name: str
    geometry: BaseGeometry
    feature_id: str | None


@dataclass
class SourceTree:
    root: Path
    sites: list[Site] = field(default_factory=list)
    commercial_candidates: set[str] = field(default_factory=set)
    metro_codes: dict[str, str] = field(default_factory=dict)
    classifications: dict[str, ClassificationOverride] = field(default_factory=dict)
    metros: list[MetroDefinition] = field(default_factory=list)
    customs: list[CustomDefinition] = field(default_factory=list)
    overrides: list[OverrideDefinition] = field(default_factory=list)
    countries: list[BoundaryFeature] = field(default_factory=list)
    states: list[BoundaryFeature] = field(default_factory=list)


def _read_csv(path: Path, expected: list[str]) -> list[dict[str, str]]:
    """Read an extract, skipping its provenance header.

    Extracts are machine-written and carry a `#` comment block naming the
    source they came from, so that a file in a diff can be traced without
    consulting the lock.
    """
    if not path.exists():
        return []
    lines = [line for line in path.read_text().splitlines() if not line.startswith("#")]
    reader = csv.DictReader(lines)
    if reader.fieldnames != expected:
        raise SourceError(f"{path} has columns {reader.fieldnames}, expected {expected}")
    return list(reader)


def load_geojson(path: Path) -> BaseGeometry:
    if not path.exists():
        raise SourceError(f"missing geometry file {path}")
    document = json.loads(path.read_text())
    kind = document.get("type")
    if kind == "FeatureCollection":
        features = document.get("features", [])
        if len(features) != 1:
            raise SourceError(f"{path} holds {len(features)} features; expected exactly one")
        return shape(features[0]["geometry"])
    if kind == "Feature":
        return shape(document["geometry"])
    if kind in {"Polygon", "MultiPolygon"}:
        return shape(document)
    raise SourceError(f"{path} is a {kind!r}; only Polygon or MultiPolygon geometry is accepted")


def _load_manifest(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    document = yaml.safe_load(path.read_text())
    return document if isinstance(document, dict) else {}


def load(root: Path) -> SourceTree:
    tree = SourceTree(root=root)
    extracts = root / "extracts"

    seen: dict[str, Site] = {}
    for row in _read_csv(extracts / "iata-locations.csv", IATA_LOCATIONS_COLUMNS):
        site = Site(
            iata=row["iata"],
            name=row["name"],
            latitude=float(row["latitude_deg"]),
            longitude=float(row["longitude_deg"]),
            kind=row["type"],
            iso_country=row["iso_country"],
            iso_region=row["iso_region"],
            municipality=row["municipality"],
            scheduled_service=row["scheduled_service"] == "yes",
            source_id=row["ident"],
        )
        if site.iata in seen:
            raise SourceError(
                f"duplicate IATA code {site.iata} in iata-locations.csv "
                f"({seen[site.iata].source_id} and {site.source_id}); "
                "the update pass must resolve this, never pick one arbitrarily"
            )
        seen[site.iata] = site
        tree.sites.append(site)

    candidates_path = extracts / "commercial-airport-candidates.csv"
    for row in _read_csv(candidates_path, COMMERCIAL_CANDIDATE_COLUMNS):
        tree.commercial_candidates.add(row["iata"])

    for row in _read_csv(extracts / "metro-codes.csv", METRO_CODE_COLUMNS):
        tree.metro_codes[row["iata"]] = row["name"]

    classifications = _load_manifest(root / "classifications" / "commercial-airports.yaml")
    for iata, entry in (classifications.get("overrides") or {}).items():
        tree.classifications[iata.upper()] = ClassificationOverride(
            iata=iata.upper(),
            commercial=bool(entry["commercial"]),
            reason=str(entry.get("reason", "")),
            evidence=tuple(entry.get("evidence", ())),
        )

    metros_path = root / "metros" / "metros.yaml"
    for entry in _load_manifest(metros_path).get("metros") or []:
        geometry_path = (metros_path.parent / entry["geometry"]).resolve()
        tree.metros.append(
            MetroDefinition(
                region_id=entry["id"],
                iata=entry["iata"].upper(),
                name=entry["name"],
                geometry=load_geojson(geometry_path),
                expansion_m=entry.get("expansion_m"),
                interpretation=entry.get("interpretation"),
                confidence=entry.get("confidence"),
                source_name=(entry.get("source") or {}).get("name"),
            )
        )

    custom_path = root / "custom" / "regions.yaml"
    for entry in _load_manifest(custom_path).get("regions") or []:
        geometry_path = (custom_path.parent / entry["geometry"]).resolve()
        tree.customs.append(
            CustomDefinition(
                region_id=entry["id"],
                name=entry["name"],
                radio_name=entry.get("radio_name", entry["name"]),
                geometry=load_geojson(geometry_path),
                expansion_m=entry.get("expansion_m"),
                priority=int(entry.get("priority", 0)),
                allow_short_code=bool(entry.get("allow_short_code", False)),
                notes=(entry.get("source") or {}).get("notes"),
            )
        )

    overrides_path = root / "overrides" / "overrides.yaml"
    for entry in _load_manifest(overrides_path).get("overrides") or []:
        geometry_path = (overrides_path.parent / entry["geometry"]).resolve()
        tree.overrides.append(
            OverrideDefinition(
                override_id=entry["id"],
                layer=entry["layer"],
                operation=entry["operation"],
                target=entry.get("target"),
                geometry=load_geojson(geometry_path),
                priority=int(entry.get("priority", 0)),
                reason=str(entry.get("reason", "")),
            )
        )

    tree.countries = _load_boundaries(extracts / "boundaries" / "country")
    tree.states = _load_boundaries(extracts / "boundaries" / "us-state")
    return tree


def _load_boundaries(directory: Path) -> list[BoundaryFeature]:
    if not directory.is_dir():
        return []
    features: list[BoundaryFeature] = []
    for path in sorted(directory.glob("*.geojson")):
        document = json.loads(path.read_text())
        properties = document.get("properties", {}) if isinstance(document, dict) else {}
        features.append(
            BoundaryFeature(
                code=path.stem.upper(),
                name=properties.get("name", path.stem),
                geometry=load_geojson(path),
                feature_id=properties.get("source_feature_id"),
            )
        )
    return features
