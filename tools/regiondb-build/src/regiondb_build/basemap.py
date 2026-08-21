"""Building the map viewer's basemap.

The viewer draws regions against real coastlines and borders so that a
boundary can be judged by eye — a metro circle in roughly the right place, a
Voronoi cell that does not cross an ocean. Without that context the regions
float in space and the viewer cannot do the one job it exists for.

The basemap is Natural Earth, self-hosted. That keeps the page free of
third-party requests, working offline and under `make site-preview`, and out
of any question about a tile provider's usage policy or what a viewer's
coordinates reveal to a third party. It is public domain, and the plan
document names it for exactly this purpose.

None of this is database input: nothing in a `.regiondb` comes from these
layers. They are viewer assets, generated here only because this is where the
geospatial dependencies already live.
"""

from __future__ import annotations

import glob
import json
import zipfile
from dataclasses import dataclass
from pathlib import Path

from pyogrio.raw import read as read_ogr
from shapely import from_wkb

# Coordinate precision for basemap geometry. Four decimals is about eleven
# meters, far finer than anything drawn at basemap zoom, and it roughly halves
# the file against the six decimals region geometry uses.
COORDINATE_DIGITS = 4


@dataclass(frozen=True)
class Layer:
    """One basemap layer: where it comes from and how much detail it keeps."""

    name: str
    source_id: str
    archive: str
    simplify_deg: float


LAYERS = (
    Layer("land", "naturalearth-land", "ne_50m_land.zip", 0.01),
    Layer("admin0", "naturalearth-admin0-lines", "ne_50m_admin_0_boundary_lines_land.zip", 0.01),
    Layer("admin1", "naturalearth-admin1-lines", "ne_50m_admin_1_states_provinces_lines.zip", 0.02),
)

# Natural Earth ranks places by prominence; rank 0 is a world capital and the
# numbers climb as towns get smaller. Keeping the low ranks gives enough
# labels to orient by without burying the regions being inspected.
PLACE_SCALERANK_MAX = 4


class BasemapError(RuntimeError):
    """The basemap could not be built from the fetched sources."""


def _round(value: float) -> float:
    return round(value, COORDINATE_DIGITS)


def _round_coordinates(node):
    if isinstance(node, (int, float)):
        return _round(float(node))
    return [_round_coordinates(item) for item in node]


def _extracted_shapefile(vendor: Path, work: Path, archive: str) -> str:
    path = vendor / archive
    if not path.exists():
        raise BasemapError(
            f"{path} is missing. Run `regiondb-build fetch` first: the basemap is built "
            "from pinned Natural Earth downloads."
        )
    destination = work / archive.replace(".zip", "")
    destination.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path) as archive_file:
        archive_file.extractall(destination)
    found = glob.glob(str(destination / "**" / "*.shp"), recursive=True)
    if not found:
        raise BasemapError(f"{path} contains no shapefile")
    return found[0]


def build(vendor: Path, work: Path, destination: Path) -> list[str]:
    """Write the viewer's basemap files, returning a line per layer."""
    destination.mkdir(parents=True, exist_ok=True)
    work.mkdir(parents=True, exist_ok=True)
    report: list[str] = []

    for layer in LAYERS:
        shapefile = _extracted_shapefile(vendor, work, layer.archive)
        _, _, geometry, _ = read_ogr(shapefile)
        features = []
        for payload in geometry:
            shape = from_wkb(payload)
            if layer.simplify_deg > 0:
                shape = shape.simplify(layer.simplify_deg, preserve_topology=True)
            if shape.is_empty:
                continue
            mapping = shape.__geo_interface__
            features.append(
                {
                    "type": "Feature",
                    "properties": {},
                    "geometry": {
                        "type": mapping["type"],
                        "coordinates": _round_coordinates(mapping["coordinates"]),
                    },
                }
            )
        document = {"type": "FeatureCollection", "features": features}
        path = destination / f"{layer.name}.geojson"
        path.write_text(json.dumps(document, separators=(",", ":")) + "\n")
        report.append(f"{layer.name}: {len(features)} features, {path.stat().st_size / 1e6:.2f} MB")

    report.append(_build_places(vendor, work, destination))
    return report


def _build_places(vendor: Path, work: Path, destination: Path) -> str:
    """City points, as a flat array rather than GeoJSON.

    Every one is a bare point with a label; a FeatureCollection would spend
    more bytes on its own scaffolding than on the data.
    """
    shapefile = _extracted_shapefile(vendor, work, "ne_50m_populated_places_simple.zip")
    meta, _, geometry, fields = read_ogr(shapefile)
    names = list(meta["fields"])
    labels = fields[names.index("name")]
    ranks = fields[names.index("scalerank")]

    places = []
    for index, payload in enumerate(geometry):
        if int(ranks[index]) > PLACE_SCALERANK_MAX:
            continue
        point = from_wkb(payload)
        places.append([str(labels[index]), _round(point.x), _round(point.y)])
    places.sort(key=lambda entry: (entry[0], entry[1], entry[2]))

    path = destination / "places.json"
    path.write_text(json.dumps(places, separators=(",", ":")) + "\n")
    return f"places: {len(places)} cities, {path.stat().st_size / 1e6:.2f} MB"
