"""Community region packs: delegation with a fence around it."""

from __future__ import annotations

import json
import shutil

import pytest
import yaml

from paths import FIXTURE_ROOT
from regiondb_build import sourcetree

# A box inside the fixture's Bay Area, safely away from the known points.
INFLUENCE = [[-122.60, 37.90], [-122.20, 37.90], [-122.20, 38.20], [-122.60, 38.20]]
INSIDE = [[-122.50, 37.95], [-122.40, 37.95], [-122.40, 38.05], [-122.50, 38.05]]
INSIDE_CHILD = [[-122.48, 37.97], [-122.42, 37.97], [-122.42, 38.03], [-122.48, 38.03]]
ESCAPES = [[-122.50, 37.95], [-121.90, 37.95], [-121.90, 38.05], [-122.50, 38.05]]


def _polygon(ring):
    closed = ring + [ring[0]]
    return {"type": "Feature", "geometry": {"type": "Polygon", "coordinates": [closed]}}


def _write_pack(root, *, pack_id="northbay", enabled=True, regions):
    pack = root / "communities" / pack_id
    (pack / "geometry").mkdir(parents=True)
    (pack / "geometry" / "influence.geojson").write_text(json.dumps(_polygon(INFLUENCE)))
    manifest = {
        "version": 1,
        "id": pack_id,
        "name": "North Bay Mesh",
        "maintainers": ["someone@example.net"],
        "influence": "geometry/influence.geojson",
    }
    if not enabled:
        manifest["enabled"] = False
    (pack / "pack.yaml").write_text(yaml.safe_dump(manifest))
    for name, ring in (("inside", INSIDE), ("child", INSIDE_CHILD), ("escapes", ESCAPES)):
        (pack / "geometry" / f"{name}.geojson").write_text(json.dumps(_polygon(ring)))
    (pack / "regions.yaml").write_text(yaml.safe_dump({"version": 1, "regions": regions}))
    return pack


@pytest.fixture
def tree_root(tmp_path):
    root = tmp_path / "regions"
    shutil.copytree(
        FIXTURE_ROOT,
        root,
        ignore=shutil.ignore_patterns("fixture.regiondb", "build-report.json", "vendor-fixture"),
    )
    return root


def test_pack_regions_join_the_custom_layer(tree_root):
    _write_pack(
        tree_root,
        regions=[
            {
                "id": "custom:northbay/petaluma-gap",
                "name": "Petaluma Gap",
                "geometry": "geometry/inside.geojson",
            },
            {
                "id": "custom:northbay/gap-core",
                "name": "Petaluma Gap Core",
                "geometry": "geometry/child.geojson",
                "parent": "custom:northbay/petaluma-gap",
            },
        ],
    )
    tree = sourcetree.load(tree_root)
    ids = {custom.region_id for custom in tree.customs}
    assert "custom:northbay/petaluma-gap" in ids
    assert "custom:northbay/gap-core" in ids
    # The fixture's own custom region still loads beside the pack.
    assert "custom:sf-bay-area" in ids


def test_disabled_pack_is_validated_but_not_compiled(tree_root):
    _write_pack(
        tree_root,
        enabled=False,
        regions=[
            {
                "id": "custom:northbay/petaluma-gap",
                "name": "Petaluma Gap",
                "geometry": "geometry/inside.geojson",
            }
        ],
    )
    tree = sourcetree.load(tree_root)
    assert not any(custom.region_id.startswith("custom:northbay/") for custom in tree.customs)


def test_disabled_pack_still_fails_validation(tree_root):
    _write_pack(
        tree_root,
        enabled=False,
        regions=[
            {
                "id": "custom:northbay/annex",
                "name": "Annexation",
                "geometry": "geometry/escapes.geojson",
            }
        ],
    )
    with pytest.raises(sourcetree.SourceError, match="escapes the pack's declared"):
        sourcetree.load(tree_root)


def test_region_escaping_the_influence_is_refused(tree_root):
    _write_pack(
        tree_root,
        regions=[
            {
                "id": "custom:northbay/annex",
                "name": "Annexation",
                "geometry": "geometry/escapes.geojson",
            }
        ],
    )
    with pytest.raises(sourcetree.SourceError, match="escapes the pack's declared"):
        sourcetree.load(tree_root)


def test_region_id_must_carry_the_pack_prefix(tree_root):
    _write_pack(
        tree_root,
        regions=[
            {
                "id": "custom:sf-bay-area",
                "name": "Identity theft",
                "geometry": "geometry/inside.geojson",
            }
        ],
    )
    with pytest.raises(sourcetree.SourceError, match="must start with"):
        sourcetree.load(tree_root)


def test_child_escaping_its_parent_is_refused(tree_root):
    _write_pack(
        tree_root,
        regions=[
            {
                "id": "custom:northbay/core",
                "name": "Core",
                "geometry": "geometry/child.geojson",
            },
            {
                "id": "custom:northbay/wider",
                "name": "Wider than its parent",
                "geometry": "geometry/inside.geojson",
                "parent": "custom:northbay/core",
            },
        ],
    )
    with pytest.raises(sourcetree.SourceError, match="escapes its parent"):
        sourcetree.load(tree_root)


def test_parent_must_come_first(tree_root):
    _write_pack(
        tree_root,
        regions=[
            {
                "id": "custom:northbay/child",
                "name": "Child",
                "geometry": "geometry/child.geojson",
                "parent": "custom:northbay/missing",
            }
        ],
    )
    with pytest.raises(sourcetree.SourceError, match="order\\s+parents before children"):
        sourcetree.load(tree_root)
