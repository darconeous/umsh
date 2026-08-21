"""The compiled fixture database: policy, determinism, and lookups."""

from __future__ import annotations

import json
import sqlite3

import pytest

from paths import REGIONS
from regiondb_build import build as build_module
from regiondb_build import emit, validate
from regiondb_build.lookup import RegionDb

KNOWN_POINTS = REGIONS / "tests" / "known-points.yaml"
CONFORMANCE = json.loads((REGIONS / "tests" / "conformance.json").read_text())


@pytest.fixture(scope="module")
def database(fixture_db):
    with RegionDb(fixture_db) as db:
        yield db


def test_format_version_and_metadata(database):
    assert database.format_version == emit.FORMAT_VERSION
    assert database.dataset_version == "fixture-1"
    assert database.metadata["coordinate_scale"] == "1e-6"
    assert "content_hash" in database.metadata


def test_known_points(database):
    assert validate.check_points(database, KNOWN_POINTS) == []


def test_cached_and_exhaustive_lookups_agree(database):
    assert validate.check_sampling(database, 2000, seed=7) == []


def test_san_carlos_is_a_location_but_not_a_commercial_airport(database):
    result = database.lookup(37.5119, -122.2495)
    keys = {match.region_key for match in result.matches}
    assert "iata-location:SQL" in keys
    assert "iata-airport:SQL" not in keys
    assert result.suggested_default_region.name == "SFO"


def test_one_radio_region_per_wire_code(database):
    result = database.lookup(37.6189, -122.3750)
    codes = [item.code for item in result.radio_regions]
    assert len(codes) == len(set(codes))
    # SFO is matched as both an airport and a metro, and collapses to one.
    semantic = [match.region_key for match in result.matches if match.radio_name == "SFO"]
    assert len(semantic) > 1
    assert sum(1 for item in result.radio_regions if item.name == "SFO") == 1


def test_forced_override_wins_its_polygon(database):
    result = database.lookup(37.58, -122.15)
    commercial = [match for match in result.matches if match.kind == "commercial_airport"]
    core = [match for match in commercial if match.membership == 0]
    assert [match.code for match in core] == ["SJC"]


def test_metro_is_containment_not_nearest(database):
    inside = {match.region_key for match in database.lookup(37.6, -122.2).matches}
    outside = {match.region_key for match in database.lookup(38.30, -122.00).matches}
    assert "iata-metro:SFO" in inside
    assert "iata-metro:SFO" not in outside


def test_custom_region_uses_a_hashed_name(database):
    from regiondb_build import regioncode

    result = database.lookup(37.6, -122.2)
    custom = next(match for match in result.matches if match.region_key == "custom:sf-bay-area")
    assert custom.radio_name == "SF Bay Area"
    assert custom.wire_code == regioncode.from_name("SF Bay Area")


def test_expansion_produces_overlapping_neighbors(database):
    result = database.lookup(37.58, -122.15)
    memberships = {match.region_key: match.membership for match in result.matches}
    assert any(value == 1 for value in memberships.values()), memberships


def test_core_parts_are_stored_only_where_expansion_moved_the_boundary(fixture_db):
    connection = sqlite3.connect(f"file:{fixture_db}?mode=ro", uri=True)
    rows = connection.execute(
        "SELECT r.layer, r.expansion_m, COUNT(p.id) FROM regions r "
        "LEFT JOIN geometry_parts p ON p.region_id = r.id AND p.role = 0 "
        "GROUP BY r.id"
    ).fetchall()
    connection.close()
    for layer, expansion, core_parts in rows:
        if expansion == 0:
            assert core_parts == 0, layer
        else:
            assert core_parts > 0, layer


def test_conformance_cases_replay(database):
    for case in CONFORMANCE["cases"]:
        result = database.lookup(case["lat"], case["lon"])
        assert [match.region_key for match in result.matches] == case["region_keys"], case
        assert [item.name for item in result.radio_regions] == case["radio_names"], case
        assert [item.code for item in result.radio_regions] == case["wire_codes"], case
        actual_default = (
            result.suggested_default_region.code if result.suggested_default_region else None
        )
        assert actual_default == case["default_wire_code"], case


def test_build_is_deterministic(fixture_root, fixture_db, tmp_path):
    rebuilt = build_module.build(
        fixture_root, tmp_path / "rebuilt.regiondb", dataset_version="fixture-1"
    )
    committed = sqlite3.connect(f"file:{fixture_db}?mode=ro", uri=True)
    expected = committed.execute(
        "SELECT value FROM metadata WHERE key = 'content_hash'"
    ).fetchone()[0]
    committed.close()
    assert rebuilt.stats.content_hash == expected, (
        "the committed fixture database is out of step with its source tree; "
        "rebuild it with `make regions-build-fixture`"
    )
