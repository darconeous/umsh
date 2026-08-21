"""The cache-off lookup path.

The committed fixture keeps the range cache on, so this suite builds a
cache-off copy of the same source tree and proves the R-tree path answers
identically. The global database ships this way, and a path only the largest
database uses is exactly the path that must not go untested.
"""

from __future__ import annotations

import shutil
import sqlite3

import pytest

from paths import FIXTURE_ROOT, REGIONS
from regiondb_build import build as build_module
from regiondb_build import validate
from regiondb_build.lookup import RegionDb


@pytest.fixture(scope="module")
def cache_off_db(tmp_path_factory):
    root = tmp_path_factory.mktemp("cache-off") / "fixture"
    shutil.copytree(FIXTURE_ROOT, root)
    (root / "fixture.regiondb").unlink()
    policy = root / "policy.yaml"
    text = policy.read_text()
    assert "enabled: true\n  max_depth: 12" in text
    policy.write_text(
        text.replace("enabled: true\n  max_depth: 12", "enabled: false\n  max_depth: 12")
    )
    output = root / "cache-off.regiondb"
    build_module.build(root, output, dataset_version="fixture-1")
    return output


def test_cache_off_database_has_no_ranges(cache_off_db):
    connection = sqlite3.connect(f"file:{cache_off_db}?mode=ro", uri=True)
    assert connection.execute("SELECT COUNT(*) FROM lookup_ranges").fetchone()[0] == 0
    connection.close()


def test_rtree_path_matches_the_cached_database(cache_off_db):
    with RegionDb(cache_off_db) as no_cache, RegionDb(FIXTURE_ROOT / "fixture.regiondb") as cached:
        for latitude, longitude in [
            (37.5119, -122.2495),
            (37.6189, -122.3750),
            (37.58, -122.15),
            (41.9, -120.0),
            (10.0, -150.0),
            (0.0, 180.0),
        ]:
            a = no_cache.lookup(latitude, longitude)
            b = cached.lookup(latitude, longitude)
            assert [m.region_key for m in a.matches] == [m.region_key for m in b.matches]
            assert a.radio_regions == b.radio_regions
            assert a.suggested_default_region == b.suggested_default_region


def test_rtree_path_agrees_with_exhaustive_scan(cache_off_db):
    with RegionDb(cache_off_db) as db:
        assert validate.check_sampling(db, 1500, seed=11) == []


def test_known_points_hold_without_the_cache(cache_off_db):
    with RegionDb(cache_off_db) as db:
        assert validate.check_points(db, REGIONS / "tests" / "known-points.yaml") == []
