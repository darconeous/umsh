"""The distillation pass, against the synthetic vendor fixture."""

from __future__ import annotations

import shutil

import pytest

from paths import REGIONS
from regiondb_build import extract

VENDOR_FIXTURE = REGIONS / "tests" / "vendor-fixture"


@pytest.fixture
def vendor_tree(tmp_path):
    root = tmp_path / "regions"
    (root / "vendor").mkdir(parents=True)
    for name in ("airports.csv", "citycodes.csv"):
        shutil.copy(VENDOR_FIXTURE / name, root / "vendor" / name)
    (root / "upstream").mkdir()
    (root / "upstream" / "lock.json").write_text(
        '{"version": 1, "sources": {"ourairports-airports": '
        '{"url": "https://example.invalid/airports.csv", "sha256": "abc", '
        '"retrieved_at": "2026-08-21T00:00:00Z"}}}'
    )
    return root


def _sites(vendor_tree):
    sites, candidates, _ = extract.airports(vendor_tree / "vendor", {})
    return {row["iata"]: row for row in sites}, {row["iata"] for row in candidates}


def test_keeps_ordinary_records(vendor_tree):
    sites, _ = _sites(vendor_tree)
    assert set(sites) >= {"SFO", "SQL", "PAO", "SJC"}
    assert sites["SFO"]["name"] == "San Francisco International Airport"
    assert sites["SFO"]["iso_country"] == "US"


def test_drops_closed_facilities(vendor_tree):
    sites, _ = _sites(vendor_tree)
    assert "CLS" not in sites


def test_drops_records_without_a_three_letter_iata_code(vendor_tree):
    sites, _ = _sites(vendor_tree)
    assert all(len(code) == 3 for code in sites)


def test_drops_out_of_range_latitudes(vendor_tree):
    sites, _ = _sites(vendor_tree)
    assert "BAD" not in sites


def test_normalizes_longitude_into_range(vendor_tree):
    sites, _ = _sites(vendor_tree)
    assert float(sites["WRP"]["longitude_deg"]) == pytest.approx(-170.0)


def test_commercial_candidates_come_from_scheduled_service(vendor_tree):
    _, candidates = _sites(vendor_tree)
    # SQL is a candidate here precisely so the committed classification has
    # something to exclude; PAO never claims scheduled service.
    assert candidates == {"SFO", "SQL", "SJC"}


def test_heliports_are_excluded_entirely(vendor_tree):
    sites, candidates = _sites(vendor_tree)
    # Excluded across the board for the time being: a helipad's IATA code
    # names a rooftop, not an area anyone would configure a repeater for.
    assert "HLP" not in sites
    assert "HLP" not in candidates


def test_refuses_to_guess_between_conflicting_duplicates(vendor_tree):
    source = vendor_tree / "vendor" / "airports.csv"
    source.write_text(
        source.read_text().replace('"Duplicate B",30.0,40.0', '"Duplicate B",31.0,41.0')
    )
    with pytest.raises(extract.ExtractError, match="conflicting positions"):
        extract.airports(vendor_tree / "vendor", {})


def test_collapses_duplicates_that_agree(vendor_tree):
    sites, _ = _sites(vendor_tree)
    assert sites["DUP"]["latitude_deg"] == "30.000000"


def test_metro_seed_ignores_codes_that_are_not_three_letters(vendor_tree):
    codes = {row["iata"] for row in extract.metro_codes(vendor_tree / "vendor")}
    assert codes == {"NYC", "LON"}


def test_output_is_sorted_and_stable(vendor_tree):
    sites, _, _ = extract.airports(vendor_tree / "vendor", {})
    codes = [row["iata"] for row in sites]
    assert codes == sorted(codes)
    again, _, _ = extract.airports(vendor_tree / "vendor", {})
    assert sites == again
