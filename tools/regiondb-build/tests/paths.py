"""Shared paths for the test suite."""

from __future__ import annotations

import pathlib

REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]
REGIONS = REPO_ROOT / "regions"
FIXTURE_ROOT = REGIONS / "tests" / "fixture"
FIXTURE_DB = FIXTURE_ROOT / "fixture.regiondb"
