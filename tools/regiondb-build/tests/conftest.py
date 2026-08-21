from __future__ import annotations

import pathlib

import pytest

from paths import FIXTURE_DB, FIXTURE_ROOT, REGIONS


@pytest.fixture(scope="session")
def regions_dir() -> pathlib.Path:
    return REGIONS


@pytest.fixture(scope="session")
def fixture_root() -> pathlib.Path:
    return FIXTURE_ROOT


@pytest.fixture(scope="session")
def fixture_db() -> pathlib.Path:
    if not FIXTURE_DB.exists():
        pytest.fail(
            f"{FIXTURE_DB} is missing. It is a committed build output; "
            "run `make regions-build-fixture` to regenerate it."
        )
    return FIXTURE_DB
