#!/bin/sh
# Copy the region database into the app bundle's resources.
#
# Runs as an Xcode shell-script build phase, after the resources phase.
# The bundled copy is the released database, not a degraded fallback: the
# app must answer region lookups on first run, offline, with no download.
#
# A tree that has never run `make regions-build` has no world database.
# Development builds fall back to the committed Bay Area fixture so a
# fresh clone still compiles and runs, loudly; an archive (ACTION=install)
# refuses instead, because a shipped build carrying the fixture would
# answer almost everywhere with nothing and the Bay Area with test
# rectangles.
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/../.." && pwd)
world="$repo_root/regions/dist/world.regiondb"
fixture="$repo_root/regions/tests/fixture/fixture.regiondb"

if [ -n "${BUILT_PRODUCTS_DIR:-}" ] && [ -n "${UNLOCALIZED_RESOURCES_FOLDER_PATH:-}" ]; then
    destination="$BUILT_PRODUCTS_DIR/$UNLOCALIZED_RESOURCES_FOLDER_PATH/world.regiondb"
elif [ $# -eq 1 ]; then
    destination="$1"
else
    echo "usage: stage-regiondb.sh <destination>  (or run as an Xcode build phase)" >&2
    exit 2
fi

if [ -f "$world" ]; then
    cp "$world" "$destination"
    echo "Staged region database: $world"
elif [ "${ACTION:-build}" = "install" ]; then
    echo "error: no regions/dist/world.regiondb — an archive must carry the real" >&2
    echo "world database, not the test fixture. Run: make regions-build" >&2
    exit 1
else
    cp "$fixture" "$destination"
    echo "warning: no regions/dist/world.regiondb; bundled the Bay Area test" >&2
    echo "fixture instead. Build the real database with: make regions-build" >&2
fi
