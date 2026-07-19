#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/../.." && pwd)
build_root="$repo_root/target/ios-persistence"
binary="$build_root/persistence-smoke"

mkdir -p "$build_root"

swiftc \
    -swift-version 6 \
    -parse-as-library \
    "$repo_root/apps/ios/UMSH/Services/Persistence/SQLiteApplicationStore.swift" \
    "$script_dir/persistence-smoke.swift" \
    -o "$binary"

"$binary"
