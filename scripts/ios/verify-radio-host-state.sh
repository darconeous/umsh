#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/../.." && pwd)
build_root="$repo_root/target/ios-radio-host-state"
binary="$build_root/radio-host-state-smoke"

mkdir -p "$build_root"

swiftc \
    -swift-version 6 \
    -parse-as-library \
    "$repo_root/apps/ios/UMSH/Services/MobileCore/MeshEngine.swift" \
    "$repo_root/apps/ios/UMSH/Models/RadioSnapshot.swift" \
    "$script_dir/radio-host-state-smoke.swift" \
    -o "$binary"

"$binary"
