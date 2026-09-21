#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/../.." && pwd)
build_root="$repo_root/target/ios-radio-accessories"
binary="$build_root/radio-accessories-smoke"

mkdir -p "$build_root"
export CLANG_MODULE_CACHE_PATH="$build_root/module-cache"

swiftc -swift-version 6 -parse-as-library \
    "$repo_root/apps/ios/UMSH/Models/DiscoveredRadio.swift" \
    "$repo_root/apps/ios/UMSH/Services/Radio/RadioAccessoryInventory.swift" \
    "$script_dir/radio-accessories-smoke.swift" \
    -o "$binary"

"$binary"
