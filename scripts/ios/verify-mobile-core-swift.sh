#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/../.." && pwd)
build_root="$repo_root/target/ios-mobile-core"
smoke_binary="$build_root/mobile-core-swift-smoke"

if [ ! -f "$build_root/host/release/libumsh_mobile_core.dylib" ]; then
    echo "Run scripts/ios/build-mobile-core.sh first" >&2
    exit 1
fi

swiftc \
    -swift-version 6 \
    "$repo_root/packages/UMSHMobileCore/Sources/UMSHMobileCore/UMSHMobileCore.swift" \
    "$script_dir/mobile-core-smoke.swift" \
    -I "$build_root/headers" \
    -L "$build_root/host/release" \
    -lumsh_mobile_core \
    -o "$smoke_binary"

DYLD_LIBRARY_PATH="$build_root/host/release" "$smoke_binary"
