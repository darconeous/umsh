#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/../.." && pwd)
build_root="$repo_root/target/ios-persistence"
core_root="$repo_root/target/ios-mobile-core"
binary="$build_root/persistence-smoke"

# The store imports UMSHMobileCore for its chat record types, so the module
# must be built from the generated bindings first.
if [ ! -f "$core_root/host/release/libumsh_mobile_core.dylib" ]; then
    echo "Run scripts/ios/build-mobile-core.sh first" >&2
    exit 1
fi

mkdir -p "$build_root"

swiftc \
    -swift-version 6 \
    -emit-module \
    -emit-module-path "$build_root/UMSHMobileCore.swiftmodule" \
    -emit-library -o "$build_root/libUMSHMobileCore.dylib" \
    -module-name UMSHMobileCore \
    "$repo_root/packages/UMSHMobileCore/Sources/UMSHMobileCore/UMSHMobileCore.swift" \
    -I "$core_root/headers" \
    -L "$core_root/host/release" \
    -lumsh_mobile_core

swiftc \
    -swift-version 6 \
    -parse-as-library \
    "$repo_root/apps/ios/UMSH/Services/Persistence/SQLiteApplicationStore.swift" \
    "$script_dir/persistence-smoke.swift" \
    -I "$build_root" \
    -I "$core_root/headers" \
    -L "$build_root" -lUMSHMobileCore \
    -L "$core_root/host/release" -lumsh_mobile_core \
    -o "$binary"

DYLD_LIBRARY_PATH="$build_root:$core_root/host/release" "$binary"
