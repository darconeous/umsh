#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/../.." && pwd)
build_root="$repo_root/target/ios-mobile-core"
generated_dir="$build_root/generated"
headers_dir="$build_root/headers"
artifact_dir="$repo_root/packages/UMSHMobileCore/Artifacts"
swift_dir="$repo_root/packages/UMSHMobileCore/Sources/UMSHMobileCore"

rm -rf "$generated_dir" "$headers_dir"
mkdir -p "$generated_dir" "$headers_dir" "$artifact_dir" "$swift_dir"

CARGO_TARGET_DIR="$build_root/host" cargo build \
    --manifest-path "$repo_root/Cargo.toml" \
    --release \
    -p umsh-mobile-core

cargo run \
    --manifest-path "$repo_root/Cargo.toml" \
    -p umsh-uniffi-bindgen \
    -- generate \
    --library "$build_root/host/release/libumsh_mobile_core.dylib" \
    --language swift \
    --out-dir "$generated_dir"

cp "$generated_dir/UMSHMobileCoreFFI.h" "$headers_dir/"
cp "$generated_dir/UMSHMobileCoreFFI.modulemap" "$headers_dir/module.modulemap"
# UniFFI's Swift template emits trailing spaces on some declaration lines.
# Normalize them so regenerated bindings remain repository-clean.
sed 's/[[:space:]]*$//' "$generated_dir/UMSHMobileCore.swift" > "$swift_dir/UMSHMobileCore.swift"

CARGO_TARGET_DIR="$build_root/rust" cargo build \
    --manifest-path "$repo_root/Cargo.toml" \
    --release \
    -p umsh-mobile-core \
    --target aarch64-apple-ios

CARGO_TARGET_DIR="$build_root/rust" cargo build \
    --manifest-path "$repo_root/Cargo.toml" \
    --release \
    -p umsh-mobile-core \
    --target aarch64-apple-ios-sim

rm -rf "$artifact_dir/UMSHMobileCoreFFI.xcframework"
xcframework="$artifact_dir/UMSHMobileCoreFFI.xcframework"
device_slice="$xcframework/ios-arm64"
simulator_slice="$xcframework/ios-arm64-simulator"
mkdir -p "$device_slice/Headers" "$simulator_slice/Headers"
cp "$build_root/rust/aarch64-apple-ios/release/libumsh_mobile_core.a" "$device_slice/"
cp "$build_root/rust/aarch64-apple-ios-sim/release/libumsh_mobile_core.a" "$simulator_slice/"
cp "$headers_dir/UMSHMobileCoreFFI.h" "$headers_dir/module.modulemap" "$device_slice/Headers/"
cp "$headers_dir/UMSHMobileCoreFFI.h" "$headers_dir/module.modulemap" "$simulator_slice/Headers/"

cp "$repo_root/scripts/ios/UMSHMobileCoreFFI.xcframework.Info.plist" "$xcframework/Info.plist"
plutil -lint "$xcframework/Info.plist"

echo "Built packages/UMSHMobileCore/Artifacts/UMSHMobileCoreFFI.xcframework"
