#!/bin/sh
set -eu
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/../.." && pwd)
build_root="$repo_root/target/ios-radio-session-recovery"
core_root="$repo_root/target/ios-mobile-core"
mkdir -p "$build_root"
export CLANG_MODULE_CACHE_PATH="$build_root/module-cache"
swiftc -swift-version 6 -emit-module \
    -emit-module-path "$build_root/UMSHMobileCore.swiftmodule" \
    -emit-library -o "$build_root/libUMSHMobileCore.dylib" \
    -module-name UMSHMobileCore \
    "$repo_root/packages/UMSHMobileCore/Sources/UMSHMobileCore/UMSHMobileCore.swift" \
    -I "$core_root/headers" -L "$core_root/host/release" -lumsh_mobile_core
swiftc -swift-version 6 -parse-as-library \
    "$repo_root/apps/ios/UMSH/Services/Radio/UlcpRadioSession.swift" \
    "$repo_root/apps/ios/UMSH/Services/Radio/RadioLinkLifecycle.swift" \
    "$repo_root/apps/ios/UMSH/Services/Radio/RadioConnection.swift" \
    "$repo_root/apps/ios/UMSH/Services/Radio/BluetoothErrorText.swift" \
    "$repo_root/apps/ios/UMSH/Services/MobileCore/MeshEngine.swift" \
    "$repo_root/apps/ios/UMSH/Features/RemoteManagement/RemoteCategoryReading.swift" \
    "$repo_root/apps/ios/UMSH/Models/RadioSnapshot.swift" \
    "$repo_root/apps/ios/UMSH/Models/DiscoveredRadio.swift" \
    "$script_dir/radio-session-recovery-smoke.swift" \
    -I "$build_root" -I "$core_root/headers" \
    -L "$build_root" -lUMSHMobileCore \
    -L "$core_root/host/release" -lumsh_mobile_core \
    -o "$build_root/radio-session-recovery-smoke"
DYLD_LIBRARY_PATH="$build_root:$core_root/host/release" "$build_root/radio-session-recovery-smoke"
