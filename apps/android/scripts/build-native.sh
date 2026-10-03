#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
: "${ANDROID_NDK_HOME:?Set ANDROID_NDK_HOME to Android NDK r28 or newer}"
case "$(uname -s)" in Linux) host=linux-x86_64;; Darwin) host=darwin-x86_64;; *) echo 'Use Linux/macOS or WSL'; exit 1;; esac
bin="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/$host/bin"
# NDK r28 supplies 16 KiB-compatible alignment for current Android devices.
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$bin/aarch64-linux-android26-clang"
export CC_aarch64_linux_android="$bin/aarch64-linux-android26-clang"
export AR_aarch64_linux_android="$bin/llvm-ar"
export CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER="$bin/x86_64-linux-android26-clang"
export CC_x86_64_linux_android="$bin/x86_64-linux-android26-clang"
export AR_x86_64_linux_android="$bin/llvm-ar"
for pair in ${UMSH_ANDROID_TARGETS:-aarch64-linux-android:arm64-v8a x86_64-linux-android:x86_64}; do
    target="${pair%%:*}"; abi="${pair#*:}"
    rustup target add "$target"
    cargo build --locked --manifest-path native/Cargo.toml --release --target "$target"
    mkdir -p "app/src/main/jniLibs/$abi"
    cp "native/target/$target/release/libumsh_android.so" "app/src/main/jniLibs/$abi/"
done
