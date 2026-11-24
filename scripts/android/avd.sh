#!/bin/sh
# The emulators the Android app is developed and tested on.
#
#   avd.sh create          make any missing AVD, then set each one up
#   avd.sh start NAME      start NAME with a window, wait for it to boot,
#                          and keep its screen on
#
# Both are arm64 images run under the Mac's hypervisor, drawn by the host's
# GPU (the default software renderer makes every frame CPU work), with the
# Mac's keyboard passed through. A setting changed on an AVD that is running
# takes effect at its next cold boot.
set -eu

: "${ANDROID_HOME:?set ANDROID_HOME to the Android SDK}"
avdmanager="$ANDROID_HOME/cmdline-tools/latest/bin/avdmanager"
emulator="$ANDROID_HOME/emulator/emulator"
adb="$ANDROID_HOME/platform-tools/adb"
avd_home="${ANDROID_AVD_HOME:-$HOME/.android/avd}"

# name api device ("" for the emulator's small default screen)
avds="umsh-api31 31 -
umsh-api36 36 pixel_7"

set_key() { # file key value
    if grep -q "^$2=" "$1"; then
        sed -i '' "s|^$2=.*|$2=$3|" "$1"
    else
        printf '%s=%s\n' "$2" "$3" >> "$1"
    fi
}

create() {
    echo "$avds" | while read -r name api device; do
        image="system-images;android-$api;default;arm64-v8a"
        if [ ! -d "$avd_home/$name.avd" ]; then
            if [ ! -d "$ANDROID_HOME/system-images/android-$api/default/arm64-v8a" ]; then
                echo "$name needs its system image; install it, accepting its license:"
                echo "  $ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager \"$image\""
                exit 1
            fi
            if [ "$device" = - ]; then
                echo no | "$avdmanager" create avd -n "$name" -k "$image"
            else
                echo no | "$avdmanager" create avd -n "$name" -k "$image" -d "$device"
            fi
        fi
        config="$avd_home/$name.avd/config.ini"
        set_key "$config" hw.gpu.enabled yes
        set_key "$config" hw.gpu.mode host
        set_key "$config" hw.keyboard yes
        set_key "$config" hw.ramSize 4096M
        set_key "$config" hw.cpu.ncore 4
        # The back camera is the emulator's virtual scene, so the QR scanner
        # runs through the real camera pipeline: start the emulator with
        # `-virtualscene-poster wall=<png>` to hang a code in the room.
        set_key "$config" hw.camera.back virtualscene
        echo "$name ready"
    done
}

start() {
    name="$1"
    [ -d "$avd_home/$name.avd" ] || { echo "no AVD $name; run: make android-avd"; exit 1; }
    for serial in $("$adb" devices | awk '/^emulator-/ { print $1 }'); do
        if [ "$("$adb" -s "$serial" emu avd name 2>/dev/null | head -1 | tr -d '\r')" = "$name" ]; then
            echo "$name is already running as $serial"
            return
        fi
    done
    mkdir -p build
    log="build/emulator-$name.log"
    nohup "$emulator" -avd "$name" > "$log" 2>&1 &
    echo "starting $name (log: $log)"
    # The new instance is the emulator serial that reports this AVD.
    serial=
    while [ -z "$serial" ]; do
        kill -0 $! 2>/dev/null || { echo "the emulator exited; see $log"; exit 1; }
        sleep 2
        for candidate in $("$adb" devices | awk '/^emulator-/ { print $1 }'); do
            if [ "$("$adb" -s "$candidate" emu avd name 2>/dev/null | head -1 | tr -d '\r')" = "$name" ]; then
                serial="$candidate"
            fi
        done
    done
    until [ "$("$adb" -s "$serial" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = 1 ]; do
        kill -0 $! 2>/dev/null || { echo "the emulator exited; see $log"; exit 1; }
        sleep 2
    done
    "$adb" -s "$serial" shell svc power stayon true
    "$adb" -s "$serial" shell input keyevent KEYCODE_WAKEUP
    echo "$name is up as $serial"
}

case "${1:-}" in
    create) create ;;
    start) start "${2:?start needs an AVD name}" ;;
    *) echo "usage: $0 create | start NAME" >&2; exit 2 ;;
esac
