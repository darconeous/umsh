.PHONY: docs rust-docs rust-docs-nightly docs-serve gh-pages web-debugger \
	build-techo-console flash-techo-console \
	build-wio-tracker-l1-console flash-wio-tracker-l1-console \
	build-t1000e-console flash-t1000e-console \
	flash-t1000e-console-serial \
	build-sensecap-solar-console flash-sensecap-solar-console \
	build-sensecap-solar flash-sensecap-solar \
	build-t1000e flash-t1000e-serial \
	build-techo flash-techo \
	build-heltec-v3-console flash-heltec-v3-console \
	build-heltec-v3 flash-heltec-v3

# ─── Firmware build / flash ──────────────────────────────────────────────────
#
# Each firmware target is built from inside its own directory so the
# per-firmware `.cargo/config.toml` (target triple + linker flags) is
# picked up. Running cargo with `--manifest-path` from the workspace
# root silently skips those flags and produces a broken ELF.
#
# `flash-*` targets convert the ELF to UF2 with the board-specific
# base address and family ID (see scripts/flash.py BOARDS dict) and
# copy it to the default bootloader mount path. The device must be in
# DFU mode first (1200-baud touch, double-tap reset, or hold the boot
# button while plugging in).
#
# `flash-<board>` flashes the **shipping image** for that board: a
# repeater and a companion radio are the same image holding different
# property values (docs/firmware-architecture.md). `<board>-console`
# is the per-board bringup harness — the only thing exercising the
# non-BLE path end to end, and the right tool before BLE stands up on a
# new board. Wio Tracker L1 has a harness and no shipping image: its
# bringup is parked at Phases 0–1.

TARGET_DIR := target/thumbv7em-none-eabihf/release

build-techo-console:
	cd firmware/techo-console && cargo build --release

flash-techo-console: build-techo-console
	scripts/flash.py --board techo --copy-default \
		$(TARGET_DIR)/firmware-techo-console

build-techo:
	cd firmware/techo && cargo build --release

flash-techo: build-techo
	scripts/flash.py --board techo --copy-default \
		$(TARGET_DIR)/firmware-techo

build-wio-tracker-l1-console:
	cd firmware/wio-tracker-l1-console && cargo build --release

flash-wio-tracker-l1-console: build-wio-tracker-l1-console
	scripts/flash.py --board wio-tracker-l1 --copy-default \
		$(TARGET_DIR)/firmware-wio-tracker-l1-console

build-t1000e-console:
	cd firmware/t1000e-console && cargo build --release

flash-t1000e-console: build-t1000e-console
	scripts/flash.py --board t1000e --copy-default \
		$(TARGET_DIR)/firmware-t1000e-console

# Serial-DFU path: required on T1000-E when the user-button bootloader entry
# exposes only /dev/tty.usbmodem* and not the UF2 mass-storage drive.
# Override the port with: make ... DFU_SERIAL_PORT=/dev/tty.usbmodem<N>
DFU_SERIAL_PORT ?= /dev/tty.usbmodem1101

flash-t1000e-console-serial: build-t1000e-console
	scripts/flash.py --board t1000e --serial-dfu $(DFU_SERIAL_PORT) \
		$(TARGET_DIR)/firmware-t1000e-console

# SenseCAP Solar Node P1-Pro. Same UF2/DFU posture as the Wio Tracker
# (Seeed XIAO nRF52840 bootloader, UF2 mass-storage drive). The board
# preset in scripts/flash.py is EXPECTED pending Phase 0 confirmation of
# the family ID and volume name.
build-sensecap-solar-console:
	cd firmware/sensecap-solar-console && cargo build --release

flash-sensecap-solar-console: build-sensecap-solar-console
	scripts/flash.py --board sensecap-solar --copy-default \
		$(TARGET_DIR)/firmware-sensecap-solar-console

build-sensecap-solar:
	cd firmware/sensecap-solar && cargo build --release

flash-sensecap-solar: build-sensecap-solar
	scripts/flash.py --board sensecap-solar --copy-default \
		$(TARGET_DIR)/firmware-sensecap-solar

build-t1000e:
	cd firmware/t1000e && cargo build --release

flash-t1000e-serial: build-t1000e
	scripts/flash.py --board t1000e --serial-dfu $(DFU_SERIAL_PORT) \
		$(TARGET_DIR)/firmware-t1000e

# ─── ESP32 firmware (firmware-esp32/ sibling workspace) ──────────────────────
#
# Espressif boards build from the excluded sibling workspace, which
# carries its own `rust-toolchain.toml` (channel = "esp", via espup).
# Each firmware is built from inside its own directory so its
# `.cargo/config.toml` (target triple + chip-quirk env overrides) is
# picked up — `-p` from the workspace root picks a wrong target.
# Flashing goes through the ROM serial bootloader via espflash over the
# CP2102 port — no UF2/DFU machinery, and the flasher cannot be bricked.
# `flash-*` targets stay attached as a serial monitor after flashing;
# override port autodetection with: make ... ESPFLASH_PORT=/dev/cu.usbserial-<N>

ESP32_TARGET_DIR := firmware-esp32/target/xtensa-esp32-none-elf/release
ESP32S3_TARGET_DIR := firmware-esp32/target/xtensa-esp32s3-none-elf/release
ESPFLASH_PORT ?=
ESPFLASH_PORT_ARG = $(if $(ESPFLASH_PORT),--port $(ESPFLASH_PORT),)
# Shared UMSH partition table. Carries the 64 KB `umsh` data partition that
# umsh_bsp_esp32::flash_store looks up by label at boot; without it the
# firmware cannot find its storage region. Flashing the table rewrites the
# layout, so a board previously flashed with the espflash default table
# loses whatever lived past the old factory partition.
ESPFLASH_PARTITIONS = --partition-table firmware-esp32/partitions-umsh.csv

build-heltec-v3-console:
	cd firmware-esp32/firmware/heltec-v3-console && cargo build --release

flash-heltec-v3-console: build-heltec-v3-console
	espflash flash --monitor $(ESPFLASH_PORT_ARG) $(ESPFLASH_PARTITIONS) \
		$(ESP32S3_TARGET_DIR)/firmware-heltec-v3-console

build-heltec-v3:
	cd firmware-esp32/firmware/heltec-v3 && cargo build --release

flash-heltec-v3: build-heltec-v3
	espflash flash --monitor $(ESPFLASH_PORT_ARG) $(ESPFLASH_PARTITIONS) \
		$(ESP32S3_TARGET_DIR)/firmware-heltec-v3

# ─── Docs ────────────────────────────────────────────────────────────────────

web-debugger:
	wasm-pack build tools/ulcp-web-debugger/engine --target web \
		--out-dir ../www/pkg --out-name umsh_ulcp_web_engine


RUSTDOC_CRATES := \
	umsh \
	umsh_core \
	umsh_crypto \
	umsh_hal \
	umsh_uri \
	umsh_chat_room \
	umsh_text \
	umsh_mac \
	umsh_node

RUSTDOC_SHARED := crates.js help.html search.index settings.html src src-files.js static.files trait.impl type.impl

docs:
	mdbook build docs/protocol/

rust-docs:
	rm -rf target/doc
	cargo doc --workspace --all-features --no-deps

rust-docs-nightly:
	rm -rf target/doc
	cargo +nightly doc --workspace --all-features --no-deps -Zrustdoc-map

docs-serve:
	mdbook serve docs/protocol/

gh-pages: docs rust-docs-nightly
	@if ! git show-ref --quiet refs/heads/gh-pages; then \
		echo "Creating gh-pages branch..."; \
		git worktree add /tmp/umsh-gh-pages --orphan -b gh-pages; \
	else \
		echo "Updating gh-pages branch..."; \
		git worktree add /tmp/umsh-gh-pages gh-pages 2>/dev/null || true; \
	fi
	rm -rf /tmp/umsh-gh-pages/docs/protocol /tmp/umsh-gh-pages/docs/rust
	mkdir -p /tmp/umsh-gh-pages/docs/protocol
	mkdir -p /tmp/umsh-gh-pages/docs/rust
	cp -r docs/protocol/book/* /tmp/umsh-gh-pages/docs/protocol/
	for path in $(RUSTDOC_SHARED) $(RUSTDOC_CRATES); do \
		cp -r target/doc/$$path /tmp/umsh-gh-pages/docs/rust/; \
	done
	cp docs/rust-index.html /tmp/umsh-gh-pages/docs/rust/index.html
	cd /tmp/umsh-gh-pages && \
		git add -A && \
		git diff --cached --quiet || git commit -m "Update GitHub Pages"
	git worktree remove /tmp/umsh-gh-pages
	@echo "gh-pages branch updated. Push with: git push origin gh-pages"
