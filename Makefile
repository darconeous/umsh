.PHONY: docs rust-docs rust-docs-nightly docs-serve gh-pages web-debugger \
	site site-serve site-check site-test site-preview \
	regions-fetch regions-update regions-update-check regions-build \
	regions-build-fixture regions-check regions-test regions-diff \
	build-techo-console flash-techo-console \
	build-wio-tracker-l1-console flash-wio-tracker-l1-console \
	build-wio-tracker-l1 flash-wio-tracker-l1 \
	build-t1000e-console flash-t1000e-console \
	flash-t1000e-console-serial \
	build-sensecap-solar-console flash-sensecap-solar-console \
	build-sensecap-solar flash-sensecap-solar \
	build-xiao-nrf52 flash-xiao-nrf52 \
	build-t1000e flash-t1000e-serial \
	build-techo flash-techo flash-techo-serial \
	build-heltec-v3-console flash-heltec-v3-console \
	build-heltec-v3 flash-heltec-v3 \
	esp-toolchain-check espflash-check \
	dfu-zip-techo dfu-zip-t1000e dfu-zip-sensecap-solar \
	dfu-zip-wio-tracker-l1 dfu-zip-xiao-nrf52 \
	merged-bin-heltec-v3 \
	release-artifacts release-stage release-publish release-mirror \
	ios-mobile-core ios-archive ios-upload \
	install-umshctl install-umsh-bridge install-dissector install-extcap \
	install-colorfilters

# ─── Firmware build / flash ──────────────────────────────────────────────────
#
# Each firmware target is built from inside its own directory so the
# per-firmware `.cargo/config.toml` (target triple + linker flags) is
# picked up. Running cargo with `--manifest-path` from the workspace
# root silently skips those flags and produces a broken ELF.
#
# `build-*` targets emit the `.uf2` alongside the ELF, packed with the
# board's base address and family ID (see the BOARDS dict in
# scripts/firmware_image.py). Building is what produces a flashable
# artifact — the same one a release attaches and the web flasher will
# serve — so `flash-*` only copies it to the bootloader volume. That
# needs no toolchain beyond Rust and Python.
#
# The device must be in DFU mode before `flash-*` (1200-baud touch,
# double-tap reset, or the board's own button gesture — the T1000-E
# wants the user button held while USB power is cycled twice, not held
# through a single plug-in).
#
# `flash-<board>` flashes the **shipping image** for that board: a
# repeater and a companion radio are the same image holding different
# property values (docs/firmware-architecture.md). `<board>-console`
# is the per-board bringup harness — the only thing exercising the
# non-BLE path end to end, and the right tool before BLE stands up on a
# new board.

TARGET_DIR := target/thumbv7em-none-eabihf/release

# Release staging. `VERSION` is the release *tag* — `fw-2026.08.01`, never the
# bare number — and it defaults to the tag on HEAD, so cutting a release takes
# no argument at all:
#
#     git tag -a fw-2026.08.01 -m "UMSH firmware 2026.08.01"
#     make release-artifacts
#
# Deriving it rather than asking for it is the point: the tag already is the
# version, and the guards below already insist HEAD sits on it, so restating
# it by hand adds nothing except a way to disagree with yourself.
#
# `ifndef` rather than `?=` so the git call runs once at parse time instead of
# on every expansion; a VERSION= on the command line is already set by then
# and wins. Off a tag it falls back to `dev`, which keeps the convert-only
# targets usable on the bench and is rejected by every release target.
ifndef VERSION
VERSION := $(shell git describe --tags --exact-match --match 'fw-*' 2>/dev/null || echo dev)
endif
RELEASE_TAG = $(VERSION)

# The bare version, which is what lands in filenames, the manifest, and the
# mirror paths. `fw-` exists to namespace git refs so `git describe
# --match 'fw-*'` cannot pick up a future crate or app tag; nothing outside
# the ref namespace needs it, and `umsh-t1000e-fw-2026.08.01.uf2` reads badly.
FW_VERSION = $(patsubst fw-%,%,$(VERSION))
FW_DIR = target/firmware-release/$(FW_VERSION)

# Release targets take the tag form and nothing else. A bare `2026.08.01`
# would otherwise look plausible and then miss the tag by one prefix.
define require-release-tag
	@case "$(VERSION)" in fw-*) ;; *) \
		echo "VERSION must be a release tag, e.g. VERSION=fw-2026.08.01 (got \"$(VERSION)\")"; \
		echo "or tag HEAD and drop the argument entirely:"; \
		echo "    git tag -a fw-2026.08.01 -m \"UMSH firmware 2026.08.01\""; \
		exit 1 ;; esac
endef

# The version the firmware reports as PROP_DEV_VERSION. Empty for ordinary
# builds, which makes each build.rs fall back to `git describe`;
# release-artifacts sets it to the tag.
#
# It has to travel through the environment because that is what cargo can
# watch: build.rs declares `rerun-if-env-changed=UMSH_FW_VERSION`, so
# changing it forces the rebuild. Creating a tag, by contrast, touches
# neither HEAD nor any ref build.rs depends on — without this, tagging and
# then packaging would quietly ship the pre-tag binary.
UMSH_FW_VERSION ?=
export UMSH_FW_VERSION

# The five boards that ship a UF2 and a DFU package. heltec-v3 is handled
# on its own — it has no UF2 bootloader and a different artifact entirely.
RELEASE_BOARDS_NRF52 = techo t1000e sensecap-solar wio-tracker-l1 xiao-nrf52

build-techo-console:
	cd firmware/techo-console && cargo build --release
	scripts/mkimage.py --board techo $(TARGET_DIR)/firmware-techo-console

flash-techo-console: build-techo-console
	scripts/flash.py --board techo --copy-default \
		$(TARGET_DIR)/firmware-techo-console.uf2

build-techo:
	cd firmware/techo && cargo build --release
	scripts/mkimage.py --board techo --hex $(TARGET_DIR)/firmware-techo

flash-techo: build-techo
	scripts/flash.py --board techo --copy-default \
		$(TARGET_DIR)/firmware-techo.uf2

build-wio-tracker-l1-console:
	cd firmware/wio-tracker-l1-console && cargo build --release
	scripts/mkimage.py --board wio-tracker-l1 $(TARGET_DIR)/firmware-wio-tracker-l1-console

flash-wio-tracker-l1-console: build-wio-tracker-l1-console
	scripts/flash.py --board wio-tracker-l1 --copy-default \
		$(TARGET_DIR)/firmware-wio-tracker-l1-console.uf2

build-wio-tracker-l1:
	cd firmware/wio-tracker-l1 && cargo build --release
	scripts/mkimage.py --board wio-tracker-l1 --hex $(TARGET_DIR)/firmware-wio-tracker-l1

flash-wio-tracker-l1: build-wio-tracker-l1
	scripts/flash.py --board wio-tracker-l1 --copy-default \
		$(TARGET_DIR)/firmware-wio-tracker-l1.uf2

build-t1000e-console:
	cd firmware/t1000e-console && cargo build --release
	scripts/mkimage.py --board t1000e --hex $(TARGET_DIR)/firmware-t1000e-console

flash-t1000e-console: build-t1000e-console
	scripts/flash.py --board t1000e --copy-default \
		$(TARGET_DIR)/firmware-t1000e-console.uf2

# Serial DFU goes straight to adafruit-nrfutil — there is nothing for us
# to add. pip installs it outside PATH on macOS, so override NRFUTIL with
# a full path if the bare name does not resolve. `--dev-type` is
# arbitrary but must be non-zero: the bootloader ignores it, the tool
# rejects packages without it.
DFU_SERIAL_PORT ?= /dev/tty.usbmodem1101
NRFUTIL ?= adafruit-nrfutil

# SoftDevice firmware IDs, passed as `--sd-req` so a package refuses to
# install on a board running a different SoftDevice. adafruit-nrfutil
# defaults to 0xFFFE ("any"), which is fine for a zip you built yourself
# thirty seconds ago and wrong for one published on the internet: the app
# base address differs with the SoftDevice (0x26000 under 6.1.1, 0x27000
# under 7.3.0), so the wrong image lands at the wrong offset. This is what
# stops that.
#
# Named by SoftDevice rather than by board because that is what the value
# actually identifies — which board uses which is a property of the board's
# `base` in scripts/firmware_image.py, and of `softdevice` in
# site/data/hardware.toml.
SD_REQ_S140_6_1_1 := 0x00B6
SD_REQ_S140_7_3_0 := 0x0123

# Package only: $(1) is the ELF path without extension (mkimage.py wrote
# $(1).hex next to it), $(2) the SoftDevice requirement, $(3) the output
# zip. Separate from dfu-serial so a release can produce the package
# without a board attached.
define dfu-genpkg
	@mkdir -p $(dir $(3))
	$(NRFUTIL) dfu genpkg --dev-type 0x0052 --sd-req $(2) \
		--application $(1).hex $(3)
endef

define dfu-serial
	$(call dfu-genpkg,$(1),$(2),$(1).zip)
	$(NRFUTIL) --verbose dfu serial -pkg $(1).zip \
		-p $(DFU_SERIAL_PORT) -b 115200
endef

flash-t1000e-console-serial: build-t1000e-console
	$(call dfu-serial,$(TARGET_DIR)/firmware-t1000e-console,$(SD_REQ_S140_7_3_0))

# SenseCAP Solar Node P1-Pro. Same UF2/DFU posture as the Wio Tracker
# (Seeed XIAO nRF52840 bootloader, UF2 mass-storage drive). The board
# preset in scripts/firmware_image.py is EXPECTED pending Phase 0 confirmation of
# the family ID and volume name.
build-sensecap-solar-console:
	cd firmware/sensecap-solar-console && cargo build --release
	scripts/mkimage.py --board sensecap-solar $(TARGET_DIR)/firmware-sensecap-solar-console

flash-sensecap-solar-console: build-sensecap-solar-console
	scripts/flash.py --board sensecap-solar --copy-default \
		$(TARGET_DIR)/firmware-sensecap-solar-console.uf2

build-sensecap-solar:
	cd firmware/sensecap-solar && cargo build --release
	scripts/mkimage.py --board sensecap-solar --hex $(TARGET_DIR)/firmware-sensecap-solar

flash-sensecap-solar: build-sensecap-solar
	scripts/flash.py --board sensecap-solar --copy-default \
		$(TARGET_DIR)/firmware-sensecap-solar.uf2

# Seeed XIAO nRF52840 + Wio-SX1262 Kit. Retail units mount their DFU
# volume as XIAO-SENSE (Seeed ships the *Sense* bootloader config on plain
# hardware); a re-bootloadered unit may present XIAO-BOOT instead, so
# --copy-default can miss. Override with `--copy-to` or drag the .uf2
# across by hand if it does. The image is packed with the generic
# 0xADA52840 family, which both configs accept — a wrong-family UF2 is
# copied with no error and silently not written.
build-xiao-nrf52:
	cd firmware/xiao-nrf52 && cargo build --release
	scripts/mkimage.py --board xiao-nrf52 --hex $(TARGET_DIR)/firmware-xiao-nrf52

flash-xiao-nrf52: build-xiao-nrf52
	scripts/flash.py --board xiao-nrf52 --copy-default \
		$(TARGET_DIR)/firmware-xiao-nrf52.uf2

build-t1000e:
	cd firmware/t1000e && cargo build --release
	scripts/mkimage.py --board t1000e --hex $(TARGET_DIR)/firmware-t1000e

flash-t1000e: build-t1000e
	scripts/flash.py --board t1000e --copy-default \
		$(TARGET_DIR)/firmware-t1000e.uf2

# For a board already sitting in DFU. The board has exactly two ways in — hold
# the user button while cycling USB power twice, or trigger it from software —
# and either one lands in the Adafruit bootloader, which presents the T1000-E
# volume *and* a CDC serial port. `flash-t1000e` uses the former, this the
# latter; both work whichever way the board got there. The bootloader's port is
# not the one the application enumerates, so pass it explicitly:
#
#     make flash-t1000e-serial DFU_SERIAL_PORT=/dev/cu.usbmodem<N>
flash-t1000e-serial: build-t1000e
	$(call dfu-serial,$(TARGET_DIR)/firmware-t1000e,$(SD_REQ_S140_7_3_0))

# The T-Echo's counterpart. Double-tapping reset puts it in the Adafruit
# bootloader, which presents the TECHOBOOT volume *and* a CDC serial port —
# `flash-techo` uses the former, this the latter. The port is not the one
# the application enumerates, so pass it explicitly:
#
#     make flash-techo-serial DFU_SERIAL_PORT=/dev/cu.usbmodem<N>
#
# This is also what exercises the S140 6.1.1 SoftDevice requirement, which
# no other target does.
flash-techo-serial: build-techo
	$(call dfu-serial,$(TARGET_DIR)/firmware-techo,$(SD_REQ_S140_6_1_1))

# ─── Release artifact conversion ─────────────────────────────────────────────
#
# Convert-only counterparts to the flash-* targets, writing into $(FW_DIR)
# under the release filenames. `release-artifacts` drives all of them; they
# are also the way to get a DFU package or a merged ESP32 image onto the
# bench without flashing anything.
#
# There is deliberately no `uf2-<board>` here: `build-<board>` already
# writes the UF2, and the release copies that exact file rather than
# converting a second time.

dfu-zip-techo: build-techo
	$(call dfu-genpkg,$(TARGET_DIR)/firmware-techo,$(SD_REQ_S140_6_1_1),$(FW_DIR)/umsh-techo-$(FW_VERSION)-dfu.zip)

dfu-zip-t1000e: build-t1000e
	$(call dfu-genpkg,$(TARGET_DIR)/firmware-t1000e,$(SD_REQ_S140_7_3_0),$(FW_DIR)/umsh-t1000e-$(FW_VERSION)-dfu.zip)

dfu-zip-sensecap-solar: build-sensecap-solar
	$(call dfu-genpkg,$(TARGET_DIR)/firmware-sensecap-solar,$(SD_REQ_S140_7_3_0),$(FW_DIR)/umsh-sensecap-solar-$(FW_VERSION)-dfu.zip)

dfu-zip-wio-tracker-l1: build-wio-tracker-l1
	$(call dfu-genpkg,$(TARGET_DIR)/firmware-wio-tracker-l1,$(SD_REQ_S140_7_3_0),$(FW_DIR)/umsh-wio-tracker-l1-$(FW_VERSION)-dfu.zip)

dfu-zip-xiao-nrf52: build-xiao-nrf52
	$(call dfu-genpkg,$(TARGET_DIR)/firmware-xiao-nrf52,$(SD_REQ_S140_7_3_0),$(FW_DIR)/umsh-xiao-nrf52-$(FW_VERSION)-dfu.zip)

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

# espup writes this on install; it puts the Xtensa GCC binaries on PATH and
# points LIBCLANG_PATH at the Xtensa clang, without which the build fails in
# a way that looks nothing like its cause. Sourcing it here rather than
# expecting it in the caller's shell is what lets `release-artifacts` build
# all six boards in one invocation. Guarded, so a machine that installed the
# toolchain some other way is unaffected. (Unrelated to the "don't set
# LIBCLANG_PATH" rule in CLAUDE.md, which is about the nRF52 workspace's
# bindgen; the Xtensa toolchain genuinely needs it.)
ESP_EXPORT ?= $(HOME)/export-esp.sh
ESP_ENV = if [ -f $(ESP_EXPORT) ]; then . $(ESP_EXPORT); fi;

# Neither the Xtensa toolchain nor espflash comes with a normal Rust install,
# and neither announces itself when missing: cargo dies inside rustup with
# "toolchain 'esp' is not installed" and no mention of espup, and a missing
# espflash surfaces as make reporting "No such file or directory" about a
# recipe line. Both are one-time per-machine setup, so the ESP32 targets ask
# first and print what to run. Each check is also a target in its own right —
# `make esp-toolchain-check` answers "is this machine set up?" without
# building anything.
ESP_SETUP_URL = firmware-esp32/README.md
# esp-radio needs the fork at least this new; older forks fail in the
# dependency graph rather than at the toolchain.
ESP_MIN_RUSTC = 1.95

esp-toolchain-check:
	@rustup run esp rustc --version >/dev/null 2>&1 || { \
		printf '%s\n' \
			'' \
			'The `esp` rustup toolchain is not installed.' \
			'' \
			'Espressif boards build with the Xtensa Rust fork, which rustup does' \
			'not carry. Install it once per machine:' \
			'' \
			'    cargo install espup espflash' \
			'    espup install' \
			'' \
			"See $(ESP_SETUP_URL)." \
			'' >&2; \
		exit 1; }
	@have=$$(rustup run esp rustc --version | cut -d' ' -f2 | cut -d- -f1); \
	if [ "$$(printf '%s\n%s\n' "$(ESP_MIN_RUSTC)" "$$have" | sort -V | head -1)" != "$(ESP_MIN_RUSTC)" ]; then \
		printf '%s\n' \
			'' \
			"Warning: the esp toolchain is rustc $$have; esp-radio wants >= $(ESP_MIN_RUSTC)." \
			'If the build fails resolving esp-* crates, refresh it with:' \
			'' \
			'    espup update' \
			'' >&2; \
	fi

espflash-check:
	@command -v espflash >/dev/null 2>&1 || { \
		printf '%s\n' \
			'' \
			'espflash is not on PATH.' \
			'' \
			'Espressif boards are flashed through the ROM serial bootloader by' \
			'espflash, which installs from crates.io:' \
			'' \
			'    cargo install espflash' \
			'' \
			"See $(ESP_SETUP_URL)." \
			'' >&2; \
		exit 1; }

build-heltec-v3-console: esp-toolchain-check
	$(ESP_ENV) cd firmware-esp32/firmware/heltec-v3-console && cargo build --release

flash-heltec-v3-console: espflash-check build-heltec-v3-console
	espflash flash --monitor $(ESPFLASH_PORT_ARG) $(ESPFLASH_PARTITIONS) \
		$(ESP32S3_TARGET_DIR)/firmware-heltec-v3-console

build-heltec-v3: esp-toolchain-check
	$(ESP_ENV) cd firmware-esp32/firmware/heltec-v3 && cargo build --release

flash-heltec-v3: espflash-check build-heltec-v3
	espflash flash --monitor $(ESPFLASH_PORT_ARG) $(ESPFLASH_PARTITIONS) \
		$(ESP32S3_TARGET_DIR)/firmware-heltec-v3

# The single-file image the web flasher writes at offset 0: second-stage
# bootloader, partition table, and application merged together.
#
# `--skip-padding` is not an optimization. Without it espflash pads the
# image out to the full flash size with 0xFF, and writing that at 0x0 runs
# straight over the `umsh` data partition at 0x300000 — every device would
# lose its identity and saved state on update. With it the image stops after
# the application and 0x300000 is never touched.
merged-bin-heltec-v3: espflash-check build-heltec-v3
	@mkdir -p $(FW_DIR)
	espflash save-image --chip esp32s3 --merge --skip-padding -s 4mb \
		$(ESPFLASH_PARTITIONS) \
		$(ESP32S3_TARGET_DIR)/firmware-heltec-v3 \
		$(FW_DIR)/umsh-heltec-v3-$(FW_VERSION).bin

# ─── Firmware releases ───────────────────────────────────────────────────────
#
# The whole flow, in order:
#
#     git tag -a fw-2026.08.01 -m "UMSH firmware 2026.08.01"
#     make release-artifacts
#     ... bench-verify the staged artifacts ...
#     git push origin main --follow-tags
#     make release-publish
#     make release-mirror   && git push origin gh-pages
#
# No target takes a version argument once HEAD is tagged. Pass
# VERSION=fw-2026.08.01 to work on a release other than the one HEAD is on.
#
# Releases are cut locally rather than in CI: this machine has the Xtensa
# toolchain the merged ESP32 image needs, and it builds xiao-nrf52, which
# CI does not. See docs/firmware-releases.md.

release-artifacts:
	$(require-release-tag)
	@git diff --quiet && git diff --cached --quiet || { \
		echo "working tree is dirty; commit or stash before cutting a release"; \
		exit 1; }
	@git rev-parse -q --verify "$(RELEASE_TAG)^{tag}" >/dev/null || { \
		echo "no annotated tag $(RELEASE_TAG). Create it first:"; \
		echo "    git tag -a $(RELEASE_TAG) -m \"UMSH firmware $(FW_VERSION)\""; \
		exit 1; }
	@test "$$(git rev-parse HEAD)" = "$$(git rev-parse "$(RELEASE_TAG)^{commit}")" || { \
		echo "HEAD is not at $(RELEASE_TAG); check out the tagged commit"; \
		exit 1; }
	rm -rf $(FW_DIR)
	@mkdir -p $(FW_DIR)
	$(MAKE) release-stage VERSION=$(VERSION) UMSH_FW_VERSION=$(RELEASE_TAG)
	scripts/release.py --version $(FW_VERSION)
	@echo
	@echo "Staged in $(FW_DIR). Verify on hardware before publishing."

# The build half, split out so the guards above run once and the version
# reaches every board's build.rs through the environment. Each dfu-zip-*
# depends on its build-*, which is also what writes the UF2 the copy below
# picks up — the release never re-converts an image, it ships the one the
# build produced.
release-stage: $(addprefix dfu-zip-,$(RELEASE_BOARDS_NRF52)) merged-bin-heltec-v3
	@for board in $(RELEASE_BOARDS_NRF52); do \
		cp $(TARGET_DIR)/firmware-$$board.uf2 \
			$(FW_DIR)/umsh-$$board-$(FW_VERSION).uf2 || exit 1; \
	done
	@echo "release-stage: collected $(words $(RELEASE_BOARDS_NRF52)) UF2 images"

# Attach the staged artifacts to a GitHub Release: the archival home for
# every file, and the download URL the manifest points at. Drafted rather
# than published outright, so the asset list can be looked at before anyone
# else can see it — promote it from the web UI, or with
# `gh release edit $(RELEASE_TAG) --draft=false`.
release-publish:
	@test -f $(FW_DIR)/manifest.json || { \
		echo "nothing staged for $(VERSION); run: make release-artifacts VERSION=$(VERSION)"; \
		exit 1; }
	gh release create $(RELEASE_TAG) --draft \
		--title "UMSH firmware $(FW_VERSION)" \
		--notes "Technology preview. See docs/firmware-releases.md for what is in here and how to flash it." \
		$(FW_DIR)/umsh-*-$(FW_VERSION).uf2 \
		$(FW_DIR)/umsh-*-$(FW_VERSION)-dfu.zip \
		$(FW_DIR)/umsh-heltec-v3-$(FW_VERSION).bin \
		$(FW_DIR)/manifest.json \
		$(FW_DIR)/SHA256SUMS
	@echo
	@echo "Drafted. Review the assets, then: gh release edit $(RELEASE_TAG) --draft=false"

# Copy what the web flasher fetches into the published tree, same-origin.
#
# GitHub's release assets send no CORS headers, so a page on umsh.dev cannot
# fetch() them — hence this mirror. Only what is actually fetched goes here:
# the DFU packages and the merged ESP32 image. UF2 files are left on the
# Release, because a browser cannot write a mass-storage volume anyway and
# the download-and-drag flow works fine from a plain GitHub link.
MIRROR_KEEP ?= 3

release-mirror:
	$(require-release-tag)
	@test -f $(FW_DIR)/manifest.json || { \
		echo "nothing staged for $(VERSION); run: make release-artifacts VERSION=$(VERSION)"; \
		exit 1; }
	$(gh-pages-open)
	@# Version directories are immutable: every URL under one is meant to be
	@# cacheable forever, which only holds if the bytes never change.
	@test ! -d $(GH_PAGES_WT)/firmware/$(FW_VERSION) || { \
		echo "/firmware/$(FW_VERSION) is already published — bump the version"; \
		git worktree remove $(GH_PAGES_WT); exit 1; }
	mkdir -p $(GH_PAGES_WT)/firmware/$(FW_VERSION)
	cp $(FW_DIR)/umsh-*-$(FW_VERSION)-dfu.zip \
		$(FW_DIR)/umsh-heltec-v3-$(FW_VERSION).bin \
		$(FW_DIR)/manifest.json \
		$(GH_PAGES_WT)/firmware/$(FW_VERSION)/
	scripts/release.py --index-mirror $(GH_PAGES_WT)/firmware --keep $(MIRROR_KEEP)
	$(call gh-pages-commit,firmware: mirror $(RELEASE_TAG))


# ─── iOS app (apps/ios) ──────────────────────────────────────────────────────
#
# Archiving and uploading are separate targets on purpose: ExportOptions.plist
# sets `destination = upload`, so `ios-upload` hands the build to App Store
# Connect. That step should never run as a side effect of building. The usual
# release is `make ios-archive ios-upload` once the archive looks right.
#
# The build number is passed on the xcodebuild command line instead of being
# stored in the project. GENERATE_INFOPLIST_FILE synthesizes CFBundleVersion
# from CURRENT_PROJECT_VERSION, and App Store Connect rejects a build number it
# has already accepted under the same MARKETING_VERSION — so every upload needs
# a fresh one. Deriving it from the commit count keeps uploads distinct and
# traceable back to a commit with no pbxproj edit to remember or commit.
# ExportOptions.plist sets `manageAppVersionAndBuildNumber = false`, so the
# number given here is the number that lands.
#
# The count only increases while you keep landing on main; archiving from a
# shorter side branch reuses a number and App Store Connect rejects the
# duplicate. Override it for that case, or any one-off:
#
#     make ios-archive IOS_BUILD_NUMBER=$(date -u +%s)
#
# The xcframework is gitignored, so a clean checkout must build umsh-mobile-core
# before Xcode can resolve the package — hence the ios-mobile-core prerequisite.

# Xcode's Organizer (Window → Organizer → Archives) lists only what sits under
# ~/Library/Developer/Xcode/Archives/<date>/. An archive written anywhere else is
# perfectly valid and uploads fine, it just never appears in that window — so the
# archive path here is the Organizer's own directory, matching where Product →
# Archive would have put it. Organizer watches the folder and picks it up live.

IOS_PROJECT := apps/ios/UMSH.xcodeproj
IOS_EXPORT_DIR := target/ios/export
IOS_BUILD_NUMBER ?= $(shell git rev-list --count HEAD)
IOS_ARCHIVES_ROOT := $(HOME)/Library/Developer/Xcode/Archives
IOS_ARCHIVE ?= $(IOS_ARCHIVES_ROOT)/$(shell date +%Y-%m-%d)/UMSH-$(IOS_BUILD_NUMBER).xcarchive

# Uploading resolves the newest UMSH archive rather than recomputing the path
# above, which would miss when the archive and the upload land on opposite sides
# of midnight. Point it somewhere specific to upload an older build:
#
#     make ios-upload IOS_UPLOAD_ARCHIVE=~/Library/Developer/Xcode/Archives/…
# The glob is loose enough to also find archives made by Xcode's own Product →
# Archive, which names them "UMSH 8-2-26, 4.08 PM.xcarchive".
IOS_UPLOAD_ARCHIVE ?= $(shell ls -dt $(IOS_ARCHIVES_ROOT)/*/UMSH*.xcarchive 2>/dev/null | head -1)

ios-mobile-core:
	scripts/ios/build-mobile-core.sh

ios-archive: ios-mobile-core
	xcodebuild -project $(IOS_PROJECT) -scheme UMSH \
		-destination 'generic/platform=iOS' \
		-archivePath "$(IOS_ARCHIVE)" \
		CURRENT_PROJECT_VERSION=$(IOS_BUILD_NUMBER) \
		archive

ios-upload:
	@test -n "$(IOS_UPLOAD_ARCHIVE)" || \
		{ echo "No archive found under $(IOS_ARCHIVES_ROOT) — run: make ios-archive"; exit 1; }
	@echo "Uploading $(IOS_UPLOAD_ARCHIVE)"
	xcodebuild -exportArchive -archivePath "$(IOS_UPLOAD_ARCHIVE)" \
		-exportOptionsPlist apps/ios/ExportOptions.plist \
		-exportPath $(IOS_EXPORT_DIR)

install-umshctl:
	cargo install --path tools/umshctl

install-umsh-bridge:
	cargo install --path tools/umsh-bridge

# ─── Wireshark ───────────────────────────────────────────────────────────────
#
# Both targets symlink rather than copy, so "install" also covers
# "update" and the installed tree can never drift from this checkout.
#
# The two directories are NOT siblings, and the difference is not
# guessable: Wireshark's Lua loader still reads the legacy personal
# config dir, but extcap only ever looks in the XDG one, so an extcap
# placed next to the dissector silently never appears. Ask Wireshark
# where it actually looks instead of hardcoding a guess.

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
	WIRESHARK_PLUGIN_DIR := $(HOME)/.config/wireshark/plugins
else
	WIRESHARK_PLUGIN_DIR := $(HOME)/.local/lib/wireshark/plugins
endif

TSHARK ?= $(shell command -v tshark 2>/dev/null || echo /Applications/Wireshark.app/Contents/MacOS/tshark)
WIRESHARK_EXTCAP_DIR := $(shell $(TSHARK) -G folders 2>/dev/null \
	| awk -F'\t' '/^Personal Extcap path:/ {print $$NF}')
ifeq ($(WIRESHARK_EXTCAP_DIR),)
	WIRESHARK_EXTCAP_DIR := $(HOME)/.local/lib/wireshark/extcap
endif

# `-n` matters on a re-run: without it `ln -s` follows the symlink left by
# the previous install and plants a second one *inside* the dissector
# directory, pointing at its own parent.
install-dissector:
	mkdir -p $(WIRESHARK_PLUGIN_DIR)
	ln -sfn "$(CURDIR)/dissectors/umsh" $(WIRESHARK_PLUGIN_DIR)/umsh

# Coloring rules cannot come from the dissector — a Lua dissector has no way
# to colour a packet-list row — so the rule that inverts protocol violations
# has to be installed into Wireshark's own rule set.
#
# The rule goes at the TOP: rules are first-match-wins, and the stock set ends
# with broad transport rules (UDP, TCP) that would otherwise claim a UMSH frame
# carried over the capture encapsulation before this one is reached.
#
# Seeding from the global file first matters. A personal colorfilters file
# replaces the defaults rather than extending them, so writing one that holds
# only this rule would silently discard every stock rule the user has.
WIRESHARK_COLORFILTERS := $(HOME)/.config/wireshark/colorfilters
WIRESHARK_STOCK_COLORFILTERS := $(shell $(TSHARK) -G folders 2>/dev/null \
	| awk -F'\t' '/^Global configuration:/ {print $$NF"/colorfilters"}')

install-colorfilters:
	@mkdir -p $(dir $(WIRESHARK_COLORFILTERS))
	@if [ ! -f "$(WIRESHARK_COLORFILTERS)" ] && [ -f "$(WIRESHARK_STOCK_COLORFILTERS)" ]; then \
		cp "$(WIRESHARK_STOCK_COLORFILTERS)" "$(WIRESHARK_COLORFILTERS)"; \
		echo "seeded $(WIRESHARK_COLORFILTERS) from the stock rules"; \
	fi
	@if grep -q 'umsh\.violation' "$(WIRESHARK_COLORFILTERS)" 2>/dev/null; then \
		echo "UMSH coloring rule already installed"; \
	else \
		cat "$(CURDIR)/dissectors/umsh/umsh-colorfilters" "$(WIRESHARK_COLORFILTERS)" \
			2>/dev/null > "$(WIRESHARK_COLORFILTERS).tmp"; \
		mv "$(WIRESHARK_COLORFILTERS).tmp" "$(WIRESHARK_COLORFILTERS)"; \
		echo "UMSH coloring rule added to $(WIRESHARK_COLORFILTERS)"; \
		echo "(restart Wireshark, or View -> Coloring Rules -> OK, to pick it up)"; \
	fi

# The dissector is a prerequisite, not a convenience: a live capture
# arriving with no dissector installed renders as undissected bytes.
# The filename here becomes the preference key prefix Wireshark saves
# the capture options under, so it must not be renamed later.
install-extcap: install-umshctl install-dissector
	mkdir -p $(WIRESHARK_EXTCAP_DIR)
	ln -sfn "$(HOME)/.cargo/bin/umshctl" $(WIRESHARK_EXTCAP_DIR)/umshctl

# ─── Docs ────────────────────────────────────────────────────────────────────

web-debugger:
	wasm-pack build tools/ulcp-web-debugger/engine --target web \
		--out-dir ../www/pkg --out-name umsh_ulcp_web_engine


# Every workspace crate is documented and published. `--no-deps` means
# target/doc holds exactly our crates plus rustdoc's shared assets, so
# gh-pages copies the tree wholesale rather than naming crates — a list
# would silently omit each new crate.
#
# A crate that only compiles for the embedded target still has to *document*
# on the host. Gate such items on `target_os = "none"` with a host fallback
# rather than on a feature alone; `#[cfg(doc)]` does not help, because it
# applies to the crate being documented and not to its dependencies.
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

# ─── Region database ─────────────────────────────────────────────────────────
#
# The compiler is a packaged Python project under tools/regiondb-build, managed
# with uv. It is the repository's only Python with third-party dependencies:
# scripts/ stays stdlib-only because building firmware must need nothing but a
# Rust toolchain, and none of this is on that path.
#
# Only regions-fetch touches the network, and only regions-update reads
# regions/vendor/. Everything else runs on the committed tree.

# Run from the repository root through uv's project flag, so every path on a
# command line is relative to where the developer actually is.
REGIONDB_BUILD := uv run --quiet --project tools/regiondb-build regiondb-build
REGIONS_ROOT ?= regions
REGIONS_FIXTURE := $(REGIONS_ROOT)/tests/fixture
DATASET_VERSION ?= $(shell date -u +%Y.%m).1

regions-fetch:
	@command -v uv >/dev/null 2>&1 || 		{ echo "uv not found. Install it from https://docs.astral.sh/uv/"; exit 1; }
	$(REGIONDB_BUILD) --root $(REGIONS_ROOT) fetch

regions-update:
	$(REGIONDB_BUILD) --root $(REGIONS_ROOT) update

# Re-derives every extract from the pinned vendor files and fails if what is
# committed differs, so an extract cannot drift from its source or be edited by
# hand without the check noticing. Needs regions-fetch first.
regions-update-check:
	$(REGIONDB_BUILD) --root $(REGIONS_ROOT) update --check

# The global build. Needs the country boundary layer from regions-update, which
# is too large to commit; see regions/README.md.
regions-build:
	$(REGIONDB_BUILD) --root $(REGIONS_ROOT) build \
		--dataset-version $(DATASET_VERSION) \
		--output $(REGIONS_ROOT)/dist/world.regiondb

# The fixture database is a committed build output. Regenerate it whenever the
# fixture source tree or the compiled format changes; the test suites compare
# against it and never build one themselves.
regions-build-fixture:
	$(REGIONDB_BUILD) --root $(REGIONS_FIXTURE) build \
		--dataset-version fixture-1 \
		--output $(REGIONS_FIXTURE)/fixture.regiondb \
		--report $(REGIONS_FIXTURE)/build-report.json

# Offline. Checks the committed fixture against its known points and proves the
# lookup cache agrees with an exhaustive scan of the same geometry.
regions-check:
	$(REGIONDB_BUILD) --root $(REGIONS_ROOT) validate \
		--db $(REGIONS_FIXTURE)/fixture.regiondb \
		--points $(REGIONS_ROOT)/tests/known-points.yaml \
		--sample 5000

regions-test: regions-check
	cd tools/regiondb-build && uv run --quiet ruff format --check .
	cd tools/regiondb-build && uv run --quiet ruff check .
	cd tools/regiondb-build && uv run --quiet pytest -q
	cargo test --locked -p umsh-regiondb

regions-diff:
	@test -n "$(OLD)" || { echo "usage: make regions-diff OLD=old-build-report.json"; exit 1; }
	$(REGIONDB_BUILD) diff $(OLD) $(REGIONS_ROOT)/dist/build-report.json

# ─── Website (umsh.dev) ──────────────────────────────────────────────────────
#
# Sources live in site/. Zola 0.23 or newer is required — it moved to Tera v2,
# and the templates use its syntax.

ZOLA ?= zola
GH_PAGES_WT := /tmp/umsh-gh-pages

site:
	@command -v $(ZOLA) >/dev/null 2>&1 || \
		{ echo "zola not found. Install it with: brew install zola"; exit 1; }
	$(ZOLA) --root site build

# Fast loop for templates and styles. Note that /docs/* 404s here — those
# trees are layered in only when the whole site is assembled.
site-serve:
	$(ZOLA) --root site serve

site-check:
	$(ZOLA) --root site check

# The flasher's serial-DFU framing, checked against golden frames generated
# from an independent transcription of the protocol. No board required.
site-test:
	node --test "site/tests/flasher/*.test.mjs"

# The published tree as it will actually look, including the books. Serve it
# with: python3 -m http.server 8000 -d target/site-preview
#
# Built against a localhost base URL rather than umsh.dev, so the preview loads
# its own stylesheet and scripts instead of the deployed ones. The flasher
# depends on this: its Content-Security-Policy is `script-src 'self'`, so a
# module served from another origin would simply be blocked. Override the port
# with SITE_PREVIEW_URL if 8000 is taken.
SITE_PREVIEW_URL ?= http://localhost:8000

site-preview: docs rust-docs-nightly
	@command -v $(ZOLA) >/dev/null 2>&1 || \
		{ echo "zola not found. Install it with: brew install zola"; exit 1; }
	$(ZOLA) --root site build --base-url $(SITE_PREVIEW_URL)
	rm -rf target/site-preview
	mkdir -p target/site-preview/docs/protocol target/site-preview/docs/rust
	cp -R site/public/. target/site-preview/
	cp -R docs/protocol/book/. target/site-preview/docs/protocol/
	cp -R target/doc/. target/site-preview/docs/rust/
	cp docs/rust-index.html target/site-preview/docs/rust/index.html
	@# Layer in whatever release has been staged locally, in the same shape
	@# `release-mirror` publishes, so the flasher's "latest release" mode has
	@# something same-origin to fetch.
	@for dir in target/firmware-release/*/; do \
		test -f "$$dir/manifest.json" || continue; \
		version=$$(basename "$$dir"); \
		mkdir -p target/site-preview/firmware/$$version; \
		cp "$$dir"/manifest.json target/site-preview/firmware/$$version/; \
		cp "$$dir"/umsh-*-dfu.zip "$$dir"/umsh-*.bin \
			target/site-preview/firmware/$$version/ 2>/dev/null || true; \
	done
	@test ! -d target/site-preview/firmware || \
		scripts/release.py --index-mirror target/site-preview/firmware --keep $(MIRROR_KEEP)
	@echo "Preview assembled. Serve it with:"
	@echo "    python3 -m http.server 8000 -d target/site-preview"

# Who owns what in the published tree:
#
#   /              the Zola site — wiped and replaced on every run
#   /docs/protocol the mdBook spec — wiped and replaced on every run
#   /docs/rust     rustdoc — wiped and replaced on every run
#   /firmware      release artifacts, written by `release-mirror`
#   /tools         reserved for the ULCP web debugger
#
# Anything landing at the published root outside Zola's control has to be
# added to the preserve list in `gh-pages`, or the next deploy deletes it.

# Check out the published branch and sync it with origin. Shared by
# `gh-pages` and `release-mirror`, which write disjoint parts of the same
# tree and must not each grow their own copy of this.
define gh-pages-open
	@if ! git show-ref --quiet refs/heads/gh-pages; then \
		echo "Creating gh-pages branch..."; \
		git worktree add $(GH_PAGES_WT) --orphan -b gh-pages; \
	else \
		echo "Updating gh-pages branch..."; \
		git fetch origin gh-pages || echo "warning: could not reach origin, using the local branch"; \
		git worktree add $(GH_PAGES_WT) gh-pages 2>/dev/null || true; \
	fi
	@# Fast-forward onto origin first. This is a no-op when the local branch
	@# is ahead and fails loudly if the two have diverged, rather than
	@# quietly discarding whatever was published from somewhere else.
	@if git show-ref --quiet refs/remotes/origin/gh-pages; then \
		git -C $(GH_PAGES_WT) merge --ff-only origin/gh-pages || \
			{ echo "gh-pages has diverged from origin. Reconcile it by hand."; exit 1; }; \
	fi
endef

# Commit the worktree and close it. $(1) is the commit message. Neither
# caller pushes: what reaches the internet stays a deliberate act.
define gh-pages-commit
	@# Pushing a tree with no CNAME makes GitHub drop the custom domain.
	@test -s $(GH_PAGES_WT)/CNAME || \
		{ echo "CNAME missing from the published tree — refusing to publish."; exit 1; }
	cd $(GH_PAGES_WT) && \
		git add -A && \
		git diff --cached --quiet || git commit -m "$(1)"
	git worktree remove $(GH_PAGES_WT)
	@echo "gh-pages branch updated. Push with: git push origin gh-pages"
endef

gh-pages: site docs rust-docs-nightly
	$(gh-pages-open)
	find $(GH_PAGES_WT) -mindepth 1 -maxdepth 1 \
		! -name .git ! -name docs ! -name firmware ! -name tools \
		-exec rm -rf {} +
	rm -rf $(GH_PAGES_WT)/docs/protocol $(GH_PAGES_WT)/docs/rust
	cp -R site/public/. $(GH_PAGES_WT)/
	mkdir -p $(GH_PAGES_WT)/docs/protocol $(GH_PAGES_WT)/docs/rust
	cp -R docs/protocol/book/. $(GH_PAGES_WT)/docs/protocol/
	cp -R target/doc/. $(GH_PAGES_WT)/docs/rust/
	cp docs/rust-index.html $(GH_PAGES_WT)/docs/rust/index.html
	touch $(GH_PAGES_WT)/.nojekyll
	$(call gh-pages-commit,Update GitHub Pages)
