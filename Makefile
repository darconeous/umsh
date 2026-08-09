.PHONY: docs rust-docs rust-docs-nightly docs-serve gh-pages web-debugger \
	site site-serve site-check site-preview \
	build-techo-console flash-techo-console \
	build-wio-tracker-l1-console flash-wio-tracker-l1-console \
	build-wio-tracker-l1 flash-wio-tracker-l1 \
	build-t1000e-console flash-t1000e-console \
	flash-t1000e-console-serial \
	build-sensecap-solar-console flash-sensecap-solar-console \
	build-sensecap-solar flash-sensecap-solar \
	build-xiao-nrf52 flash-xiao-nrf52 \
	build-t1000e flash-t1000e-serial \
	build-techo flash-techo \
	build-heltec-v3-console flash-heltec-v3-console \
	build-heltec-v3 flash-heltec-v3 \
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

build-techo-console:
	cd firmware/techo-console && cargo build --release
	scripts/mkimage.py --board techo $(TARGET_DIR)/firmware-techo-console

flash-techo-console: build-techo-console
	scripts/flash.py --board techo --copy-default \
		$(TARGET_DIR)/firmware-techo-console.uf2

build-techo:
	cd firmware/techo && cargo build --release
	scripts/mkimage.py --board techo $(TARGET_DIR)/firmware-techo

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
	scripts/mkimage.py --board wio-tracker-l1 $(TARGET_DIR)/firmware-wio-tracker-l1

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

define dfu-serial
	$(NRFUTIL) dfu genpkg --dev-type 0x0052 \
		--application $(1).hex $(1).zip
	$(NRFUTIL) --verbose dfu serial -pkg $(1).zip \
		-p $(DFU_SERIAL_PORT) -b 115200
endef

flash-t1000e-console-serial: build-t1000e-console
	$(call dfu-serial,$(TARGET_DIR)/firmware-t1000e-console)

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
	scripts/mkimage.py --board sensecap-solar $(TARGET_DIR)/firmware-sensecap-solar

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
	scripts/mkimage.py --board xiao-nrf52 $(TARGET_DIR)/firmware-xiao-nrf52

flash-xiao-nrf52: build-xiao-nrf52
	scripts/flash.py --board xiao-nrf52 --copy-default \
		$(TARGET_DIR)/firmware-xiao-nrf52.uf2

build-t1000e:
	cd firmware/t1000e && cargo build --release
	scripts/mkimage.py --board t1000e --hex $(TARGET_DIR)/firmware-t1000e

flash-t1000e: build-t1000e
	scripts/flash.py --board t1000e --copy-default \
		$(TARGET_DIR)/firmware-t1000e.uf2

# For a board already sitting in serial DFU. The board has exactly two ways
# into DFU — hold the user button while cycling USB power twice, or trigger it
# from software — and the button path lands in the UF2 bootloader, which this
# target cannot talk to. Use `flash-t1000e` there.
flash-t1000e-serial: build-t1000e
	$(call dfu-serial,$(TARGET_DIR)/firmware-t1000e)

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

# The published tree as it will actually look, including the books. Serve it
# with: python3 -m http.server 8000 -d target/site-preview
site-preview: site docs rust-docs-nightly
	rm -rf target/site-preview
	mkdir -p target/site-preview/docs/protocol target/site-preview/docs/rust
	cp -R site/public/. target/site-preview/
	cp -R docs/protocol/book/. target/site-preview/docs/protocol/
	cp -R target/doc/. target/site-preview/docs/rust/
	cp docs/rust-index.html target/site-preview/docs/rust/index.html
	@echo "Preview assembled. Serve it with:"
	@echo "    python3 -m http.server 8000 -d target/site-preview"

# Who owns what in the published tree:
#
#   /              the Zola site — wiped and replaced on every run
#   /docs/protocol the mdBook spec — wiped and replaced on every run
#   /docs/rust     rustdoc — wiped and replaced on every run
#   /firmware      release artifacts, written by the firmware release flow
#   /tools         reserved for the ULCP web debugger
#
# Anything landing at the published root outside Zola's control has to be
# added to the preserve list below, or the next deploy deletes it.
gh-pages: site docs rust-docs-nightly
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
	@# Pushing a tree with no CNAME makes GitHub drop the custom domain.
	@test -s $(GH_PAGES_WT)/CNAME || \
		{ echo "CNAME missing from the built site — refusing to publish."; exit 1; }
	cd $(GH_PAGES_WT) && \
		git add -A && \
		git diff --cached --quiet || git commit -m "Update GitHub Pages"
	git worktree remove $(GH_PAGES_WT)
	@echo "gh-pages branch updated. Push with: git push origin gh-pages"
