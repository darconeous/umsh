.PHONY: docs rust-docs rust-docs-nightly docs-serve gh-pages \
	build-companion-cli-techo flash-companion-cli-techo \
	build-companion-cli-wio-tracker-l1 flash-companion-cli-wio-tracker-l1 \
	build-companion-cli-t1000e flash-companion-cli-t1000e \
	flash-companion-cli-t1000e-serial \
	build-companion-ncp-techo flash-companion-ncp-techo

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

TARGET_DIR := target/thumbv7em-none-eabihf/release

build-companion-cli-techo:
	cd firmware/companion-cli-techo && cargo build --release

flash-companion-cli-techo: build-companion-cli-techo
	scripts/flash.py --board techo --copy-default \
		$(TARGET_DIR)/firmware-companion-cli-techo

build-companion-ncp-techo:
	cd firmware/companion-ncp-techo && cargo build --release

flash-companion-ncp-techo: build-companion-ncp-techo
	scripts/flash.py --board techo --copy-default \
		$(TARGET_DIR)/firmware-companion-ncp-techo

build-companion-cli-wio-tracker-l1:
	cd firmware/companion-cli-wio-tracker-l1 && cargo build --release

flash-companion-cli-wio-tracker-l1: build-companion-cli-wio-tracker-l1
	scripts/flash.py --board wio-tracker-l1 --copy-default \
		$(TARGET_DIR)/firmware-companion-cli-wio-tracker-l1

build-companion-cli-t1000e:
	cd firmware/companion-cli-t1000e && cargo build --release

flash-companion-cli-t1000e: build-companion-cli-t1000e
	scripts/flash.py --board t1000e --copy-default \
		$(TARGET_DIR)/firmware-companion-cli-t1000e

# Serial-DFU path: required on T1000-E when the user-button bootloader entry
# exposes only /dev/tty.usbmodem* and not the UF2 mass-storage drive.
# Override the port with: make ... DFU_SERIAL_PORT=/dev/tty.usbmodem<N>
DFU_SERIAL_PORT ?= /dev/tty.usbmodem1101

flash-companion-cli-t1000e-serial: build-companion-cli-t1000e
	scripts/flash.py --board t1000e --serial-dfu $(DFU_SERIAL_PORT) \
		$(TARGET_DIR)/firmware-companion-cli-t1000e

# ─── Docs ────────────────────────────────────────────────────────────────────


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
