.PHONY: docs rust-docs rust-docs-nightly docs-serve gh-pages \
	build-hello-techo flash-hello-techo \
	build-hello-wio-tracker-l1 flash-hello-wio-tracker-l1

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

build-hello-techo:
	cd firmware/hello-techo && cargo build --release

flash-hello-techo: build-hello-techo
	scripts/flash.py --board techo --copy-default \
		$(TARGET_DIR)/firmware-hello-techo

build-hello-wio-tracker-l1:
	cd firmware/hello-wio-tracker-l1 && cargo build --release

flash-hello-wio-tracker-l1: build-hello-wio-tracker-l1
	scripts/flash.py --board wio-tracker-l1 --copy-default \
		$(TARGET_DIR)/firmware-hello-wio-tracker-l1

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
