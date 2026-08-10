+++
title = "Flasher"
description = "Plug in a radio and flash the latest UMSH firmware from your browser."
template = "flasher.html"
weight = 4
+++

## Building from source

The flasher installs published releases. To build the firmware yourself you
need a Rust toolchain and nothing else—Rust cross-compiles for the nRF52840
on its own:

```bash
git clone https://github.com/darconeous/umsh.git
```

Espressif boards need one extra step, because the Xtensa processors use their
own Rust compiler:

```bash
cargo install espup espflash && espup install
```

Put the board into its bootloader, then run its `make flash-<board>` target.
Per-board details—entry gestures, UF2 family IDs, and the quirks worth knowing
before flashing by hand—live with the code, in the repository's `docs/hardware/`
tree.
