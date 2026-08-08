+++
title = "Flashing"
description = "How to get UMSH firmware onto a radio."
template = "flasher.html"
weight = 4
+++

<div class="notice">
<p><strong>A browser-based flasher is on the way.</strong> The plan is the
usual thing: plug the radio into a USB port, pick it from a list, click a
button, and let the page do the rest — no toolchain, no downloads, no command
line. It will need Chrome, Edge, or Opera, since those are the browsers that
can talk to serial devices.</p>
<p>It is not built yet, and it is waiting on a firmware release process so
that there is something for it to install. Until then, flashing means
building from source, which is not difficult.</p>
</div>

## Building and flashing from source

You will need a Rust toolchain, and for the nRF52840 boards, `arm-none-eabi-objcopy`
from the GNU Arm Embedded toolchain. Clone the repository, put your board into
its bootloader as described below, and run the one command for it. The
firmware only links in release mode, which the make targets already handle.

```bash
git clone https://github.com/darconeous/umsh.git
```

Espressif boards need one extra step, because the Xtensa processors need
their own Rust compiler:

```bash
cargo install espup espflash && espup install
```

The instructions below cover getting each board into its bootloader, which is
the part that differs. If a flash appears to succeed but the board comes back
running the same firmware it had before, read the notes for your board — on
some of them that failure is completely silent.
