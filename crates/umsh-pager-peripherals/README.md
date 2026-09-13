# T-LoRa Pager peripherals

Small `no_std` drivers used by the ESP32 Pager BSP. The host tests exercise
the register transactions and pure input/power policies without ESP32 hardware.

- `input`: full-cycle quadrature decoding, button debounce, and TCA8418 FIFO.
  The board calls the quadrature decoder from GPIO interrupts on both edges
  of both channels. Only the push button uses timed sampling.
- `power`: XL9555 switched domains, BQ25896 charging, and BQ27220 telemetry.
  Fuel-gauge calibration and learned capacity are never rewritten.
- `rtc`: PCF85063A retained time, oscillator validity, and calendar conversion.
- `display`: the ST7796 landscape window and a monochrome framebuffer,
  converted to RGB565 in four-row transfers.

Board register values and panel initialization follow
[LilyGo's Pager implementation](https://github.com/Xinyuan-LilyGO/LilyGoLib/blob/master/src/LilyGo_LoRa_Pager.cpp)
and its [peripheral libraries](https://github.com/Xinyuan-LilyGO/LilyGoLib-ThirdParty).
The charger profile follows the
[BQ25896 datasheet](https://www.ti.com/lit/ds/symlink/bq25896.pdf).
These are application drivers, with no patched or vendored dependencies.

Run `cargo test -p umsh-pager-peripherals` from the repository root.
