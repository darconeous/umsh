/* Memory layout for the Seeed Wio Tracker L1 / L1 Pro.
 *
 * Verified against an in-hand device in DFU mode (INFO_UF2.TXT) and
 * cross-referenced with the MeshCore S140 v7 linker script.
 *
 * IMPORTANT: this is NOT the same layout as the T-Echo. The Wio
 * Tracker ships with S140 v7.3.0 (vs. T-Echo's v6.1.1), so the app
 * starts at 0x27000 instead of 0x26000.
 *
 * See docs/firmware-plan-wio-tracker-l1.md and
 * docs/seeed-wio-tracker-l1-pro-hardware.md.
 *
 *   nRF52840 flash:  0x00000000 .. 0x00100000   (1024K total)
 *     MBR + SoftDevice (S140 v7.3.0):  0x00000000 .. 0x00027000  ( 156K, reserved)
 *     App:                             0x00027000 .. 0x000F4000  ( 820K)
 *     Bootloader:                      0x000F4000 .. 0x000FF000  (  44K)
 *     Bootloader settings:             0x000FF000 .. 0x00100000  (   4K)
 *
 *   nRF52840 RAM:    0x20000000 .. 0x20040000   ( 256K total)
 *
 * S140 sits dormant unless `sd_softdevice_enable()` is called; until
 * then we have full peripheral ownership and the full 256K of RAM.
 */

MEMORY
{
  FLASH : ORIGIN = 0x00027000, LENGTH = 820K
  RAM   : ORIGIN = 0x20000000, LENGTH = 256K
}
