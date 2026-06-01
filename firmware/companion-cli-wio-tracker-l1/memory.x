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
 *     App:                             0x00027000 .. 0x000E4000  ( 756K)
 *     NV storage region:               0x000E4000 .. 0x000F4000  (  64K)
 *     Bootloader:                      0x000F4000 .. 0x000FF000  (  44K)
 *     Bootloader settings:             0x000FF000 .. 0x00100000  (   4K)
 *
 *   nRF52840 RAM:    0x20000000 .. 0x20040000   ( 256K total)
 *
 * S140 sits dormant unless `sd_softdevice_enable()` is called; until
 * then we have full peripheral ownership and the full 256K of RAM.
 *
 * The 64 KB NV storage region is owned by `umsh-bsp-nrf52840::flash_store`
 * (sequential-storage over NVMC). See `docs/firmware-storage-plan.md`.
 * The linker MUST NOT place app code into this range.
 */

MEMORY
{
  FLASH : ORIGIN = 0x00027000, LENGTH = 756K
  RAM   : ORIGIN = 0x20000000, LENGTH = 256K
}
