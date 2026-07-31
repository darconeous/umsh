/* Memory layout for the SenseCAP Solar Node P1 / P1-Pro.
 *
 * EXPECTED to be byte-identical to the T1000-E and Wio Tracker L1: same
 * Seeed XIAO nRF52840 bootloader family, same S140 v7.3.0 SoftDevice, so
 * the app starts at 0x27000. CONFIRM the app-start address against the
 * in-hand device's INFO_UF2.TXT in Phase 0 before the first flash.
 *
 * See docs/hardware/sensecap-solar-node-p1-pro-hardware.md.
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
 * (sequential-storage over NVMC). The linker MUST NOT place app code into
 * this range.
 */

MEMORY
{
  FLASH : ORIGIN = 0x00027000, LENGTH = 756K
  RAM   : ORIGIN = 0x20000000, LENGTH = 256K
}
