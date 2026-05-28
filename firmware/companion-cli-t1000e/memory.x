/* Memory layout for the T1000-E.
 *
 * Confirmed in Phase 0 by reading INFO_UF2.TXT from the bootloader
 * mass-storage drive and scanning the first-block target address in
 * CURRENT.UF2 (see docs/firmware-plan-t1000e.md Phase 0 section).
 *
 * Bootloader: Seeed fork 0.9.1-5-g488711a, Board-ID nRF52840-T1000-E-v1
 * SoftDevice: S140 7.3.0 (larger footprint than v6 → app at 0x27000, not 0x26000)
 * UF2 family: 0x28860057 (Seeed VID 0x2886 | T1000-E PID 0x0057)
 *
 *   nRF52840 flash:  0x00000000 .. 0x00100000   (1024K total)
 *     MBR + SoftDevice slot:  0x00000000 .. 0x00027000   ( 156K, reserved)
 *     App:                    0x00027000 .. 0x000E4000   ( 756K)
 *     NV storage region:      0x000E4000 .. 0x000F4000   (  64K)
 *     Bootloader + UICR:      0x000F4000 .. 0x00100000   (  48K)
 *
 *   nRF52840 RAM:    0x20000000 .. 0x20040000   ( 256K total)
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
