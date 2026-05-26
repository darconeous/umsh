/* Memory layout for the LilyGO T-Echo.
 *
 * The T-Echo ships with the same Adafruit nRF52 UF2 bootloader as the
 * T1000-E (with the SoftDevice slot reserved at 0x1000..0x26000), so
 * the layout is identical. Phase 0 of the bringup plan confirms this
 * against INFO_UF2.TXT on the actual board before flashing.
 *
 * See docs/firmware-plan-techo.md.
 *
 *   nRF52840 flash:  0x00000000 .. 0x00100000   (1024K total)
 *     MBR + SoftDevice slot:  0x00000000 .. 0x00026000   ( 152K, reserved)
 *     App:                    0x00026000 .. 0x000E4000   ( 760K)
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
  FLASH : ORIGIN = 0x00026000, LENGTH = 760K
  RAM   : ORIGIN = 0x20000000, LENGTH = 256K
}
