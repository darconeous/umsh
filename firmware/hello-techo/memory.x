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
 *     App:                    0x00026000 .. 0x000F4000   ( 824K)
 *     Bootloader + UICR:      0x000F4000 .. 0x00100000   (  48K)
 *
 *   nRF52840 RAM:    0x20000000 .. 0x20040000   ( 256K total)
 */

MEMORY
{
  FLASH : ORIGIN = 0x00026000, LENGTH = 824K
  RAM   : ORIGIN = 0x20000000, LENGTH = 256K
}
