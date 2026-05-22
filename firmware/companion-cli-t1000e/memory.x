/* Memory layout for the T1000-E.
 *
 * Assumes the stock Adafruit nRF52 UF2 bootloader (Meshtastic flavor) with
 * the SoftDevice slot reserved at 0x1000..0x26000 — see the BLE
 * future-proofing notes in docs/firmware-plan-t1000e.md.
 *
 * The exact app FLASH window must be confirmed in Phase 0 by reading
 * INFO_UF2.TXT off the bootloader's UF2 mass-storage drive. Until then,
 * these values are best-guess based on the standard Meshtastic layout.
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
