/* Seeed XIAO nRF52840 + Wio-SX1262 Kit: S140 v7.3.0 reserves through
 * 0x27000 (confirmed on a retail unit 2026-08-03 from the pre-flashed
 * image's vector table; 0x26000 holds SoftDevice tail data, not a vector
 * table — this board does NOT use the T-Echo's 0x26000). The final 64 KiB
 * of application space (0xE4000..0xF4000) is dedicated to ULCP security
 * persistence (ble_store / snapshot / identity / ux / counter journals),
 * same as the other nRF52840 device boards — see nrf52-tracker's
 * proto_store.rs, which hard-codes those page addresses.
 *
 * Note the UF2-writable window on this board's bootloader ends at
 * 0xEA000, not 0xF4000: USER_FLASH_END = BOOTLOADER_REGION_START (0xF4000)
 * minus a 40 KiB DFU app-data reserve, confirmed by direct probe. Blocks
 * above that line are silently dropped, with the UF2 copy still reporting
 * success. FLASH below ends at 0xE4000, so a linked image can never reach
 * the ceiling — the linker runs out of region first, with an error,
 * which is the failure mode we want. The NV region above it is written at
 * runtime through NVMC (which has no such limit) and is not part of any
 * UF2 image.
 */
MEMORY
{
  FLASH : ORIGIN = 0x00027000, LENGTH = 756K
  RAM   : ORIGIN = 0x20000000, LENGTH = 256K
}
