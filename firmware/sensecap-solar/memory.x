/* SenseCAP Solar Node P1 / P1-Pro: S140 v7.3.0 reserves through 0x27000
 * (confirmed Phase 0, INFO_UF2.TXT). The final 64 KiB of application space
 * (0xE4000..0xF4000) is dedicated to companion security persistence
 * (ble_store / snapshot / identity journals), same as the T-1000E NCP. */
MEMORY
{
  FLASH : ORIGIN = 0x00027000, LENGTH = 756K
  RAM   : ORIGIN = 0x20000000, LENGTH = 256K
}
