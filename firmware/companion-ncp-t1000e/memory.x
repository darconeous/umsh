/* Seeed T1000-E: S140 v7 reserves through 0x27000. The final 64 KiB of
 * application space remains dedicated to companion security persistence. */
MEMORY
{
  FLASH : ORIGIN = 0x00027000, LENGTH = 756K
  RAM   : ORIGIN = 0x20000000, LENGTH = 256K
}
