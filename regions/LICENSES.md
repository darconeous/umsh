# Data licensing

The code in this repository is MIT OR Apache-2.0. The compiled region database
is a different artifact with different terms, and this file tracks them
separately rather than assuming the source license carries over.

| Source | License | Obligation |
|---|---|---|
| OurAirports | Public Domain | none |
| `datasets/country-codes` | PDDL 1.0 | attribution requested |
| Marine Regions EEZ + land union (VLIZ) | CC BY 4.0 | attribution required |
| US Census TIGER/Line | US Government work | none; record vintage |
| `lxndrblz/Airports` `citycodes.csv` | **CC BY-SA 4.0** | attribution **and share-alike** |
| UMSH metros, custom regions, overrides | MIT OR Apache-2.0 | none |

Every compiled database carries a `sources` table with the name, URL, license,
and attribution of each dataset that contributed to it, so an artifact separated
from this repository still says where it came from.

## The share-alike question

`citycodes.csv` is CC BY-SA 4.0, which can extend share-alike terms to a
derivative work. UMSH uses it only as a seed list of metropolitan IATA
codes — three-letter codes and their names, facts rather than creative
expression — and none of its coordinates or geometry. Whether that makes the
compiled database a derivative work of it is a question about the boundary
between a database's contents and its structure, and this file is not the place
it gets settled.

**This needs a human decision before a database is published.** Two ways to
close it: get comfortable stating the position above and attribute the source
in the release, or drop the metro seed list and enumerate the supported metro
codes by hand, since every metro needs a reviewed polygon anyway and the seed
list saves only the typing. The second removes the question entirely.

Nothing here is legal advice, and the implementation is deliberately not making
this call on its own.
