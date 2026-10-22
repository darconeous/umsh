#!/usr/bin/env python3
"""Generate the first emoji manifest for communicators.

Run once, and again only to regenerate the face, heart, and hand additions
after a Twemoji upgrade: the manifest it writes is maintained by hand from
then on, and the firmware build reads nothing else. Review the diff.

The set (docs/emoji-support-plan.md, "The default set"):

1. Every face, heart, and hand: all of Smileys & Emotion, and the hand
   subgroups of People & Body.
2. The emoji Unicode ranks most used, rows 0-10 of its frequency ranking
   (each used at least 1/2048 as often as the most used). An item brings
   its gendered forms, as the ranking folds them into one.
3. Families kept whole: every keycap, the colored circles and squares, and
   the non-country flags.
4. No skin tones and no country or subdivision flags.

Only sequences Twemoji draws are written.

usage: emoji_manifest.py EMOJI_TEST FREQUENCY_HTML TWEMOJI_SVG_DIR > manifest.txt
"""

import html
import os
import re
import sys

TONES = set(range(0x1F3FB, 0x1F400))
ZWJ, VS16 = 0x200D, 0xFE0F
GENDER = {0x2640, 0x2642}
ADULTS = (0x1F9D1, 0x1F468, 0x1F469)
LAST_ROW = 10

WHOLE_GROUPS = {"Smileys & Emotion"}
WHOLE_SUBGROUPS = {
    "hand-fingers-open",
    "hand-fingers-partial",
    "hand-single-finger",
    "hand-fingers-closed",
    "hands",
    "hand-prop",
    "keycap",
    "flag",
}
EXCLUDED_SUBGROUPS = {"country-flag", "subdivision-flag"}
COLORS = "red|orange|yellow|green|blue|purple|brown|black|white"
COLORED_SHAPE = re.compile(rf"^({COLORS}) (circle|large square)$")


def strip(cps):
    return tuple(c for c in cps if c != VS16 and c not in TONES)


def ranking(path):
    """Each ranked item, keyed without FE0F or tones, to its row."""
    page = open(path, encoding="utf-8").read()
    text = re.sub(r"\s+", " ", html.unescape(re.sub("<[^>]+>", " ", page)))
    body = text[text.find(" 0 😂") :]
    parts = re.split(r" (\d+) ", " " + body)
    rows = {}
    for k in range(1, len(parts) - 1, 2):
        row = int(parts[k])
        if rows and row == 1 and max(rows.values()) > LAST_ROW:
            break  # the page's trailing script restarts the numbering
        for item in parts[k + 1].split():
            rows.setdefault(strip(tuple(ord(c) for c in item)), row)
    return rows


def row_of(cps, rows):
    """The best row of `cps` or of the item it is a gendered form of."""
    key = strip(cps)
    candidates = [key]
    if len(key) >= 3 and key[-2] == ZWJ and key[-1] in GENDER:
        candidates.append(key[:-2])
    for c in list(candidates):
        if c and c[0] in ADULTS and ZWJ in c:
            candidates += [(a,) + c[1:] for a in ADULTS]
    return min((rows[c] for c in candidates if c in rows), default=None)


def svg_names(cps):
    """The file names Twemoji may give a sequence's art."""
    names = ["-".join(f"{c:x}" for c in cps)]
    bare = tuple(c for c in cps if c != VS16)
    names.append("-".join(f"{c:x}" for c in bare))
    if len(bare) > 1:
        names.append("-".join(f"{c:x}" for c in (bare[0], VS16) + bare[1:]))
    return names


def main():
    test_path, frequency_path, svg_dir = sys.argv[1:4]
    rows = ranking(frequency_path)
    drawn = {name[:-4] for name in os.listdir(svg_dir) if name.endswith(".svg")}

    out = []
    group = subgroup = None
    written_group = written_subgroup = None
    for line in open(test_path, encoding="utf-8"):
        line = line.rstrip("\n")
        if line.startswith("# group:"):
            group = line.split(":", 1)[1].strip()
            continue
        if line.startswith("# subgroup:"):
            subgroup = line.split(":", 1)[1].strip()
            continue
        if not line or line.startswith("#"):
            continue
        fields, _, comment = line.partition("#")
        codes, status = (f.strip() for f in fields.split(";"))
        if status != "fully-qualified":
            continue
        cps = tuple(int(c, 16) for c in codes.split())
        name = re.sub(r"^\S+ E\d+\.\d+ ", "", comment.strip())
        if any(c in TONES for c in cps) or subgroup in EXCLUDED_SUBGROUPS:
            continue
        row = row_of(cps, rows)
        wanted = (
            group in WHOLE_GROUPS
            or subgroup in WHOLE_SUBGROUPS
            or (subgroup == "geometric" and COLORED_SHAPE.match(name))
            or (row is not None and row <= LAST_ROW)
        )
        if not wanted or not any(n in drawn for n in svg_names(cps)):
            continue
        if group != written_group:
            out.append(f"\n# group: {group}")
            written_group = group
        if subgroup != written_subgroup:
            out.append(f"\n# subgroup: {subgroup}")
            written_subgroup = subgroup
        out.append(line)

    print(
        "# The emoji communicators draw, one sequence per line in emoji-test.txt\n"
        "# syntax and CLDR order. Generated once by scripts/emoji_manifest.py and\n"
        "# maintained by hand since: add a line to draw another emoji. The\n"
        "# sequence's art must be in twemoji/svg."
    )
    print("\n".join(out).lstrip("\n").join(["\n", "\n"]), end="")


if __name__ == "__main__":
    main()
