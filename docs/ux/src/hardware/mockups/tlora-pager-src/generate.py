#!/usr/bin/env python3
"""Generate the T-LoRa Pager messenger mockup canvas as one SVG.

Screens are authored in device pixels (480x222) and drawn at 2x.

From this directory:

    python3 generate.py ../tlora-pager-messenger.svg /tmp/pager-native
    sh render_native.sh /tmp/pager-native ../tlora-pager-native /tmp/chrome-profile
    python3 native_viewer.py ../tlora-pager-native ../tlora-pager-native/index.html

The second argument writes each screen alone at panel size; render_native.sh
rasterizes those at one pixel per panel pixel with headless Chrome and
quantizes to RGB565 (needs Google Chrome and ImageMagick). deantenna.py, which
needs Pillow, made pager-photo.png from the site's board photo.
"""
import hashlib
import os
import random
import sys
from xml.sax.saxutils import escape

SANS = "'Helvetica Neue', Helvetica, Arial, sans-serif"
MONO = "Menlo, 'SF Mono', Consolas, monospace"

C = dict(
    bg="#0B0D10",
    chrome="#0E1115",
    line="#20252C",
    text="#EEF1F5",
    text2="#9AA3AE",
    text3="#7F8995",
    accent="#4DA3FF",
    secret="#A585FF",  # the accent where what is sent has forward secrecy
    focus="#18304D",
    out="#2A62C9",
    out_secret="#7045CC",
    inb="#23272E",
    green="#3DD68C",
    amber="#F5B544",
    red="#FF6B5E",
    field="#161A20",
    panel="#11151A",
    menu="#1B2027",
    menuline="#2E3540",
    key="#4A525C",
)

W, H = 480, 222
STRIP = 18  # status strip height
HDR = 28  # conversation header height

# ---------------------------------------------------------------- metrics
_HELV = {}
for ch, w in zip(
    "abcdefghijklmnopqrstuvwxyz",
    [556, 556, 500, 556, 556, 278, 556, 556, 222, 222, 500, 222, 833,
     556, 556, 556, 556, 333, 500, 278, 556, 500, 722, 500, 500, 500],
):
    _HELV[ch] = w
for ch, w in zip(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    [667, 667, 722, 722, 667, 611, 778, 722, 278, 500, 667, 556, 833,
     722, 778, 667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611],
):
    _HELV[ch] = w
for ch in "0123456789":
    _HELV[ch] = 556
_HELV.update({" ": 278, ".": 278, ",": 278, ":": 278, ";": 278, "!": 278,
              "?": 556, "'": 191, "’": 222, '"': 355, "-": 333,
              "–": 556, "—": 1000, "·": 278, "…": 1000,
              "(": 333, ")": 333, "/": 278, "%": 889, "*": 389, "+": 584,
              "−": 584, "#": 556, "@": 1015, "♥": 700})


def tw(s, size, bold=False, mono=False):
    if mono:
        return len(s) * size * 0.602
    k = 1.06 if bold else 1.0
    return sum(_HELV.get(ch, 600) for ch in s) * size / 1000 * k


def fit(s, size, maxw, bold=False):
    if tw(s, size, bold) <= maxw:
        return s
    while s and tw(s + "…", size, bold) > maxw:
        s = s[:-1]
    return s.rstrip() + "…"


def wrap(s, size, maxw, bold=False):
    lines, cur = [], ""
    for word in s.split(" "):
        trial = word if not cur else cur + " " + word
        if tw(trial, size, bold) <= maxw:
            cur = trial
        else:
            if cur:
                lines.append(cur)
            cur = word
    if cur:
        lines.append(cur)
    return lines


# ---------------------------------------------------------------- primitives
def T(x, y, s, size=14, fill=None, w=400, anchor="start", mono=False,
      extra=""):
    fill = fill or C["text"]
    a = f'<text x="{x:.1f}" y="{y:.1f}" font-size="{size}" fill="{fill}"'
    if mono:
        a += f' font-family="{MONO}"'
    if w != 400:
        a += f' font-weight="{w}"'
    if anchor != "start":
        a += f' text-anchor="{anchor}"'
    return a + f"{extra}>{escape(s)}</text>"


def R(x, y, w, h, fill="none", rx=0, stroke=None, sw=1, extra=""):
    a = (f'<rect x="{x:.1f}" y="{y:.1f}" width="{w:.1f}" height="{h:.1f}"'
         f' fill="{fill}"')
    if rx:
        a += f' rx="{rx}"'
    if stroke:
        a += f' stroke="{stroke}" stroke-width="{sw}"'
    return a + f"{extra}/>"


def P(d, stroke=None, fill="none", sw=1.2, extra=""):
    a = f'<path d="{d}" fill="{fill}"'
    if stroke:
        a += (f' stroke="{stroke}" stroke-width="{sw}"'
              ' stroke-linecap="round" stroke-linejoin="round"')
    return a + f"{extra}/>"


def CIRC(cx, cy, r, fill="none", stroke=None, sw=1):
    a = f'<circle cx="{cx:.1f}" cy="{cy:.1f}" r="{r}" fill="{fill}"'
    if stroke:
        a += f' stroke="{stroke}" stroke-width="{sw}"'
    return a + "/>"


def LINE(x1, y1, x2, y2, stroke=None, sw=1):
    return (f'<path d="M{x1:.1f} {y1:.1f} L{x2:.1f} {y2:.1f}" '
            f'stroke="{stroke or C["line"]}" stroke-width="{sw}"/>')


def rrect(x, y, w, h, tl, tr, br, bl):
    return (f"M{x+tl:.1f} {y:.1f} H{x+w-tr:.1f} "
            f"Q{x+w:.1f} {y:.1f} {x+w:.1f} {y+tr:.1f} V{y+h-br:.1f} "
            f"Q{x+w:.1f} {y+h:.1f} {x+w-br:.1f} {y+h:.1f} H{x+bl:.1f} "
            f"Q{x:.1f} {y+h:.1f} {x:.1f} {y+h-bl:.1f} V{y+tl:.1f} "
            f"Q{x:.1f} {y:.1f} {x+tl:.1f} {y:.1f} Z")


# ---------------------------------------------------------------- glyphs
# Avatars follow the iOS app's AvatarStyle / ChannelAvatar / PeerAvatarShape,
# which are canonical.
ROUNDED = "ui-rounded, 'SF Pro Rounded', 'Helvetica Neue', sans-serif"
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

# Per-node presentation: hint text override (star-truncated) and role shape.
NODES = {
    "Jo Reyes": {"hint": "H1x*"},
    "Riverbend Camp": {"shape": "triangle"},
    "Member 4Fz*": {"hint": "4Fz*", "shape": "hexagon"},
}


def _bytes(label, n=3):
    return hashlib.sha256(label.encode()).digest()[:n]


def address(name):
    """A fake 44-digit address whose leading digits are the node's hint."""
    rnd = random.Random(name)
    digits = "".join(rnd.choice(B58) for _ in range(44))
    hint = NODES.get(name, {}).get("hint")
    if hint:
        stem = hint.rstrip("*")
        digits = stem + digits[len(stem):]
    return digits


def hint_text(name):
    return NODES.get(name, {}).get("hint") or address(name)[:4]


def _apca_prefers_white(r, g, b):
    def lum(r, g, b):
        y = 0.2126729 * r ** 2.4 + 0.7151522 * g ** 2.4 + 0.0721750 * b ** 2.4
        return y + (0.022 - y) ** 1.414 if y < 0.022 else y
    bg = lum(r, g, b)
    white = max(0, 1 ** 0.62 - bg ** 0.65)
    black = max(0, bg ** 0.56 - lum(0, 0, 0) ** 0.57)
    return white > black


def _hex(r, g, b):
    return "#%02X%02X%02X" % tuple(round(v * 255) for v in (r, g, b))


def channel_style(name):
    import colorsys
    canonical = name.lower()
    if canonical == "public":
        return "#0A84FF", "#fff", "P"
    if canonical == "emergency":
        return "#FF453A", "#fff", "E"
    words = [w for w in name.replace("-", " ").replace("_", " ").split()]
    initials = "".join(w[0] for w in words[:4]).upper()
    r, g, b = (v / 255 for v in _bytes("chan:" + name))
    h, s, v = colorsys.rgb_to_hsv(r, g, b)
    dark = v < 0.62
    s = min(s, 0.85) if dark else min(s, 0.45)
    v = 0.42 if dark else 0.90
    return _hex(*colorsys.hsv_to_rgb(h, s, v)), "#fff" if dark else "#000", \
        initials


def _rounded_polygon(pts, rad):
    import math
    n = len(pts)
    d = []
    for i in range(n):
        p0, p1, p2 = pts[i - 1], pts[i], pts[(i + 1) % n]
        v1 = (p0[0] - p1[0], p0[1] - p1[1])
        v2 = (p2[0] - p1[0], p2[1] - p1[1])
        l1, l2 = math.hypot(*v1), math.hypot(*v2)
        ang = math.acos((v1[0] * v2[0] + v1[1] * v2[1]) / (l1 * l2))
        t = rad / math.tan(ang / 2)
        a = (p1[0] + v1[0] / l1 * t, p1[1] + v1[1] / l1 * t)
        b = (p1[0] + v2[0] / l2 * t, p1[1] + v2[1] / l2 * t)
        d.append(("M" if i == 0 else "L") + f"{a[0]:.2f} {a[1]:.2f}")
        d.append(f"A{rad:.2f} {rad:.2f} 0 0 1 {b[0]:.2f} {b[1]:.2f}")
    return "".join(d) + "Z"


def peer_outline(cx, cy, size, shape):
    import math
    if shape == "circle":
        return None
    bottom = cy + size / 2
    if shape == "triangle":
        h = size * 1.16
        hb = h / math.sqrt(3)
        pts = [(cx, bottom - h), (cx + hb, bottom), (cx - hb, bottom)]
        return _rounded_polygon(pts, size * 0.16)
    top = cy - size / 2
    hw = size / math.sqrt(3)
    he = hw / 2
    pts = [(cx - hw, cy), (cx - he, top), (cx + he, top), (cx + hw, cy),
           (cx + he, bottom), (cx - he, bottom)]
    return _rounded_polygon(pts, size * 0.2)


def _lines(x, cy, lines, fs, spacing, fill, family):
    lh = fs * 1.0 + spacing
    total = lh * (len(lines) - 1)
    o = []
    for i, line in enumerate(lines):
        y = cy - total / 2 + i * lh + fs * 0.36
        o.append(f'<text x="{x:.1f}" y="{y:.1f}" font-size="{fs:.2f}" '
                 f'fill="{fill}" font-weight="700" text-anchor="middle" '
                 f'font-family="{family}">{escape(line)}</text>')
    return o


def avatar(cx, cy, r, name, kind="peer", ring=None):
    size = 2 * r
    out = []
    if kind == "channel":
        fill, text, initials = channel_style(name)
        out.append(R(cx - r, cy - r, size, size, fill, rx=size * 0.25))
        lines = ([initials[:2], initials[2:]] if len(initials) > 2
                 else [initials])
        ratio = {1: 0.76, 2: 0.52}.get(len(initials), 0.40)
        out += _lines(cx, cy, lines, size * ratio, size * -0.02, text, ROUNDED)
        return out
    shape = NODES.get(name, {}).get("shape", "circle")
    r8, g8, b8 = (v / 255 for v in _bytes("node:" + name))
    fill = _hex(r8, g8, b8)
    text = "#fff" if _apca_prefers_white(r8, g8, b8) else "#000"
    path = peer_outline(cx, cy, size, shape)
    out.append(CIRC(cx, cy, r, fill) if path is None else P(path, fill=fill))
    ht = hint_text(name)
    # The pager's avatars are small, so the hint is set far larger than the
    # iOS ratio: the 2x2 block fills the shape's inner area.
    scale = 0.82 if shape == "triangle" else 1
    fs = size * 0.38 * scale
    ty = cy + (size * (0.5 - 1.16 / 3) if shape == "triangle" else 0)
    out += _lines(cx, ty, [ht[:2], ht[2:]], fs, size * scale * 0.03, text,
                  MONO)
    return out


def battery(x, y, segs=3, bolt=False):
    o = [R(x, y, 19, 9, rx=2, stroke=C["text2"], sw=1),
         R(x + 19.5, y + 2.5, 1.8, 4, C["text2"], rx=0.6)]
    for i in range(segs):
        o.append(R(x + 2 + i * 3.9, y + 2, 3.1, 5, C["text"], rx=0.5))
    if bolt:
        o.append(P(f"M{x-5} {y-1} L{x-8} {y+5} H{x-5.5} L{x-7} {y+10} "
                   f"L{x-2.5} {y+3.5} H{x-5} Z", fill=C["text"]))
    return o


def gnss(cx, cy, col=None):
    col = col or C["text2"]
    return [CIRC(cx, cy, 3.6, stroke=col, sw=1.1), CIRC(cx, cy, 1.1, col),
            P(f"M{cx} {cy-6} V{cy-4} M{cx} {cy+4} V{cy+6} "
              f"M{cx-6} {cy} H{cx-4} M{cx+4} {cy} H{cx+6}", col, sw=1.1)]


def bt(cx, cy, col=None):
    col = col or C["text2"]
    return [P(f"M{cx-3} {cy-3} L{cx+3} {cy+3} L{cx} {cy+6} V{cy-6} "
              f"L{cx+3} {cy-3} L{cx-3} {cy+3}", col, sw=1.1)]


def bell(cx, cy, col=None, slash=False):
    col = col or C["text2"]
    o = [P(f"M{cx-4} {cy+3} Q{cx-3.5} {cy+1} {cx-3.5} {cy-1} "
           f"Q{cx-3.5} {cy-5} {cx} {cy-5} Q{cx+3.5} {cy-5} {cx+3.5} {cy-1} "
           f"Q{cx+3.5} {cy+1} {cx+4} {cy+3} Z M{cx-1.3} {cy+4.5} "
           f"H{cx+1.3}", col, sw=1.1)]
    if slash:
        o.append(P(f"M{cx-5} {cy-5} L{cx+5} {cy+5}", col, sw=1.2))
    return o




# ---------------------------------------------------------------- type scale
# Sized for the real panel: about 54 x 25 mm at ~227 ppi. Body text is 20 px
# (~2.3 mm) and nothing is smaller than 16 px (~1.8 mm).
F_BODY = 20
F_SEC = 17
F_SMALL = 16

STRIP = 22  # status strip height
HDR = 30  # pushed-screen header height
TOP = STRIP + HDR
COMP_H = 34
COMP_Y = H - COMP_H  # composer top
BAR_H = 24  # the composer, collapsed while reading
BAR_Y = H - BAR_H


def scaled(items, cx, cy, k):
    """Scale a group of glyph primitives about (cx, cy)."""
    return ([f'<g transform="translate({cx:.1f},{cy:.1f}) scale({k}) '
             f'translate({-cx:.1f},{-cy:.1f})">'] + items + ["</g>"])


_cl_n = [0]


def clip(items, x, y, w, h):
    _cl_n[0] += 1
    cid = f"cl{_cl_n[0]}"
    return ([f'<clipPath id="{cid}"><rect x="{x}" y="{y}" width="{w}" '
             f'height="{h}"/></clipPath><g clip-path="url(#{cid})">']
            + items + ["</g>"])


DEVICE_NAME = "Juniper"


ALT_COL = "#F5A524"  # the Alt key's orange, which its symbol legends share


def shift_icon(cx, cy, mode):
    """Shift's state: 'once' an outlined arrow, 'lock' filled with a bar."""
    top, mid, foot = cy - 7.5, cy - 0.5, cy + 3.5
    d = (f"M{cx} {top} L{cx+7} {mid} H{cx+3.2} V{foot} H{cx-3.2} V{mid} "
         f"H{cx-7} Z")
    if mode == "lock":
        return [P(d, C["text"], C["text"], sw=1.2),
                R(cx - 4.5, cy + 5.5, 9, 2.2, C["text"], rx=0.8)]
    return [P(d, C["text"], sw=1.5)]


def alt_icon(cx, cy, mode):
    """Alt's state, drawn as its orange key: outlined once, filled with a bar
    when locked."""
    x, y, w, h = cx - 7.5, cy - 7, 15, 10
    if mode == "lock":
        return [R(x, y, w, h, ALT_COL, rx=4),
                R(cx - 4.5, cy + 5.5, 9, 2.2, ALT_COL, rx=0.8)]
    return [R(x + 0.75, y + 0.75, w - 1.5, h - 1.5, rx=3.5, stroke=ALT_COL,
              sw=1.5)]


def status(time="14:32", segs=3, bolt=False, silent=False, phone=True,
           batt_col=None, shift=None, alt=None):
    """shift, alt: None, 'once' or 'lock', shown left of the status icons in
    keyboard order."""
    o = [R(0, 0, W, STRIP, C["chrome"])]
    o.append(T(8, 16.5, DEVICE_NAME, F_SMALL, C["text2"], 600))
    o.append(T(W / 2, 16.5, time, F_SMALL, C["text"], 700, "middle"))
    b = battery(449, 6.5, segs, bolt)
    if batt_col:
        b = [s.replace(C["text"], batt_col).replace(C["text2"], batt_col)
             for s in b]
    o += scaled(b, 459, 11, 1.3)
    x = 426
    o += scaled(gnss(x, 11), x, 11, 1.3)
    x -= 20
    if phone:
        o += scaled(bt(x, 11), x, 11, 1.3)
        x -= 20
    if silent:
        o += scaled(bell(x, 11, slash=True), x, 11, 1.3)
        x -= 20
    x -= 6
    if shift:
        o += scaled(shift_icon(x, 11, shift), x, 11, 1.15)
        x -= 24
    if alt:
        o += scaled(alt_icon(x, 11, alt), x, 11, 1.15)
    return o


def glyph_chats(cx, cy, col):
    return [P(rrect(cx - 8, cy - 7, 16, 11.5, 3.5, 3.5, 3.5, 3.5), col, sw=1.4),
            P(f"M{cx-4} {cy+4.5} L{cx-5.5} {cy+8} L{cx} {cy+4.5}", col,
              sw=1.4)]


def glyph_peers(cx, cy, col):
    pts = [(cx, cy - 6), (cx - 7, cy + 5), (cx + 7, cy + 5)]
    o = [P(f"M{pts[0][0]} {pts[0][1]} L{pts[1][0]} {pts[1][1]} "
           f"L{pts[2][0]} {pts[2][1]} Z", col, sw=1.2)]
    for (x, y) in pts:
        o.append(CIRC(x, y, 2.6, C["chrome"], col, 1.4))
    return o


def glyph_device(cx, cy, col):
    import math
    o = [CIRC(cx, cy, 4.6, stroke=col, sw=1.6), CIRC(cx, cy, 1.4, col)]
    for i in range(8):
        a = i * math.pi / 4
        o.append(P(f"M{cx+6*math.cos(a):.2f} {cy+6*math.sin(a):.2f} "
                   f"L{cx+8.2*math.cos(a):.2f} {cy+8.2*math.sin(a):.2f}",
                   col, sw=2.2))
    return o


def glyph_plus(cx, cy, col, r=15):
    return [CIRC(cx, cy, r, stroke=col, sw=1.8),
            P(f"M{cx-6} {cy} H{cx+6} M{cx} {cy-6} V{cy+6}", col, sw=2.2)]


def glyph_pencil(cx, cy, col):
    return [P(f"M{cx-5} {cy+5} L{cx-4} {cy+1} L{cx+3} {cy-6} L{cx+6} {cy-3} "
              f"L{cx-1} {cy+4} Z M{cx+1} {cy-4} L{cx+4} {cy-1}", col, sw=1.4)]


def glyph_warn(cx, cy, col, k=1.0):
    return [P(f"M{cx} {cy-8*k} L{cx+9*k} {cy+7*k} H{cx-9*k} Z", col,
              sw=1.8 * k),
            P(f"M{cx} {cy-2.5*k} V{cy+2*k}", col, sw=2 * k),
            CIRC(cx, cy + 4.6 * k, 1.2 * k, col)]


RAIL_W = 66


def rail(active, focused=False, unread=2):
    o = [R(0, STRIP, RAIL_W, H - STRIP, C["chrome"]),
         LINE(RAIL_W - 0.5, STRIP, RAIL_W - 0.5, H)]
    items = [("Chats", glyph_chats), ("Peers", glyph_peers),
             ("Device", glyph_device)]
    cell = (H - STRIP) / 3
    for i, (name, g) in enumerate(items):
        y0 = STRIP + i * cell
        on = name == active
        col = C["accent"] if on else C["text3"]
        if on and focused:
            o.append(R(4, y0 + 4, RAIL_W - 8, cell - 8, C["focus"], rx=8,
                       stroke=C["accent"], sw=1.8))
        elif on:
            o.append(R(0, y0 + 10, 4, cell - 20, C["accent"], rx=2))
        cx, cy = RAIL_W / 2, y0 + 26
        o += scaled(g(cx, cy, col), cx, cy, 1.5)
        o.append(T(cx, y0 + 56, name, F_SMALL, col, 700 if on else 500,
                   "middle"))
        if name == "Chats" and unread:
            o.append(CIRC(cx + 13, cy - 11, 8.5, C["red"]))
            o.append(T(cx + 13, cy - 6.5, str(unread), 12.5, "#fff", 700,
                       "middle"))
    return o


def section_label(x, y, s, col=None):
    return T(x, y, s, F_SMALL, col or C["text2"], 700)


def switch(right, cy, on):
    """An on/off setting: knob position and fill carry the state, no words."""
    w, h = 40, 22
    x, y = right - w, cy - h / 2
    o = [R(x, y, w, h, C["accent"] if on else "#3A414B", rx=h / 2)]
    kx = x + w - h / 2 if on else x + h / 2
    o.append(CIRC(kx, cy, h / 2 - 2.5, "#fff" if on else "#C9CED6"))
    return o


def signal_bars(x, y, n=3, col=None):
    col = col or C["green"]
    o = []
    for i in range(4):
        h = 4 + i * 3
        o.append(R(x + i * 4.6, y - h, 3.2, h, col if i < n else C["text3"],
                   rx=0.6))
    return o


def chevron(x, cy, col=None):
    return P(f"M{x-4} {cy-6} L{x+2} {cy} L{x-4} {cy+6}", col or C["text3"],
             sw=2)


# Reaction glyphs follow the iOS palette (🩷 👍 👎 🤣 ‼️ ❓) in emoji colors.
# They are drawn, not set: the panel has no color emoji font, and a font
# glyph is a few pixels at this size. Each fills about a 20 px box at k=1.
REACTIONS = ["<3", "+1", "-1", "ha", "!", "?"]
E_PINK = "#FF8FC4"
E_YELLOW = "#FFC83D"
E_SHADE = "#B87A0E"
E_INK = "#4A2E08"
E_TEAR = "#5AB8FF"
E_RED = "#F0453A"


def heart(cx, cy, k=1.0):
    return P(f"M{cx} {cy+5.5*k} C{cx-8*k} {cy+0.5*k} {cx-6.5*k} {cy-6*k} "
             f"{cx-3.2*k} {cy-6*k} C{cx-1.4*k} {cy-6*k} {cx} {cy-4.6*k} "
             f"{cx} {cy-3.4*k} C{cx} {cy-4.6*k} {cx+1.4*k} {cy-6*k} "
             f"{cx+3.2*k} {cy-6*k} C{cx+6.5*k} {cy-6*k} {cx+8*k} {cy+0.5*k} "
             f"{cx} {cy+5.5*k} Z", fill=E_PINK)


def thumb(cx, cy, down=False):
    """A fist with the thumb up, or turned over for down."""
    hand = ("M-8 -0.3 L-4 -0.3 L-2 -6.3 Q-1 -9.3 1.5 -8.3 Q3 -7.3 2.5 -4.3 "
            "L1.5 -0.8 L6 -0.8 Q8 -0.8 8 1.2 Q8 2.7 7 3.2 Q8.2 4 7.6 5.4 "
            "Q8 6.6 7 7.4 Q7.6 8.6 6 9.2 L-5 9.2 Q-8 9.2 -8 6.7 Z")
    turn = " rotate(180)" if down else ""
    return [f'<g transform="translate({cx:.1f},{cy:.1f}){turn}">',
            P(hand, E_SHADE, E_YELLOW, sw=0.9),
            P("M3 3.2 H7 M3 5.4 H7.4 M3 7.4 H6.8", E_SHADE, sw=0.9),
            "</g>"]


def laugh(cx, cy):
    """Rolling on the floor laughing: a tilted face, eyes shut, tears."""
    return [f'<g transform="translate({cx:.1f},{cy:.1f}) rotate(-20)">',
            CIRC(0, 0, 8.6, E_YELLOW),
            P("M-6 -4.8 L-2.6 -3.2 L-6 -1.6 M6 -4.8 L2.6 -3.2 L6 -1.6",
              E_INK, sw=1.5),
            P("M-5.6 0.6 H5.6 Q5.6 7 0 7 Q-5.6 7 -5.6 0.6 Z", fill=E_INK),
            P("M-4.9 0.6 H4.9 L4.7 2.2 H-4.7 Z", fill="#fff"),
            P("M-8.4 -2.4 Q-12.2 1.4 -10 3.2 Q-7.8 4 -8.4 -2.4 Z",
              fill=E_TEAR),
            P("M8.4 -2.4 Q12.2 1.4 10 3.2 Q7.8 4 8.4 -2.4 Z", fill=E_TEAR),
            "</g>"]


def bangs(cx, cy):
    o = []
    for x in (cx - 3.6, cx + 3.6):
        o.append(P(f"M{x-2:.1f} {cy-8.6:.1f} H{x+2:.1f} L{x+1.1:.1f} "
                   f"{cy+3:.1f} H{x-1.1:.1f} Z", E_RED, E_RED, sw=1))
        o.append(CIRC(x, cy + 7, 1.9, E_RED))
    return o


def question(cx, cy):
    return [P(f"M{cx-4.6} {cy-4.2} C{cx-4.6} {cy-10.2} {cx+5} {cy-10.2} "
              f"{cx+5} {cy-4.6} C{cx+5} {cy-1.2} {cx} {cy-1.2} {cx} {cy+2.8}",
              E_RED, sw=3.2),
            CIRC(cx, cy + 7.2, 2, E_RED)]


def reaction_glyph(tok, cx, cy, k=1.0):
    g = {"<3": lambda: [heart(cx, cy + 0.5, 1.35)],
         "+1": lambda: thumb(cx, cy),
         "-1": lambda: thumb(cx, cy, down=True),
         "ha": lambda: laugh(cx, cy),
         "!": lambda: bangs(cx, cy),
         "?": lambda: question(cx, cy)}[tok]()
    return g if k == 1 else scaled(g, cx, cy, k)


def menu_card(mx, my, mw, mh):
    return [R(mx + 1, my + 3, mw, mh, "#000", rx=12, extra=' opacity="0.5"'),
            R(mx, my, mw, mh, C["menu"], rx=12, stroke=C["menuline"])]


def menu_items(mx, my, mw, labels, focus=0, ih=32, danger=()):
    o = []
    yy = my
    for i, label in enumerate(labels):
        if i == focus:
            o.append(R(mx + 5, yy, mw - 10, ih - 2, C["focus"], rx=7,
                       stroke=C["accent"], sw=1.6))
        col = C["red"] if label in danger else C["text"]
        o.append(T(mx + 16, yy + ih / 2 + 6, label, F_BODY, col,
                   700 if i == focus else 400))
        yy += ih
    return o


# ---------------------------------------------------------------- list rows
# Lists clip their last row at the bottom edge when more follow; the row
# height is chosen so that the overflow row shows about half its height.
ROW = 44


def chat_row(y, kind, name, preview, time, unread=False, muted=False,
             focused=False, x0=RAIL_W, draft=False):
    o = []
    if focused:
        o.append(R(x0, y, W - x0, ROW, C["focus"]))
        o.append(R(x0, y, 4, ROW, C["accent"]))
    cy = y + ROW / 2
    o += avatar(x0 + 25, cy, 17, name, kind)
    nx = x0 + 51
    tx = W - 10
    o.append(T(tx, y + 19.5, time, F_SMALL,
               C["accent"] if unread else C["text3"], 600, "end"))
    nright = tx - tw(time, F_SMALL) - 8
    if muted:
        o += scaled(bell(nright - 6, y + 14, C["text3"], slash=True),
                    nright - 6, y + 14, 1.3)
        nright -= 20
    nm_col = C["red"] if name == "EMERGENCY" else C["text"]
    o.append(T(nx, y + 20, fit(name, F_BODY, nright - nx, True), F_BODY,
               nm_col, 700 if unread else 600))
    pright = W - (26 if unread else 10)
    px = nx
    if draft:
        o.append(T(nx, y + 39, "Draft", F_SEC, C["amber"], 700))
        px = nx + tw("Draft", F_SEC, True) + 6
    o.append(T(px, y + 39, fit(preview, F_SEC, pright - px), F_SEC,
               C["text2"] if unread else C["text3"]))
    if unread:
        o.append(CIRC(W - 14, y + 33.5, 5, C["accent"]))
    if not focused:
        o.append(LINE(nx, y + ROW - 0.5, W, y + ROW - 0.5))
    return o


def setting_row(x0, y, label, val, focused=False, chev=False, rh=36,
                danger=False, muted=False):
    o = []
    if focused:
        o.append(R(x0 + 4, y + 1, W - x0 - 8, rh - 2, C["focus"], rx=8,
                   stroke=C["accent"], sw=1.6))
    col = C["red"] if danger else (C["text3"] if muted else C["text"])
    o.append(T(x0 + 12, y + rh / 2 + 7, label, F_BODY, col,
               700 if focused else 400))
    right = W - 14
    if chev:
        o.append(chevron(right - 2, y + rh / 2))
        right -= 16
    if isinstance(val, bool):
        o += switch(right, y + rh / 2, val)
    elif val:
        o.append(T(right, y + rh / 2 + 6, val, F_SEC, C["text2"], 400, "end"))
    if not focused:
        o.append(LINE(x0 + 12, y + rh - 0.5, W, y + rh - 0.5))
    return o


# ---------------------------------------------------------------- transcript
B_FS = F_BODY
B_LH = 24
B_PX = 11
B_PY = 4
B_MAX = 330


# Reactions on a message, after the iOS ReactionBadgeView: round chips over
# the bubble's outer top corner (top-left on a sent message, top-right on a
# received one), overlapping like a hand of cards. Ours is in the bubble color
# and sits frontmost at the corner; matching reactions share a chip with a
# count; one dot trail per cluster falls outside the bubble.
CHIP_R = 14
CHIP_STEP = 21
CHIP_RISE = 6  # chip center above the bubble's top edge
CHIP_THEIRS = "#323A45"


def reaction_reserve(it):
    """Space a reacted message keeps above its bubble for the chips, and for
    a count badge when there is one. A sender label beside the cluster
    shares it."""
    if not it.get("reactions"):
        return 0
    counted = any(n > 1 for _, n, _ in it["reactions"])
    need = CHIP_RISE + CHIP_R + 2 + (6 if counted else 0)
    return max(0, need - (18 if it.get("sender") else 0))


def reaction_cluster(bx, by, bw, outbound, reactions):
    """reactions: (token, count, includes mine) per chip, in arrival order."""
    mine = [r for r in reactions if r[2]]
    theirs = [r for r in reactions if not r[2]]
    chips = mine + theirs if outbound else theirs + mine
    n = len(chips)
    cy = by - CHIP_RISE
    side = -1 if outbound else 1  # toward the outer side
    corner = bx if outbound else bx + bw
    # (cx, chip) from back to front.
    placed = [(corner + i * CHIP_STEP if outbound
               else corner - (n - 1 - i) * CHIP_STEP, c)
              for i, c in enumerate(chips)]
    if outbound:
        placed.reverse()
    o = []
    for j, (cx, (tok, count, is_mine)) in enumerate(placed):
        fill = C["out"] if is_mine else CHIP_THEIRS
        if j == n - 1:
            # The thought-dot trail, from the corner chip only.
            for d, r in ((14.8, 4.1), (20.5, 2.1)):
                o.append(CIRC(cx + side * d, cy + d, r + 2, C["bg"]))
                o.append(CIRC(cx + side * d, cy + d, r, fill))
        o.append(CIRC(cx, cy, CHIP_R + 2, C["bg"]))
        o.append(CIRC(cx, cy, CHIP_R, fill))
        o += reaction_glyph(tok, cx, cy, 0.78)
    for cx, (tok, count, is_mine) in placed:
        if count > 1:
            bx_ = cx + side * 11
            o.append(CIRC(bx_, cy - 11, 9, C["bg"]))
            o.append(T(bx_, cy - 5.5, str(count), F_SMALL, C["text"], 700,
                       "middle"))
    return o


def layout_items(items):
    """Return a list of (item, height, gap_before)."""
    out = []
    prev = None
    for it in items:
        k = it["k"]
        if k in ("date", "status", "tomb", "parts"):
            h = 21
        elif k == "invite":
            h = 64
        elif k == "gap":
            h = B_LH + 2 * B_PY
        else:
            lines = wrap(it["text"], B_FS, B_MAX - 2 * B_PX)
            it["_lines"] = lines
            h = len(lines) * B_LH + 2 * B_PY
            if it.get("quote"):
                h += QUOTE_H
            if it.get("sender"):
                h += 18
            h += reaction_reserve(it)
        if prev is None or k in ("date", "status", "parts"):
            gap = 0 if k in ("status", "parts") else 3
        elif k == "date" or prev["k"] == "date":
            gap = 6
        else:
            same = (prev["k"] == k and prev.get("who") == it.get("who"))
            gap = 3 if same else 8
        if k not in ("status", "parts"):
            prev = it
        out.append((it, h, gap))
    return out


# A reply's quote of the message it answers, inside the top of its bubble.
QUOTE_H = 42


def quote_block(x, y, w, outbound, who, snippet, secret=False):
    """The answered message's sender and the start of its text, behind a
    bar, as the composer's Replying-to strip draws them. In my bubbles, in
    tints of the bubble: violet under forward secrecy."""
    if not outbound:
        bar, name, body = C["accent"], C["accent"], C["text2"]
    elif secret:
        bar, name, body = "#DDD0FF", "#ECE4FF", "#D6CCF5"
    else:
        bar, name, body = "#CFE0FF", "#E4EDFF", "#C9D8F5"
    return [R(x, y + 5, 3, QUOTE_H - 9, bar, rx=1.5),
            T(x + 10, y + 19, fit(who, F_SMALL, w - 10, True), F_SMALL, name,
              700),
            T(x + 10, y + 36, fit(snippet, F_SMALL, w - 10), F_SMALL, body)]


def quote_width(who, snippet):
    return min(B_MAX - 2 * B_PX,
               10 + max(tw(who, F_SMALL, True), tw(snippet, F_SMALL)))


def part_dots(x, cy, present, count, missing=()):
    """One dot per part of a message arriving in pieces: filled when
    received, hollow while awaited, amber once given up on."""
    o = []
    for i in range(count):
        cx = x + 5 + i * 13
        if i in missing:
            o.append(CIRC(cx, cy, 4, stroke=C["amber"], sw=1.6))
        elif i < present:
            o.append(CIRC(cx, cy, 4.5, C["text2"]))
        else:
            o.append(CIRC(cx, cy, 4, stroke=C["text3"], sw=1.6))
    return o


def invite_card(x, y, focused, name="Trail Crew", kind="channel",
                sub="Channel invite"):
    """A link that is a message's whole body, drawn as a card: a channel
    invitation, or a peer's contact."""
    w, h = 300, 64
    o = []
    if focused:
        o.append(P(rrect(x - 3.5, y - 3.5, w + 7, h + 7, 17, 17, 17, 17),
                   C["accent"], sw=2.2))
    o.append(P(rrect(x, y, w, h, 14, 14, 14, 5), fill=C["inb"]))
    o += avatar(x + 30, y + h / 2, 20, name, kind)
    o.append(T(x + 60, y + 27, name, F_BODY, C["text"], 700))
    o.append(T(x + 60, y + 49, sub, F_SEC, C["text2"]))
    o.append(chevron(x + w - 16, y + h / 2))
    return o, w


def transcript(items, top, bottom, channel=False):
    lay = layout_items(items)
    total = sum(h + g for _, h, g in lay)
    y = bottom - 4 - total
    o = []
    pos = {}
    in_x = 42 if channel else 8
    for idx, (it, h, gap) in enumerate(lay):
        y += gap
        k = it["k"]
        hidden = top - y
        if (y + h <= top + 12 or (k in ("date", "status") and hidden > 0)
                or (k == "status" and idx - 1 not in pos)):
            # Off screen, or a label that would be cut. A status line goes
            # with its bubble. A bubble above the top is clipped under the
            # header: the history's clipped row, saying there is more.
            y += h
            continue
        if k == "date":
            # The day, then the time, as the iOS separator sets them.
            day, time = it["day"], it["time"]
            gap_w = tw(" ", F_SMALL)
            dw = tw(day, F_SMALL, True) + gap_w + tw(time, F_SMALL)
            dx = W / 2 - dw / 2
            o.append(T(dx, y + 15, day, F_SMALL, C["text3"], 700))
            o.append(T(dx + tw(day, F_SMALL, True) + gap_w, y + 15, time,
                       F_SMALL, C["text3"]))
        elif k == "status":
            col = {"amber": C["amber"]}.get(it.get("tone"), C["text3"])
            if it.get("side") == "in":
                o.append(T(in_x + 4, y + 18, it["text"], F_SMALL, col, 600))
            else:
                o.append(T(W - 8, y + 18, it["text"], F_SMALL, col, 600,
                           "end"))
        elif k == "parts":
            o += part_dots(in_x + 2, y + 12, it["present"], it["count"],
                           it.get("missing", ()))
        elif k == "tomb":
            o.append(T(in_x + 4, y + 16, it["text"], F_SEC, C["text3"],
                       extra=' font-style="italic"'))
        elif k == "gap":
            # Waiting on a repair: the dots of someone typing, in the slot
            # the missing message will take.
            bw, bh = 62, h
            o.append(P(rrect(in_x, y, bw, bh, 14, 14, 14, 5), fill=C["inb"]))
            for i, shade in enumerate((C["text2"], C["text3"], "#4B535E")):
                o.append(CIRC(in_x + 17 + i * 14, y + bh / 2, 4, shade))
            pos[idx] = (in_x, y, bw, bh)
        elif k == "invite":
            g, w = invite_card(in_x, y, it.get("focused"),
                               **it.get("card", {}))
            o += g
            pos[idx] = (in_x, y, w, h)
        else:
            lines = it["_lines"]
            bw = max(tw(line, B_FS) for line in lines) + 2 * B_PX
            if it.get("pending"):
                bw += tw(" ", B_FS) + tw("\u22ef", B_FS, True)
            if it.get("quote"):
                bw = max(bw, quote_width(*it["quote"]) + 2 * B_PX)
            by = y
            if it.get("sender"):
                o.append(T(in_x + 4, y + 14, it["sender"], F_SMALL,
                           C["text2"], 700))
                by += 18
            by += reaction_reserve(it)
            bh = len(lines) * B_LH + 2 * B_PY
            qh = QUOTE_H if it.get("quote") else 0
            bh += qh
            if k == "out":
                bx = W - 8 - bw
                d = rrect(bx, by, bw, bh, 14, 14, 5, 14)
                fill = C["out_secret"] if it.get("secret") else C["out"]
            else:
                bx = in_x
                d = rrect(bx, by, bw, bh, 14, 14, 14, 5)
                fill = C["inb"]
                if channel and it.get("avatar"):
                    o += avatar(20, by + bh - 15, 15, it["who"], "peer")
            if it.get("focused"):
                o.append(P(rrect(bx - 3.5, by - 3.5, bw + 7, bh + 7, 17, 17,
                                 17, 17), C["accent"], sw=2.2))
            o.append(P(d, fill=fill))
            if qh:
                o += quote_block(bx + B_PX, by, bw - 2 * B_PX, k == "out",
                                 *it["quote"], secret=it.get("secret"))
            for li, line in enumerate(lines):
                o.append(T(bx + B_PX, by + qh + B_PY + 18 + li * B_LH, line,
                           B_FS, "#fff" if k == "out" else C["text"]))
            if it.get("pending"):
                # Where the parts still to come will go.
                lx = bx + B_PX + tw(lines[-1], B_FS) + tw(" ", B_FS)
                ly = by + qh + B_PY + 18 + (len(lines) - 1) * B_LH
                o.append(T(lx, ly, "\u22ef", B_FS,
                           C["amber"] if it["pending"] == "missing"
                           else C["text3"], 700))
            if it.get("reactions"):
                o += reaction_cluster(bx, by, bw, k == "out",
                                      it["reactions"])
            pos[idx] = (bx, by, bw, bh)
        y += h
    return clip(o, 0, top, W, bottom - top), pos


def screen_header(name, kind=None, sub=None, y=STRIP, col=None, back=True):
    """Header of a pushed screen: Back chevron, optional avatar, title."""
    c = y + HDR / 2
    o = [R(0, y, W, HDR, C["bg"]), LINE(0, y + HDR - 0.5, W, y + HDR - 0.5)]
    x = 8
    if back:
        o.append(P(f"M{13} {c-6} L{7} {c} L{13} {c+6}", C["text3"], sw=2))
        x = 22
    if kind:
        o += avatar(x + 13, c, 13, name, kind)
        x += 32
    o.append(T(x, c + 7, name, F_BODY, col or C["text"], 700))
    if sub:
        sx = x + tw(name, F_BODY, True) + 10
        o.append(T(sx, c + 6, fit(sub, F_SMALL, W - 8 - sx), F_SMALL,
                   C["text3"], 500))
    return o


# A text field is focused-but-inactive until typing or Enter activates it;
# active shows the cursor, and the wheel then moves that cursor.
ACTIVE_FIELD = "#1A2333"
ACTIVE_FIELD_SECRET = "#221A36"


def field_frame(fx, fy, fw, fh, mode, rx=14, secret=False):
    """mode: 'active', 'inactive' (focused, no cursor) or 'away'. secret:
    violet while active, as what it sends goes under forward secrecy."""
    if mode == "active":
        fill, ring = ((ACTIVE_FIELD_SECRET, C["secret"]) if secret
                      else (ACTIVE_FIELD, C["accent"]))
        return [R(fx, fy, fw, fh, fill, rx=rx, stroke=ring, sw=2.2)]
    if mode == "inactive":
        return [R(fx, fy, fw, fh, C["field"], rx=rx, stroke=C["accent"],
                  sw=1.3)]
    return [R(fx, fy, fw, fh, C["field"], rx=rx, stroke=C["menuline"],
              sw=1.2)]


def caret(x, top, h=20, col=None):
    return R(x, top, 2.5, h, col or C["accent"])


def composer(text=None, placeholder=None, mode="active", y=COMP_Y,
             dim_text=False, at=None, secret=False):
    """at: cursor position as a character index into text (default: end).
    secret: the chat holds a session with forward secrecy."""
    o = [R(0, y, W, H - y, C["bg"])]
    fx, fw, fy, fh = 8, W - 16, y + 3, COMP_H - 6
    o += field_frame(fx, fy, fw, fh, mode, secret=secret)
    ink = C["secret"] if secret else None
    if text:
        col = C["text3"] if dim_text else C["text"]
        o.append(T(fx + 12, fy + 20.5, fit(text, F_BODY, fw - 24), F_BODY,
                   col))
        if mode == "active":
            k = len(text) if at is None else at
            o.append(caret(fx + 12 + tw(text[:k], F_BODY) + 0.5, fy + 4,
                           col=ink))
    else:
        if mode == "active":
            o.append(caret(fx + 12, fy + 4, col=ink))
        o.append(T(fx + 16, fy + 20.5, placeholder, F_BODY, C["text3"]))
    return o


def composer_bar(draft=None, placeholder="Message"):
    """The composer collapsed to one dim line while focus is in the messages.
    Turning back down past the newest message reopens it."""
    o = [R(0, BAR_Y, W, BAR_H, C["chrome"]),
         LINE(0, BAR_Y + 0.5, W, BAR_Y + 0.5)]
    o += scaled(glyph_pencil(16, BAR_Y + 12, C["text3"]), 16, BAR_Y + 12, 1.2)
    s = draft or placeholder
    o.append(T(30, BAR_Y + 17.5, fit(s, F_SMALL, W - 40), F_SMALL,
               C["text2"] if draft else C["text3"]))
    return o



# ---------------------------------------------------------------- boards
NODES.update({
    "Unsaved 7cQa": {"hint": "7cQ*", "shape": "hexagon"},
    "Self 9Xk2": {"hint": "9Xk2"},
})


def screen_chats(focus=1, unread=1):
    o = [R(0, 0, W, H, C["bg"])]
    rows = [
        dict(kind="peer", name="Ridge Medic", preview=DRAFT, time="2m",
             draft=True),
        dict(kind="channel", name="Trail Crew", preview="Sam: Will wait 10 min",
             time="9m", unread=True),
        dict(kind="peer", name="Pat Okafor",
             preview="You: Bring the spare antenna?", time="41m"),
        dict(kind="channel", name="Public",
             preview="Kit: Anyone near Mill Creek?", time="1h", muted=True),
        dict(kind="peer", name="Jo Reyes", preview="Thanks!", time="3h"),
    ]
    for i, r in enumerate(rows):
        o += chat_row(STRIP + i * ROW, focused=(i == focus), **r)
    o += rail("Chats", unread=unread)
    o += status()
    return o


def screen_find():
    o = [R(0, 0, W, H, C["bg"])]
    y = STRIP
    fx = RAIL_W + 6
    o += field_frame(fx, y + 3, W - 6 - fx, 28, "active", rx=14)
    o += scaled([CIRC(fx + 14, y + 16, 4, stroke=C["text2"], sw=1.3),
                 P(f"M{fx+17} {y+19} L{fx+20} {y+22}", C["text2"], sw=1.4)],
                fx + 15, y + 17, 1.4)
    tx = fx + 30
    o.append(T(tx, y + 24, "ri", F_BODY, C["text"]))
    o.append(caret(tx + tw("ri", F_BODY) + 1, y + 7))
    o.append(T(W - 18, y + 23, "5 found", F_SMALL, C["text3"], 500, "end"))
    body = []
    yy = y + 34
    groups = [
        ("Conversations", "peer", "Ridge Medic", "", "2m", True),
        ("Peers", "peer", "Rick Alvarez", "3 hops", "3h", False),
        (None, "peer", "Riverbend Camp", "Nearby", "12m", False),
        (None, "peer", "Ridge Runner", "2 hops", "1d", False),
    ]
    for label, kind, name, meta, time, top in groups:
        if label:
            body.append(section_label(RAIL_W + 10, yy + 15, label))
            yy += 20
        rh = 34
        if top:
            # Enter's target while the field is active: tinted, with no
            # focus bar, since focus is in the field.
            body.append(R(RAIL_W, yy, W - RAIL_W, rh, C["focus"]))
        cy = yy + rh / 2
        body += avatar(RAIL_W + 23, cy, 14, name, kind)
        nx = RAIL_W + 45
        body.append(f'<text x="{nx}" y="{cy+7:.1f}" font-size="{F_BODY}" '
                    f'fill="{C["text"]}" font-weight="600"><tspan '
                    f'fill="{C["accent"]}" font-weight="800">{name[:2]}'
                    f'</tspan>{escape(name[2:])}</text>')
        if meta:
            px = nx + tw(name, F_BODY, True) + 10
            body.append(T(px, cy + 6.5, meta, F_SEC, C["text3"]))
        if time:
            body.append(T(W - 10, cy + 6, time, F_SMALL, C["text3"], 600,
                          "end"))
        yy += rh
    o += clip(body, RAIL_W, y + 34, W - RAIL_W, H - y - 34)
    o += rail("Chats", unread=1)
    o += status()
    return o


RIDGE = [
    {"k": "in", "who": "rm",
     "text": "At the north junction yet? Sam says the creek is high"},
    {"k": "out", "who": "me", "text": "Just passed it. ETA 20 min."},
    {"k": "status", "text": "Delivered"},
    {"k": "in", "who": "rm", "text": "See you at the hut"},
]


def ridge_items(**over):
    items = [dict(i) for i in RIDGE]
    for idx, patch in over.items():
        items[int(idx[1:])].update(patch)
    return items


RIDGE_SUB = "2 hops"
DRAFT = "On my way, save me some hot coffee"
DRAFT_AT = len("On my way, save me some hot")  # inserting "hot", mid-sentence


def ridge_header():
    return screen_header("Ridge Medic", "peer", RIDGE_SUB)


def screen_conversation(mode="active", secret=False):
    o = [R(0, 0, W, H, C["bg"])]
    tr, _ = transcript(ridge_items(), TOP, COMP_Y)
    o += tr
    o += ridge_header()
    o += composer(DRAFT, mode=mode, at=DRAFT_AT, secret=secret)
    o += status()
    return o


def screen_reading():
    """Focus in the messages: the composer folds to one line."""
    o = [R(0, 0, W, H, C["bg"])]
    tr, _ = transcript(ridge_items(i1={"focused": True}), TOP, BAR_Y)
    o += tr
    o += ridge_header()
    o += composer_bar(DRAFT)
    o += status()
    return o


LONG_IN = ("Hut is open and the stove works. Water from the spring is fine "
           "if you filter it. Snow starts about 200 m above the hut, so "
           "leave the trail runners and bring boots. The bunk room sleeps "
           "six; we have four, so there is room for you and Sam. Radio "
           "check at 19:00 on the usual channel.")


def screen_tall(scroll=58):
    """A message taller than the view, partway through being read.

    scroll: how far the bubble's top sits above the transcript's top.
    """
    o = [R(0, 0, W, H, C["bg"])]
    lines = wrap(LONG_IN, B_FS, B_MAX + 60 - 2 * B_PX)
    bw = max(tw(line, B_FS) for line in lines) + 2 * B_PX
    bh = len(lines) * B_LH + 2 * B_PY
    bx, by = 8, TOP - scroll
    body = [P(rrect(bx - 3.5, by - 3.5, bw + 7, bh + 7, 17, 17, 17, 17),
              C["accent"], sw=2.2),
            P(rrect(bx, by, bw, bh, 14, 14, 14, 5), fill=C["inb"])]
    for i, line in enumerate(lines):
        body.append(T(bx + B_PX, by + B_PY + 18 + i * B_LH, line, B_FS,
                      C["text"]))
    o += clip(body, 0, TOP, W, BAR_Y - TOP)
    o += ridge_header()
    o += composer_bar(DRAFT)
    o += status()
    return o


def screen_actions():
    o = [R(0, 0, W, H, C["bg"])]
    tr, pos = transcript(ridge_items(i3={"focused": True}), TOP, BAR_Y)
    o += tr
    o += ridge_header()
    o += composer_bar(DRAFT)
    mw = 236
    mx = W - 8 - mw
    my = TOP + 6
    o += reaction_menu(mx, my, mw, ["Reply", "Copy", "Details"])
    o += status()
    return o


def screen_reacted():
    o = [R(0, 0, W, H, C["bg"])]
    tr, _ = transcript(ridge_items(i1={"focused": True,
                                       "reactions": [("<3", 1, False)]}),
                       TOP, BAR_Y)
    o += tr
    o += ridge_header()
    o += composer_bar(DRAFT)
    o += status()
    return o


def reaction_menu(mx, my, mw, labels, focus=0, ih=32):
    mh = 44 + len(labels) * ih + 6
    o = menu_card(mx, my, mw, mh)
    cx, cy = mx + 8 + 17, my + 22
    for t in REACTIONS:
        o.append(CIRC(cx, cy, 17, "#2A313B"))
        o += reaction_glyph(t, cx, cy)
        cx += 37
    o.append(LINE(mx, my + 44.5, mx + mw, my + 44.5, C["menuline"]))
    o += menu_items(mx, my + 47, mw, labels, focus, ih)
    return o


def screen_details():
    o = [R(0, 0, W, H, C["bg"])]
    body = []
    y = TOP
    for label, val in [("Received", "14:29"), ("Hops", "3"),
                       ("Route", "Gh* → 4Tn"),
                       ("Signal", "−97 dBm"),
                       ("Signal-to-noise", "6.5 dB"),
                       ("Source", "Authenticated")]:
        body += setting_row(0, y, label, val)
        y += 36
    o += clip(body, 0, TOP, W, H - TOP)
    o += screen_header("Message details")
    o += status()
    return o


def screen_reply():
    o = [R(0, 0, W, H, C["bg"])]
    qh = 42
    qy = COMP_Y - qh
    tr, _ = transcript(ridge_items(), TOP, qy)
    o += tr
    o += ridge_header()
    o.append(R(0, qy, W, qh, C["bg"]))
    o.append(R(12, qy + 4, 3, qh - 6, C["accent"], rx=1.5))
    o.append(T(24, qy + 18, "Replying to Ridge Medic", F_SMALL, C["accent"],
               700))
    o.append(T(24, qy + 37, "At the north junction yet? Sam says\u2026",
               F_SEC, C["text2"]))
    o += composer("Yes, at the sign")
    o += status()
    return o


def screen_long():
    """A draft longer than the composer's three-line cap."""
    o = [R(0, 0, W, H, C["bg"])]
    draft = ("Trail is washed out past the second creek crossing, so we are "
             "taking the ridge route instead. Should add about 40 min. Sam and "
             "Kit are with me; Lee went back to move the truck. We have water "
             "and the spare radio, and I will check in again from the saddle")
    lh, cap = 24, 3
    fx, fw = 8, W - 16
    lines = wrap(draft, F_BODY, fw - 34)
    shown = lines[-cap:]
    fh = cap * lh + 10
    fy = H - 3 - fh
    top = fy - 3
    tr, _ = transcript(ridge_items(), TOP, top)
    o += tr
    o += ridge_header()
    o.append(R(0, top, W, H - top, C["bg"]))
    o += field_frame(fx, fy, fw, fh, "active")
    for i, line in enumerate(shown):
        o.append(T(fx + 12, fy + 5 + 17.5 + i * lh, line, F_BODY, C["text"]))
    cx = fx + 12 + tw(shown[-1], F_BODY) + 0.5
    o.append(caret(cx, fy + 5 + (cap - 1) * lh + 2))
    # Position within the draft: the visible lines are the last ones.
    track_top, track_h = fy + 8, fh - 16
    frac = len(shown) / len(lines)
    o.append(R(fx + fw - 9, track_top, 3, track_h, C["menuline"], rx=1.5))
    o.append(R(fx + fw - 9, track_top + track_h * (1 - frac), 3,
               track_h * frac, C["text2"], rx=1.5))
    o += status()
    return o


CREW = [
    {"k": "in", "who": "Sam Ito", "sender": "Sam",
     "text": "At the saddle", "avatar": "peer"},
    {"k": "in", "who": "Member 4Fz*", "sender": "Member 4Fz*",
     "text": "Two of us behind you", "avatar": "peer"},
    {"k": "out", "who": "me", "text": "Switchbacks, 15 min out"},
    {"k": "status", "text": "Sent"},
]


def screen_channel():
    o = [R(0, 0, W, H, C["bg"])]
    tr, _ = transcript([dict(i) for i in CREW], TOP, COMP_Y, channel=True)
    o += tr
    o += screen_header("Trail Crew", "channel", "Channel")
    o += composer(placeholder="Message Trail Crew", mode="inactive")
    o += status()
    return o


def screen_channel_actions():
    o = [R(0, 0, W, H, C["bg"])]
    items = [dict(i) for i in CREW]
    items[1]["focused"] = True
    tr, _ = transcript(items, TOP, BAR_Y, channel=True)
    o += tr
    o += screen_header("Trail Crew", "channel", "Channel")
    o += composer_bar(placeholder="Message Trail Crew")
    mw = 236
    o += reaction_menu(W - 8 - mw, STRIP + 4, mw,
                       ["Reply", "View member", "Copy", "Details"], focus=1,
                       ih=30)
    o += status()
    return o


def screen_channel_reactions():
    o = [R(0, 0, W, H, C["bg"])]
    items = [dict(i) for i in CREW]
    items[1].update(focused=True,
                    reactions=[("+1", 2, True), ("!", 1, False)])
    tr, _ = transcript(items, TOP, BAR_Y, channel=True)
    o += tr
    o += screen_header("Trail Crew", "channel", "Channel")
    o += composer_bar(placeholder="Message Trail Crew")
    o += status()
    return o


def detail_head(name, kind, line2, y=TOP, line2_col=None):
    """Avatar, name and one line of context at the top of a detail screen."""
    o = avatar(32, y + 30, 22, name, kind)
    o.append(T(64, y + 25, name, F_BODY, C["text"], 700))
    o.append(T(64, y + 46, line2, F_SMALL, line2_col or C["text3"], 500))
    return o


def screen_member():
    o = [R(0, 0, W, H, C["bg"])]
    body = detail_head("Member 4Fz*", "peer", "Heard in Trail Crew · 2m")
    y = TOP + 62
    body += setting_row(0, y, "Request identity", None, focused=True)
    y += 36
    body += setting_row(0, y, "Hint", "4Fz*")
    y += 36
    body += setting_row(0, y, "Address", "Not yet known", muted=True)
    o += clip(body, 0, TOP, W, H - TOP)
    o += screen_header("Member")
    o += status()
    return o


def screen_invite():
    o = [R(0, 0, W, H, C["bg"])]
    items = [
        {"k": "out", "who": "me", "text": "Which channel is the crew on?"},
        {"k": "in", "who": "po", "text": "This one:"},
        {"k": "invite", "who": "po", "focused": True},
    ]
    tr, _ = transcript(items, TOP, BAR_Y)
    o += tr
    o += screen_header("Pat Okafor", "peer", "Direct")
    o += composer_bar()
    o += status()
    return o


def screen_join():
    o = [R(0, 0, W, H, C["bg"])]
    body = detail_head("Trail Crew", "channel", "Private channel")
    y = TOP + 58
    body += scaled(glyph_warn(18, y + 12, C["amber"]), 18, y + 12, 0.9)
    body.append(T(34, y + 18, "Anyone with this invite can read and post.",
                  F_SEC, C["amber"], 500))
    y += 28
    body += setting_row(0, y, "Name", "Trail Crew", chev=True)
    y += 36
    body.append(R(4, y + 1, W - 8, 34, C["focus"], rx=8, stroke=C["accent"],
                  sw=1.6))
    body.append(T(W / 2, y + 25, "Join channel", F_BODY, C["accent"], 700,
                  "middle"))
    o += clip(body, 0, TOP, W, H - TOP)
    o += screen_header("Join channel")
    o += status()
    return o


def screen_emergency():
    o = [R(0, 0, W, H, C["bg"])]
    items = [
        {"k": "in", "who": "Kit Moreno", "sender": "Kit Moreno",
         "text": "Heard a slide near mile 3?", "avatar": "peer"},
        {"k": "in", "who": "Lee Park", "sender": "Lee Park",
         "text": "Rockslide on FS 42 at mile 3", "avatar": "peer"},
        {"k": "in", "who": "Ranger Station", "sender": "Ranger Station",
         "text": "Copy. Crew on the way.", "avatar": "peer"},
    ]
    tr, _ = transcript(items, TOP, COMP_Y, channel=True)
    o += tr
    o += screen_header("EMERGENCY", "channel", "Not encrypted",
                       col=C["red"])
    o += composer(placeholder="Message EMERGENCY", mode="inactive")
    o += status()
    return o


def screen_trouble():
    o = [R(0, 0, W, H, C["bg"])]
    items = [
        {"k": "in", "who": "po", "text": "Is Bald Knob back up?"},
        {"k": "out", "who": "me", "text": "Not yet, Saturday."},
        {"k": "status", "text": "Delivered"},
        {"k": "out", "who": "me", "text": "Bring the spare antenna?",
         "focused": True},
        {"k": "status", "text": "Unconfirmed", "tone": "amber"},
    ]
    ah = 21
    ay = COMP_Y - ah
    tr, _ = transcript(items, TOP, ay)
    o += tr
    o += screen_header("Pat Okafor", "peer", "Direct")
    o.append(R(0, ay, W, ah, C["bg"]))
    o.append(T(W - 8, ay + 16, "Airtime limit · Send in 1:40", F_SMALL,
               C["amber"], 700, "end"))
    o += composer("Also the 18650s", mode="away")
    o += status()
    return o


def banner(title_parts, icon, w=330):
    """A passive card lying on the header, centered and narrower than it,
    so the header shows at both ends and the banner never reads as the
    screen you are on."""
    x = (W - w) / 2
    y = STRIP + 1
    h = HDR + 2
    c = y + h / 2
    o = [R(x + 1, y + 2, w, h, "#000", rx=11, extra=' opacity="0.55"'),
         R(x, y, w, h, "#1E2631", rx=11, stroke="#34414F")]
    o += icon(x + 17, c)
    px = x + 36
    for s, col, wt in title_parts:
        s = fit(s, F_SEC, x + w - 10 - px, wt > 400)
        o.append(T(px, c + 6, s, F_SEC, col, wt))
        px += tw(s, F_SEC, wt > 400) + 8
    return o


# ---------------------------------------------------------------- message states
def screen_times():
    o = [R(0, 0, W, H, C["bg"])]
    items = [
        {"k": "in", "who": "rm", "text": "Hut tomorrow?"},
        {"k": "out", "who": "me", "text": "Leaving at 7"},
        {"k": "status", "text": "Delivered"},
        {"k": "date", "day": "Today", "time": "07:12"},
        {"k": "in", "who": "rm", "text": "Stove is lit"},
        {"k": "in", "who": "rm", "text": "Coffee in ten"},
    ]
    tr, _ = transcript(items, TOP, BAR_Y)
    o += tr
    o += ridge_header()
    o += composer_bar()
    o += status(time="07:31")
    return o


def screen_reply_received():
    o = [R(0, 0, W, H, C["bg"])]
    items = [dict(CREW[2]),
             {"k": "in", "who": "Sam Ito", "sender": "Sam",
              "text": "Wind is up, layer on", "avatar": "peer",
              "quote": ("You", "Switchbacks, 15 min out")}]
    tr, _ = transcript(items, TOP, BAR_Y, channel=True)
    o += tr
    o += screen_header("Trail Crew", "channel", "Channel")
    o += composer_bar(placeholder="Message Trail Crew")
    o += status()
    return o


def screen_edited_deleted():
    o = [R(0, 0, W, H, C["bg"])]
    items = [
        {"k": "in", "who": "rm", "text": "Meet at the north junction"},
        {"k": "status", "side": "in", "text": "Edited"},
        {"k": "tomb", "text": "Message deleted"},
        {"k": "in", "who": "rm", "text": "Creek is fine after all"},
    ]
    tr, _ = transcript(items, TOP, COMP_Y)
    o += tr
    o += ridge_header()
    o += composer(placeholder="Message", mode="inactive")
    o += status()
    return o


def screen_gap():
    o = [R(0, 0, W, H, C["bg"])]
    items = [
        {"k": "in", "who": "po", "text": "Bald Knob repeater is up"},
        {"k": "gap", "who": "po"},
        {"k": "in", "who": "po", "text": "Try the valley from the saddle"},
    ]
    tr, _ = transcript(items, TOP, COMP_Y)
    o += tr
    o += screen_header("Pat Okafor", "peer", "Direct")
    o += composer(placeholder="Message", mode="inactive")
    o += status()
    return o


def screen_gap_settled():
    o = [R(0, 0, W, H, C["bg"])]
    items = [
        {"k": "in", "who": "po", "text": "It covers the north side now"},
        {"k": "status", "side": "in", "text": "Received late"},
        {"k": "tomb", "text": "Message unavailable"},
        {"k": "in", "who": "po", "text": "See you Saturday"},
    ]
    tr, _ = transcript(items, TOP, BAR_Y)
    o += tr
    o += screen_header("Pat Okafor", "peer", "Direct")
    o += composer_bar()
    o += status()
    return o


def screen_parts(missing=False):
    o = [R(0, 0, W, H, C["bg"])]
    items = [
        {"k": "out", "who": "me", "text": "How is the trail past the creek?"},
        {"k": "status", "text": "Delivered"},
        {"k": "in", "who": "rm",
         "text": "Washed out past the second crossing, so take the ridge",
         "pending": "missing" if missing else "waiting"},
        {"k": "parts", "present": 2, "count": 3,
         "missing": (2,) if missing else ()},
    ]
    tr, _ = transcript(items, TOP, COMP_Y)
    o += tr
    o += ridge_header()
    o += composer(placeholder="Message", mode="inactive")
    o += status()
    return o


# ---------------------------------------------------------------- forward secrecy
def screen_secret_sent():
    o = [R(0, 0, W, H, C["bg"])]
    items = [
        {"k": "in", "who": "po", "text": "Can you grab the big map?"},
        {"k": "out", "who": "me", "text": "Leaving the trailhead now"},
        {"k": "out", "who": "me", "text": "Bringing the map", "secret": True,
         "quote": ("Pat Okafor", "Can you grab the big map?")},
        {"k": "status", "text": "Delivered"},
    ]
    tr, _ = transcript(items, TOP, COMP_Y)
    o += tr
    o += screen_header("Pat Okafor", "peer", "Direct")
    o += composer(placeholder="Message", mode="inactive")
    o += status()
    return o


def choice_card(labels, mw, focus=0, ih=34, danger=()):
    """Choices on a card centered over a screen, below the status strip."""
    mh = len(labels) * ih + 10
    mx = (W - mw) / 2
    my = STRIP + (H - STRIP - mh) / 2
    return (menu_card(mx, my, mw, mh)
            + menu_items(mx, my + 5, mw, labels, focus, ih, danger))


def screen_resend():
    o = [R(0, 0, W, H, C["bg"])]
    items = ridge_items() + [
        {"k": "out", "who": "me", "text": DRAFT, "secret": True},
        {"k": "status", "text": "Unconfirmed", "tone": "amber"},
    ]
    tr, _ = transcript(items, TOP, COMP_Y)
    o += tr
    o += ridge_header()
    o += composer(placeholder="Message", mode="away")
    o += choice_card(["Try again", "Send without forward secrecy", "Cancel"],
                     360)
    o += status()
    return o


CHAT_MENU = ["Show peer", "Delete"]


def screen_chat_menu():
    """Holding the wheel on a chat: its menu, under the row."""
    o = screen_chats(focus=2)[:-len(status())]
    mw = 200
    mh = len(CHAT_MENU) * 32 + 10
    mx, my = W - 8 - mw, STRIP + 3 * ROW - 4
    o += menu_card(mx, my, mw, mh)
    o += menu_items(mx, my + 5, mw, CHAT_MENU, 0, danger=("Delete",))
    o += status()
    return o


def screen_delete_chat():
    o = screen_chats(focus=2)[:-len(status())]
    o += choice_card(["Delete chat", "Cancel"], 236, focus=1,
                     danger=("Delete chat",))
    o += status()
    return o


def screen_banner():
    o = screen_conversation()[:-len(status())]
    o += banner([("Trail Crew", C["text"], 700),
                 ("Sam: Will wait 10 min", C["text2"], 400)],
                lambda x, c: avatar(x, c, 12, "Trail Crew", "channel"))
    o += status()
    return o


# ---------------------------------------------------------------- locking
LOCK_TIME = "14:32"
LOCK_DATE = "Sunday, October 19"
LOCK_BAR_X = 462  # the unlock bar, right of everything
LOCK_TOP = 30  # below the device name and icons
LOCK_BOTTOM = 190  # above the unlock hint


def padlock(cx, cy, col, open_=False):
    shackle = (f"M{cx-3.5} {cy-1} V{cy-4} Q{cx-3.5} {cy-8} {cx} {cy-8} "
               f"Q{cx+3.5} {cy-8} {cx+3.5} {cy-4}")
    shackle += f" V{cy-3}" if open_ else f" V{cy-1}"
    return [P(shackle, col, sw=1.4),
            R(cx - 5.5, cy - 1, 11, 8.5, col, rx=1.5)]


def lock_top(segs=3, bolt=False):
    """The device name and status icons, on the background: the time is the
    screen's own."""
    o = [T(12, 19, DEVICE_NAME, F_SMALL, C["text2"], 600)]
    o += scaled(battery(449, 8.5, segs, bolt), 459, 13, 1.3)
    x = 418 if bolt else 426
    o += scaled(gnss(x, 13), x, 13, 1.3)
    o += scaled(bt(x - 20, 13), x - 20, 13, 1.3)
    return o


def unlock_bar(fill, ready=False):
    """fill: how far the wheel has turned toward the mark, 0 to 1."""
    col = C["green"] if ready else C["accent"]
    h = LOCK_BOTTOM - LOCK_TOP
    o = [R(LOCK_BAR_X - 3, LOCK_TOP, 6, h, C["line"], rx=3)]
    if fill:
        o.append(R(LOCK_BAR_X - 3, LOCK_TOP, 6, h * fill, col, rx=3))
    cy = LOCK_BOTTOM + 8
    o.append(P(f"M{LOCK_BAR_X-4} {cy-2} L{LOCK_BAR_X} {cy+2} "
               f"L{LOCK_BAR_X+4} {cy-2}",
               col if fill else C["text3"], sw=1.6))
    return o


def unlock_hint(ready=False):
    s = "Press to unlock" if ready else "Scroll down and press to unlock"
    col = C["green"] if ready else C["text3"]
    w = tw(s, F_SMALL, ready)
    x = (W - w) / 2 + 9
    o = scaled(padlock(x - 13, 207, col, open_=ready), x - 13, 207, 1.1)
    o.append(T(x, 213, s, F_SMALL, col, 700 if ready else 500))
    return o


def unread_badge(x, cy, n):
    o = scaled(glyph_chats(x + 9, cy, C["text2"]), x + 9, cy, 1.3)
    s = str(n)
    bw = max(22, tw(s, F_SMALL, True) + 12)
    o.append(R(x + 26, cy - 11, bw, 22, C["red"], rx=11))
    o.append(T(x + 26 + bw / 2, cy + 6, s, F_SMALL, "#fff", 700, "middle"))
    return o


LOCK_CARDS = [
    ("peer", "Jo Reyes", "now", "Are you on the ridge yet?"),
    ("peer", "Pat Okafor", "2m", "Got the antenna. Bringing two."),
    ("channel", "Trail Crew", "9m", "Sam: Will wait 10 min at the saddle"),
    ("peer", "Rick Alvarez", "14m", "Road is open past the gate"),
]


def screen_lock(fill=0.0, ready=False):
    """The lock screen with what arrived since the device locked."""
    o = [R(0, 0, W, H, C["bg"])]
    o += lock_top()
    o.append(T(14, 88, LOCK_TIME, 54, C["text"], 700))
    o.append(T(16, 114, LOCK_DATE, F_SEC, C["text2"]))
    o += unread_badge(16, 148, 4)
    x0, x1 = 196, 450
    body = []
    y = LOCK_TOP
    for kind, name, t, text in LOCK_CARDS:
        body.append(R(x0, y, x1 - x0, 52, C["panel"], rx=10,
                      stroke=C["line"]))
        body += avatar(x0 + 20, y + 26, 12, name, kind)
        tw_t = tw(t, F_SMALL, True)
        body.append(T(x0 + 40, y + 22, fit(name, F_SEC, x1 - x0 - 60 - tw_t,
                                           True), F_SEC, C["text"], 700))
        body.append(T(x1 - 10, y + 21, t, F_SMALL, C["text3"], 600, "end"))
        body.append(T(x0 + 40, y + 43, fit(text, F_SMALL, x1 - x0 - 50),
                      F_SMALL, C["text2"]))
        y += 58
    o += clip(body, 0, LOCK_TOP, W, LOCK_BOTTOM - LOCK_TOP)
    o += unlock_bar(1.0 if ready else fill, ready)
    o += unlock_hint(ready)
    return o


def screen_lock_quiet():
    """Nothing new: the time takes the middle."""
    o = [R(0, 0, W, H, C["bg"])]
    o += lock_top(segs=2, bolt=True)
    cx = (LOCK_BAR_X - 12) / 2 + 6
    o.append(T(cx, 108, LOCK_TIME, 72, C["text"], 700, "middle"))
    o.append(T(cx, 138, LOCK_DATE, F_SEC, C["text2"], 400, "middle"))
    # Charging: the charge, under the date.
    s = "64%"
    w = tw(s, F_SEC, True)
    bx = cx - (w + 14) / 2
    o.append(P(f"M{bx+5} {157} L{bx} {166} H{bx+4} L{bx+2} {174} "
               f"L{bx+9} {163} H{bx+5} Z", fill=C["green"]))
    o.append(T(bx + 14, 171, s, F_SEC, C["green"], 700))
    o += unlock_bar(0)
    o += unlock_hint()
    return o


def lock_diagram(x0, y0):
    """The lock states. Returns (svg list, width, height)."""
    bw, bh = 250, 96
    gap = 190
    xs = [x0 + i * (bw + gap) for i in range(4)]
    names = [("Unlocked", "Where you left off"),
             ("Locked, dark", "Panel off"),
             ("Lock screen", "Lit 15 s, then fades"),
             ("Ready to unlock", "For 2 s")]
    o = []
    for x, (nm, sub) in zip(xs, names):
        o.append(R(x, y0, bw, bh, "#FFFFFF", rx=16, stroke="#C9CBD1",
                   sw=1.5))
        o.append(T(x + 22, y0 + 42, nm, 21, INK, 700))
        o.append(T(x + 22, y0 + 70, sub, 16, INK2))
    col = "#2F6FDB"
    gray = "#8A8F98"
    green = "#15803D"
    top, bot = y0, y0 + bh

    def over(a, b, label, c=col):
        sx, ex = xs[a] + bw - 50, xs[b] + 50
        return _arrow(f"M{sx} {top} C{sx+70} {top-70} {ex-70} {top-70} "
                      f"{ex} {top}", (ex, top), (ex - 30, top - 40), c,
                      label, (sx + ex) / 2, top - 74 - 22 *
                      (label.count("\n")))

    def under(a, b, label, c=gray, depth=70):
        sx, ex = xs[a] + 50, xs[b] + bw - 50
        return _arrow(f"M{sx} {bot} C{sx-70} {bot+depth} {ex+70} "
                      f"{bot+depth} {ex} {bot}", (ex, bot),
                      (ex + 30, bot + 40), c, label, (sx + ex) / 2,
                      bot + depth + 4)

    o += over(0, 1, "Screen timed out, then 1 s\nwithout input")
    o += over(1, 2, "Any key, a small turn,\nor a message")
    o += over(2, 3, "Turned down five\nsteps, to the mark")
    o += under(2, 1, "Faded out, or\nthe lock button")
    o += under(3, 2, "No press in time")
    # Unlocked -> Lock screen, over the top of everything.
    sx, ex = xs[0] + bw / 2, xs[2] + bw / 2
    o += _arrow(f"M{sx} {top} C{sx} {top-200} {ex} {top-200} {ex} {top}",
                (ex, top), (ex, top - 40), col, "The lock button",
                (sx + ex) / 2, top - 162)
    # Ready -> Unlocked, the long way under everything.
    sx, ex = xs[3] + bw / 2, xs[0] + bw / 2
    o += _arrow(f"M{sx} {bot} C{sx} {bot+230} {ex} {bot+230} {ex} {bot}",
                (ex, bot), (ex, bot + 40), green, "Press",
                (sx + ex) / 2, bot + 196)
    width = xs[3] + bw - x0
    height = bh + 230
    return o, width, height


def peer_row(y, name, meta, t, bars=None, dim=False):
    o = []
    cy = y + ROW / 2
    o += avatar(RAIL_W + 25, cy, 17, name)
    nx = RAIL_W + 51
    o.append(T(nx, y + 20, name, F_BODY, C["text2"] if dim else C["text"],
               600))
    o.append(T(W - 10, y + 19.5, t, F_SMALL, C["text3"], 600, "end"))
    mx = nx
    if bars:
        o += signal_bars(nx, y + 38, bars)
        mx += 22
    o.append(T(mx, y + 39, meta, F_SEC, C["text3"]))
    o.append(LINE(nx, y + ROW - 0.5, W, y + ROW - 0.5))
    return o


def add_row(x0, y, label, rh=ROW, focused=False):
    o = []
    if focused:
        o.append(R(x0, y, W - x0, rh, C["focus"]))
        o.append(R(x0, y, 4, rh, C["accent"]))
    o += glyph_plus(x0 + 25, y + rh / 2, C["accent"], r=14)
    o.append(T(x0 + 51, y + rh / 2 + 7, label, F_BODY, C["accent"], 600))
    o.append(LINE(x0 + 51, y + rh - 0.5, W, y + rh - 0.5))
    return o


def screen_peers():
    o = [R(0, 0, W, H, C["bg"])]
    y = STRIP
    o += add_row(RAIL_W, y, "Add peer")
    y += ROW
    for name, meta, t, bars in [("Pat Okafor", "Direct", "5m", 3),
                                ("Jo Reyes", "3 hops", "1h", None),
                                ("Rick Alvarez", "3 hops", "3h", None),
                                ("Sam Ito", "2 hops", "4h", None)]:
        o += peer_row(y, name, meta, t, bars)
        y += ROW
    o += rail("Peers", focused=True, unread=1)
    o += status()
    return o


def mono_field(x, y, w, text, per_line, mode="active", lh=26):
    """A field for a long code (address, key): monospace, wrapped at a fixed
    column so the groups line up."""
    lines = [text[i:i + per_line] for i in range(0, len(text), per_line)]
    if not lines or len(lines[-1]) == per_line:
        lines.append("")
    h = len(lines) * lh + 10
    o = field_frame(x, y, w, h, mode, rx=12)
    for i, line in enumerate(lines):
        o.append(T(x + 12, y + 5 + 19 + i * lh, line, F_BODY, C["text"],
                   mono=True))
    if mode == "active":
        cx = x + 12 + tw(lines[-1], F_BODY, mono=True) + 0.5
        o.append(caret(cx, y + 5 + (len(lines) - 1) * lh + 3))
    return o, h


def screen_enter_address():
    o = [R(0, 0, W, H, C["bg"])]
    body = [section_label(10, TOP + 20, "Address or invitation")]
    typed = address("Unsaved 7cQa")[:30]
    f, fh = mono_field(8, TOP + 28, W - 16, typed, 22)
    body += f
    y = TOP + 28 + fh + 6
    body += avatar(28, y + 20, 16, "Unsaved 7cQa")
    body.append(T(54, y + 18, "7cQ*", F_BODY, C["text"], 700, mono=True))
    body.append(T(54, y + 37, "14 more characters", F_SMALL, C["amber"],
                  600))
    y += 44
    body += setting_row(0, y, "Message", None, muted=True)
    o += clip(body, 0, TOP, W, H - TOP)
    o += screen_header("Enter an address")
    o += status()
    return o


def b58(n, seed):
    rnd = random.Random(seed)
    return "".join(rnd.choice(B58) for _ in range(n))


def screen_peer_detail():
    o = [R(0, 0, W, H, C["bg"])]
    body = []
    y = STRIP
    body += detail_head("Pat Okafor", "peer", "Saved peer · Direct", y)
    body.append(T(10, y + 77, address("Pat Okafor"), F_SMALL, C["text2"],
                  mono=True))
    yy = y + 84
    for label, val, kind, focused in [
        ("Message", None, "action", True),
        ("Share contact", None, "action", False),
        ("Route", "Direct · −97 dBm", "read", False),
        ("Last heard", "5 min ago", "read", False),
        ("Forward secrecy", "Off", "read", False),
        ("Ping", None, "action", False),
    ]:
        body += setting_row(0, yy, label, val, focused, chev=kind == "action",
                            rh=34)
        yy += 34
    o += clip(body, 0, STRIP, W, H - STRIP)
    o += status()
    return o


def qr_modules(n=33, seed=11):
    rnd = random.Random(seed)
    m = [[rnd.random() < 0.48 for _ in range(n)] for _ in range(n)]

    def finder(r0, c0):
        for r in range(-1, 8):
            for c in range(-1, 8):
                rr, cc = r0 + r, c0 + c
                if 0 <= rr < n and 0 <= cc < n:
                    m[rr][cc] = (0 <= r <= 6 and 0 <= c <= 6 and
                                 (r in (0, 6) or c in (0, 6) or
                                  (2 <= r <= 4 and 2 <= c <= 4)))
    finder(0, 0)
    finder(0, n - 7)
    finder(n - 7, 0)
    for i in range(8, n - 8):
        m[6][i] = m[i][6] = i % 2 == 0
    # alignment pattern (version 4 at 26,26)
    a = n - 7
    for r in range(-2, 3):
        for c in range(-2, 3):
            m[a + r][a + c] = max(abs(r), abs(c)) != 1
    return m


def screen_share():
    o = [R(0, 0, W, H, C["bg"])]
    mods = qr_modules()
    n = len(mods)
    s = 4.6  # pixels per module: set by scanning, not by type size
    side = (n + 4) * s
    qx, qy = 8, STRIP + (H - STRIP - side) / 2
    o.append(R(qx, qy, side, side, "#fff", rx=4))
    d = []
    for r in range(n):
        for c in range(n):
            if mods[r][c]:
                x = qx + (c + 2) * s
                y = qy + (r + 2) * s
                d.append(f"M{x:.1f} {y:.1f}h{s}v{s}h-{s}z")
    o.append(P("".join(d), fill="#000"))
    x0 = qx + side + 12
    o.append(T(x0, STRIP + 28, DEVICE_NAME, F_BODY, C["text"], 700))
    addr = b58(44, 3)
    o.append(T(x0, STRIP + 54, addr[:22], F_SMALL, C["text2"], mono=True))
    o.append(T(x0, STRIP + 74, addr[22:], F_SMALL, C["text2"], mono=True))
    y = STRIP + 88
    rh = 36
    # Shows: a picker turned in place.
    o.append(R(x0 - 6, y + 1, W - x0 + 2, rh - 2, C["focus"], rx=8,
               stroke=C["accent"], sw=1.6))
    o.append(T(x0 + 4, y + 25, "Shows", F_BODY, C["text"], 700))
    val = "Identity"
    vx = W - 22
    o.append(T(vx, y + 24, val, F_SEC, C["text"], 700, "end"))
    lx = vx - tw(val, F_SEC, True) - 10
    o.append(P(f"M{lx} {y+12} L{lx-6} {y+18} L{lx} {y+24}", C["accent"],
               sw=2))
    o.append(P(f"M{vx+6} {y+12} L{vx+12} {y+18} L{vx+6} {y+24}",
               C["accent"], sw=2))
    y += rh
    o.append(T(x0 + 4, y + 25, "Location", F_BODY, C["text"]))
    o += switch(W - 10, y + rh / 2, False)
    o += status()
    return o


# ---------------------------------------------------------------- exchanging contacts
# Until both people confirm the code, Add peer shows a nearby device only by
# its model and a color from its session key, which is new every time Add
# peer opens. No name, address, hint or avatar is sent or shown.
SESSION_MINE = "#C46BD8"  # Juniper's Pager, this session
SESSION_DECK = "#2BB3A3"  # Pat's T-Deck, this session
SESSION_PHONE = "#E39A3B"  # someone's iPhone, this session
EXCHANGE_CODE = "482 931"


def nearness(cx, cy, n, col=None):
    """How close a device on Add peer is: arcs lit from the inside out."""
    col = col or C["accent"]
    o = [CIRC(cx - 9, cy, 2.6, col)]
    for i in range(3):
        r = 6 + i * 5
        c = col if i < n else "#3A414B"
        o.append(P(f"M{cx-9+r*0.6:.1f} {cy-r*0.8:.1f} "
                   f"A{r} {r} 0 0 1 {cx-9+r*0.6:.1f} {cy+r*0.8:.1f}",
                   c, sw=2))
    return o


def tap_glyph(cx, cy, col):
    """Two devices back to back: a tap works here. Boards without NFC
    never show it."""
    return [P(rrect(cx - 11, cy - 8, 9, 16, 2.5, 2.5, 2.5, 2.5), col, sw=1.5),
            P(rrect(cx + 2, cy - 8, 9, 16, 2.5, 2.5, 2.5, 2.5), col, sw=1.5),
            P(f"M{cx-4} {cy-12} Q{cx} {cy-15} {cx+4} {cy-12}", col, sw=1.4),
            P(f"M{cx-4} {cy+12} Q{cx} {cy+15} {cx+4} {cy+12}", col, sw=1.4)]


def check_mark(cx, cy, col, k=1.0):
    return [P(f"M{cx-6*k} {cy} L{cx-2*k} {cy+4*k} L{cx+6*k} {cy-5*k}", col,
              sw=2.4 * k)]


def device_glyph(cx, cy, r, col, kind="landscape"):
    """A nearby device before anything is exchanged: its session color and
    the outline of its kind of hardware, never an avatar."""
    ink = C["bg"]
    o = [CIRC(cx, cy, r, col)]
    k = r / 17
    if kind == "phone":
        o.append(P(rrect(cx - 5.5 * k, cy - 9 * k, 11 * k, 18 * k, 2.5 * k,
                         2.5 * k, 2.5 * k, 2.5 * k), ink, sw=1.8 * k))
        o.append(LINE(cx - 2 * k, cy + 6 * k, cx + 2 * k, cy + 6 * k, ink,
                      1.6 * k))
    else:
        o.append(P(rrect(cx - 10 * k, cy - 7 * k, 20 * k, 14 * k, 2.5 * k,
                         2.5 * k, 2.5 * k, 2.5 * k), ink, sw=1.8 * k))
        o.append(R(cx - 6.5 * k, cy - 4 * k, 13 * k, 4.5 * k, ink, rx=1))
        for i in range(4):
            o.append(CIRC(cx - 5.4 * k + i * 3.6 * k, cy + 3.5 * k, 0.9 * k,
                          ink))
    return o


def nearby_row(y, model, col, n, kind="landscape", focused=False, dim=False):
    o = []
    cy = y + ROW / 2
    if focused:
        o.append(R(4, y + 1, W - 8, ROW - 2, C["focus"], rx=8,
                   stroke=C["accent"], sw=1.6))
    o += device_glyph(30, cy, 17, col, kind)
    o.append(T(56, cy + 7, model, F_BODY, C["text2"] if dim else C["text"],
               700 if focused else 600))
    o += nearness(W - 30, cy, n, C["text3"] if dim else None)
    if not focused:
        o.append(LINE(56, y + ROW - 0.5, W, y + ROW - 0.5))
    return o


def you_mark(col):
    """This device's own session color, at the right of the Add peer
    header, so two people can tell which row is which."""
    c = STRIP + HDR / 2
    o = device_glyph(W - 22, c, 11, col)
    o.append(T(W - 40, c + 6, "You", F_SEC, C["text3"], 600, "end"))
    return o


def push_buttons(labels, focus=0, y=H - 46):
    """Two choices side by side at the bottom; turning moves between them."""
    o = []
    bw, gap = 180, 16
    x0 = (W - 2 * bw - gap) / 2
    for i, label in enumerate(labels):
        bx = x0 + i * (bw + gap)
        if i == focus:
            o.append(R(bx, y, bw, 36, C["focus"], rx=10, stroke=C["accent"],
                       sw=1.6))
        else:
            o.append(R(bx, y, bw, 36, C["field"], rx=10,
                       stroke=C["menuline"]))
        o.append(T(bx + bw / 2, y + 24, label, F_BODY,
                   C["accent"] if i == focus else C["text2"],
                   700 if i == focus else 500, "middle"))
    return o


def screen_add_peer():
    o = [R(0, 0, W, H, C["bg"])]
    body = [section_label(12, TOP + 19, "Nearby")]
    body += scaled(tap_glyph(W - 30, TOP + 13, C["text2"]), W - 30, TOP + 13,
                   1.25)
    y = TOP + 26
    body += nearby_row(y, "T-Deck", SESSION_DECK, 3, focused=True)
    y += ROW
    body += nearby_row(y, "iPhone", SESSION_PHONE, 1, "phone", dim=True)
    y += ROW
    body += setting_row(0, y, "Enter an address", None, chev=True)
    y += 36
    body += setting_row(0, y, "Show my code", None, chev=True)
    o += clip(body, 0, TOP, W, H - TOP)
    o += screen_header("Add peer")
    o += you_mark(SESSION_MINE)
    o += status()
    return o


def screen_exchange_request():
    """Pat's T-Deck, also on Add peer, when Juniper presses its row."""
    global DEVICE_NAME
    saved, DEVICE_NAME = DEVICE_NAME, "Pat Okafor"
    o = [R(0, 0, W, H, C["bg"])]
    body = [section_label(12, TOP + 19, "Nearby")]
    body += nearby_row(TOP + 26, "T-LoRa Pager", SESSION_MINE, 3)
    o += clip(body, 0, TOP, W, H - TOP)
    o += screen_header("Add peer")
    o += you_mark(SESSION_DECK)
    mw, ih = 330, 34
    mh = 62 + 2 * ih + 8
    mx = (W - mw) / 2
    my = STRIP + (H - STRIP - mh) / 2
    o += menu_card(mx, my, mw, mh)
    o += device_glyph(mx + 32, my + 31, 19, SESSION_MINE)
    o.append(T(mx + 60, my + 27, "T-LoRa Pager", F_BODY, C["text"], 700))
    o.append(T(mx + 60, my + 48, "Exchange contacts?", F_SEC, C["text2"]))
    o += menu_items(mx, my + 62, mw, ["Exchange", "Not now"], 0, ih)
    o += status()
    DEVICE_NAME = saved
    return o


def device_header(model, col, sub):
    c = STRIP + HDR / 2
    o = [R(0, STRIP, W, HDR, C["bg"]),
         LINE(0, STRIP + HDR - 0.5, W, STRIP + HDR - 0.5)]
    o.append(P(f"M13 {c-6} L7 {c} L13 {c+6}", C["text3"], sw=2))
    o += device_glyph(35, c, 13, col)
    o.append(T(54, c + 7, model, F_BODY, C["text"], 700))
    o.append(T(54 + tw(model, F_BODY, True) + 10, c + 6, sub, F_SMALL,
               C["text3"], 500))
    return o


def screen_exchange_code(state="ask"):
    """state: ask, waiting, differ."""
    o = [R(0, 0, W, H, C["bg"])]
    o += device_header("T-Deck", SESSION_DECK, "Exchanging")
    cy = TOP + 50
    by = H - 46
    if state == "differ":
        o += scaled(glyph_warn(W / 2, cy - 6, C["red"]), W / 2, cy - 6, 2.0)
        o.append(T(W / 2, cy + 40, "Codes differ. Nothing saved.", F_BODY,
                   C["text"], 600, "middle"))
        o += push_buttons(["Try again", "Done"])
    else:
        o.append(T(W / 2, cy + 14, EXCHANGE_CODE, 42, C["text"], 700,
                   "middle", mono=True, extra=' letter-spacing="3"'))
        o.append(T(W / 2, cy + 44, "Same code on the other screen?", F_SEC,
                   C["text2"], 500, "middle"))
        if state == "waiting":
            o += check_mark(W / 2 - 150, by + 17, C["green"])
            o.append(T(W / 2 - 134, by + 23, "Same", F_BODY, C["green"],
                       700))
            o.append(T(W / 2 - 40, by + 23, "Waiting for T-Deck", F_BODY,
                       C["text2"], 500))
            for i, shade in enumerate((C["text2"], C["text2"], "#3A414B")):
                o.append(CIRC(W / 2 + 166 + i * 9, by + 17, 2.4, shade))
        else:
            o += push_buttons(["Same", "Different"])
    o += status()
    return o


def peer_sheet(name, focus="Message"):
    """The sheet for a peer who is not saved: what an exchange, a tap or a
    contact card opens. It opens on Message; Save peer is one turn down.
    Nothing is saved until Save peer is pressed."""
    o = [R(0, 0, W, H, C["bg"])]
    body = avatar(32, TOP + 30, 22, name)
    body.append(T(64, TOP + 37, name, F_BODY, C["text"], 700))
    body.append(T(10, TOP + 76, address(name), F_SMALL, C["text2"],
                  mono=True))
    yy = TOP + 84
    for label, chev in [("Message", True), ("Save peer", False)]:
        body += setting_row(0, yy, label, None, label == focus, chev=chev,
                            rh=34)
        yy += 34
    o += clip(body, 0, TOP, W, H - TOP)
    o += screen_header("Peer")
    o += status()
    return o


def screen_exchanged():
    return peer_sheet("Pat Okafor", focus="Save peer")


def screen_contact_in_chat():
    o = [R(0, 0, W, H, C["bg"])]
    items = [
        {"k": "out", "who": "me", "text": "Who has the hut radio?"},
        {"k": "in", "who": "po", "text": "Rick does:"},
        {"k": "invite", "who": "po", "focused": True,
         "card": {"name": "Rick Alvarez", "kind": "peer", "sub": "Contact"}},
    ]
    tr, _ = transcript(items, TOP, BAR_Y)
    o += tr
    o += screen_header("Pat Okafor", "peer", "Direct")
    o += composer_bar()
    o += status()
    return o


def screen_introduced():
    return peer_sheet("Rick Alvarez")


def screen_share_contact():
    o = [R(0, 0, W, H, C["bg"])]
    body = [section_label(12, TOP + 19, "Send Rick Alvarez to")]
    y = TOP + 26
    for i, (name, kind, meta) in enumerate([
            ("Jo Reyes", "peer", "Direct chat"),
            ("Trail Crew", "channel", "Channel"),
            ("Sam Ito", "peer", "Direct chat")]):
        cy = y + ROW / 2
        if i == 0:
            body.append(R(4, y + 1, W - 8, ROW - 2, C["focus"], rx=8,
                          stroke=C["accent"], sw=1.6))
        body += avatar(30, cy, 17, name, kind)
        body.append(T(56, y + 20, name, F_BODY, C["text"],
                      700 if i == 0 else 600))
        body.append(T(56, y + 39, meta, F_SEC, C["text3"]))
        if i:
            body.append(LINE(56, y + ROW - 0.5, W, y + ROW - 0.5))
        y += ROW
    o += clip(body, 0, TOP, W, H - TOP)
    o += screen_header("Share contact")
    o += status()
    return o


def screen_channel_card():
    o = [R(0, 0, W, H, C["bg"])]
    body = detail_head("Trail Crew", "channel", "Private channel · From a card")
    y = TOP + 58
    body += scaled(glyph_warn(18, y + 12, C["amber"]), 18, y + 12, 0.9)
    body.append(T(34, y + 18, "Anyone with this card can read and post.",
                  F_SEC, C["amber"], 500))
    y += 28
    body += setting_row(0, y, "Name", "Trail Crew", chev=True)
    y += 36
    body.append(R(4, y + 1, W - 8, 34, C["focus"], rx=8, stroke=C["accent"],
                  sw=1.6))
    body.append(T(W / 2, y + 25, "Join channel", F_BODY, C["accent"], 700,
                  "middle"))
    o += clip(body, 0, TOP, W, H - TOP)
    o += screen_header("Join channel")
    o += status()
    return o


PRESETS = ["Long range", "Medium range", "Short range"]


def screen_device(row=None, preset="Long range", share=False, picker=None):
    """Settings drill down. row None: the category list; else inside Radio.

    picker: the focused option while Preset's choice list is open.
    """
    if row is None:
        return _device_categories(preset)
    return _device_radio(row, preset, share, picker)


def _device_categories(preset):
    o = [R(0, 0, W, H, C["bg"])]
    cats = [("Identity", DEVICE_NAME), ("Channels", "4 joined"),
            ("Radio", preset), ("Alerts", "Silent"), ("Display", ""),
            ("Keyboard", ""), ("Clock", "GNSS"), ("Phone link", "Paired"),
            ("Maintenance", "")]
    body = []
    y = STRIP
    for c, v in cats:
        body += setting_row(RAIL_W, y, c, v, focused=c == "Radio", chev=True)
        y += 36
    o += clip(body, RAIL_W, STRIP, W - RAIL_W, H - STRIP)
    o += rail("Device", unread=1)
    o += status(silent=True)
    return o


def _device_radio(row, preset, share, picker):
    o = [R(0, 0, W, H, C["bg"])]
    rows = [("Region", "United States", True), ("Preset", preset, True),
            ("Forwarding", True, False), ("Share location", share, False),
            ("Airtime", "3% this hour", False)]
    body = []
    y = TOP
    for i, (label, val, chev) in enumerate(rows):
        body += setting_row(0, y, label, val, focused=i == row, chev=chev)
        y += 36
    o += clip(body, 0, TOP, W, H - TOP)
    o += screen_header("Radio")
    if picker is not None:
        mw, ih = 260, 34
        mh = len(PRESETS) * ih + 10
        mx = W - 10 - mw
        my = TOP + (H - TOP - mh) / 2
        o += menu_card(mx, my, mw, mh)
        yy = my + 5
        for opt in PRESETS:
            if opt == picker:
                o.append(R(mx + 5, yy, mw - 10, ih - 2, C["focus"], rx=7,
                           stroke=C["accent"], sw=1.6))
            o.append(T(mx + 36, yy + 23, opt, F_BODY, C["text"],
                       700 if opt == picker else 400))
            if opt == preset:
                o.append(P(f"M{mx+13} {yy+16} L{mx+18} {yy+21} "
                           f"L{mx+26} {yy+11}", C["accent"], sw=2.4))
            yy += ih
    o += status(silent=True)
    return o


def screen_add_channel():
    o = [R(0, 0, W, H, C["bg"])]
    body = [section_label(10, TOP + 20, "Channel name or invitation")]
    key = b58(44, 7)
    typed = ("umsh:ck:" + key)[:49]
    f, fh = mono_field(8, TOP + 28, W - 16, typed, 36)
    body += f
    y = TOP + 28 + fh + 8
    body.append(T(10, y + 16, "Private channel · 3 characters short",
                  F_SMALL, C["amber"], 600))
    y += 26
    body += setting_row(0, y, "Join", None, muted=True)
    o += clip(body, 0, TOP, W, H - TOP)
    o += screen_header("Add channel")
    o += status(silent=True)
    return o


def battery_icon(x, cy, col):
    """A battery outline for a banner icon, empty."""
    return [R(x - 9, cy - 5, 16, 10, rx=2, stroke=col, sw=1.5),
            R(x + 7.5, cy - 2, 2, 4, col, rx=0.6),
            R(x - 7, cy - 3, 2.5, 6, col, rx=0.5)]


def screen_battery_low():
    o = screen_conversation("inactive")[:-len(status())]
    o += banner([("Battery low", C["amber"], 700), ("9%", C["text2"], 400)],
                lambda x, c: battery_icon(x, c, C["amber"]), w=250)
    o += status(segs=0, batt_col=C["amber"])
    return o


def screen_battery_empty():
    """The last frame before the power path opens: a blinking empty battery,
    with no words to translate."""
    o = [R(0, 0, W, H, C["bg"])]
    cx, cy = W / 2, H / 2
    o += scaled(battery_icon(cx, cy, C["red"]), cx, cy, 5)
    return o


def setup_status():
    o = [R(0, 0, W, STRIP, C["chrome"])]
    o += scaled(battery(449, 6.5, 3), 459, 11, 1.3)
    return o


def screen_setup_name():
    o = [R(0, 0, W, H, C["bg"])]
    o += avatar(34, STRIP + 32, 22, "Self 9Xk2")
    o.append(T(66, STRIP + 27, "Welcome to UMSH", F_BODY, C["text"], 700))
    o.append(T(66, STRIP + 48, "This device is 9Xk2", F_SMALL, C["text3"],
               500))
    y = STRIP + 66
    o.append(section_label(10, y + 15, "What to call you"))
    y += 22
    o += field_frame(8, y, W - 16, 32, "active", rx=12)
    o.append(T(20, y + 23, "Juniper", F_BODY, C["text"]))
    o.append(caret(20 + tw("Juniper", F_BODY) + 1, y + 6))
    y += 36
    o.append(T(10, y + 16, "Nearby nodes see this name.", F_SMALL,
               C["text3"], 500))
    y += 24
    o += setting_row(0, y, "Continue", None, chev=True)
    o += setup_status()
    return o


def screen_setup_profile():
    o = [R(0, 0, W, H, C["bg"])]
    body = []
    y = TOP
    for i, r in enumerate(["UMSH USA/Canada (recommended)",
                           "MeshCore USA/Canada (recommended)",
                           "MeshCore Australia", "MeshCore Australia (narrow)",
                           "MeshCore Australia (mid)"]):
        body += setting_row(0, y, r, None, focused=i == 0)
        y += 36
    o += clip(body, 0, TOP, W, H - TOP)
    o += screen_header("Radio profile", back=True)
    o += setup_status()
    return o


def screen_setup_time_zone():
    """The zones, west to east, starting on the one set: UTC until now."""
    o = [R(0, 0, W, H, C["bg"])]
    zones = [("UTC−2", ""), ("Azores Time", "UTC"),
             ("Cape Verde Time", "UTC−1"), ("Greenwich Mean Time", "UTC"),
             ("Irish Time", "UTC+1")]
    body = []
    y = TOP
    for i, (name, off) in enumerate(zones):
        current = name == "Greenwich Mean Time"
        body += setting_row(0, y, "", off, focused=current)
        if current:
            body.append(P(f"M14 {y+18} L19 {y+23} L27 {y+13}", C["accent"],
                          sw=2.4))
        body.append(T(36, y + 25, name, F_BODY, C["text"],
                      700 if current else 400))
        y += 36
    o += clip(body, 0, TOP, W, H - TOP)
    o += screen_header("Time zone", back=True)
    o += setup_status()
    return o


# ---------------------------------------------------------------- keyboard
EMOJI = "'Apple Color Emoji', 'Noto Color Emoji', sans-serif"


def glyph_text(x, y, s, size, fill=None, anchor="middle"):
    return (f'<text x="{x:.1f}" y="{y:.1f}" font-size="{size}" '
            f'font-family="{EMOJI}" fill="{fill or C["text"]}" '
            f'text-anchor="{anchor}">{escape(s)}</text>')


def kb_conversation(text=None, at=None, placeholder="Message", **mods):
    """The Ridge Medic conversation, composer active, with modifier state in
    the strip."""
    o = [R(0, 0, W, H, C["bg"])]
    tr, _ = transcript(ridge_items(), TOP, COMP_Y)
    o += tr
    o += ridge_header()
    o += composer(text, placeholder, "active", at=at)
    o += status(**mods)
    return o


def screen_kb_sentence():
    return kb_conversation(None, shift="once")


def screen_kb_period():
    return kb_conversation("See you at the hut. ", shift="once")


def screen_kb_caps():
    return kb_conversation("Meet at the TRAILHEAD", shift="lock")


def screen_kb_alt():
    return kb_conversation("Meet at 5", alt="once")


def screen_kb_numbers():
    o = [R(0, 0, W, H, C["bg"])]
    y = TOP + 14
    o.append(section_label(10, y + 12, "Transmit power"))
    y += 20
    o += field_frame(8, y, W - 16, 34, "active", rx=12)
    o.append(T(20, y + 24, "22", F_BODY, C["text"]))
    o.append(caret(20 + tw("22", F_BODY) + 1, y + 7))
    o.append(T(W - 20, y + 23, "dBm", F_SEC, C["text3"], 500, "end"))
    o += screen_header("Radio")
    o += status(silent=True, alt="lock")
    return o


PICKER_TABS = ["\U0001F552", "\U0001F600", "\U0001F44B", "❤️",
               "★", "é", "€"]
PICKER_SMILEYS = [
    "😀😃😄😁😆😅😂🙂😉😊😇",
    "😍🥰😘😋😛🤔🤨😐😑😶🙄",
    "😏😣😥😮🤐😯😪😫😴😌😜",
]
PICKER_HEA = [
    "❤️🧡💛💚💙💜🖤🤍🤎💔❣️",
    "💕💞💓💗💖💘💝🙉🎧🤕😍",
    "😻💑🫶🩷🩵🩶💟♥️🫀🗣️🧑‍⚕️",
]
CELL = 41


def _graphemes(s):
    out = []
    for ch in s:
        if out and (ch in "️‍" or out[-1].endswith("‍")):
            out[-1] += ch
        else:
            out.append(ch)
    return out


def picker(rows, focus, tabs=True, query=None):
    """The character picker over the conversation, above the composer so the
    insertion point stays in view."""
    px, py, pw = 6, TOP + 4, W - 12
    ph = COMP_Y - 4 - py
    o = menu_card(px, py, pw, ph)
    head = 30
    if tabs:
        tx = px + 22
        for i, t in enumerate(PICKER_TABS):
            on = i == 1
            o.append(glyph_text(tx, py + 22, t, 18,
                                C["text"] if on else C["text3"]))
            if on:
                o.append(R(tx - 13, py + head - 3, 26, 3, C["accent"], rx=1.5))
            tx += 40
    else:
        o += scaled([CIRC(px + 18, py + 15, 4, stroke=C["text2"], sw=1.3),
                     P(f"M{px+21} {py+18} L{px+24} {py+21}", C["text2"],
                       sw=1.4)], px + 19, py + 16, 1.4)
        o.append(T(px + 36, py + 22, query, F_BODY, C["text"]))
        o.append(caret(px + 36 + tw(query, F_BODY) + 1, py + 6))
    o.append(LINE(px, py + head + 0.5, px + pw, py + head + 0.5,
                  C["menuline"]))
    grid = []
    gy = py + head + 4
    for r, row in enumerate(_graphemes_rows(rows)):
        for c, g in enumerate(row):
            cx = px + 12 + c * CELL + CELL / 2
            cy = gy + r * CELL + CELL / 2
            if (r, c) == focus:
                grid.append(R(cx - CELL / 2 + 1, cy - CELL / 2 + 1, CELL - 2,
                              CELL - 2, C["focus"], rx=8, stroke=C["accent"],
                              sw=2))
            grid.append(glyph_text(cx, cy + 9, g, 25))
    o += clip(grid, px, py + head + 1, pw, ph - head - 1)
    return o


def _graphemes_rows(rows):
    return [_graphemes(r) for r in rows]


def screen_kb_picker():
    o = kb_conversation("Thanks ", **{})[:-len(status())]
    o += picker(PICKER_SMILEYS, (0, 6))
    o += status()
    return o


def screen_kb_picker_filter():
    o = kb_conversation("Thanks ", **{})[:-len(status())]
    o += picker(PICKER_HEA, (0, 0), tabs=False, query="hea")
    o += status()
    return o


def keyboard_glyph(cx, cy, col, lit):
    o = [R(cx - 14, cy - 6, 28, 16, rx=3, stroke=col, sw=1.8)]
    for r in range(2):
        for c in range(5):
            o.append(R(cx - 10.5 + c * 4.6, cy - 2.5 + r * 4.2, 2.6, 2.4, col,
                       rx=0.5))
    o.append(R(cx - 6, cy + 5.6, 12, 2, col, rx=0.8))
    if lit:
        for dx, ang in ((-10, -1), (0, 0), (10, 1)):
            o.append(P(f"M{cx+dx+ang*1.5} {cy-10} L{cx+dx+ang*3.5} {cy-15}",
                       col, sw=1.8))
    return o


def sun_glyph(cx, cy, col):
    import math
    o = [CIRC(cx, cy, 5, col)]
    for i in range(8):
        a = i * math.pi / 4
        o.append(P(f"M{cx+8*math.cos(a):.1f} {cy+8*math.sin(a):.1f} "
                   f"L{cx+11*math.cos(a):.1f} {cy+11*math.sin(a):.1f}", col,
                   sw=2))
    return o


def hud(content_w):
    """A centered transient card for a level or toggle; no words."""
    w, h = content_w, 56
    x, y = (W - w) / 2, (H - h) / 2 + 8
    return [R(x + 1, y + 3, w, h, "#000", rx=14, extra=' opacity="0.55"'),
            R(x, y, w, h, "#1E2631", rx=14, stroke="#34414F")], x, y, h


def screen_kb_light():
    o = kb_conversation("Thanks ", **{})[:-len(status())]
    g, x, y, h = hud(96)
    o += g
    o += scaled(keyboard_glyph(x + 48, y + h / 2 + 4, C["text"], True),
                x + 48, y + h / 2, 1.5)
    o += status()
    return o


def screen_kb_brightness():
    o = screen_chats()[:-len(status())]
    g, x, y, h = hud(250)
    o += g
    o += sun_glyph(x + 30, y + h / 2, C["text"])
    n, lit = 10, 7
    bx = x + 56
    for i in range(n):
        o.append(R(bx + i * 18, y + h / 2 - 6, 14, 12,
                   C["text"] if i < lit else "#3A414B", rx=3))
    o += status(alt=None)
    return o


def screen_kb_settings():
    o = [R(0, 0, W, H, C["bg"])]
    body = []
    y = TOP
    for i, (label, on) in enumerate([("Capitalize sentences", True),
                                     ("Period on double space", True),
                                     ("Keyboard light", True)]):
        body += setting_row(0, y, label, on, focused=i == 0)
        y += 36
    o += clip(body, 0, TOP, W, H - TOP)
    o += screen_header("Keyboard")
    o += status(silent=True)
    return o


# ---------------------------------------------------------------- clock
# The Clock boards show the 12-hour setting; the rest of the canvas is 24-hour.
TIME_12 = "2:32 PM"


def screen_clock():
    o = [R(0, 0, W, H, C["bg"])]
    rows = [("Set automatically", True, False),
            ("Date and time", "Oct 19, " + TIME_12, False),
            ("Time zone", "Pacific Time", True),
            ("24-hour time", False, False),
            ("Last set from", "GNSS, 4m ago", False)]
    body = []
    y = TOP
    for i, (label, val, chev) in enumerate(rows):
        body += setting_row(0, y, label, val, focused=i == 0, chev=chev,
                            muted=label == "Date and time")
        y += 36
    o += clip(body, 0, TOP, W, H - TOP)
    o += screen_header("Clock")
    o += status(time=TIME_12, silent=True)
    return o


def screen_set_time():
    """Date and time, set by hand: a part at a time."""
    o = [R(0, 0, W, H, C["bg"])]
    fs = 24
    groups = [["Oct", "19", "2026"], ["2", "32", "PM"]]
    focus = (0, 1)
    pad, gap, group_gap, sh = 12, 6, 26, 40
    colon = 16  # between the hour and the minute
    widths = [[tw(s, fs, True) + 2 * pad for s in g] for g in groups]
    total = (sum(sum(w) for w in widths) + group_gap + colon - gap
             + sum((len(g) - 1) * gap for g in groups))
    x = (W - total) / 2
    y = TOP + 26
    for gi, (g, ws) in enumerate(zip(groups, widths)):
        for si, (s, w) in enumerate(zip(g, ws)):
            on = (gi, si) == focus
            o += field_frame(x, y, w, sh, "active" if on else "away", rx=9)
            o.append(T(x + w / 2, y + 28, s, fs, C["text"],
                       700 if on else 500, "middle"))
            if on:
                cx = x + w / 2
                o.append(P(f"M{cx-6} {y-6} L{cx} {y-12} L{cx+6} {y-6}",
                           C["accent"], sw=2))
                o.append(P(f"M{cx-6} {y+sh+6} L{cx} {y+sh+12} "
                           f"L{cx+6} {y+sh+6}", C["accent"], sw=2))
            x += w + gap
            if (gi, si) == (1, 0):
                o.append(T(x + (colon - gap) / 2 - 1, y + 27, ":", fs,
                           C["text2"], 700, "middle"))
                x += colon - gap
        x += group_gap - gap
    o.append(T(W / 2, TOP + 104, "Pacific Time, UTC−7", F_SEC, C["text2"],
               400, "middle"))
    o += setting_row(0, H - 44, "Set", None)
    o += screen_header("Date and time")
    o += status(time="", silent=True)
    return o


def screen_time_zone():
    o = [R(0, 0, W, H, C["bg"])]
    zones = [("Alaska Time", "UTC−8"), ("Gambier Time", "UTC−9"),
             ("Pacific Time", "UTC−7"), ("Pitcairn Time", "UTC−8"),
             ("Arizona", "UTC−7")]
    body = []
    y = TOP
    for name, off in zones:
        current = name == "Pacific Time"
        body += setting_row(0, y, "", off, focused=current)
        if current:
            body.append(P(f"M14 {y+18} L19 {y+23} L27 {y+13}", C["accent"],
                          sw=2.4))
        body.append(T(36, y + 25, name, F_BODY, C["text"],
                      700 if current else 400))
        y += 36
    o += clip(body, 0, TOP, W, H - TOP)
    o += screen_header("Time zone")
    o += status(time=TIME_12, silent=True)
    return o


def clock_glyph(cx, cy, col):
    return [CIRC(cx, cy, 7, stroke=col, sw=1.3),
            P(f"M{cx} {cy-4} V{cy} L{cx+3} {cy+2}", col, sw=1.3)]


def screen_lock_no_time():
    """The lock screen before the clock is known: no time and no date."""
    o = screen_lock()
    # Replace the time and date with the clock's state.
    o = [s for s in o if LOCK_TIME not in s and LOCK_DATE not in s]
    o += scaled(clock_glyph(32, 70, C["text2"]), 32, 70, 2.4)
    o.append(T(16, 114, "Clock not set", F_SEC, C["text2"], 600))
    return o


# The Shift and Alt state machine, drawn for the canvas and the UX book.
def _arrow(d, end, toward, col, label=None, lx=0, ly=0, anchor="middle"):
    import math
    ex, ey = end
    tx, ty = toward
    a = math.atan2(ey - ty, ex - tx)
    k = 11
    head = (f"M{ex:.1f} {ey:.1f} L{ex-k*math.cos(a-0.4):.1f} "
            f"{ey-k*math.sin(a-0.4):.1f} L{ex-k*math.cos(a+0.4):.1f} "
            f"{ey-k*math.sin(a+0.4):.1f} Z")
    o = [P(d, col, sw=2.4), P(head, fill=col)]
    if label:
        for i, line in enumerate(label.split("\n")):
            o.append(T(lx, ly + i * 22, line, 17, col, 600, anchor))
    return o


def modifier_diagram(x0, y0):
    """Returns (svg list, width, height)."""
    bw, bh = 250, 112
    cols = [x0 + 150, x0 + 590, x0 + 1030]
    lanes = [("Shift", shift_icon, y0 + 40), ("Alt", alt_icon, y0 + 560)]
    names = ["Off", "One-shot", "Locked"]
    lock_names = {"Shift": "Caps lock", "Alt": "Symbol lock"}
    o = []
    box = {}
    for lane, icon, ly in lanes:
        o.append(T(x0, ly + bh / 2 + 9, lane, 26, INK, 700))
        for i, (bx, nm) in enumerate(zip(cols, names)):
            o.append(R(bx, ly, bw, bh, "#FFFFFF", rx=16, stroke="#C9CBD1",
                       sw=1.5))
            chip_x = bx + 20
            o.append(R(chip_x, ly + 30, 56, 52, C["chrome"], rx=10))
            if i:
                o += scaled(icon(chip_x + 28, ly + 58, "once" if i == 1
                                 else "lock"), chip_x + 28, ly + 56, 2)
            title = lock_names[lane] if i == 2 else nm
            o.append(T(bx + 94, ly + 52, title, 21, INK, 700))
            sub = {0: "Keys type their own legend",
                   1: "Applies to the next key",
                   2: "Applies until released"}[i]
            for j, line in enumerate(wrap(sub, 16, bw - 104)):
                o.append(T(bx + 94, ly + 76 + j * 20, line, 16, INK2))
            box[(lane, i)] = (bx, ly)
    col = "#2F6FDB"
    for lane, _, ly in lanes:
        top, bot = ly, ly + bh
        a, b, c = cols
        # Off -> One-shot, over the top.
        o += _arrow(f"M{a+bw-60} {top} C{a+bw+20} {top-60} {b-20} {top-60} "
                    f"{b+40} {top}", (b + 40, top), (b + 10, top - 40), col,
                    "Tap", (a + bw + b) / 2, top - 52)
        # One-shot -> Off, under: a slow second tap, or the key it applied to.
        o += _arrow(f"M{b+40} {bot} C{b-20} {bot+60} {a+bw+20} {bot+60} "
                    f"{a+bw-60} {bot}", (a + bw - 60, bot),
                    (a + bw - 30, bot + 40), col,
                    "Tap again slowly,\nor type the key", (a + bw + b) / 2,
                    bot + 70)
        # One-shot -> Locked.
        o += _arrow(f"M{b+bw-60} {top} C{b+bw+20} {top-60} {c-20} {top-60} "
                    f"{c+40} {top}", (c + 40, top), (c + 10, top - 40), col,
                    "Tap again quickly", (b + bw + c) / 2, top - 52)
        # Locked -> Off, along the bottom.
        o += _arrow(f"M{c+bw/2} {bot} C{c+bw/2} {bot+190} {a+bw/2} "
                    f"{bot+190} {a+bw/2} {bot}", (a + bw / 2, bot),
                    (a + bw / 2, bot + 40), "#8A8F98",
                    "Tap Shift or Alt", (a + c + bw) / 2, bot + 170)
    # Across lanes: one modifier armed, then the other, locks the other.
    sb = box[("Shift", 1)]
    ab = box[("Alt", 1)]
    sl = box[("Shift", 2)]
    al = box[("Alt", 2)]
    red = "#C2410C"
    o += _arrow(f"M{ab[0]+bw-30} {ab[1]} L{sl[0]+30} {sl[1]+bh}",
                (sl[0] + 30, sl[1] + bh), (ab[0] + bw - 30, ab[1]), red)
    o += _arrow(f"M{sb[0]+bw-30} {sb[1]+bh} L{al[0]+30} {al[1]}",
                (al[0] + 30, al[1]), (sb[0] + bw - 30, sb[1] + bh), red)
    mx = (sb[0] + bw + sl[0]) / 2
    my = (sb[1] + bh + ab[1]) / 2
    o.append(T(mx - 40, my + 10, "Alt, then Shift", 17, red, 600, "end"))
    o.append(T(mx - 40, my + 32, "→ caps lock", 17, red, 600, "end"))
    o.append(T(mx + 40, my + 10, "Shift, then Alt", 17, red, 600))
    o.append(T(mx + 40, my + 32, "→ symbol lock", 17, red, 600))
    # Auto-capitalize arms Shift.
    s0 = box[("Shift", 1)]
    o += _arrow(f"M{s0[0]+bw/2} {s0[1]-90} L{s0[0]+bw/2} {s0[1]}",
                (s0[0] + bw / 2, s0[1]), (s0[0] + bw / 2, s0[1] - 90),
                "#15803D")
    o.append(T(s0[0] + bw / 2 - 12, s0[1] - 66, "Start of a sentence", 17,
               "#15803D", 600, "end"))
    width = cols[2] + bw - x0
    height = lanes[1][2] + bh + 200 - y0
    return o, width, height


def keyboard_diagram_svg():
    o, w, h = modifier_diagram(40, 130)
    W2, H2 = w + 80, h + 130 + 40
    head = (f'<svg xmlns="http://www.w3.org/2000/svg" width="{W2}" '
            f'height="{H2}" viewBox="0 0 {W2} {H2}" role="img" '
            f'aria-labelledby="t" font-family="{SANS}"><title id="t">Shift '
            f'and Alt modifier states</title>'
            f'<rect width="{W2}" height="{H2}" fill="{CANVAS_BG}"/>')
    return head + "\n" + "\n".join(o) + "\n</svg>\n"


# ---------------------------------------------------------------- canvas
CANVAS_BG = "#ECECEF"
INK = "#1C1C1E"
INK2 = "#3A3A3C"
SCALE = 2
BEZ = 12
BOARD_W = W * SCALE + 2 * BEZ
BOARD_H = H * SCALE + 2 * BEZ

_clip_n = [0]


def place_screen(x, y, body, scale=SCALE):
    _clip_n[0] += 1
    cid = f"scr{_clip_n[0]}"
    return ([f'<clipPath id="{cid}"><rect width="{W}" height="{H}"/>'
             f'</clipPath>',
             f'<g transform="translate({x},{y}) scale({scale})">'
             f'<g clip-path="url(#{cid})">']
            + body + ["</g></g>"])


def board(x, y, title, body, notes):
    o = [T(x, y - 14, title, 22, INK, 700)]
    o.append(R(x, y, BOARD_W, BOARD_H, "#050607", rx=16,
               extra=' filter="url(#shadow)"'))
    o += place_screen(x + BEZ, y + BEZ, body)
    ny = y + BOARD_H + 30
    for line in wrap(notes, 17, BOARD_W - 10):
        o.append(T(x + 2, ny, line, 17, INK2))
        ny += 24
    return o


def marker(x, y, n):
    return [CIRC(x, y, 17, "#E5484D"),
            T(x, y + 7, str(n), 20, "#fff", 800, "middle")]


# site/static/images/boards/tlora-pager.png with the antennas removed by
# deantenna.py.
PHOTO = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                     "pager-photo.png")
PHOTO_W, PHOTO_H = 360, 254
PHOTO_TOP = 157  # rows cropped off the original
PHOTO_SCREEN = (69, 176 - PHOTO_TOP, 190)  # x, y, width of the panel
PHOTO_K = 3.2  # canvas scale of the photo
HW_W, HW_H = PHOTO_W * PHOTO_K, PHOTO_H * PHOTO_K


def hardware(x, y):
    """The site's product photo with the Chats screen in its panel."""
    import base64
    data = base64.b64encode(open(PHOTO, "rb").read()).decode()
    k = PHOTO_K
    o = [f'<image x="{x}" y="{y}" width="{HW_W:.1f}" height="{HW_H:.1f}" '
         f'href="data:image/png;base64,{data}"/>']
    px, py, pw = PHOTO_SCREEN
    s = pw * k / W
    o += place_screen(x + px * k, y + py * k, screen_chats(), scale=s)

    def at(u, v):
        """Canvas position of a point in the original photo."""
        return x + u * k, y + (v - PHOTO_TOP) * k
    o += marker(*at(318, 208), 1)  # wheel
    o += marker(*at(318, 325), 2)  # Enter
    o += marker(*at(3, 296), 3)  # letters
    o += marker(*at(318, 258), 4)  # Backspace, under the wheel
    return o


def legend_panel(x, y, w, title, entries, numbered=True):
    """numbered: mark entries 1..n, or the first n when it is a number."""
    o = [T(x, y, title, 26, INK, 700)]
    yy = y + 46
    for i, (head, body) in enumerate(entries, 1):
        tx = x
        if numbered is True or i <= numbered:
            o += marker(x + 17, yy - 7, i)
            tx = x + 46
        o.append(T(tx, yy, head, 19, INK, 700))
        yy += 27
        for line in wrap(body, 18, w - (tx - x)):
            o.append(T(tx, yy, line, 18, INK2))
            yy += 25
        yy += 18
    return o


def main(path, native_dir=None):
    random.seed(1)
    margin = 80
    gap = 64
    cols = 3
    cw = cols * BOARD_W + (cols - 1) * gap
    cwidth = cw + 2 * margin
    o = []
    o.append(T(margin, 130, "UMSH messenger · LilyGO T-LoRa Pager", 56,
               INK, 700))
    o.append(T(margin, 178, "480×222 landscape, no touch. Side wheel "
               "with press, 31-key keyboard. Screens drawn at 2×.", 22,
               INK2))
    hy = 270
    o += hardware(margin, hy)
    lx = margin + HW_W + 110
    lw = 760
    o += legend_panel(lx, hy + 10, lw, "Controls", [
        ("Wheel", "On the right edge. Turn moves focus. In an active text "
         "field it moves the cursor: a character per click, a word at a "
         "time when spun fast. Press selects, or ends typing."),
        ("Enter", "Open in lists. In a text field: start typing, then Send."),
        ("Letters", "Always text. Typing activates the focused field, or a "
         "list’s filter. Never commands."),
        ("Backspace", "The arrow key under the wheel. Erases while a field "
         "is active; everywhere else it is Back. Leaving never loses a "
         "draft."),
        ("Boot and power", "Not on this face, and not used for navigation."),
    ], numbered=4)
    px = lx + lw + 90
    pw = cwidth - margin - px
    o += legend_panel(px, hy + 10, pw, "Departures from the iOS app", [
        ("Rail, not tab bar", "Chats, Peers and Device sit on a rail beside "
         "the top-level lists. Back moves focus onto it."),
        ("No hidden search", "Typing on any list filters it. Typing a name "
         "is how a new chat starts."),
        ("No long-press", "Focus a message with the wheel and press it. A "
         "link in a message is its first action."),
        ("Big type, fewer rows", "Body text is 20 px, about 2.3 mm on this "
         "panel, and nothing is under 16 px."),
        ("The last row is clipped", "When a list or the history continues, "
         "its last row is cut by the screen edge. No scroll bars."),
        ("No hint strip", "Field states carry the controls: a cursor means "
         "keys type; no cursor means Backspace is Back."),
        ("No radio chrome", "The radio is built in, so the strip shows only "
         "the device name, time, phone link, GNSS and battery."),
        ("Banners take no keys", "Enter always belongs to the composer."),
    ], numbered=False)

    sections = [
        ("Chats and conversations", [
            ("Chats", screen_chats(),
             "Home. Two lines per chat; the fifth row is clipped, so the list "
             "plainly goes on. A draft shows in place of the last message. "
             "The rail badge counts unread chats."),
            ("Find", screen_find(),
             "Letters typed on a list start a filter, active at once. Enter "
             "opens the tinted top result; press moves into the results. "
             "Groups follow iOS search."),
            ("Conversation, typing", screen_conversation(),
             "Active: heavier border and a cursor, here inserting “hot” "
             "mid-sentence. Turning moves the cursor, a word at a time when "
             "spun. Press is Done; Enter sends."),
            ("Conversation, not typing", screen_conversation("inactive"),
             "How a chat opens: the field is focused but inactive, with no "
             "cursor. Backspace leaves and keeps the draft; typing or Enter "
             "activates it, cursor where it was left. Turning goes up into "
             "the messages."),
            ("Reading", screen_reading(),
             "With focus in the messages the composer folds to one line, "
             "giving the history most of the screen. Turning down past the "
             "newest message unfolds it, field inactive."),
            ("Tall message", screen_tall(),
             "A message taller than the view scrolls line by line while "
             "focused, its cut edges showing there is more; focus moves on "
             "only once its last line is in view."),
            ("Long draft", screen_long(),
             "The composer grows upward to three lines; past that it scrolls "
             "within itself to follow the cursor, and the bar shows where. "
             "Sideways scrolling would hide the start of the message."),
            ("Message actions", screen_actions(),
             "Pressing a focused message opens what the iOS long-press "
             "gives, reactions first. Typing closes the menu and goes to the "
             "composer."),
            ("Reaction", screen_reacted(),
             "A chip over the bubble’s outer top corner, as on iOS: top-left "
             "on a sent message, top-right on a received one, gray when "
             "it is someone else’s."),
            ("Message details", screen_details(),
             "From Details. The rows of the iOS sheet that a reader on a "
             "communicator needs; the list continues to the source check. "
             "Delivery state lives under the bubble, not here."),
            ("Reply", screen_reply(),
             "The quoted message sits above the composer. Backspace only "
             "erases while typing; after Done, the first Backspace drops the "
             "reply and keeps the text, the next leaves."),
            ("Send trouble", screen_trouble(),
             "The unconfirmed message is focused and pressed to retry. When "
             "airtime is spent, the composer keeps the draft and says when "
             "Send returns, inline rather than in an alert."),
            ("Message while writing", screen_banner(),
             "Banners are passive. They never take a key, so Enter still "
             "sends the draft they interrupted. A haptic tick, then it times "
             "out; the chat waits at the top of Chats."),
        ]),
        ("Message states", [
            ("Times", screen_times(),
             "After an hour’s quiet, a separator says when the conversation "
             "picked up again: the day, then the time, as on iOS. Today, "
             "Yesterday, a weekday within the week, then the date. Each "
             "message’s own time is in Details."),
            ("Reply", screen_reply_received(),
             "A reply quotes the start of the message it answers, with its "
             "sender, at the top of its bubble, as the composer’s strip does "
             "while you write one. When the answered message is not here, "
             "the reply shows without a quote."),
            ("Edited and deleted", screen_edited_deleted(),
             "An edited message shows its new text and says so under the "
             "bubble. A deleted one leaves a line in its place, with no "
             "bubble, menu, or reactions."),
            ("Missing message", screen_gap(),
             "A message missing from the sequence has been asked for again. "
             "The typing dots hold its place until it comes, so it lands "
             "where it was sent rather than at the end."),
            ("Found or lost", screen_gap_settled(),
             "Above, the missing message came and fills its slot, marked "
             "late. Below, its sender could no longer supply the next one, "
             "and a line marks the loss."),
            ("Arriving in parts", screen_parts(),
             "A long message shows as its parts arrive. The dots count them, "
             "filled as each comes in, and the ellipsis marks where the rest "
             "will go."),
            ("Part missing", screen_parts(missing=True),
             "A part that never came: the message is shown without it, the "
             "ellipsis and its dot turn amber, and the message no longer "
             "waits."),
        ]),
        ("Forward secrecy", [
            ("Typing under forward secrecy",
             screen_conversation(secret=True),
             "In a chat that holds a session with forward secrecy, the "
             "composer is violet while you edit: what it sends goes under "
             "the session. Not typing, it is the usual blue."),
            ("Sent under forward secrecy", screen_secret_sent(),
             "A message sent while the composer was violet stays violet, "
             "and a reply’s quote takes its tints. Those sent before the "
             "session stay blue."),
            ("Sending again", screen_resend(),
             "Pressing an unconfirmed violet message asks how to send it "
             "again. Try again keeps forward secrecy; only the second "
             "choice sends without it, and the message turns blue. "
             "Backspace cancels."),
        ]),
        ("Channels", [
            ("Channel", screen_channel(),
             "Sender label and avatar on each run, by the iOS authority "
             "order; an unidentified member shows its hint. Group sends end "
             "at Sent: multicast has no acknowledgment."),
            ("Channel message actions", screen_channel_actions(),
             "A member’s message adds View member, the way to reach someone "
             "you have only heard in a channel."),
            ("Several reactions", screen_channel_reactions(),
             "Matching reactions share a chip with a count. Yours takes the "
             "bubble color and sits in front at the corner, with the "
             "cluster’s one trail of dots."),
            ("Member", screen_member(),
             "A channel message carries only a hint. Request identity asks "
             "over the channel; when the identity arrives the address fills "
             "in and Message and Save peer appear."),
            ("Channel invite", screen_invite(),
             "An invitation link renders as a card, since a link inside text "
             "cannot take focus. Pressing it opens the actions with Join "
             "Trail Crew first."),
            ("Join channel", screen_join(),
             "The invitation’s preview. Nothing is joined or sent until Join "
             "channel. Region and hops from the link apply silently, as on "
             "iOS."),
            ("Channel card", screen_channel_card(),
             "Boards with NFC. A tag carrying a channel invitation opens the "
             "same screen; the warning names the card, since a card can be "
             "lent or copied."),
            ("Add channel", screen_add_channel(),
             "Device › Channels › Add channel. One field takes a channel name "
             "or a umsh:ck: invitation, and the preview says which as you "
             "type. A name is short; a key is the painful case shown."),
            ("EMERGENCY", screen_emergency(),
             "Joined from the start. Traffic is signed and unencrypted, so "
             "every sender is named and anyone in range can read it. It "
             "alerts like any other chat."),
        ]),
        ("Peers", [
            ("Peers, rail focused", screen_peers(),
             "Backspace from a top-level list lands on the rail; turning "
             "switches lists live, press enters. Add peer heads the list."),
            ("Add peer", screen_add_peer(),
             "Opens on Nearby: devices that also have Add peer open, nearest "
             "first, by model and a color that is new each time the screen "
             "opens. No name, address or avatar is sent or shown until its "
             "holder presses Same. You is this device’s color. The arcs "
             "show how close; the back-to-back glyph shows only on boards "
             "with NFC."),
            ("Asked to exchange", screen_exchange_request(),
             "Pat’s T-Deck, drawn at the Pager’s size, when Juniper presses "
             "its row. Pat knows who asked "
             "by who is standing there. Not now declines; nothing else is "
             "sent."),
            ("Compare", screen_exchange_code(),
             "Both screens show the same six digits only if nobody is in the "
             "middle. Nothing of this device has been sent yet: Same sends "
             "its address and name. Turning moves between the buttons."),
            ("Waiting", screen_exchange_code("waiting"),
             "After Same, which sent this device’s address and name, until "
             "the other side presses Same too and sends its own. Leaving "
             "here cancels."),
            ("Codes differ", screen_exchange_code("differ"),
             "Either side pressing Different lands both here, and whatever "
             "either received is dropped. Nothing is saved. Try again goes "
             "back to Nearby under a new color."),
            ("Exchanged", screen_exchanged(),
             "Where both land once the codes match, or after a tap on boards "
             "with NFC: the ordinary sheet for a peer who is not saved. It "
             "opens on Message; turning down reaches Save peer, shown here. "
             "Nothing is saved until it is pressed."),
            ("Enter an address", screen_enter_address(),
             "Add peer › Enter an address. Takes a 44-character address or a "
             "umsh:n: invitation. The address wraps at a fixed column; the "
             "avatar appears from the first characters, and Message unlocks "
             "when it is complete."),
            ("Peer detail", screen_peer_detail(),
             "The full address fits on one line. One focusable list of "
             "readouts and actions follows; Forget is last and asks to "
             "confirm. Share contact sends the peer to a chat."),
            ("Share", screen_share(),
             "A version-4 QR at about 5 px per module, sized for scanning "
             "rather than type. Turning on Shows switches between the "
             "identity and joined channels. The pattern is illustrative. "
             "On boards with NFC, a phone tapping the device while this is "
             "open reads the same link; Add peer never serves it."),
            ("Contact in a chat", screen_contact_in_chat(),
             "A message whose whole body is a umsh:n: link renders as a "
             "contact card, as invites do for channels. Pressing it opens "
             "its actions with Show first, as Join is for an invite: a "
             "saved peer’s page, or else the unsaved-peer sheet."),
            ("Contact opened", screen_introduced(),
             "The same unsaved-peer sheet, as it opens: Message focused, "
             "Save peer one turn down."),
            ("Share contact", screen_share_contact(),
             "From a peer’s page. Picks a chat; the contact goes there as an "
             "ordinary message."),
        ]),
        ("Device, power and first run", [
            ("Device", screen_device(),
             "Settings drill down: categories with a one-word summary, press "
             "to enter. Radio detail lives here too, since the radio is "
             "built in."),
            ("Battery low", screen_battery_low(),
             "A passive banner, like a message’s, and the strip’s battery "
             "turns amber. It does not take a key or cover the composer."),
            ("Battery empty", screen_battery_empty(),
             "The last thing shown before the power path opens: the empty "
             "battery blinks a few times, then the panel goes dark. No words "
             "to translate, and no controls."),
            ("First run: name", screen_setup_name(),
             "The identity exists before this screen. The name is optional: "
             "Continue with it empty and peers see the bare hint."),
            ("First run: radio profile", screen_setup_profile(),
             "Required before the first transmission, since it sets what the "
             "radio may use. The same list is Device › Radio later."),
            ("First run: time zone", screen_setup_time_zone(),
             "Asked even with a GNSS fix, which gives the time but not the "
             "zone. The list starts on the zone set, UTC until now; letters "
             "narrow it. Device › Clock › Time zone later."),
        ]),
        ("Keyboard", [
            ("Start of a sentence", screen_kb_sentence(),
             "Shift arms itself where a sentence starts, shown by the outlined "
             "arrow in the strip. The next letter is a capital; tapping Shift "
             "instead disarms it."),
            ("Double space", screen_kb_period(),
             "“hut” then two quick spaces typed “hut. ”, and Shift armed for "
             "the next sentence. Only when the key before the first space was "
             "a letter; moving the cursor in between breaks the sequence."),
            ("Caps lock", screen_kb_caps(),
             "Shift tapped twice quickly, or Alt then Shift. The filled arrow "
             "with a bar stays until Shift or Alt is tapped."),
            ("Alt, once", screen_kb_alt(),
             "Alt tapped once: the next key types its orange legend, here "
             "about to type “?”, and Alt disarms. Held instead, Alt applies "
             "while it is down and the strip shows nothing."),
            ("Numbers-only field", screen_kb_numbers(),
             "A numeric field opens in symbol lock, so the top row types "
             "digits and Alt+F the minus sign. Space types a space. No "
             "capitalizing or double-space period here."),
            ("Character picker", screen_kb_picker(),
             "Alt+Space. Turning walks the grid and its categories in order; "
             "press inserts at the cursor and closes. Backspace closes "
             "without inserting. The third row is clipped: the grid goes on."),
            ("Picker, filtered", screen_kb_picker_filter(),
             "Letters typed in the picker filter it by name, in place of the "
             "category row."),
            ("Keyboard light", screen_kb_light(),
             "Space while the picker is open toggles the keyboard light and "
             "closes the picker, so Alt+Space, Space is the light switch."),
            ("Brightness", screen_kb_brightness(),
             "Holding Alt down while turning the wheel sets the screen "
             "brightness. Only a held Alt: a one-shot or locked Alt leaves "
             "the wheel to move focus or the cursor."),
            ("Keyboard settings", screen_kb_settings(),
             "Device › Keyboard. The two typing aids can be turned off "
             "everywhere; fields that never want them turn them off for "
             "themselves."),
        ]),
        ("Locking", [
            ("Lock screen", screen_lock(),
             "A key or a small turn lights a locked device to this. So does "
             "every message that would alert, with the haptic tick, its card "
             "landing on top and the 15 s starting over. One card per chat "
             "heard from since locking; the badge counts unread chats."),
            ("Scrolling to unlock", screen_lock(fill=0.55),
             "Turning down fills the bar, five steps to the mark; turning "
             "up empties it. The cards stay put: the wheel only feeds the "
             "bar. Pressing before the bar is full does nothing."),
            ("Ready to unlock", screen_lock(ready=True),
             "Past the mark the bar turns green and the hint changes. A "
             "press within 2 s unlocks, back to where you were, with the "
             "cards’ chats at the top of Chats; otherwise the bar empties "
             "and it starts over."),
            ("Nothing new", screen_lock_quiet(),
             "With no cards, the time takes the middle. While charging, the "
             "charge shows under the date. After 15 s the screen fades, then "
             "goes dark, sooner than when unlocked."),
            ("Clock not set", screen_lock_no_time(),
             "Until the clock is known, no time or date shows anywhere: not "
             "here, in the strip, or in Details. Ages of messages heard since "
             "power-on are measured, not read off the clock, so they stay."),
        ]),
        ("Clock", [
            ("Clock", screen_clock(),
             "Device › Clock. Set automatically takes the time from GNSS, or "
             "from the phone when linked; Date and time is then a readout. "
             "Last set from says where the time came from, and when."),
            ("Date and time", screen_set_time(),
             "With Set automatically off. Turning moves between the parts; "
             "pressing one lets turning change it, and digits type it. Set "
             "starts the minute at zero seconds."),
            ("Time zone", screen_time_zone(),
             "Zones by name, west to east, with today’s offset, daylight "
             "saving included. Letters filter the list, as on every list."),
        ]),
        ("Deleting a chat", [
            ("Chat menu", screen_chat_menu(),
             "A press opens a chat when the wheel comes back up; holding it "
             "down opens the chat’s menu instead. A channel’s says Show "
             "channel."),
            ("Delete chat", screen_delete_chat(),
             "Asks to confirm, Cancel focused, as Forget does. The chat and "
             "its messages go; the peer stays saved, and their next message "
             "starts a new chat."),
        ]),
    ]
    by = hy + HW_H + 140
    boards = []
    n = 0
    for sname, items in sections:
        o.append(T(margin, by, sname, 34, INK, 700))
        by += 70
        for i, (name, body, notes) in enumerate(items):
            n += 1
            title = f"{n} · {name}"
            boards.append((title, body, notes))
            r, c = divmod(i, cols)
            bx = margin + c * (BOARD_W + gap)
            o += board(bx, by + r * (BOARD_H + 230), title, body, notes)
        by += -(-len(items) // cols) * (BOARD_H + 230) + 40
    o.append(T(margin, by, "Shift and Alt", 34, INK, 700))
    o.append(T(margin, by + 38, "Each modifier is off, one-shot or locked. "
               "Held down, either applies only while it is down and changes "
               "no state.", 19, INK2))
    dg, _, dh = modifier_diagram(margin, by + 130)
    o += dg
    by += 130 + dh + 40
    o.append(T(margin, by, "Locking and unlocking", 34, INK, 700))
    o.append(T(margin, by + 38, "The lock button is the one at the bottom "
               "edge, also the bootloader button. A password, later, would "
               "follow the press.", 19, INK2))
    dg, _, dh = lock_diagram(margin + 20, by + 270)
    o += dg
    by += 270 + dh + 40
    height = by


    # Walkthrough: changing settings with the wheel alone.
    steps = [
        (screen_device(),
         "Turn to Radio; press to open it. Its summary shows the current "
         "preset."),
        (screen_device(row=1),
         "Radio opens as its own screen. Turn to Preset; press to change "
         "it."),
        (screen_device(row=1, picker="Medium range"),
         "The choices open in place, the current one checked. Turn to "
         "Medium range; press to choose. Backspace cancels."),
        (screen_device(row=3, preset="Medium range", share=True),
         "Preset reads Medium range. Turn to Share location; press flips "
         "the switch. Changes apply at once; there is no Save."),
        (screen_device(preset="Medium range", share=True),
         "Backspace steps back out to the categories; a second Backspace "
         "goes to the rail."),
    ]
    sy = height + 40
    o.append(T(margin, sy, "Changing a setting", 34, INK, 700))
    o.append(T(margin, sy + 38, "Turn moves, press selects, Backspace goes "
               "back. No text field is involved, so Backspace is always "
               "Back.", 19, INK2))
    fs = 1.2
    fbez = 7
    fw = W * fs + 2 * fbez
    fh = H * fs + 2 * fbez
    fgap = (cw - len(steps) * fw) / (len(steps) - 1)
    fy = sy + 70
    for i, (body, caption) in enumerate(steps):
        fx = margin + i * (fw + fgap)
        o.append(R(fx, fy, fw, fh, "#050607", rx=10,
                   extra=' filter="url(#shadow)"'))
        o += place_screen(fx + fbez, fy + fbez, body, scale=fs)
        if i < len(steps) - 1:
            ax = fx + fw + fgap / 2
            ay = fy + fh / 2
            o.append(P(f"M{ax-5} {ay-9} L{ax+4} {ay} L{ax-5} {ay+9}", INK2,
                       sw=3))
        o += marker(fx + 17, fy + fh + 30, i + 1)
        cy = fy + fh + 37
        for line in wrap(caption, 17, fw - 46):
            o.append(T(fx + 44, cy, line, 17, INK2))
            cy += 24
    height = fy + fh + 170

    head = (f'<svg xmlns="http://www.w3.org/2000/svg" width="{cwidth}" '
            f'height="{height}" viewBox="0 0 {cwidth} {height}" role="img" '
            f'aria-labelledby="t" font-family="{SANS}"><title id="t">UMSH '
            f'messenger on the LilyGO T-LoRa Pager, mockups</title><defs>'
            f'<filter id="shadow" x="-5%" y="-5%" width="110%" height="110%">'
            f'<feDropShadow dx="0" dy="3" stdDeviation="8" '
            f'flood-opacity="0.22"/></filter></defs>'
            f'<rect width="{cwidth}" height="{height}" fill="{CANVAS_BG}"/>')
    with open(path, "w") as f:
        f.write(head + "\n" + "\n".join(o) + "\n</svg>\n")
    # The state diagram alone, for the UX book.
    with open(os.path.join(os.path.dirname(path), "keyboard-modifiers.svg"),
              "w") as f:
        f.write(keyboard_diagram_svg())

    if native_dir:
        # Each screen alone, in panel pixels, for rasterizing at 1:1.
        import re
        os.makedirs(native_dir, exist_ok=True)
        for title, body, _ in boards:
            num, name = title.split(" · ")
            slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
            with open(os.path.join(native_dir, f"{int(num):02d}-{slug}.svg"),
                      "w") as f:
                f.write(f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" '
                        f'height="{H}" viewBox="0 0 {W} {H}" '
                        f'font-family="{SANS}">' + "".join(body) + "</svg>\n")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else None)
