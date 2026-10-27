#!/usr/bin/env python3
"""Generate the communicator Route and Ping mockups as one SVG.

Drawn with generate.py's palette, type scale, rows and avatars, so these
boards match the messenger canvas. From this directory:

    python3 route_ping.py ../communicator-route-ping.svg
"""
import math
import re
import sys

import generate as g
from generate import C, CIRC, H, LINE, P, R, STRIP, T, TOP, W
from generate import F_BODY, F_SEC, F_SMALL

g.NODES.update({
    "Pat Okafor": {},
    "Spencer Butte": {"hint": "BtC5", "shape": "triangle"},
    "Skinner Ridge": {"hint": "55Hk", "shape": "triangle"},
    "Mt. Pisgah": {"hint": "Pg3e", "shape": "triangle"},
    "Fox Hollow": {"hint": "Fx9b", "shape": "triangle"},
    "Eugene Bridge": {"hint": "Eb2W", "shape": "hexagon"},
    "Mary's Peak": {"hint": "Mq7t", "shape": "triangle"},
    "7N*": {"hint": "7N*", "shape": "hexagon"},
})
PEER = "Pat Okafor"
RH = 34  # the peer screen's row height
NH = 32  # a node's row on a path
LH = 22  # a leg's row on a path
RAIL_X = 26
RAIL = "#3A414B"


# ---------------------------------------------------------------- glyphs
def node_avatar(cx, cy, r, name):
    """A node on the path. A hint no known node matches is drawn in the
    iOS app's neutral gray: a router hint is too short to color."""
    out = g.avatar(cx, cy, r, name)
    if name.endswith("*") and name != "Member 4Fz*":
        out[0] = re.sub(r'fill="#[0-9A-Fa-f]{6}"', 'fill="#808080"', out[0],
                        count=1)
    return out


def spinner(cx, cy, phase=0, r=7):
    """The ring of dots Details spins while a repeater is asked."""
    o = []
    for i in range(8):
        behind = (phase - i) % 8
        col = {0: C["accent"], 1: "#2F6FB0", 2: "#25496E"}.get(behind,
                                                              "#2A3038")
        a = i / 8 * 2 * math.pi
        o.append(CIRC(cx + r * math.sin(a), cy - r * math.cos(a), 1.9, col))
    return o


def magnifier(cx, cy, col):
    return [CIRC(cx - 2, cy - 2, 5, stroke=col, sw=2),
            P(f"M{cx+2} {cy+2} L{cx+6} {cy+6}", col, sw=2.2)]


def link_glyph(x, cy, col):
    """A bridge: the hop crossed a point-to-point link, not the air."""
    return [R(x, cy - 4, 10, 8, stroke=col, sw=1.7, rx=4),
            R(x + 6, cy - 4, 10, 8, stroke=col, sw=1.7, rx=4)]


def bars_for(snr_tenths):
    return 4 if snr_tenths >= 70 else 3 if snr_tenths >= 30 else \
        2 if snr_tenths >= -50 else 1


def bars_color(n):
    return {4: C["green"], 3: C["green"], 2: C["amber"], 1: C["red"]}[n]


def dbm(v):
    return f"{'−' if v < 0 else ''}{abs(v)} dBm"


def db(tenths):
    return f"{'−' if tenths < 0 else ''}{abs(tenths) // 10}.{abs(tenths) % 10} dB"


# ---------------------------------------------------------------- the path
def path_list(items, y, focus=None, asking=None, dim=False):
    """A route as a list, this device first and the peer last.

    items alternate nodes and legs. Nodes: "You", a name, or
    ("unnamed", n). Legs: (rssi, snr_tenths), "bridge", "dashed",
    "moving" or None for a hop with no reading. focus and asking index
    the nodes. A node is a row the wheel stops on; a leg with a reading
    is a caption between two rows, saying how that hop was heard, and one
    without is only the rail.
    """
    hl = []
    o = []
    rail = []
    rows = []
    nodes = 0
    legs = items[1::2]
    for i, item in enumerate(items[::2]):
        rows.append((y, item))
        leg = legs[i] if i < len(legs) else None
        y += NH + (LH if isinstance(leg, tuple) or leg == "bridge"
                   else 16 if leg in ("dashed", "moving") else 8)
    end = rows[-1][0] + NH
    # The rail first, under everything.
    for i, leg in enumerate(items[1::2]):
        a = rows[i][0] + NH / 2 + 15
        b = rows[i + 1][0] + NH / 2 - 15
        dashed = leg in ("dashed", "moving") or any(
            isinstance(rows[k][1], tuple) for k in (i, i + 1))
        extra = ' stroke-dasharray="2 5"' if dashed else ""
        rail.append(P(f"M{RAIL_X} {a:.1f} V{b:.1f}",
                      "#2A3038" if dim else RAIL, sw=2.4, extra=extra))
        ly = rows[i][0] + NH + LH / 2
        if leg == "moving":
            # The request in flight, with the spinner's fading trail.
            mid = (rows[i][0] + NH + rows[i + 1][0]) / 2
            for k, col in ((0, C["accent"]), (-6, "#2F6FB0"),
                           (-12, "#25496E")):
                rail.append(CIRC(RAIL_X, mid + 6 + k, 3.4 + k / 10, col))
        elif leg == "bridge":
            o += link_glyph(48, ly, C["text3"])
            o.append(T(72, ly + 5.5, "Bridge", F_SMALL, C["text3"], 500))
        elif isinstance(leg, tuple):
            rssi, snr = leg
            n = bars_for(snr)
            o += g.signal_bars(48, ly + 6.5, n, bars_color(n))
            o.append(T(72, ly + 5.5, f"{dbm(rssi)} · SNR {db(snr)}", F_SMALL,
                       C["text3"], 500))
    for i, (ry, item) in enumerate(rows):
        cy = ry + NH / 2
        focused = i == focus
        if focused:
            hl.append(R(4, ry + 1, W - 8, NH - 2, C["focus"], rx=8,
                        stroke=C["accent"], sw=1.6))
        name_col = C["text"] if not dim else C["text3"]
        weight = 700 if focused else 400
        trailing = None
        if item == "You":
            rail += g.device_glyph(RAIL_X, cy, 12, C["text2"])
            o.append(T(50, cy + 7, "You", F_BODY, C["text2"], weight))
        elif isinstance(item, tuple):
            for k in (-8, 0, 8):
                rail.append(CIRC(RAIL_X, cy + k, 2.6, C["bg"],
                                 stroke=C["text3"], sw=1.4))
            o.append(T(50, cy + 7, f"{item[1]} unnamed", F_BODY, C["text3"]))
        else:
            av = node_avatar(RAIL_X, cy, 13, item)
            rail += (['<g opacity="0.4">'] + av + ["</g>"]) if dim else av
            o.append(T(50, cy + 7, item, F_BODY, name_col, weight))
            if item == PEER:
                pass
            elif item.endswith("*"):
                trailing = "asking" if i == asking else "lookup"
            else:
                trailing = "open"
        if trailing == "open":
            o.append(g.chevron(W - 16, cy))
        elif trailing == "lookup":
            o += magnifier(W - 20, cy, C["accent"])
        elif trailing == "asking":
            o += spinner(W - 22, cy, 2, r=8)
        nodes += 1
    return hl + rail + o, end


def route_screen(sub, items, rows, focus=None, asking=None, scroll=0,
                 dim=False, row_focus=None):
    o = [R(0, 0, W, H, C["bg"])]
    y = TOP + 6 - scroll
    body, y = path_list(items, y, focus, asking, dim)
    y += 10
    for i, (label, val, kind) in enumerate(rows):
        body += g.setting_row(0, y, label, val, focused=i == row_focus,
                              chev=kind == "go", rh=RH, danger=kind == "red")
        y += RH
    o += g.clip(body, 0, TOP, W, H - TOP)
    o += g.screen_header("Route", sub=sub)
    o += g.status()
    return o


ROUTE_ROWS = [("Confirmed", "4 min ago", "read"), ("Reset route", None, "red")]


# ---------------------------------------------------------------- screens
def screen_peer():
    o = [R(0, 0, W, H, C["bg"])]
    body = []
    y = STRIP - 20  # scrolled: Share contact is going off the top
    for label, val, kind, focused in [
        ("Share contact", None, "go", False),
        ("Alias", "Pat Okafor", "read", False),
        ("Route", "3 hops", "go", True),
        ("Last heard", "5 min ago", "read", False),
        ("Forward secrecy", False, "read", False),
        ("Ping", None, "go", False),
    ]:
        body += g.setting_row(0, y, label, val, focused, chev=kind == "go",
                              rh=RH)
        y += RH
    o += g.clip(body, 0, STRIP, W, H - STRIP)
    o += g.status()
    return o


# A route names its repeaters, not how each hop was heard.
SOURCE = ["You", None, "Spencer Butte", None, "7N*", None, PEER]


def screen_route():
    return route_screen("3 hops", SOURCE, ROUTE_ROWS, focus=1)


def screen_route_end():
    return route_screen("3 hops", SOURCE, ROUTE_ROWS, focus=2, asking=2,
                        scroll=60)


LONG = [x for name in ["You", "Spencer Butte", "Mt. Pisgah", "Fox Hollow",
                       "Eugene Bridge", "Mary's Peak", "Coburg Hills",
                       "7N*", "Bald Hill", "Lorane", "Hendricks Park",
                       "Skinner Ridge"] for x in (name, None)] + [PEER]


def screen_route_long():
    # Twelve hops, turned to the middle of the path.
    return route_screen("12 hops", LONG, ROUTE_ROWS, focus=4,
                        scroll=96)


def screen_repeater():
    """What a repeater on the path opens: the screen a repeater opens from
    a message's Details."""
    o = [R(0, 0, W, H, C["bg"])]
    y = STRIP
    body = g.detail_head("Spencer Butte", "peer", "Repeater · heard 2m", y)
    body.append(T(10, y + 77, g.address("Spencer Butte"), F_SMALL,
                  C["text2"], mono=True))
    yy = y + 84
    for label, val, kind, focused in [
        ("Save peer", None, "action", True),
        ("Request identity", None, "action", False),
        ("Last heard", "2 min ago", "read", False),
    ]:
        body += g.setting_row(0, yy, label, val, focused,
                              chev=kind == "go", rh=RH)
        yy += RH
    o += g.clip(body, 0, STRIP, W, H - STRIP)
    o += g.status()
    return o


def screen_route_direct():
    return route_screen("Direct", ["You", (-97, 65), PEER],
                        [("Confirmed", "1 min ago", "read"),
                         ("Reset route", None, "red")], row_focus=1)


def screen_route_flood():
    return route_screen("Flood · 4 hops",
                        ["You", "dashed", ("unnamed", 3), "dashed", PEER],
                        [("Confirmed", "12 min ago", "read"),
                         ("Reset route", None, "red")], row_focus=1,
                        scroll=38)


def screen_route_unknown():
    return route_screen("Not learned", ["You", "dashed", PEER],
                        [("Ping", None, "go")], dim=True, row_focus=0)


def hero_line(mark, big, big_col, right=None):
    y = TOP + 22
    o = list(mark(24, y - 1))
    o.append(T(44, y + 10, big, 28, big_col, 700))
    if right:
        o.append(T(W - 14, y + 7, right, F_SEC, C["text2"], 400, "end"))
    return o


def ping_screen(hero, items, again=True, dim=False, earlier=()):
    """The result first, then Ping again where the wheel starts, then the
    path, then the pings before this one."""
    o = [R(0, 0, W, H, C["bg"])]
    body = list(hero)
    y = TOP + 44
    if again:
        body += g.setting_row(0, y, "Ping again", None, focused=True, rh=RH)
        y += RH + 6
    part, y = path_list(items, y, dim=dim)
    body += part
    if earlier:
        body.append(g.section_label(12, y + 26, "Earlier"))
        y += 32
        for value, ago, col in earlier:
            body.append(T(12, y + RH / 2 + 7, value, F_BODY, col))
            body.append(T(W - 14, y + RH / 2 + 6, ago, F_SEC, C["text3"], 400,
                          "end"))
            body.append(LINE(12, y + RH - 0.5, W, y + RH - 0.5))
            y += RH
    o += g.clip(body, 0, TOP, W, H - TOP)
    o += g.screen_header("Ping", sub=PEER)
    o += g.status()
    return o


def screen_ping_waiting():
    hero = hero_line(lambda x, y: spinner(x, y, 3, r=8), "1.2 s", C["text2"])
    return ping_screen(hero, ["You", "moving", PEER], again=False, dim=True)


def screen_ping_reply():
    hero = hero_line(lambda x, y: [CIRC(x, y, 11, C["green"])]
                     + g.check_mark(x, y, C["bg"], 0.9),
                     "1.4 s", C["text"], "3 hops")
    return ping_screen(hero, ["You", (-97, 65), "Spencer Butte", (-104, 38),
                              "Skinner Ridge", (-110, -15), PEER],
                       earlier=[("No reply", "1m", C["amber"])])


def screen_ping_timeout():
    hero = hero_line(lambda x, y: [CIRC(x, y, 11, C["amber"])]
                     + [P(f"M{x} {y-6} V{y+1}", C["bg"], sw=2.6),
                        CIRC(x, y + 5.5, 1.6, C["bg"])],
                     "No reply", C["amber"])
    return ping_screen(hero, ["You", "dashed", PEER], dim=True,
                       earlier=[("1.6 s · 3 hops", "3m", C["text"])])


BOARDS = [
    ("Route", "The Route row opens the path the next message to this peer "
     "takes, as a list from this device to the peer. Each repeater is a row "
     "the wheel stops on.", [
        ("1 · Peer, Route focused", screen_peer(),
         "Route gains a chevron and opens the Route screen. Ping does the "
         "same for the Ping screen and no longer shows the last round trip "
         "in its row. The value is the route in use, not the last frame "
         "heard."),
        ("2 · Route, source route", screen_route(),
         "Turn moves from repeater to repeater, then into the rows below. "
         "You and the peer are not stops. A route records which repeaters "
         "it crosses, not how each hop was heard, so the hops carry no "
         "readings."),
        ("3 · Route, asking a repeater", screen_route_end(),
         "Turned to the end. A hint no known node matches shows the search "
         "glyph; press asks who it is, steered down the hops before it, and "
         "the dots spin as in Details. The answer names it in place."),
        ("4 · Route, twelve hops", screen_route_long(),
         "A long path is just a longer list; the last row is clipped to show "
         "it goes on."),
        ("5 · A repeater, opened", screen_repeater(),
         "Pressing a known repeater opens the same screen a repeater opens "
         "from a message's Details. Backspace returns to the route, focus "
         "where it was."),
        ("6 · Route, direct", screen_route_direct(),
         "One hop, and this device heard it, so it has a reading. No stops "
         "on the path: the wheel starts in the rows."),
        ("7 · Route, flood", screen_route_flood(),
         "A flood route counts its repeaters but cannot name them, so they "
         "are one dashed span."),
        ("8 · Route, nothing learned", screen_route_unknown(),
         "No route yet, so the next message floods. Ping, the quickest way "
         "to learn one, is the only row."),
    ]),
    ("Ping", "Ping is its own screen. Opening it sends at once; Backspace "
     "leaves, and a reply that lands later still counts.", [
        ("9 · Ping, waiting", screen_ping_waiting(),
         "The time counts up beside the spinner. A ping floods, so there is "
         "no path to draw until one comes back: only that it has left."),
        ("10 · Ping, reply", screen_ping_reply(),
         "Round trip and hops, then Ping again, where the wheel starts. "
         "Turning down walks the path the reply took, in the Route "
         "screen's list. A ping is traced with signal, so here each hop "
         "carries its reading, as the node nearer this device heard it. "
         "Earlier lists this visit's pings."),
        ("11 · Ping, no reply", screen_ping_timeout(),
         "Nothing came back. Ping again is focused, so a press retries."),
    ]),
]


def main(path_out):
    margin, gap, cols = 80, 64, 3
    cw = cols * g.BOARD_W + (cols - 1) * gap
    cwidth = cw + 2 * margin
    o = [T(margin, 130, "Route and Ping · communicator", 56, g.INK, 700),
         T(margin, 178, "T-LoRa Pager, 480×222, drawn at 2×. Turn moves, "
           "press selects, Backspace goes back.", 22, g.INK2)]
    y = 270
    for title, intro, boards in BOARDS:
        o.append(T(margin, y, title, 34, g.INK, 700))
        o.append(T(margin, y + 38, intro, 19, g.INK2))
        y += 110
        for i in range(0, len(boards), cols):
            row = boards[i:i + cols]
            deepest = 0
            for j, (btitle, body, notes) in enumerate(row):
                x = margin + j * (g.BOARD_W + gap)
                o += g.board(x, y, btitle, body, notes)
                deepest = max(deepest, len(g.wrap(notes, 17, g.BOARD_W - 10)))
            y += g.BOARD_H + 30 + deepest * 24 + 80
        y += 20
    height = y
    head = (f'<svg xmlns="http://www.w3.org/2000/svg" width="{cwidth}" '
            f'height="{height}" viewBox="0 0 {cwidth} {height}" role="img" '
            f'aria-labelledby="t" font-family="{g.SANS}"><title id="t">Route '
            f'and Ping on the communicator, mockups</title><defs>'
            f'<filter id="shadow" x="-5%" y="-5%" width="110%" height="110%">'
            f'<feDropShadow dx="0" dy="3" stdDeviation="8" '
            f'flood-opacity="0.22"/></filter></defs>'
            f'<rect width="{cwidth}" height="{height}" fill="{g.CANVAS_BG}"/>')
    with open(path_out, "w") as f:
        f.write(head + "\n" + "\n".join(o) + "\n</svg>\n")


if __name__ == "__main__":
    main(sys.argv[1])
