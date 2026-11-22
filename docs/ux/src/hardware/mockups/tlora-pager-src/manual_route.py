#!/usr/bin/env python3
"""Generate the communicator manual-route mockups as one SVG.

The iOS manual path (docs/ux/src/apps/ios/product-structure.md, "Manual
path") carried over to the wheel and keyboard, drawn with generate.py's and
route_ping.py's palette, rows and path rail. From this directory:

    python3 manual_route.py ../communicator-manual-route.svg
"""
import sys

import generate as g
import route_ping as rp
from generate import C, CIRC, H, LINE, P, R, STRIP, T, TOP, W
from generate import F_BODY, F_SEC, F_SMALL

g.NODES.update({
    "Coburg Hills": {"hint": "Cb4r", "shape": "triangle"},
    "8C*": {"hint": "8C*", "shape": "hexagon"},
    "3D*": {"hint": "3D*", "shape": "hexagon"},
    "59*": {"hint": "59*", "shape": "hexagon"},
})
PEER = rp.PEER
RH = 34
RAIL_X = rp.RAIL_X


# ---------------------------------------------------------------- glyphs
def grip(cx, cy, col):
    """A hop can be moved."""
    return [P(f"M{cx-7} {cy-4} H{cx+7} M{cx-7} {cy} H{cx+7} "
              f"M{cx-7} {cy+4} H{cx+7}", col, sw=1.6)]


def updown(cx, cy, col, k=1.0):
    """Turning moves or changes what is focused."""
    return [P(f"M{cx-5*k} {cy-3*k} L{cx} {cy-8*k} L{cx+5*k} {cy-3*k} "
              f"M{cx-5*k} {cy+3*k} L{cx} {cy+8*k} L{cx+5*k} {cy+3*k}", col,
              sw=2 * k)]


def flood_dots(cx, cy, off=False):
    """The route's unnamed flood hops, as the Route screen draws them."""
    col = C["line"] if off else C["text3"]
    return [CIRC(cx, cy + k, 2.6, C["bg"], stroke=col, sw=1.4)
            for k in ((0,) if off else (-8, 0, 8))]


def focus_box(y, rh=RH, lifted=False):
    if lifted:
        return [R(7, y + 4, W - 8, rh - 2, "#000", rx=8,
                  extra=' opacity="0.55"'),
                R(4, y - 1, W - 8, rh - 2, "#1F3D63", rx=8,
                  stroke=C["accent"], sw=2.2)]
    return [R(4, y + 1, W - 8, rh - 2, C["focus"], rx=8, stroke=C["accent"],
              sw=1.6)]


def value_pill(right, cy, text, active):
    """A value the wheel changes. Press makes it active; turning then
    changes it, and press sets it."""
    if not active:
        return [T(right, cy + 6, text, F_SEC, C["text2"], 400, "end")]
    w = g.tw(text, F_SEC, True) + 44
    x = right - w + 6
    return ([R(x, cy - 13, w, 26, g.ACTIVE_FIELD, rx=13, stroke=C["accent"],
               sw=2)]
            + updown(x + 15, cy, C["accent"], 0.8)
            + [T(right - 8, cy + 6, text, F_SEC, C["text"], 700, "end")])


# ---------------------------------------------------------------- the editor
def edit_list(entries, y, focus=None, lifted=None, active=None):
    """The draft route, You first and the peer last, then the rows below.

    entries: ("you",), ("hop", name), ("add",), ("flood", value),
    ("peer",), ("row", label, value, kind). kind is "go", "read",
    "accent", "ping" or "value". focus, lifted and active index entries.
    """
    hl, rail, o = [], [], []
    centers = []
    flood_on = False
    for i, e in enumerate(entries):
        cy = y + RH / 2
        kind = e[0]
        foc = i == focus
        wt = 700 if foc else 400
        if i == lifted:
            hl += focus_box(y, lifted=True)
        elif foc:
            hl += focus_box(y)
        if kind in ("you", "hop", "add", "flood", "peer"):
            centers.append((cy, kind))
        if kind == "you":
            rail += g.device_glyph(RAIL_X, cy, 12, C["text2"])
            o.append(T(50, cy + 7, "You", F_BODY, C["text2"]))
        elif kind == "peer":
            rail += rp.node_avatar(RAIL_X, cy, 13, PEER)
            o.append(T(50, cy + 7, PEER, F_BODY, C["text2"]))
        elif kind == "hop":
            av = rp.node_avatar(RAIL_X, cy, 13, e[1])
            if i == lifted:
                hl += av  # drawn with the lifted row, over the rail
            else:
                rail += av
            o.append(T(50, cy + 7, e[1], F_BODY, C["text"],
                       700 if foc or i == lifted else 400))
            if i == lifted:
                o += updown(W - 22, cy, C["accent"])
            else:
                o += grip(W - 22, cy, C["text3"] if foc else C["line"])
        elif kind == "add":
            rail += [CIRC(RAIL_X, cy, 12, C["bg"])] + g.glyph_plus(
                RAIL_X, cy, C["accent"], r=11)
            o.append(T(50, cy + 7, "Add hop", F_BODY, C["accent"],
                       700 if foc else 600))
        elif kind == "flood":
            value = e[1]
            hops = any(x[0] == "hop" for x in entries)
            flood_on = value != "Off"
            rail += flood_dots(RAIL_X, cy, off=not flood_on)
            o.append(T(50, cy + 7, "Then flood" if hops else "Flood",
                       F_BODY, C["text"], wt))
            o += value_pill(W - 14, cy, value, i == active)
        elif kind == "row":
            _, label, val, rk = e
            col = C["accent"] if rk == "accent" else C["text"]
            o.append(T(12, cy + 7, label, F_BODY, col,
                       700 if foc or rk == "accent" else 400))
            right = W - 14
            if rk == "go":
                o.append(g.chevron(right - 2, cy))
                right -= 16
            if rk == "ping" and val:
                o.append(T(right, cy + 6, val, F_SEC, C["green"], 600,
                           "end"))
                o += g.check_mark(right - g.tw(val, F_SEC, True) - 14, cy,
                                  C["green"], 0.85)
            elif rk == "value":
                o += value_pill(right, cy, val, i == active)
            elif val:
                o.append(T(right, cy + 6, val, F_SEC, C["text2"], 400,
                           "end"))
            if not foc:
                o.append(LINE(12, y + RH - 0.5, W, y + RH - 0.5))
        y += RH
    # The rail joins the path's rows; the span from the flood row to the
    # peer is dashed while the route may flood there.
    seg = []
    for (a, ka), (b, kb) in zip(centers, centers[1:]):
        dashed = ka == "flood" and flood_on
        extra = ' stroke-dasharray="2 5"' if dashed else ""
        seg.append(P(f"M{RAIL_X} {a + 14:.1f} V{b - 14:.1f}", rp.RAIL,
                     sw=2.4, extra=extra))
    return hl + seg + rail + o, y


def editor(entries, scroll=0, focus=None, lifted=None, active=None,
           sub=PEER, title="Edit route"):
    o = [R(0, 0, W, H, C["bg"])]
    body, _ = edit_list(entries, TOP + 4 - scroll, focus, lifted, active)
    o += g.clip(body, 0, TOP, W, H - TOP)
    o += g.screen_header(title, sub=sub)
    o += g.status()
    return o


DRAFT = [("you",), ("hop", "Spencer Butte"), ("hop", "Skinner Ridge"),
         ("hop", "7N*"), ("add",), ("flood", "1 hop"), ("peer",),
         ("row", "Ping along route", None, "go"),
         ("row", "Hold for", "1 hour", "value"),
         ("row", "Save", None, "accent")]


def screen_editor():
    return editor(DRAFT, focus=1)


def screen_hop_menu():
    o = editor(DRAFT, focus=3)[:-len(g.status())]
    labels = ["Move", "Remove"]
    mw = 200
    mh = len(labels) * 32 + 10
    mx, my = W - 8 - mw, TOP + 4 + 3 * RH - mh + 2  # above the row
    o += g.menu_card(mx, my, mw, mh)
    o += g.menu_items(mx, my + 5, mw, labels, 0, danger=("Remove",))
    o += g.status()
    return o


def screen_moving():
    moved = [("you",), ("hop", "Spencer Butte"), ("hop", "7N*"),
             ("hop", "Skinner Ridge"), ("add",), ("flood", "1 hop"),
             ("peer",)] + DRAFT[7:]
    return editor(moved, lifted=2)


def screen_flood_active():
    return editor(DRAFT, scroll=4 * RH - 8, focus=5, active=5)


def screen_editor_end():
    rows = DRAFT[:7] + [("row", "Ping along route", "3.8 s", "ping"),
                        ("row", "Hold for", "1 hour", "value"),
                        ("row", "Save", None, "accent")]
    return editor(rows, scroll=6 * RH - 8, focus=9)


def screen_direct():
    rows = [("you",), ("add",), ("flood", "Off"), ("peer",),
            ("row", "Ping along route", None, "go"),
            ("row", "Hold for", "1 hour", "value"),
            ("row", "Save", None, "accent")]
    return editor(rows, focus=1)


def screen_leave():
    o = editor(DRAFT, focus=1)[:-len(g.status())]
    o += g.choice_card(["Save", "Discard changes", "Keep editing"], 300,
                       focus=0, danger=("Discard changes",))
    o += g.status()
    return o


# ---------------------------------------------------------------- Route
SOURCE = ["You", None, "Spencer Butte", None, "Skinner Ridge", None, "7N*",
          None, PEER]


def screen_route_learned():
    return rp.route_screen("3 hops", SOURCE,
                           [("Confirmed", "4 min ago", "read"),
                            ("Edit route", None, "go"),
                            ("Reset route", None, "red")],
                           row_focus=1, scroll=142)


def screen_route_held():
    return rp.route_screen("Manual · 3 hops", SOURCE,
                           [("Then flood", "1 hop", "read"),
                            ("Held", "52 min left", "read"),
                            ("Confirmed", "2 min ago", "read"),
                            ("Edit route", None, "go"),
                            ("Clear manual route", None, "red")],
                           row_focus=3, scroll=190)


def screen_peer_held():
    o = [R(0, 0, W, H, C["bg"])]
    body = []
    y = STRIP
    for label, val, kind, focused in [
        ("Alias", "Pat Okafor", "read", False),
        ("Route", "Manual · 3 hops", "go", True),
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


# ---------------------------------------------------------------- Add hop
def node_row(y, name, right=None, bars=None, dim=False, focused=False,
             sub=None, tint=False, finish=False):
    o = []
    cy = y + RH / 2
    if tint:
        o.append(R(0, y, W, RH, C["focus"]))
    elif focused:
        o += focus_box(y)
    av = rp.node_avatar(RAIL_X, cy, 13, name)
    o += (['<g opacity="0.4">'] + av + ["</g>"]) if dim else av
    col = C["text3"] if dim else C["text"]
    o.append(T(50, cy + 7, name, F_BODY, col, 700 if focused else 400,
               mono=name.endswith("*")))
    x = 50 + g.tw(name, F_BODY, focused, mono=name.endswith("*")) + 10
    if bars:
        b = g.signal_bars(x, cy + 7, bars, rp.bars_color(bars))
        o += (['<g opacity="0.4">'] + b + ["</g>"]) if dim else b
        x += 24
    if sub:
        o.append(T(x, cy + 6, sub, F_SEC, C["text3"]))
    if finish:
        o.append(T(W - 14, cy + 6, "Finish here", F_SEC, C["accent"], 700,
                   "end"))
    elif right:
        o.append(T(W - 14, cy + 6, right, F_SMALL, C["text3"], 600, "end"))
    if not focused and not tint:
        o.append(LINE(50, y + RH - 0.5, W, y + RH - 0.5))
    return o


def text_row(y, label, right=None, focused=False, col=None, busy=False):
    o = focus_box(y) if focused else []
    o.append(T(50, y + RH / 2 + 7, label, F_BODY, col or C["accent"],
               700 if focused else 600))
    if busy:
        o += rp.spinner(W - 24, y + RH / 2, 3, r=8)
    elif right:
        o.append(T(W - 14, y + RH / 2 + 6, right, F_SMALL, C["text3"], 600,
                   "end"))
    if not focused:
        o.append(LINE(50, y + RH - 0.5, W, y + RH - 0.5))
    return o


def label_row(y, left, right=None):
    o = [g.section_label(12, y + 19, left)]
    if right:
        o.append(T(W - 14, y + 19, right, F_SMALL, C["text3"], 500, "end"))
    return o


NR = 44  # a neighbor's row: name, then how the reporting router heard it


def nb_row(y, name, reading=None, age=None, dist=None, bridged=False,
           stale=False, focused=False, trailing=None):
    """One repeater a router reported hearing, in the form every neighbor
    list uses, on Neighbors and in Add hop alike.

    reading is (rssi, snr_tenths) as the router heard it. trailing: "open"
    (a known node), "lookup" or "asking" (a bare hint), "finish" or
    "inpath" (Add hop). A row the router has not heard for hours, or one
    already on the route, is faded.
    """
    o = []
    cy = y + NR / 2
    if focused:
        o += focus_box(y, rh=NR)
    dim = stale or trailing == "inpath"
    fade = (lambda part: ['<g opacity="0.4">'] + part + ["</g>"]) if dim \
        else (lambda part: part)
    o += fade(rp.node_avatar(RAIL_X, cy, 14, name))
    hint = name.endswith("*")
    o.append(T(50, y + 20, name, F_BODY, C["text3"] if dim else C["text"],
               700 if focused else 400, mono=hint))
    line2 = []
    x = 50
    if bridged:
        line2 += rp.link_glyph(x, y + 33, C["text3"])
        x += 22
        parts = ["Bridged"]
    else:
        rssi, snr = reading
        n = rp.bars_for(snr)
        line2 += g.signal_bars(x, y + 39, n, rp.bars_color(n))
        x += 24
        parts = [f"{rp.dbm(rssi)} · SNR {rp.db(snr)}"]
    parts += [p for p in (age, dist) if p]
    line2.append(T(x, y + 38, " · ".join(parts), F_SMALL, C["text3"], 500))
    o += fade(line2)
    right = W - 16
    if trailing == "open":
        o.append(g.chevron(right, cy))
    elif trailing == "lookup":
        o += rp.magnifier(right - 4, cy, C["accent"])
    elif trailing == "asking":
        o += rp.spinner(right - 6, cy, 2, r=8)
    elif trailing == "finish":
        o.append(T(W - 14, y + 20, "Finish here", F_SEC, C["accent"], 700,
                   "end"))
    elif trailing == "inpath":
        o.append(T(W - 14, y + 20, "In path", F_SEC, C["text3"], 600, "end"))
    if not focused:
        o.append(LINE(50, y + NR - 0.5, W, y + NR - 0.5))
    return o


def note_row(y, title, line, col):
    """A reading that did not land, in the list where it would have."""
    if not line:
        return [T(50, y + NR / 2 + 7, title, F_BODY, col),
                LINE(50, y + NR - 0.5, W, y + NR - 0.5)]
    return [T(50, y + 20, title, F_BODY, col, 700),
            T(50, y + 38, line, F_SMALL, C["text3"], 500),
            LINE(50, y + NR - 0.5, W, y + NR - 0.5)]


def add_hop(rows, scroll=0, field=None, found=None):
    o = [R(0, 0, W, H, C["bg"])]
    top = TOP
    if field is not None:
        fy = TOP + 3
        o += g.field_frame(8, fy, W - 16, 28, "active", rx=14)
        o += g.scaled([CIRC(22, fy + 13, 4, stroke=C["text2"], sw=1.3),
                       P(f"M25 {fy+16} L28 {fy+19}", C["text2"], sw=1.4)],
                      23, fy + 14, 1.4)
        o.append(T(40, fy + 21, field, F_BODY, C["text"], mono=True))
        o.append(g.caret(40 + g.tw(field, F_BODY, mono=True) + 1, fy + 4))
        if found:
            o.append(T(W - 22, fy + 20, found, F_SMALL, C["text3"], 500,
                       "end"))
        top = TOP + 34
    body = []
    y = top - scroll
    for kind, *args in rows:
        if kind == "label":
            body += label_row(y, *args)
            y += 26
        elif kind == "node":
            name, kw = args
            body += node_row(y, name, **kw)
            y += RH
        elif kind == "nb":
            name, kw = args
            body += nb_row(y, name, **kw)
            y += NR
        elif kind == "note":
            body += note_row(y, *args)
            y += NR
        else:
            label, kw = args
            body += text_row(y, label, **kw)
            y += RH
    o += g.clip(body, 0, top, W, H - top)
    o += g.screen_header("Add hop 4", sub="after 7N*")
    o += g.status()
    return o


NEIGHBORS = [
    ("label", "Heard by Skinner Ridge", "Read 12m ago"),
    ("nb", PEER, dict(reading=(-101, 15), age="6m", trailing="finish",
                      focused=True)),
    ("nb", "Mt. Pisgah", dict(reading=(-88, 75), age="4m", dist="6.1 km")),
    ("nb", "8C*", dict(reading=(-95, 30), age="20m")),
    ("nb", "Spencer Butte", dict(reading=(-84, 85), age="1m",
                                 trailing="inpath")),
    ("nb", "Coburg Hills", dict(reading=(-104, -35), age="1d", stale=True)),
    ("text", "Load more", dict(right="5 of 9")),
    ("text", "Refresh", dict()),
    ("label", "Known repeaters", None),
    ("node", "Fox Hollow", dict(right="2h")),
    ("node", "Eugene Bridge", dict(right="1d")),
]


def screen_add_hop():
    # Hop 3 was Skinner Ridge before 7N* was added; draw hop 3's sheet.
    return add_hop_titled(NEIGHBORS, "Add hop 3", "after Skinner Ridge")


def add_hop_titled(rows, title, sub, **kw):
    o = add_hop(rows, **kw)[:-len(g.status())]
    o = [s for s in o if "Add hop 4" not in s and "after 7N*" not in s]
    o += g.screen_header(title, sub=sub)
    o += g.status()
    return o


def screen_add_hop_more():
    return add_hop_titled(NEIGHBORS, "Add hop 3", "after Skinner Ridge",
                          scroll=26 + 4 * NR - 14)


# ---------------------------------------------------------------- Neighbors
REPEATER = "Spencer Butte"


def screen_repeater_neighbors_row():
    """A repeater's page offers Neighbors because it advertises repeating."""
    o = [R(0, 0, W, H, C["bg"])]
    y = TOP
    body = g.detail_head(REPEATER, "peer", "Repeater · heard 2m", y)
    body.append(T(10, y + 77, g.address(REPEATER), F_SMALL, C["text2"],
                  mono=True))
    yy = y + 84
    for label, focused, chev in [("Save peer", False, False),
                                 ("Neighbors", True, True),
                                 ("Ping", False, True)]:
        body += g.setting_row(0, yy, label, None, focused, chev=chev, rh=RH)
        yy += RH
    o += g.clip(body, 0, TOP, W, H - TOP)
    o += g.screen_header(REPEATER)
    o += g.status()
    return o


def neighbors(rows, scroll=0):
    o = add_hop(rows, scroll=scroll)[:-len(g.status())]
    o = [s for s in o if "Add hop 4" not in s and "after 7N*" not in s]
    o += g.screen_header("Neighbors", sub=REPEATER)
    o += g.status()
    return o


HEARD = [
    ("nb", "Mt. Pisgah", dict(reading=(-88, 75), age="4m", dist="6.1 km",
                              trailing="open", focused=True)),
    ("nb", "Skinner Ridge", dict(reading=(-96, 35), age="9m",
                                 dist="11 km", trailing="open")),
    ("nb", "8C*", dict(reading=(-95, 30), age="20m", trailing="lookup")),
    ("nb", "Eugene Bridge", dict(bridged=True, age="2m", trailing="open")),
    ("nb", "Coburg Hills", dict(reading=(-104, -35), age="1d",
                                dist="24 km", stale=True, trailing="open")),
    ("text", "Load more", dict(right="5 of 9")),
    ("text", "Refresh", dict()),
]


def screen_neighbors():
    return neighbors([("label", "Read 12m ago", None)] + HEARD)


def screen_neighbors_end():
    rows = [("label", "Read 12m ago", None)] + HEARD
    rows[1] = ("nb", "Mt. Pisgah", dict(reading=(-88, 75), age="4m",
                                        dist="6.1 km", trailing="open"))
    rows[3] = ("nb", "8C*", dict(reading=(-95, 30), age="20m",
                                 trailing="asking", focused=True))
    return neighbors(rows, scroll=26 + NR + 10)


def screen_neighbors_unread():
    return neighbors([
                      ("note", "Not read", None, C["text3"]),
                      ("text", "Refresh", dict(focused=True))])


def screen_neighbors_asking():
    rows = [("label", "Read 12m ago", None)] + HEARD
    rows[1] = ("nb", "Mt. Pisgah", dict(reading=(-88, 75), age="4m",
                                        dist="6.1 km", trailing="open"))
    rows[-1] = ("text", "Refresh", dict(focused=True, busy=True))
    return neighbors(rows, scroll=26 + 5 * NR + 2 * RH - (H - TOP))


def screen_neighbors_no_answer():
    rows = [("label", "Read 12m ago", None)] + HEARD[:-1] + [
        ("note", "No answer", "Out of reach, or it keeps no neighbor list",
         C["amber"]),
        ("text", "Refresh", dict(focused=True))]
    rows[1] = ("nb", "Mt. Pisgah", dict(reading=(-88, 75), age="4m",
                                        dist="6.1 km", trailing="open"))
    return neighbors(rows, scroll=26 + 6 * NR + 2 * RH - (H - TOP))


def screen_add_hop_hintonly():
    rows = [("label", "Known repeaters", None),
            ("node", "Mt. Pisgah", dict(right="4m", focused=True)),
            ("node", "Fox Hollow", dict(right="2h")),
            ("node", "Eugene Bridge", dict(right="1d")),
            ("node", "Mary's Peak", dict(right="3d")),
            ("node", "Coburg Hills", dict(right="5d"))]
    return add_hop(rows)


def screen_hint_typed():
    rows = [("label", "Router hint", None),
            ("node", "7N*", dict(sub="5EBD · Unknown node", tint=True))]
    return add_hop_titled(rows, "Add hop 3", "after Skinner Ridge",
                          field="7Nq4", found="1 found")


def screen_hint_both():
    rows = [("label", "Router hints", None),
            ("node", "3D*", dict(sub="Prefix · 20D3", tint=True)),
            ("node", "59*", dict(sub="Hex · 3D9F"))]
    return add_hop_titled(rows, "Add hop 3", "after Skinner Ridge",
                          field="3D9F", found="2 found")


# ---------------------------------------------------------------- while held
def screen_switch_prompt():
    o = [R(0, 0, W, H, C["bg"])]
    items = [
        {"k": "out", "who": "me", "text": "Leaving the trailhead now"},
        {"k": "status", "text": "Delivered · flooded"},
        {"k": "out", "who": "me", "text": "Pass is clear"},
        {"k": "status", "text": "Delivered · flooded"},
    ]
    tr, _ = g.transcript(items, TOP, g.COMP_Y)
    o += tr
    o += g.screen_header(PEER, "peer", "Manual · 3 hops")
    o += g.composer(placeholder="Message", mode="away")
    mw, ih = 420, 34
    mh = 64 + 2 * ih + 8
    mx = (W - mw) / 2
    my = STRIP + (H - STRIP - mh) / 2
    o += g.menu_card(mx, my, mw, mh)
    o.append(T(mx + 16, my + 27, "Switch to the learned route?", F_BODY,
               C["text"], 700))
    o.append(T(mx + 16, my + 51, "Learned: 2 hops, via Mt. Pisgah",
               F_SMALL, C["text2"], 500))
    o += g.menu_items(mx, my + 62, mw, ["Use learned route",
                                        "Keep manual route"], 0, ih)
    o += g.status()
    return o


BOARDS = [
    ("Route", "The Route screen gains Edit route. While a manual route is "
     "held, the route names it, and Clear manual route takes Reset route's "
     "place.", [
        ("1 · Route, learned", screen_route_learned(),
         "Edit route sits between Confirmed and Reset route. It opens the "
         "editor seeded with the route shown; with nothing learned, the "
         "editor starts with only You and the peer."),
        ("2 · Route, manual route held", screen_route_held(),
         "The header reads Manual. Then flood and Held join Confirmed. Held "
         "counts down instead of naming a time, so it needs no clock. Clear "
         "manual route returns to the learned route, or to flooding, without "
         "asking."),
        ("3 · Peer, manual route held", screen_peer_held(),
         "The peer's Route row and the conversation header say Manual too, "
         "so a held route is never a surprise."),
    ]),
    ("Editor", "One screen, the iOS editor's rows in one list. Turn walks "
     "the hops, then the rows below. You and the peer are fixed, so they "
     "are not stops.", [
        ("4 · Edit route", screen_editor(),
         "Seeded from the learned route. Each hop is a stop. The grip says "
         "it moves. Add hop sits after the last repeater and goes away at "
         "15."),
        ("5 · A hop's menu", screen_hop_menu(),
         "Press on a hop: Move or Remove. No confirmation; nothing is "
         "saved until Save."),
        ("6 · Moving a hop", screen_moving(),
         "Move lifts the hop. Turning carries it through the others; press "
         "puts it down, Backspace puts it back where it was."),
        ("7 · Then flood, changing", screen_flood_active(),
         "Press makes the value active; turning steps Off, 1 hop … 15 "
         "hops; press sets it. The rail past it is dashed while it is on. "
         "Hold for works the same: 30 min, 1 hour, 4 hours, 12 hours, 1 day."),
        ("8 · Ping along route, then Save", screen_editor_end(),
         "Ping along route opens the Ping screen for the unsaved draft and "
         "comes back with its result in the row. Save holds the route from "
         "now; Backspace returns to Route."),
        ("9 · A direct route", screen_direct(),
         "Every hop removed. The flood row reads Flood, counted from this "
         "device, and the route saves as direct."),
        ("10 · Leaving with changes", screen_leave(),
         "Backspace with unsaved changes asks. Without changes it just "
         "leaves."),
    ]),
    ("Add hop", "Add hop opens a list of candidates for the next hop. "
     "Choosing one appends it and moves on to the hop after it; Backspace "
     "returns to the editor with every hop added so far.", [
        ("11 · Add hop, neighbors", screen_add_hop(),
         "What the previous hop last reported hearing, in the Neighbors row "
         "form (17), asked along the route so far; for hop 1, this device's "
         "own list. Opening sends nothing. When the peer is among them, it "
         "pins to the top with Finish here, which ends the route."),
        ("12 · Add hop, further down", screen_add_hop_more(),
         "Load more and Refresh each send one request. Nodes already on the "
         "route are dimmed and say In path. Known repeaters follow, most "
         "recently heard first."),
        ("13 · Add hop after a bare hint", screen_add_hop_hintonly(),
         "A hop known only by its hint has no address to ask, so only Known "
         "repeaters are listed."),
        ("14 · Typing a router hint", screen_hint_typed(),
         "Typing filters, as on every list. Four or more Base58 characters "
         "also offer the router hint they fix, with its hex. Enter adds the "
         "tinted top result."),
        ("15 · A hint read two ways", screen_hint_both(),
         "“3D9F” is a Base58 prefix and also four hex digits, so both are "
         "offered, each labeled. A prefix that straddles two hints is "
         "offered twice the same way."),
    ]),
    ("While held", "A held route is used for every send to the peer. A "
     "missed ack still falls back to one flood, and the route stays.", [
        ("16 · Switch to the learned route?", screen_switch_prompt(),
         "After two sends in a row miss on the manual route while their "
         "floods are acknowledged (one, if this device moved far). Once per "
         "saved route. Keep manual route stops asking until it is edited."),
    ]),
    ("Neighbors", "The repeaters one router reports hearing, a page at a "
     "time. Opening shows the last listing and sends nothing; every page is "
     "one exchange across the mesh.", [
        ("17 · A repeater, Neighbors focused", screen_repeater_neighbors_row(),
         "Offered on any node that advertises repeating, whatever its role, "
         "and from a saved peer's page the same way."),
        ("18 · Neighbors", screen_neighbors(),
         "Name, then how the router heard each one: bars, RSSI and SNR, how "
         "long ago, and how far from the router when both placed "
         "themselves. A known node opens its page, which has Neighbors "
         "too."),
        ("19 · Asking who a hint is", screen_neighbors_end(),
         "A bare hint shows the search glyph. Press asks it who it is, "
         "steered down the route to the router; the answer names it in "
         "place. Bridged: heard over a link, not the air. Rows unheard for "
         "6 hours fade."),
        ("20 · Refreshing", screen_neighbors_asking(),
         "Load more asks for the page after the last one held; Refresh asks "
         "for the top again. Either spins in its own row, and the rows stay "
         "until the answer replaces them."),
        ("21 · No answer", screen_neighbors_no_answer(),
         "The listing held stays. The line says why, and Refresh is focused, "
         "so a press asks again."),
        ("22 · Never read", screen_neighbors_unread(),
         "Not read until Refresh. A router asked that lists nobody says "
         "None instead."),
    ]),
]


def main(path_out):
    margin, gap, cols = 80, 64, 3
    cw = cols * g.BOARD_W + (cols - 1) * gap
    cwidth = cw + 2 * margin
    o = [T(margin, 130, "Manual route and Neighbors · communicator", 56, g.INK, 700),
         T(margin, 178, "T-LoRa Pager, 480×222, drawn at 2×. Turn moves, "
           "press selects, Backspace goes back. Modeled on the iOS manual "
           "path.", 22, g.INK2)]
    y = 270
    for title, intro, boards in BOARDS:
        o.append(T(margin, y, title, 34, g.INK, 700))
        for k, line in enumerate(g.wrap(intro, 19, cw)):
            o.append(T(margin, y + 38 + 26 * k, line, 19, g.INK2))
        y += 110 + 26 * (len(g.wrap(intro, 19, cw)) - 1)
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
            f'aria-labelledby="t" font-family="{g.SANS}"><title id="t">Manual '
            f'route on the communicator, mockups</title><defs>'
            f'<filter id="shadow" x="-5%" y="-5%" width="110%" height="110%">'
            f'<feDropShadow dx="0" dy="3" stdDeviation="8" '
            f'flood-opacity="0.22"/></filter></defs>'
            f'<rect width="{cwidth}" height="{height}" fill="{g.CANVAS_BG}"/>')
    with open(path_out, "w") as f:
        f.write(head + "\n" + "\n".join(o) + "\n</svg>\n")


if __name__ == "__main__":
    main(sys.argv[1])
