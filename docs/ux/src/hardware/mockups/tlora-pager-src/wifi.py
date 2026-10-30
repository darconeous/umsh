#!/usr/bin/env python3
"""Generate the communicator Device › Wi-Fi mockups as one SVG.

Drawn with generate.py's palette, type scale, rows and switches, so these
boards match the messenger canvas. From this directory:

    python3 wifi.py ../communicator-wifi.svg
"""
import sys

import generate as g
from generate import C, CIRC, H, LINE, P, R, STRIP, T, TOP, W
from generate import F_BODY, F_SEC, F_SMALL
from route_ping import spinner

RH = 36  # a settings row
CH = 52  # the network the device is on, or is joining
LBL = 28  # a section label's band
DIM = "#3A414B"

# The strip's fan, from umsh-ux-communicator's build.rs, in icon units.
FAN_DOT = "M-1.1 3.7 A1.1 1.1 0 1 0 1.1 3.7 A1.1 1.1 0 1 0 -1.1 3.7 Z"
FAN_ARCS = ["M-1.98 1.72 A2.8 2.8 0 0 1 1.98 1.72",
            "M-3.96 -0.26 A5.6 5.6 0 0 1 3.96 -0.26",
            "M-5.94 -2.24 A8.4 8.4 0 0 1 5.94 -2.24"]
FAN_CROSS = "M-1.5 2.2 L1.5 5.2 M1.5 2.2 L-1.5 5.2"


# ---------------------------------------------------------------- glyphs
def fan(cx, cy, level, col, k=1.3, lost=False):
    """Signal as the strip draws it: lit arcs for level 1-3, the rest dim.
    lost: the strip's crossed fan, a network selected and not joined."""
    o = [f'<g transform="translate({cx:.1f},{cy:.1f}) scale({k})" '
         f'stroke-linecap="round">']
    sw = 1.1 if k <= 1.4 else 0.95
    if lost:
        for d in FAN_ARCS[1:]:
            o.append(P(d, col, sw=sw))
        o.append(P(FAN_CROSS, col, sw=sw))
    else:
        o.append(P(FAN_DOT, fill=col if level else DIM))
        for i, d in enumerate(FAN_ARCS):
            o.append(P(d, col if i < level else DIM, sw=sw))
    o.append("</g>")
    return o


def small_lock(cx, cy, col):
    return g.scaled(g.padlock(cx, cy, col), cx, cy, 0.85)


def strip(wifi=None):
    """The status strip, with the fan left of Bluetooth as status.rs puts
    it: 'up', 'joining' or 'lost', and nothing while the station names no
    network (searching, paused, or off)."""
    o = g.status()
    if wifi:
        o += fan(386, 12, 3 if wifi == "up" else 2, C["text"],
                 lost=wifi == "lost")
    return o


# ---------------------------------------------------------------- rows
def network_row(y, ssid, level, secured=True, focused=False, heard=True,
                chev=False):
    """A network in a list: name, then a padlock if it takes a password,
    then its signal. A saved network not heard has no signal and is dim."""
    o = g.setting_row(0, y, ssid, None, focused, chev=chev, rh=RH,
                      muted=not heard)
    right = W - 14 - (16 if chev else 0)
    cy = y + RH / 2
    if heard:
        o += fan(right - 9, cy, level, C["text2"], k=1.35)
    if secured:
        o += small_lock(right - (34 if heard else 6), cy + 1, C["text3"])
    return o


CURRENT = {
    # state: (fan level, lost, fan color, line, line color)
    "joining": (2, False, C["text2"], "Joining", C["text2"]),
    "address": (3, False, C["text"], "Getting address", C["text2"]),
    "up": (3, False, C["text"], "Connected", C["green"]),
    "auth": (0, True, C["amber"], "Wrong password", C["amber"]),
    "not_found": (0, True, C["amber"], "Not in range", C["amber"]),
}


def current_row(y, ssid, state, focused=False):
    """The selected network, under the switch: the strip's fan, its name,
    and what the link is doing."""
    level, lost, col, line, line_col = CURRENT[state]
    o = []
    if focused:
        o.append(R(4, y + 1, W - 8, CH - 2, C["focus"], rx=8,
                   stroke=C["accent"], sw=1.6))
    o += fan(27, y + CH / 2 + 1, level, col, k=1.9, lost=lost)
    o.append(T(52, y + 23, ssid, F_BODY, C["text"], 700))
    if state == "joining":
        o += spinner(60, y + 37.5, 3, r=5)
        o.append(T(72, y + 43, line, F_SMALL, line_col, 500))
    else:
        o.append(T(52, y + 43, line, F_SMALL, line_col, 500))
    o.append(g.chevron(W - 16, y + CH / 2))
    if not focused:
        o.append(LINE(12, y + CH - 0.5, W, y + CH - 0.5))
    return o


SH = 40  # the station's state while it is on no network


def state_row(y, state):
    """What the station is doing while it names no network: 'searching'
    for a saved network to join, or 'paused' after Disconnect. Not a stop
    for the wheel."""
    if state == "searching":
        o = spinner(27, y + SH / 2, 2, r=8)
        line = "Searching"
    else:
        o = fan(27, y + SH / 2 + 1, 0, C["text3"], k=1.9)
        line = "Disconnected"
    o.append(T(52, y + SH / 2 + 7, line, F_BODY, C["text2"]))
    o.append(LINE(12, y + SH - 0.5, W, y + SH - 0.5))
    return o


def label_band(y, s, scanning=False):
    o = [g.section_label(12, y + 21, s)]
    if scanning:
        o += spinner(12 + g.tw(s, F_SMALL, True) + 14, y + 15, 2, r=6)
    return o


def readout(y, label, value, glyph=None):
    """A row that only reports: not a stop for the wheel."""
    o = g.setting_row(0, y, label, value, rh=RH)
    if glyph:
        o += glyph(W - 14 - g.tw(value, F_SEC) - 16, y + RH / 2)
    return o


# ---------------------------------------------------------------- screens
def page(title, body, wifi=None, sub=None, sub_col=None, scroll=0):
    o = [R(0, 0, W, H, C["bg"])]
    o += g.clip(body, 0, TOP, W, H - TOP)
    o += g.screen_header(title, sub=None if sub_col else sub)
    if sub_col:
        sx = 22 + g.tw(title, F_BODY, True) + 10
        o.append(T(sx, STRIP + 21, sub, F_SMALL, sub_col, 500))
    o += strip(wifi)
    return o


def rows(y, items):
    """items: (label, value, kind, focused); kind 'go', 'act', 'red' or
    'read'."""
    o = []
    for label, val, kind, focused in items:
        o += g.setting_row(0, y, label, val, focused, chev=kind == "go",
                           rh=RH, danger=kind == "red")
        y += RH
    return o, y


NEARBY = [("Trailhead Café", 3, False), ("Okafor-5G", 3, True),
          ("NETGEAR47", 2, True), ("Basin Library", 1, False),
          ("Pat's iPhone", 1, True)]


def screen_device():
    o = [R(0, 0, W, H, C["bg"])]
    body = []
    y = STRIP
    for label, val in [("Clock", "GNSS"), ("Sounds", ""),
                       ("Bluetooth", "Connected"), ("Wi-Fi", "Okafor-5G"),
                       ("GNSS", ""), ("Battery", "82%")]:
        body += g.setting_row(g.RAIL_W, y, label, val,
                              focused=label == "Wi-Fi", chev=True)
        y += RH
    o += g.clip(body, g.RAIL_W, STRIP, W - g.RAIL_W, H - STRIP)
    o += g.rail("Device", unread=1)
    o += strip("up")
    return o


def screen_off():
    body, _ = rows(TOP, [("Wi-Fi", False, "act", True)])
    return page("Wi-Fi", body)


def screen_first_scan():
    y = TOP - 14
    body, y = rows(y, [("Wi-Fi", True, "act", False)])
    body += label_band(y, "Nearby", scanning=True)
    y += LBL
    for name, level, secured in NEARBY[:4]:
        body += network_row(y, name, level, secured,
                            focused=name == "Okafor-5G")
        y += RH
    return page("Wi-Fi", body)


def screen_list_end():
    y = TOP - 4
    body = []
    for name, level, secured in NEARBY[2:]:
        body += network_row(y, name, level, secured)
        y += RH
    more, _ = rows(y, [("Other network", None, "go", False),
                       ("Scan again", None, "act", True)])
    return page("Wi-Fi", body + more)


def password_screen(title, text, action, enabled=True, sub=None,
                    sub_col=None, wifi=None):
    y = TOP + 8
    body = [g.section_label(12, y + 14, "Password")]
    y += 22
    body += g.field_frame(8, y, W - 16, 34, "active", rx=12)
    body.append(T(20, y + 24, text, F_BODY, C["text"]))
    body.append(g.caret(20 + g.tw(text, F_BODY) + 1, y + 7))
    y += 42
    body += g.setting_row(0, y, action, None, rh=RH, muted=not enabled)
    return page(title, body, wifi=wifi, sub=sub, sub_col=sub_col)


def screen_password():
    return password_screen("Okafor-5G", "trailmix29", "Join")


def screen_joining():
    y = TOP
    body, y = rows(y, [("Wi-Fi", True, "act", False)])
    body += current_row(y, "Okafor-5G", "joining", focused=True)
    y += CH
    body += label_band(y, "Nearby")
    y += LBL
    for name, level, secured in [NEARBY[0], NEARBY[2]]:
        body += network_row(y, name, level, secured)
        y += RH
    return page("Wi-Fi", body, wifi="joining")


def screen_connected():
    y = TOP
    body, y = rows(y, [("Wi-Fi", True, "act", False)])
    body += current_row(y, "Okafor-5G", "up", focused=True)
    y += CH
    body += label_band(y, "Saved")
    y += LBL
    body += network_row(y, "Home", 2, chev=True)
    y += RH
    body += network_row(y, "Basecamp", 0, heard=False, chev=True)
    return page("Wi-Fi", body, wifi="up")


def screen_wrong_password():
    y = TOP
    body, y = rows(y, [("Wi-Fi", True, "act", False)])
    body += current_row(y, "Okafor-5G", "auth", focused=True)
    y += CH
    body += label_band(y, "Saved")
    y += LBL
    body += network_row(y, "Home", 2, chev=True)
    return page("Wi-Fi", body, wifi="lost")


def screen_searching():
    """Saved networks, none in range: the device looks for one by itself."""
    y = TOP
    body, y = rows(y, [("Wi-Fi", True, "act", False)])
    body += state_row(y, "searching")
    y += SH
    body += label_band(y, "Saved")
    y += LBL
    body += network_row(y, "Okafor-5G", 0, heard=False, chev=True,
                        focused=True)
    y += RH
    body += network_row(y, "Home", 0, heard=False, chev=True)
    return page("Wi-Fi", body)


def screen_paused():
    """After Disconnect: on, joining nothing until a network is picked."""
    y = TOP
    body, y = rows(y, [("Wi-Fi", True, "act", False)])
    body += state_row(y, "paused")
    y += SH
    body += label_band(y, "Saved")
    y += LBL
    body += network_row(y, "Okafor-5G", 3, chev=True, focused=True)
    y += RH
    body += network_row(y, "Home", 2, chev=True)
    return page("Wi-Fi", body)


AUTO = ("Join automatically", True, "act", False)


def screen_sheet_up():
    y = TOP
    body, y = rows(y, [("Disconnect", None, "act", True), AUTO,
                       ("Change password", None, "go", False)])
    body += readout(y, "Signal", "−58 dBm",
                    lambda x, cy: fan(x, cy, 3, C["text2"], k=1.35))
    y += RH
    body += readout(y, "Address", "192.168.1.42")
    return page("Okafor-5G", body, wifi="up", sub="Connected",
                sub_col=C["green"])


def screen_sheet_end():
    y = TOP - (8 * RH - (H - TOP))  # Forget's bottom at the screen's
    body, y = rows(y, [("Disconnect", None, "act", False), AUTO,
                       ("Change password", None, "go", False)])
    for label, val in [("Signal", "−58 dBm"), ("Address", "192.168.1.42"),
                       ("Channel", "36 · 5 GHz"), ("Security", "WPA2")]:
        body += readout(y, label, val, (lambda x, cy: fan(
            x, cy, 3, C["text2"], k=1.35)) if label == "Signal" else None)
        y += RH
    more, _ = rows(y, [("Forget", None, "red", True)])
    return page("Okafor-5G", body + more, wifi="up", sub="Connected",
                sub_col=C["green"])


def screen_sheet_wrong():
    body, _ = rows(TOP, [("Change password", None, "go", True),
                         ("Disconnect", None, "act", False), AUTO,
                         ("Security", "WPA2", "read", False),
                         ("Forget", None, "red", False)])
    return page("Okafor-5G", body, wifi="lost", sub="Wrong password",
                sub_col=C["amber"])


def screen_change_password():
    return password_screen("Okafor-5G", "trailmix2", "Save",
                           sub="Wrong password", sub_col=C["amber"],
                           wifi="lost")


def screen_saved_sheet():
    body, _ = rows(TOP, [("Join", None, "act", True),
                         ("Join automatically", False, "act", False),
                         ("Change password", None, "go", False),
                         ("Security", "WPA2", "read", False),
                         ("Forget", None, "red", False)])
    return page("Home", body, wifi="up")


def screen_forget():
    o = screen_sheet_end()
    o.append(R(0, STRIP, W, H - STRIP, "#000", extra=' opacity="0.45"'))
    o += g.choice_card(["Forget", "Cancel"], 220, focus=1, danger=("Forget",))
    return o


def screen_other():
    y = TOP + 8
    body = g.field_frame(8, y, W - 16, 34, "active", rx=12)
    body.append(T(20, y + 24, "Basecamp", F_BODY, C["text"]))
    body.append(g.caret(20 + g.tw("Basecamp", F_BODY) + 1, y + 7))
    y += 40
    body += g.setting_row(0, y, "Security", "WPA2", chev=True, rh=RH)
    y += RH + 4
    body += g.field_frame(8, y, W - 16, 34, "away", rx=12)
    body.append(T(20, y + 24, "Password", F_BODY, C["text3"]))
    y += 40
    body += g.setting_row(0, y, "Join", None, rh=RH, muted=True)
    return page("Other network", body)


BOARDS = [
    ("Joining a network", "Device › Wi-Fi turns the station on and off and "
     "joins networks on the device itself, keyboard and all. Saved networks "
     "join by themselves, as on a phone. A phone can do the same over ULCP "
     "and is never needed.", [
        ("1 · Device, Wi-Fi focused", screen_device(),
         "Wi-Fi sits after Bluetooth, on boards with a station. Its value is "
         "the network it is on, and nothing otherwise."),
        ("2 · Off", screen_off(),
         "Only the switch. Off powers the station down and forgets nothing. "
         "Turned on, it joins a saved network in range by itself."),
        ("3 · On, nothing saved", screen_first_scan(),
         "Opening the screen while on scans once. Networks appear as they "
         "are heard, one row per name, strongest first; the dots beside "
         "Nearby spin until the scan ends. A padlock means it takes a "
         "password."),
        ("4 · Nearby, end of the list", screen_list_end(),
         "Other network joins one that hides its name. Scan again is "
         "last. Networks this device cannot join (enterprise, WEP) are left "
         "out."),
        ("5 · Password", screen_password(),
         "Pressing a network with a padlock asks for its password, the field "
         "already active. It shows as typed. Enter joins; Join stays dim "
         "until the length is one the network's mode allows. An open network "
         "joins on the press, with no screen."),
        ("6 · Joining", screen_joining(),
         "Join saves the network, set to join automatically, joins it, and "
         "comes back here with focus on it. The strip's fan shows while the "
         "station names a network: on it, joining it, or failing."),
        ("7 · Connected", screen_connected(),
         "The network in use is its own row under the switch. Saved lists "
         "the others, heard or not; a press opens one. Nearby follows, "
         "without what is already saved."),
        ("8 · Searching", screen_searching(),
         "No saved network in range, so the device looks for one, backing "
         "off between scans. Searching takes the network row's place and "
         "is not a stop. No fan in the strip: there is no network to show."),
    ]),
    ("A network", "Pressing the network in use, or a saved one, opens its "
     "sheet. Backspace returns to the list.", [
        ("9 · The network in use", screen_sheet_up(),
         "What the link is doing beside the name. Join automatically is on "
         "for every network saved here; off, the device joins it only when "
         "told to."),
        ("10 · Disconnected", screen_paused(),
         "Disconnect leaves and joins nothing by itself, the network kept. "
         "Pressing a saved network and Join ends that, as does turning "
         "Wi-Fi off and on, or restarting."),
        ("11 · Turned to the end", screen_sheet_end(),
         "Readouts are not stops for the wheel. Address is the IPv4 address "
         "in use. Forget is last."),
        ("12 · Forget", screen_forget(),
         "Confirmed, Cancel focused. Forgetting the network in use sends the "
         "device looking for another saved one."),
        ("13 · Wrong password", screen_wrong_password(),
         "The row says why the network is not joined yet: Wrong password, "
         "Not in range, Refused. Getting address is between joined and an "
         "address. A network picked by hand keeps being tried; one the "
         "device chose gives way to the next saved network in range."),
        ("14 · Its sheet", screen_sheet_wrong(),
         "Change password comes first when the password is what failed."),
        ("15 · Change password", screen_change_password(),
         "The old password is never shown; this replaces it. Save retries "
         "at once."),
        ("16 · A saved network", screen_saved_sheet(),
         "Join comes first, and joining one leaves the network in use. "
         "This one joins only when told to."),
    ]),
    ("Hidden networks", "A network that hides its name is joined by typing "
     "it.", [
        ("17 · Other network", screen_other(),
         "Name, Security (the modes this device can join), and Password, "
         "which goes away for Open. Join saves it as hidden, so the device "
         "asks for it by name."),
    ]),
]


def main(path_out):
    margin, gap, cols = 80, 64, 3
    cw = cols * g.BOARD_W + (cols - 1) * gap
    cwidth = cw + 2 * margin
    o = [T(margin, 130, "Wi-Fi · communicator", 56, g.INK, 700),
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
            f'aria-labelledby="t" font-family="{g.SANS}"><title id="t">Wi-Fi '
            f'on the communicator, mockups</title><defs>'
            f'<filter id="shadow" x="-5%" y="-5%" width="110%" height="110%">'
            f'<feDropShadow dx="0" dy="3" stdDeviation="8" '
            f'flood-opacity="0.22"/></filter></defs>'
            f'<rect width="{cwidth}" height="{height}" fill="{g.CANVAS_BG}"/>')
    with open(path_out, "w") as f:
        f.write(head + "\n" + "\n".join(o) + "\n</svg>\n")


if __name__ == "__main__":
    main(sys.argv[1])
