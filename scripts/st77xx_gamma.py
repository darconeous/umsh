#!/usr/bin/env python3
"""Fit a Sitronix ST7789/ST7796 panel's gamma tables to a target gamma.

Measure the panel with the communicator's Gamma chart (Device > Display >
Gamma), which reads the gamma at 50% of white and at each half below it,
then pass the readings with the E0h/E1h tables they were taken under:

    python3 scripts/st77xx_gamma.py \\
        --e0 "d0 0d 14 0d 0d 09 38 44 4e 3a 17 18 2f 30" \\
        --e1 "d0 09 0f 08 07 14 37 44 4d 38 15 16 2c 3e" \\
        --readings 2.6 2.6 2.6 2.5 2.53 2.51 2.45

It prints new tables for `crates/umsh-display-st77xx/src/panel.rs` and the
brightness each data level gets, before and after, against the target.

The model is the datasheets' gray-scale voltage formulas (ST7796S §10.9,
ST7789V §8.19; identical, as are the table layouts). With inversion on, as
these IPS panels run, data level d drives gamma index 63 - d. Each reading
gives the panel's brightness at one drive voltage; below the darkest, each
further halving is taken to need RATIO times the voltage of the one before,
as the measured halvings shrink toward the panel's cutoff. Both tables are
fit together: their mean against the target, the difference between them
held near the original's. Standard library only.
"""

import argparse
import math
import random

# J0[1:0] and J1[1:0]: the interpolated levels' share of their span.
J0 = {  # VP3, VP5, VP7..VP12
    0: (0.50, 0.50, 0.86, 0.71, 0.57, 0.43, 0.29, 0.14),
    1: (0.56, 0.44, 0.71, 0.57, 0.40, 0.29, 0.17, 0.06),
    2: (0.50, 0.50, 0.80, 0.63, 0.49, 0.34, 0.20, 0.09),
    3: (0.60, 0.42, 0.66, 0.49, 0.34, 0.23, 0.14, 0.06),
}
J1 = {  # VP51..VP56, VP58, VP60
    0: (0.86, 0.71, 0.57, 0.43, 0.29, 0.14, 0.50, 0.50),
    1: (0.86, 0.71, 0.60, 0.46, 0.34, 0.17, 0.56, 0.50),
    2: (0.86, 0.77, 0.63, 0.46, 0.31, 0.14, 0.47, 0.50),
    3: (0.89, 0.80, 0.69, 0.51, 0.37, 0.20, 0.47, 0.53),
}
FIELDS = ["V63", "V0", "V1", "V2", "V4", "V6", "J0", "V13", "V20", "V36", "V27",
          "V43", "J1", "V50", "V57", "V59", "V61", "V62"]
LIMITS = dict(V63=15, V0=15, V1=63, V2=63, V4=31, V6=31, J0=3, V13=15, V20=127,
              V36=7, V27=7, V43=127, J1=3, V50=15, V57=31, V59=31, V61=63, V62=63)
# The endpoints, white and black, stay as they are.
FREE = [f for f in FIELDS if f not in ("V0", "V63")]
RATIO = 0.85


def decode(b):
    return dict(
        V63=b[0] >> 4, V0=b[0] & 15, V1=b[1] & 63, V2=b[2] & 63, V4=b[3] & 31,
        V6=b[4] & 31, J0=(b[5] >> 4) & 3, V13=b[5] & 15, V20=b[6] & 127,
        V36=(b[7] >> 4) & 7, V27=b[7] & 7, V43=b[8] & 127, J1=(b[9] >> 4) & 3,
        V50=b[9] & 15, V57=b[10] & 31, V59=b[11] & 31, V61=b[12] & 63, V62=b[13] & 63)


def encode(r):
    return [r["V63"] << 4 | r["V0"], r["V1"], r["V2"], r["V4"], r["V6"],
            r["J0"] << 4 | r["V13"], r["V20"], r["V36"] << 4 | r["V27"], r["V43"],
            r["J1"] << 4 | r["V50"], r["V57"], r["V59"], r["V61"], r["V62"]]


def volts(r):
    """Each gamma index's source voltage, as a share of the reference span."""
    v = [0.0] * 64

    def top(reg, k):
        return (k - reg) / 129.0

    v[0] = top(r["V0"], 129)
    v[1] = top(r["V1"], 128)
    v[2] = top(r["V2"], 128)
    v[20] = top(r["V20"], 128)
    v[43] = top(r["V43"], 128)
    v[61] = top(r["V61"], 64)
    v[62] = top(r["V62"], 64)
    v[63] = top(r["V63"], 23)
    v[4] = (v[2] - v[20]) * (57 - r["V4"]) / 60 + v[20]
    v[6] = (v[2] - v[20]) * (47 - r["V6"]) / 60 + v[20]
    v[13] = (v[2] - v[20]) * (21 - r["V13"]) / 60 + v[20]
    j = J0[r["J0"]]
    v[3] = (v[2] - v[4]) * j[0] + v[4]
    v[5] = (v[4] - v[6]) * j[1] + v[6]
    for n, i in enumerate(range(7, 13)):
        v[i] = (v[6] - v[13]) * j[2 + n] + v[13]
    for i in range(14, 20):
        v[i] = (v[13] - v[20]) / 7 * (20 - i) + v[20]
    v[27] = (v[20] - v[43]) * (20 - r["V27"]) / 25 + v[43]
    v[36] = (v[20] - v[43]) * (11 - r["V36"]) / 25 + v[43]
    for i in range(21, 27):
        v[i] = (v[20] - v[27]) / 7 * (27 - i) + v[27]
    for i in range(28, 36):
        v[i] = (v[27] - v[36]) / 9 * (36 - i) + v[36]
    for i in range(37, 43):
        v[i] = (v[36] - v[43]) / 7 * (43 - i) + v[43]
    v[50] = (v[43] - v[61]) * (54 - r["V50"]) / 60 + v[61]
    v[57] = (v[43] - v[61]) * (44 - r["V57"]) / 60 + v[61]
    v[59] = (v[43] - v[61]) * (34 - r["V59"]) / 60 + v[61]
    for i in range(44, 50):
        v[i] = (v[43] - v[50]) / 7 * (50 - i) + v[50]
    k = J1[r["J1"]]
    for n, i in enumerate(range(51, 57)):
        v[i] = (v[50] - v[57]) * k[n] + v[57]
    v[58] = (v[57] - v[59]) * k[6] + v[59]
    v[60] = (v[59] - v[61]) * k[7] + v[61]
    return v


def chart_gamma(level, share):
    """The gamma the chart reads for six-bit `level` on a field of `share`:
    red and blue are the five-bit level below, weighted by their light."""
    five = level >> 1
    red = ((five << 1) | (five >> 4)) / 63
    return math.log(share) / math.log(0.2848 * red + 0.7152 * level / 63)


class Response:
    """The panel's brightness, in stops below white, against drive voltage."""

    def __init__(self, mean, readings):
        self.knots = [(mean[0], 0.0)]
        for k, reading in enumerate(readings):
            share = 0.5 ** (k + 1)
            level = min(range(1, 63),
                        key=lambda lv: abs(round(chart_gamma(lv, share), 2) - reading))
            self.knots.append((mean[63 - level], -(k + 1.0)))
        step = self.knots[-2][0] - self.knots[-1][0]
        while self.knots[-1][1] > -16:
            step *= RATIO
            self.knots.append((self.knots[-1][0] - step, self.knots[-1][1] - 1))

    def stops(self, u):
        if u >= self.knots[0][0]:
            return 0.0
        for (u0, s0), (u1, s1) in zip(self.knots, self.knots[1:]):
            if u1 <= u <= u0:
                return s0 + (s1 - s0) * (u - u0) / (u1 - u0)
        return self.knots[-1][1]


def fit(e0, e1, readings, gamma, black, spread, seed=2):
    vp0, vn0 = volts(decode(e0)), volts(decode(e1))
    mean0 = [(a + b) / 2 for a, b in zip(vp0, vn0)]
    diff0 = [a - b for a, b in zip(vp0, vn0)]
    response = Response(mean0, readings)

    def target(d):
        return black + (1 - black) * (d / 63) ** gamma

    goal = [None] + [math.log2(target(63 - i)) for i in range(1, 63)]

    def err(rp, rn):
        vp, vn = volts(rp), volts(rn)
        if any(vp[i] < vp[i + 1] or vn[i] < vn[i + 1] for i in range(63)):
            return 1e9
        curve = sum((response.stops((vp[i] + vn[i]) / 2) - goal[i]) ** 2 for i in range(1, 63))
        apart = sum(((vp[i] - vn[i]) - diff0[i]) ** 2 for i in range(1, 63))
        return curve + spread * apart

    params = [("p", f) for f in FREE] + [("n", f) for f in FREE]

    def descend(rp, rn):
        best = err(rp, rn)
        for _ in range(60):
            improved = False
            for side, f in params:
                for val in range(LIMITS[f] + 1):
                    tp, tn = dict(rp), dict(rn)
                    (tp if side == "p" else tn)[f] = val
                    e = err(tp, tn)
                    if e < best - 1e-12:
                        best, rp, rn, improved = e, tp, tn, True
            if not improved:
                break
        return rp, rn, best

    rng = random.Random(seed)
    rp, rn, e = descend(decode(e0), decode(e1))
    for _ in range(30):
        kp, kn = dict(rp), dict(rn)
        for side, f in rng.sample(params, 4):
            t = kp if side == "p" else kn
            t[f] = max(0, min(LIMITS[f], t[f] + rng.randint(-4, 4)))
        a, b, e2 = descend(kp, kn)
        if e2 < e:
            rp, rn, e = a, b, e2

    vp, vn = volts(rp), volts(rn)
    rows = []
    for d in (1, 2, 3, 4, 6, 8, 10, 13, 18, 28, 38, 50, 58, 62):
        i = 63 - d
        rows.append((d, 2 ** response.stops(mean0[i]), 2 ** response.stops((vp[i] + vn[i]) / 2),
                     target(d)))
    return encode(rp), encode(rn), rows


def table(text):
    values = [int(b, 16) for b in text.replace(",", " ").split()]
    if len(values) != 14:
        raise argparse.ArgumentTypeError("a gamma table is 14 bytes")
    return values


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--e0", type=table, required=True, help="E0h (positive) table, hex bytes")
    parser.add_argument("--e1", type=table, required=True, help="E1h (negative) table, hex bytes")
    parser.add_argument("--readings", type=float, nargs="+", required=True,
                        help="the Gamma chart's readings, 50%% of white first")
    parser.add_argument("--gamma", type=float, default=2.2, help="target gamma (2.2)")
    parser.add_argument("--black", type=float, default=0.001,
                        help="black floor, as a share of white (0.001)")
    parser.add_argument("--spread", type=float, default=200.0,
                        help="weight holding E0h and E1h apart as they were (200)")
    args = parser.parse_args()
    if len(args.readings) < 2:
        parser.error("at least two readings")
    e0, e1, rows = fit(args.e0, args.e1, args.readings, args.gamma, args.black, args.spread)
    for name, t in (("0xe0", e0), ("0xe1", e1)):
        print(f"{name}: " + ", ".join(f"0x{b:02x}" for b in t))
    print("\n d   before%   after%  target%")
    for d, before, after, goal in rows:
        print(f"{d:2} {before * 100:9.3f} {after * 100:8.3f} {goal * 100:8.3f}")


if __name__ == "__main__":
    main()
