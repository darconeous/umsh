"""The adaptive lookup cache.

The compiled database always carries exact effective polygons, so a lookup can
always be answered exactly. The cache exists so that the overwhelming majority
of lookups — positions nowhere near any boundary — are answered by one indexed
range query and no geometry at all.

The world is subdivided as a quadtree. For each cell, every region is one of
three things: it covers the whole cell, it misses the cell entirely, or its
boundary runs through the cell. A cell with no boundaries through it is emitted
immediately with the complete answer for every position inside it. Otherwise it
is subdivided, and at the depth limit it is emitted with the regions known to
cover it plus the short list of regions that must actually be tested.

The classification uses real geometric relations rather than sampled points.
Sampling would miss a region small enough to sit wholly inside a cell without
containing the sample.
"""

from __future__ import annotations

from dataclasses import dataclass

from shapely.geometry import box
from shapely.prepared import prep

from .morton import MAX_DEPTH, cell_bounds, cell_range


@dataclass
class Leaf:
    """One resolved quadtree cell, as an inclusive range of max-depth keys."""

    start_key: int
    end_key: int
    base: tuple[int, ...]
    candidates: tuple[int, ...]


@dataclass
class CacheStats:
    leaves: int
    ranges: int
    boundary_leaves: int
    max_candidates: int
    max_depth_reached: int


def build(
    region_ids: list[int],
    geometries: list,
    max_depth: int,
) -> tuple[list[Leaf], CacheStats]:
    """Build merged lookup ranges over `geometries`, parallel to `region_ids`."""
    if max_depth < 0 or max_depth > MAX_DEPTH:
        raise ValueError(f"cache depth {max_depth} outside 0..{MAX_DEPTH}")

    prepared = {
        identifier: prep(geometry)
        for identifier, geometry in zip(region_ids, geometries, strict=True)
    }
    leaves: list[Leaf] = []
    stats = {"boundary": 0, "max_candidates": 0, "max_depth": 0}

    def visit(depth: int, x: int, y: int, base: tuple[int, ...], candidates: list[int]) -> None:
        stats["max_depth"] = max(stats["max_depth"], depth)
        min_lon, min_lat, max_lon, max_lat = cell_bounds(depth, x, y)
        cell = box(min_lon, min_lat, max_lon, max_lat)

        covering: list[int] = []
        mixed: list[int] = []
        for identifier in candidates:
            shape = prepared[identifier]
            if not shape.intersects(cell):
                continue
            if shape.contains(cell):
                covering.append(identifier)
            else:
                # Includes a region that merely touches the cell's edge: a
                # position on that edge is inside the region, so the cell
                # cannot answer without testing it.
                mixed.append(identifier)

        resolved = tuple(sorted(set(base) | set(covering)))
        start, end = cell_range(depth, x, y)

        if not mixed:
            leaves.append(Leaf(start, end, resolved, ()))
            return
        if depth >= max_depth:
            stats["boundary"] += 1
            stats["max_candidates"] = max(stats["max_candidates"], len(mixed))
            leaves.append(Leaf(start, end, resolved, tuple(sorted(mixed))))
            return

        # Children in Morton order, so leaves come out already sorted by key.
        for child_y in (0, 1):
            for child_x in (0, 1):
                visit(depth + 1, x * 2 + child_x, y * 2 + child_y, resolved, mixed)

    visit(0, 0, 0, (), list(region_ids))
    merged = merge(leaves)
    return merged, CacheStats(
        leaves=len(leaves),
        ranges=len(merged),
        boundary_leaves=stats["boundary"],
        max_candidates=stats["max_candidates"],
        max_depth_reached=stats["max_depth"],
    )


def merge(leaves: list[Leaf]) -> list[Leaf]:
    """Coalesce adjacent leaves that answer identically."""
    merged: list[Leaf] = []
    for leaf in leaves:
        if (
            merged
            and merged[-1].end_key + 1 == leaf.start_key
            and merged[-1].base == leaf.base
            and merged[-1].candidates == leaf.candidates
        ):
            merged[-1] = Leaf(merged[-1].start_key, leaf.end_key, leaf.base, leaf.candidates)
        else:
            merged.append(leaf)
    return merged
