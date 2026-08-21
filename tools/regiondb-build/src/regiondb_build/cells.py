"""The adaptive lookup cache.

A lookup can always be answered exactly from the core polygons and the
sampled-dilation rule. The cache exists so that the overwhelming majority of
lookups — positions nowhere near any boundary — are answered by one indexed
range query and no geometry at all.

The world is subdivided as a quadtree. Each region is classified against a
cell with two shapes: its core, and a superset of its sampled-dilation reach.
A cell inside the core is guaranteed member territory — the position sample
alone hits. A cell disjoint from the reach is guaranteed non-member territory,
because the sample pattern never lands in core from outside it. Everything in
between becomes a candidate the reader resolves with the real sampled test, so
the classification bounds the answer from both sides without ever having to
reproduce the sample pattern geometrically.

The classification uses real geometric relations rather than sampled probe
points. Probing would miss a region small enough to sit wholly inside a cell
without containing the probe.
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
    cores: list,
    reaches: list,
    max_depth: int,
) -> tuple[list[Leaf], CacheStats]:
    """Build merged lookup ranges; `cores` and `reaches` parallel `region_ids`."""
    if max_depth < 0 or max_depth > MAX_DEPTH:
        raise ValueError(f"cache depth {max_depth} outside 0..{MAX_DEPTH}")

    prepared_cores = {
        identifier: prep(geometry) for identifier, geometry in zip(region_ids, cores, strict=True)
    }
    prepared_reaches = {
        identifier: prep(geometry) for identifier, geometry in zip(region_ids, reaches, strict=True)
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
            if not prepared_reaches[identifier].intersects(cell):
                continue
            if prepared_cores[identifier].contains(cell):
                covering.append(identifier)
            else:
                # Includes a region whose reach merely touches the cell's
                # edge: a position on that edge may sample into the core, so
                # the cell cannot answer without testing it.
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
