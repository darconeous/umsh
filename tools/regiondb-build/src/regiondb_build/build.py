"""The `build` command: a source tree in, one `.regiondb` out."""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path

from . import cells, emit, geom, sourcetree
from . import compile as compile_module
from . import policy as policy_module
from .model import Region


class BuildError(RuntimeError):
    """The build could not produce a usable database."""


@dataclass
class BuildOutcome:
    database: Path
    report: dict
    stats: emit.EmitStats


def build(
    root: Path,
    output: Path,
    *,
    dataset_version: str,
    created_at: str | None = None,
) -> BuildOutcome:
    started = time.monotonic()
    settings = policy_module.load(root / "policy.yaml")
    tree = sourcetree.load(root)
    result = compile_module.compile_tree(tree, settings)

    if not result.regions:
        raise BuildError(f"{root} compiled to no regions at all")

    leaves, cache_stats = _build_cache(result.regions, settings)

    metadata = {
        "format_version": str(emit.FORMAT_VERSION),
        "dataset_version": dataset_version,
        "policy_digest": settings.digest,
        "distance_model": settings.distance_model,
        "cache_max_depth": str(settings.cache_max_depth if settings.cache_enabled else 0),
        "geometry_format_version": "1",
        "coordinate_scale": "1e-6",
        "builder": "regiondb-build",
        "metro_polygons": str(result.counts.get("metro", 0)),
    }
    if created_at:
        metadata["created_at"] = created_at

    stats = emit.write(
        output,
        regions=result.regions,
        sources=result.sources,
        leaves=leaves,
        metadata=metadata,
    )

    warnings = list(result.warnings)
    if stats.size_bytes > settings.fail_bytes:
        raise BuildError(
            f"{output} is {stats.size_bytes / 1_048_576:.1f} MiB, past the configured hard "
            f"limit of {settings.fail_bytes / 1_048_576:.1f} MiB"
        )
    if stats.size_bytes > settings.warn_bytes:
        warnings.append(
            f"database is {stats.size_bytes / 1_048_576:.1f} MiB, over the "
            f"{settings.warn_bytes / 1_048_576:.1f} MiB budget"
        )

    report = {
        "dataset_version": dataset_version,
        "format_version": emit.FORMAT_VERSION,
        "content_hash": stats.content_hash,
        "policy_digest": settings.digest,
        "source_root": str(root),
        "counts": {
            **result.counts,
            "positioned_iata_sites": len(tree.sites),
            "commercial_candidates": len(tree.commercial_candidates),
            "classification_overrides": len(tree.classifications),
            "regions": len(result.regions),
        },
        "geometry": {
            "parts": stats.parts,
            "core_vertices": stats.core_vertices,
            "effective_vertices": stats.effective_vertices,
        },
        "cache": {
            "enabled": settings.cache_enabled,
            "max_depth": settings.cache_max_depth,
            "leaves": cache_stats.leaves,
            "ranges": cache_stats.ranges,
            "boundary_leaves": cache_stats.boundary_leaves,
            "max_candidates": cache_stats.max_candidates,
            "region_sets": stats.region_sets,
        },
        "database": {"path": str(output), "size_bytes": stats.size_bytes},
        "applied_overrides": result.applied_overrides,
        "region_keys": sorted(region.region_key for region in result.regions),
        "max_radio_regions_observed": _max_radio_regions(result.regions),
        "warnings": warnings,
        "duration_s": round(time.monotonic() - started, 2),
    }
    return BuildOutcome(database=output, report=report, stats=stats)


def _build_cache(regions: list[Region], settings) -> tuple[list[cells.Leaf], cells.CacheStats]:
    """Build the lookup ranges, or one whole-world range if the cache is off."""
    identifiers = list(range(1, len(regions) + 1))
    ordered = sorted(regions, key=lambda item: (item.priority, item.region_key))
    geometries = [
        region.effective if region.effective is not None else region.core for region in ordered
    ]
    if not settings.cache_enabled:
        from .morton import MAX_DEPTH, cell_range

        start, end = cell_range(0, 0, 0)
        leaf = cells.Leaf(start, end, (), tuple(identifiers))
        return [leaf], cells.CacheStats(1, 1, 1, len(identifiers), MAX_DEPTH)
    return cells.build(identifiers, geometries, settings.cache_max_depth)


def _max_radio_regions(regions: list[Region]) -> int:
    """An upper bound on how many distinct codes one position can produce.

    Computed from overlapping bounding boxes rather than exactly: this is a
    sanity number for the report, and an exact answer would cost another full
    geometric pass for no decision it would change.
    """
    from shapely.strtree import STRtree

    geometries = [
        region.effective if region.effective is not None else region.core for region in regions
    ]
    if not geometries:
        return 0
    tree = STRtree(geometries)
    return max(len(tree.query(geometry)) for geometry in geometries)


__all__ = ["BuildError", "BuildOutcome", "build", "geom"]
