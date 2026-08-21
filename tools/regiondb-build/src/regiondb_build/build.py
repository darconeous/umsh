"""The `build` command: a source tree in, one `.regiondb` out."""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path

from . import cells, emit, geom, sourcetree
from . import compile as compile_module
from . import policy as policy_module


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
            "vertices": stats.vertices,
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
        "warnings": warnings,
        "duration_s": round(time.monotonic() - started, 2),
    }
    return BuildOutcome(database=output, report=report, stats=stats)


def _build_cache(regions, settings) -> tuple[list[cells.Leaf], cells.CacheStats]:
    """Build the lookup ranges, or none at all when the cache is off.

    An empty lookup_ranges table is the documented signal that a database has
    no cache: readers fall back to the R-tree candidate path over the same
    effective polygons. Emitting one whole-world range instead would be
    catastrophically worse than no cache — every lookup would test every
    region.
    """
    if not settings.cache_enabled:
        return [], cells.CacheStats(0, 0, 0, 0, 0)
    identifiers = list(range(1, len(regions) + 1))
    ordered = sorted(regions, key=lambda item: (item.priority, item.region_key))
    # Classification needs two shapes per region: the core (a cell inside it is
    # guaranteed member territory) and a superset of the sampled-dilation
    # coverage (a cell outside it is guaranteed non-member territory). The
    # margin on the buffer keeps it a superset of the sample reach; anything
    # between the two becomes a candidate the reader tests exactly.
    cores = [region.core for region in ordered]
    reaches = [
        region.core
        if region.expansion_m <= 0
        else geom.buffer_m(region.core, region.expansion_m * 1.02 + 100)
        for region in ordered
    ]
    return cells.build(identifiers, cores, reaches, settings.cache_max_depth)


__all__ = ["BuildError", "BuildOutcome", "build", "geom"]
