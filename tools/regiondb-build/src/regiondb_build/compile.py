"""Compiling a source tree into regions.

This is the stage that turns policy plus committed data into the set of regions
the database will hold: generated nearest-site cores, administrative and
hand-authored containment cores, manual overrides on top of both, and then the
expansion that produces each region's effective routing coverage.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import geom, overrides, regioncode, voronoi
from .model import (
    LAYER_COMMERCIAL_AIRPORT,
    LAYER_COUNTRY,
    LAYER_CUSTOM,
    LAYER_METRO,
    LAYER_NAMESPACE,
    LAYER_POSITIONED_IATA,
    LAYER_US_STATE,
    Region,
    Site,
    SourceRecord,
)
from .policy import Policy
from .sourcetree import SourceTree

# Layer order values are spaced so a within-layer priority can be folded into
# the same integer without reaching the next layer.
PRIORITY_STRIDE = 1000


class CompileError(ValueError):
    """The source tree cannot be compiled as written."""


@dataclass
class CompileResult:
    regions: list[Region]
    sources: list[SourceRecord]
    warnings: list[str] = field(default_factory=list)
    applied_overrides: list[str] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)


def classify_commercial(tree: SourceTree) -> tuple[list[Site], list[str]]:
    """Decide which positioned sites are ordinary passenger gateways.

    `scheduled_service` is where the candidate list comes from and nothing
    more. The field means "some scheduled flight exists", which is not the same
    question as "would someone here call this their airport" — San Carlos is
    the standing counterexample — so the committed classification file has the
    final say in both directions.
    """
    by_iata = {site.iata: site for site in tree.sites}
    warnings: list[str] = []

    selected = {iata for iata in tree.commercial_candidates if iata in by_iata}
    missing = tree.commercial_candidates - set(by_iata)
    if missing:
        warnings.append(
            f"{len(missing)} commercial candidates have no positioned site and were dropped: "
            + ", ".join(sorted(missing)[:10])
        )

    for iata, override in sorted(tree.classifications.items()):
        if iata not in by_iata:
            warnings.append(
                f"classification override for {iata} matches no positioned site; "
                "the airport may have been retired upstream"
            )
            continue
        if override.commercial:
            if iata not in selected:
                warnings.append(
                    f"{iata} is classified commercial by hand but upstream does not list "
                    "scheduled service; the override is doing real work here"
                )
            selected.add(iata)
        else:
            if iata not in selected:
                warnings.append(
                    f"classification override excludes {iata}, which upstream no longer "
                    "proposes as a candidate; the override may be obsolete"
                )
            selected.discard(iata)

    return [by_iata[iata] for iata in sorted(selected)], warnings


def _radio_identity(
    layer: str, code: str, display_name: str, radio_name: str, allow_short_code: bool
) -> int:
    if len(radio_name.encode("utf-8")) > regioncode.REGION_NAME_MAX_LEN:
        raise CompileError(
            f"region {layer}:{code} has radio name {radio_name!r}, which is "
            f"{len(radio_name.encode('utf-8'))} bytes; the limit is "
            f"{regioncode.REGION_NAME_MAX_LEN}"
        )
    if regioncode.is_short_code_form(radio_name):
        if layer == LAYER_CUSTOM and not allow_short_code:
            raise CompileError(
                f"custom region {code!r} has radio name {radio_name!r}, which the runtime "
                "reads as a short code, not as a name — it would claim an IATA or ISO "
                "identity. Rename it, or set `allow_short_code: true` to say the "
                "short-code identity is deliberate."
            )
        return regioncode.from_short_code(radio_name)
    return regioncode.from_name(radio_name)


def _priority(policy: Policy, layer: str, within: int = 0) -> int:
    return policy.layer(layer).order * PRIORITY_STRIDE + within


def _default_rank(policy: Policy, layer: str) -> int | None:
    ordered: list[str] = []
    for entry in policy.default_preference:
        name = entry.rsplit("_", 1)[0]
        if name not in ordered:
            ordered.append(name)
    return ordered.index(layer) if layer in ordered else None


def _generated_regions(
    policy: Policy,
    layer: str,
    sites: list[Site],
    source_key: str,
    warnings: list[str],
) -> list[Region]:
    settings = policy.layer(layer)
    if not settings.enabled or not sites:
        return []
    if settings.max_radius_m is None:
        raise CompileError(f"layer {layer!r} is generated and needs a max_radius_m")

    cells = voronoi.build_cells(
        sites, settings.max_radius_m, policy.curve_error_m, policy.cap_error_m
    )
    warnings.extend(voronoi.validate_cells(cells, settings.max_radius_m))

    namespace = LAYER_NAMESPACE[layer]
    regions: list[Region] = []
    for cell in cells:
        site = cell.site
        regions.append(
            Region(
                region_key=f"{namespace}:{site.iata}",
                namespace=namespace,
                code=site.iata,
                display_name=site.name,
                radio_name=site.iata,
                wire_code=_radio_identity(layer, site.iata, site.name, site.iata, False),
                layer=layer,
                priority=_priority(policy, layer),
                expansion_m=settings.expansion_m,
                core=cell.geometry,
                default_rank=_default_rank(policy, layer),
                source_key=source_key,
                source_feature_id=site.source_id,
                site=site,
                notes=site.municipality or None,
            )
        )
    return regions


def compile_tree(tree: SourceTree, policy: Policy) -> CompileResult:
    warnings: list[str] = []
    regions: list[Region] = []
    counts: dict[str, int] = {}

    commercial_sites, classification_warnings = classify_commercial(tree)
    warnings.extend(classification_warnings)

    commercial = _generated_regions(
        policy, LAYER_COMMERCIAL_AIRPORT, commercial_sites, "ourairports-airports", warnings
    )
    positioned = _generated_regions(
        policy, LAYER_POSITIONED_IATA, tree.sites, "ourairports-airports", warnings
    )
    regions.extend(commercial)
    regions.extend(positioned)
    counts["commercial_airport"] = len(commercial)
    counts["positioned_iata"] = len(positioned)

    regions.extend(_metro_regions(tree, policy))
    regions.extend(_boundary_regions(tree, policy, LAYER_COUNTRY))
    regions.extend(_boundary_regions(tree, policy, LAYER_US_STATE))
    regions.extend(_custom_regions(tree, policy))
    counts["metro"] = sum(1 for region in regions if region.layer == LAYER_METRO)
    counts["country"] = sum(1 for region in regions if region.layer == LAYER_COUNTRY)
    counts["us_state"] = sum(1 for region in regions if region.layer == LAYER_US_STATE)
    counts["custom"] = sum(1 for region in regions if region.layer == LAYER_CUSTOM)

    applied = overrides.apply(regions, tree.overrides, policy)
    counts["overrides"] = len(applied)

    regions = [region for region in regions if not region.core.is_empty]

    # Expansion is not compiled into geometry. Each region carries its
    # expansion distance, and the lookup's sampled-dilation rule resolves it
    # at query time against the core polygons; see sampling.py.

    warnings.extend(validate(regions))

    return CompileResult(
        regions=regions,
        sources=_sources(tree),
        warnings=warnings,
        applied_overrides=applied,
        counts=counts,
    )


def _metro_regions(tree: SourceTree, policy: Policy) -> list[Region]:
    settings = policy.layer(LAYER_METRO)
    if not settings.enabled:
        return []
    namespace = LAYER_NAMESPACE[LAYER_METRO]
    regions = []
    for metro in tree.metros:
        core = geom.simplify_m(
            geom.normalize(metro.geometry, name=metro.region_id),
            policy.simplify_m["metro"],
        )
        expansion = metro.expansion_m if metro.expansion_m is not None else settings.expansion_m
        regions.append(
            Region(
                region_key=f"{namespace}:{metro.iata}",
                namespace=namespace,
                code=metro.iata,
                display_name=metro.name,
                radio_name=metro.iata,
                wire_code=_radio_identity(LAYER_METRO, metro.iata, metro.name, metro.iata, False),
                layer=LAYER_METRO,
                priority=_priority(policy, LAYER_METRO),
                expansion_m=int(expansion),
                core=core,
                default_rank=_default_rank(policy, LAYER_METRO),
                source_key="metros",
                notes=metro.interpretation,
                provenance=[f"metro boundary: {metro.source_name or 'unstated source'}"],
            )
        )
    return regions


def _boundary_regions(tree: SourceTree, policy: Policy, layer: str) -> list[Region]:
    settings = policy.layer(layer)
    if not settings.enabled:
        return []
    features = tree.countries if layer == LAYER_COUNTRY else tree.states
    namespace = LAYER_NAMESPACE[layer]
    source_key = "marineregions-eez-land" if layer == LAYER_COUNTRY else "census-tiger-states"
    regions = []
    for feature in features:
        core = geom.simplify_m(
            geom.normalize(feature.geometry, name=f"{namespace}:{feature.code}"),
            policy.simplify_m[layer],
        )
        regions.append(
            Region(
                region_key=f"{namespace}:{feature.code}",
                namespace=namespace,
                code=feature.code,
                display_name=feature.name,
                radio_name=feature.code,
                wire_code=_radio_identity(layer, feature.code, feature.name, feature.code, False),
                layer=layer,
                priority=_priority(policy, layer),
                expansion_m=settings.expansion_m,
                core=core,
                default_rank=_default_rank(policy, layer),
                source_key=source_key,
                source_feature_id=feature.feature_id,
            )
        )
    return regions


def _custom_regions(tree: SourceTree, policy: Policy) -> list[Region]:
    settings = policy.layer(LAYER_CUSTOM)
    if not settings.enabled:
        return []
    regions = []
    for custom in tree.customs:
        namespace, _, code = custom.region_id.partition(":")
        if not code:
            raise CompileError(
                f"custom region id {custom.region_id!r} needs a namespace, as in "
                "`custom:rogue-valley`"
            )
        core = geom.simplify_m(
            geom.normalize(custom.geometry, name=custom.region_id),
            policy.simplify_m["custom"],
        )
        expansion = custom.expansion_m if custom.expansion_m is not None else settings.expansion_m
        regions.append(
            Region(
                region_key=custom.region_id,
                namespace=namespace,
                code=code,
                display_name=custom.name,
                radio_name=custom.radio_name,
                wire_code=_radio_identity(
                    LAYER_CUSTOM, code, custom.name, custom.radio_name, custom.allow_short_code
                ),
                layer=LAYER_CUSTOM,
                priority=_priority(policy, LAYER_CUSTOM, custom.priority),
                expansion_m=int(expansion),
                core=core,
                default_rank=_default_rank(policy, LAYER_CUSTOM),
                source_key="manual",
                notes=custom.notes,
            )
        )
    return regions


def _sources(tree: SourceTree) -> list[SourceRecord]:
    return [
        SourceRecord(
            source_key="ourairports-airports",
            name="OurAirports airport database",
            url="https://ourairports.com/data/",
            license="Public Domain",
            attribution="OurAirports",
        ),
        SourceRecord(
            source_key="marineregions-eez-land",
            name="Marine Regions EEZ and land union",
            url="https://www.marineregions.org/",
            license="CC BY 4.0",
            attribution="Flanders Marine Institute (VLIZ)",
        ),
        SourceRecord(
            source_key="census-tiger-states",
            name="US Census TIGER/Line states",
            url="https://www.census.gov/geographies/mapping-files/time-series/geo/tiger-line-file.html",
            license="US Government work, no copyright",
            attribution="US Census Bureau",
        ),
        SourceRecord(
            source_key="metros",
            name="UMSH metropolitan region definitions",
            license="MIT OR Apache-2.0",
            attribution="UMSH project",
        ),
        SourceRecord(
            source_key="manual",
            name="UMSH hand-authored regions",
            license="MIT OR Apache-2.0",
            attribution="UMSH project",
        ),
    ]


def _dilated(region: Region):
    """A conservative superset of a region's sampled-dilation coverage.

    Used only to decide whether two same-code regions could cover one
    position. The sampled member set is contained in the true geodesic
    dilation, which the AEQD buffer approximates from inside by well under a
    percent; the two-percent margin keeps this a superset.
    """
    if region.expansion_m <= 0:
        return region.core
    return geom.buffer_m(region.core, region.expansion_m * 1.02 + 100)


def validate(regions: list[Region]) -> list[str]:
    """Checks that run on every build, whatever the source tree."""
    warnings: list[str] = []

    by_code: dict[int, list[Region]] = {}
    for region in regions:
        by_code.setdefault(region.wire_code, []).append(region)

    for code, sharing in sorted(by_code.items()):
        if len(sharing) < 2:
            continue
        names = {region.radio_name.casefold() for region in sharing}
        for index, first in enumerate(sharing):
            for second in sharing[index + 1 :]:
                if _dilated(first).intersects(_dilated(second)):
                    if len(names) == 1:
                        # Same radio name from different layers, e.g. the metro
                        # and airport senses of one IATA code. The final list
                        # collapses them; both semantic matches survive.
                        continue
                    raise CompileError(
                        f"regions {first.region_key} and {second.region_key} both encode as "
                        f"0x{code:04X} and can cover the same position; a radio could not "
                        "tell them apart. Rename one, or waive this deliberately."
                    )
        if len(names) > 1:
            warnings.append(
                f"0x{code:04X} is shared by remote regions "
                + ", ".join(sorted(region.region_key for region in sharing))
            )

    for region in regions:
        if region.core.is_empty:
            warnings.append(f"{region.region_key}: core geometry is empty")

    return warnings
