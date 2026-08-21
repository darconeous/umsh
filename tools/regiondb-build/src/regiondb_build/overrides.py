"""Manual corrections to generated and sourced boundaries.

Overrides act on *core* geometry, before expansion, so that a hand-drawn
routing boundary is expanded the same way a generated one is. They are applied
highest priority first, and two overrides of equal priority that fight over the
same ground are an error rather than a silent race.

`force` exists because a generated layer is a partition: moving ground into one
region necessarily takes it from a neighbor, and doing that by editing one
Voronoi cell in isolation would leave a hole or an overlap. A force operation
does both halves at once.
"""

from __future__ import annotations

from shapely.geometry.base import BaseGeometry

from . import geom
from .model import Region
from .policy import Policy
from .sourcetree import OverrideDefinition

OPERATIONS = ("force", "include", "exclude", "replace")


class OverrideError(ValueError):
    """An override is unusable or conflicts with another."""


def apply(
    regions: list[Region], definitions: list[OverrideDefinition], policy: Policy
) -> list[str]:
    """Apply every override in place, returning the notes for the build report."""
    for definition in definitions:
        if definition.operation not in OPERATIONS:
            raise OverrideError(
                f"override {definition.override_id} has unknown operation "
                f"{definition.operation!r}; expected one of {', '.join(OPERATIONS)}"
            )
        if definition.layer not in policy.layers:
            raise OverrideError(
                f"override {definition.override_id} names unknown layer {definition.layer!r}"
            )

    _reject_conflicting_forces(definitions)

    by_key = {region.region_key: region for region in regions}
    applied: list[str] = []

    for definition in sorted(definitions, key=lambda item: (-item.priority, item.override_id)):
        polygon = geom.normalize(definition.geometry, name=f"override {definition.override_id}")
        exclusive = policy.layer(definition.layer).exclusive_core

        if definition.operation == "exclude":
            target = _target(by_key, definition)
            target.core = geom.polygonal(target.core.difference(polygon))
        elif definition.operation == "replace":
            target = _target(by_key, definition)
            if target.site is not None:
                raise OverrideError(
                    f"override {definition.override_id} tries to replace the core of "
                    f"{target.region_key}, which is generated; use `force` instead, so "
                    "the neighbors it borders are adjusted with it"
                )
            target.core = polygon
        else:
            target = _target(by_key, definition)
            if definition.operation == "force":
                if not exclusive:
                    raise OverrideError(
                        f"override {definition.override_id} forces an assignment in "
                        f"non-exclusive layer {definition.layer!r}; use `include` there, "
                        "which does not take ground from anything"
                    )
                for other in regions:
                    if other.layer == definition.layer and other is not target:
                        other.core = geom.polygonal(other.core.difference(polygon))
            target.core = geom.polygonal(target.core.union(polygon))

        target.provenance.append(
            f"{definition.operation} by {definition.override_id}: {definition.reason}"
        )
        applied.append(
            f"{definition.override_id}: {definition.operation} on {definition.target} "
            f"({definition.layer})"
        )

    return applied


def _target(by_key: dict[str, Region], definition: OverrideDefinition) -> Region:
    if not definition.target:
        raise OverrideError(f"override {definition.override_id} names no target region")
    try:
        return by_key[definition.target]
    except KeyError as error:
        raise OverrideError(
            f"override {definition.override_id} targets {definition.target!r}, "
            "which no compiled region matches"
        ) from error


def _reject_conflicting_forces(definitions: list[OverrideDefinition]) -> None:
    forces = [item for item in definitions if item.operation == "force"]
    for index, first in enumerate(forces):
        for second in forces[index + 1 :]:
            if first.layer != second.layer or first.priority != second.priority:
                continue
            if _overlaps(first.geometry, second.geometry):
                raise OverrideError(
                    f"overrides {first.override_id} and {second.override_id} both force "
                    f"an assignment in layer {first.layer!r} over the same ground at "
                    f"priority {first.priority}; give one of them a higher priority so "
                    "the outcome is stated rather than incidental"
                )


def _overlaps(first: BaseGeometry, second: BaseGeometry) -> bool:
    intersection = first.intersection(second)
    return not intersection.is_empty and intersection.area > 0
