"""Loading and validating `policy.yaml`.

Every value that can change a lookup result is hashed into the build metadata,
so that two databases claiming the same dataset version cannot have been built
under different rules.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from .model import LAYERS

SUPPORTED_FORMAT_VERSION = 1


class PolicyError(ValueError):
    """The policy file is missing something the build needs, or contradicts itself."""


@dataclass(frozen=True)
class LayerPolicy:
    name: str
    enabled: bool
    order: int
    expansion_m: int
    exclusive_core: bool
    max_radius_m: float | None
    default_eligible: bool


@dataclass(frozen=True)
class Policy:
    format_version: int
    distance_model: str
    curve_error_m: float
    cap_error_m: float
    maritime_reach_m: float
    border_simplify_m: float
    simplify_m: dict[str, float]
    cache_enabled: bool
    cache_max_depth: int
    layers: dict[str, LayerPolicy]
    default_preference: tuple[str, ...]
    include_territories: bool
    warn_bytes: int
    fail_bytes: int
    digest: str
    raw: dict[str, Any]

    def layer(self, name: str) -> LayerPolicy:
        try:
            return self.layers[name]
        except KeyError as error:
            raise PolicyError(f"policy defines no layer {name!r}") from error

    def enabled_layers(self) -> list[str]:
        return [name for name in LAYERS if self.layers[name].enabled]


def load(path: Path) -> Policy:
    raw = yaml.safe_load(path.read_text())
    if not isinstance(raw, dict):
        raise PolicyError(f"{path} is not a mapping")

    format_version = raw.get("format_version")
    if format_version != SUPPORTED_FORMAT_VERSION:
        raise PolicyError(
            f"{path} declares format_version {format_version!r}; "
            f"this builder writes {SUPPORTED_FORMAT_VERSION}"
        )

    geometry = raw.get("geometry", {})
    cache = raw.get("lookup_cache", {})
    size = raw.get("size", {})

    layers: dict[str, LayerPolicy] = {}
    raw_layers = raw.get("layers", {})
    for name in LAYERS:
        entry = raw_layers.get(name)
        if entry is None:
            raise PolicyError(f"{path} is missing layer {name!r}")
        layers[name] = LayerPolicy(
            name=name,
            enabled=bool(entry.get("enabled", True)),
            order=int(entry["order"]),
            expansion_m=int(entry.get("expansion_m", 0)),
            exclusive_core=bool(entry.get("exclusive_core", False)),
            max_radius_m=(
                float(entry["max_radius_m"]) if entry.get("max_radius_m") is not None else None
            ),
            default_eligible=bool(entry.get("default_eligible", False)),
        )

    preference = tuple(raw.get("default_region", {}).get("preference", ()))
    for entry in preference:
        layer_name = entry.rsplit("_", 1)[0]
        if layer_name not in layers:
            raise PolicyError(f"default_region preference names unknown layer {layer_name!r}")
        if not layers[layer_name].default_eligible:
            raise PolicyError(
                f"default_region preference includes {entry!r}, but layer "
                f"{layer_name!r} is not marked default_eligible"
            )

    canonical = json.dumps(raw, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(canonical.encode()).hexdigest()

    return Policy(
        format_version=format_version,
        distance_model=str(raw.get("distance", {}).get("model", "WGS84")),
        curve_error_m=float(geometry.get("curve_error_m", 50)),
        cap_error_m=float(geometry.get("cap_error_m", 1000)),
        maritime_reach_m=float(geometry.get("maritime_reach_m", 100_000)),
        border_simplify_m=float(geometry.get("border_simplify_m", 2_000)),
        simplify_m={
            "country": float(geometry.get("country_simplify_m", 0)),
            "us_state": float(geometry.get("state_simplify_m", 0)),
            "metro": float(geometry.get("metro_simplify_m", 0)),
            "custom": float(geometry.get("custom_simplify_m", 0)),
        },
        cache_enabled=bool(cache.get("enabled", True)),
        cache_max_depth=int(cache.get("max_depth", 16)),
        layers=layers,
        default_preference=preference,
        include_territories=bool(raw.get("us_state", {}).get("include_territories", False)),
        warn_bytes=int(size.get("warn_bytes", 10 * 1024 * 1024)),
        fail_bytes=int(size.get("fail_bytes", 32 * 1024 * 1024)),
        digest=digest,
        raw=raw,
    )
