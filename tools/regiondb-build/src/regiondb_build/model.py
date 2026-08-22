"""The compiled region model shared by every stage of the build."""

from __future__ import annotations

from dataclasses import dataclass, field

from shapely.geometry.base import BaseGeometry

# Layer identifiers. These name geographic policy, not radio behavior: the
# radio sees only the region code a layer happens to produce.
LAYER_COMMERCIAL_AIRPORT = "commercial_airport"
LAYER_POSITIONED_IATA = "positioned_iata"
LAYER_METRO = "metro"
LAYER_COUNTRY = "country"
LAYER_US_STATE = "us_state"
LAYER_CUSTOM = "custom"

LAYERS = (
    LAYER_COMMERCIAL_AIRPORT,
    LAYER_POSITIONED_IATA,
    LAYER_METRO,
    LAYER_COUNTRY,
    LAYER_US_STATE,
    LAYER_CUSTOM,
)

# The namespace a layer's regions live in. Namespaces exist so tooling can tell
# `iata-airport:SFO` from `iata-metro:SFO`; they are never transmitted.
LAYER_NAMESPACE = {
    LAYER_COMMERCIAL_AIRPORT: "iata-airport",
    LAYER_POSITIONED_IATA: "iata-location",
    LAYER_METRO: "iata-metro",
    LAYER_COUNTRY: "country",
    LAYER_US_STATE: "us-state",
    LAYER_CUSTOM: "custom",
}

MEMBERSHIP_CORE = 0
MEMBERSHIP_EXPANDED = 1


@dataclass
class Site:
    """A positioned IATA location: an airport today, possibly a rail station later."""

    iata: str
    name: str
    latitude: float
    longitude: float
    kind: str
    iso_country: str
    iso_region: str
    municipality: str
    scheduled_service: bool
    source_id: str

    @property
    def position(self) -> tuple[float, float]:
        return self.longitude, self.latitude


@dataclass
class Region:
    """One compiled region, before and after expansion."""

    region_key: str
    namespace: str
    code: str
    display_name: str
    radio_name: str
    wire_code: int
    layer: str
    priority: int
    expansion_m: int
    core: BaseGeometry
    default_rank: int | None = None
    source_key: str | None = None
    source_feature_id: str | None = None
    site: Site | None = None
    notes: str | None = None
    flags: int = 0
    provenance: list[str] = field(default_factory=list)

    @property
    def kind(self) -> str:
        return self.layer


@dataclass
class SourceRecord:
    """Provenance for one upstream dataset, carried into the database."""

    source_key: str
    name: str
    url: str | None = None
    revision: str | None = None
    sha256: str | None = None
    license: str | None = None
    attribution: str | None = None
