/**
 * The region map: a debugger for the compiled geographic database.
 *
 * The page opens an actual `.regiondb` — the same file a phone downloads —
 * and answers a click with the same code the runtime runs, from
 * `regiondb.mjs`. A viewer that could disagree with the runtime would be
 * worse than no viewer, because it would be believed. The shared conformance
 * fixture is what keeps that true; see `site/tests/regions/`.
 *
 * Everything is same-origin: the basemap, the database, and the WebAssembly
 * payload. Opening the map tells no third party where you are looking.
 */

import sqlite3InitModule from "./vendor/sqlite-wasm/sqlite3.mjs";
// MapLibre 6 ships named exports only, with no default. Importing the
// namespace keeps the call sites reading like the library's own
// documentation without pretending a default export exists.
import * as maplibregl from "./vendor/maplibre-gl/maplibre-gl.mjs";

import { decode, fromE6 } from "./geometry.mjs";
import { RegionDb, MEMBERSHIP_CORE } from "./regiondb.mjs";

const BASE = new URL(".", import.meta.url);

/** Layers in presentation order, with the color each is drawn in. */
const LAYERS = [
  { id: "commercial_airport", label: "Commercial airport", color: "#d64545" },
  { id: "positioned_iata", label: "Positioned IATA", color: "#e08a3c" },
  { id: "metro", label: "Metro", color: "#8a5cd6" },
  { id: "country", label: "Country", color: "#3c7fe0" },
  { id: "us_state", label: "US state", color: "#3ca08a" },
  { id: "custom", label: "Custom", color: "#c94f9c" },
];

/** Above this many parts in view, region fills are dropped for outlines. */
const FILL_BUDGET = 2500;

const state = {
  database: null,
  map: null,
  enabled: new Set(LAYERS.map((layer) => layer.id)),
  marker: null,
  placeMarkers: [],
};

// The app fills the viewport below the sticky site header, whose height is
// content-dependent; measure the real thing instead of guessing in CSS.
// The test harness has no header, and the stylesheet's fallback covers it.
const siteHeader = document.querySelector(".site-header");
if (siteHeader !== null) {
  const measure = () =>
    document.documentElement.style.setProperty(
      "--site-header-h",
      `${siteHeader.offsetHeight}px`,
    );
  measure();
  new ResizeObserver(measure).observe(siteHeader);
}

const ui = {
  status: document.getElementById("map-status"),
  result: document.getElementById("lookup-result"),
  layers: document.getElementById("layer-toggles"),
  search: document.getElementById("region-search"),
  coordinates: document.getElementById("coordinate-form"),
  meta: document.getElementById("database-meta"),
  file: document.getElementById("database-file"),
};

function setStatus(message, kind = "info") {
  ui.status.textContent = message;
  ui.status.dataset.kind = kind;
  ui.status.hidden = message === "";
}

/** Adapt the SQLite WASM binding to the row-array shape the reader expects. */
function makeHandle(sqlite3, bytes) {
  const pointer = sqlite3.wasm.allocFromTypedArray(bytes);
  const db = new sqlite3.oo1.DB();
  const rc = sqlite3.capi.sqlite3_deserialize(
    db.pointer,
    "main",
    pointer,
    bytes.length,
    bytes.length,
    sqlite3.capi.SQLITE_DESERIALIZE_FREEONCLOSE | sqlite3.capi.SQLITE_DESERIALIZE_RESIZEABLE,
  );
  if (rc !== 0) throw new Error(`could not open the database (SQLite error ${rc})`);
  return {
    exec(sql, params = []) {
      return db.exec({ sql, bind: params, rowMode: "array", returnValue: "resultRows" });
    },
  };
}

async function loadDatabase(bytes) {
  setStatus("Opening the database…");
  const sqlite3 = await sqlite3InitModule({ print: () => {}, printErr: () => {} });
  state.database = new RegionDb(makeHandle(sqlite3, bytes));
  renderMetadata();
  refreshRegions();
  setStatus("");
}

function renderMetadata() {
  const db = state.database;
  const sources = db.handle.exec(
    "SELECT name, license, attribution, url FROM sources ORDER BY source_key",
  );
  const counts = new Map(
    db.handle.exec("SELECT layer, COUNT(*) FROM regions GROUP BY layer"),
  );

  const rows = LAYERS.filter((layer) => counts.has(layer.id))
    .map((layer) => `<tr><td>${escape(layer.label)}</td><td>${counts.get(layer.id)}</td></tr>`)
    .join("");

  ui.meta.innerHTML = `
    <dl class="kv">
      <dt>Dataset</dt><dd>${escape(db.datasetVersion)}</dd>
      <dt>Format</dt><dd>${db.formatVersion}</dd>
      <dt>Regions</dt><dd>${db.regions.size}</dd>
      <dt>Content hash</dt><dd><code>${escape((db.metadata.get("content_hash") ?? "").slice(0, 16))}</code></dd>
    </dl>
    <table class="region-table"><tbody>${rows}</tbody></table>
    <h3>Sources</h3>
    <ul class="sources">
      ${sources
        .map(
          ([name, license, attribution, url]) =>
            `<li>${url ? `<a href="${escape(url)}" rel="noreferrer">${escape(name)}</a>` : escape(name)}
             — ${escape(license ?? "license unstated")}${attribution ? `, ${escape(attribution)}` : ""}</li>`,
        )
        .join("")}
    </ul>`;
}

/**
 * Load only the geometry the viewport needs.
 *
 * The world database holds thirteen thousand parts; handing all of them to
 * the map at once would stall the page for no benefit, since almost none of
 * it would be on screen.
 */
function refreshRegions() {
  const db = state.database;
  if (db === null || state.map === null) return;

  const bounds = state.map.getBounds();
  const west = bounds.getWest();
  const east = bounds.getEast();
  const south = bounds.getSouth();
  const north = bounds.getNorth();

  const features = [];
  // A viewport wider than the world, or one straddling the antimeridian,
  // is asked for in pieces rather than as one impossible box.
  const spans = east - west >= 360 ? [[-180, 180]] : splitAtAntimeridian(west, east);
  for (const [left, right] of spans) {
    for (const [regionId, payload] of db.handle.exec(
      "SELECT p.region_id, p.geometry FROM effective_rtree r " +
        "JOIN geometry_parts p ON p.id = r.part_id " +
        "WHERE r.max_lon >= ? AND r.min_lon <= ? AND r.max_lat >= ? AND r.min_lat <= ?",
      [left, right, south, north],
    )) {
      const region = db.regions.get(regionId);
      if (region === undefined || !state.enabled.has(region.layer)) continue;
      features.push({
        type: "Feature",
        properties: {
          regionKey: region.regionKey,
          layer: region.layer,
          code: region.code,
          radioName: region.radioName,
          expansionM: region.expansionM,
        },
        geometry: { type: "Polygon", coordinates: ringsToCoordinates(decode(payload)) },
      });
    }
  }

  state.map.getSource("regions").setData({ type: "FeatureCollection", features });
  const dense = features.length > FILL_BUDGET;
  for (const layer of LAYERS) {
    state.map.setLayoutProperty(
      `regions-fill-${layer.id}`,
      "visibility",
      dense ? "none" : "visible",
    );
  }
  setStatus(
    dense
      ? `${features.length} parts in view — fills hidden for legibility, outlines still exact.`
      : "",
  );
}

function splitAtAntimeridian(west, east) {
  return west <= east ? [[west, east]] : [[west, 180], [-180, east]];
}

function ringsToCoordinates(rings) {
  return rings.map((ring) => {
    const coordinates = [];
    for (let index = 0; index < ring.points.length; index += 2) {
      coordinates.push([fromE6(ring.points[index]), fromE6(ring.points[index + 1])]);
    }
    coordinates.push(coordinates[0]);
    return coordinates;
  });
}

function runLookup(latitude, longitude) {
  const db = state.database;
  if (db === null) {
    setStatus("Load a database first.", "warn");
    return;
  }

  let result;
  try {
    result = db.lookup(latitude, longitude);
  } catch (error) {
    setStatus(error.message, "warn");
    return;
  }

  if (state.marker !== null) state.marker.remove();
  state.marker = new maplibregl.Marker({ color: "#111" })
    .setLngLat([longitude, latitude])
    .addTo(state.map);

  // A four-column table cannot live honestly in a panel-width card — it
  // wraps its own tokens. Each match is a two-line row instead: the
  // semantic key with its membership, then the radio-facing string and
  // wire code beneath.
  const rows = result.matches
    .map((match) => {
      const core = match.membership === MEMBERSHIP_CORE;
      const layer = LAYERS.find((entry) => entry.id === match.layer);
      return `<li class="match-row">
        <span class="swatch" style="background:${layer ? layer.color : "#888"}"></span>
        <span class="match-main">
          <span class="match-key"><code>${escape(match.regionKey)}</code></span>
          <span class="match-detail">${escape(match.radioName)}
            · <code>0x${match.wireCode.toString(16).toUpperCase().padStart(4, "0")}</code></span>
        </span>
        <span class="match-membership${core ? "" : " match-membership--expanded"}"
          ${core ? "" : `title="Only the ${match.expansionM} m expansion margin reaches this position"`}
        >${core ? "core" : "expanded"}</span>
      </li>`;
    })
    .join("");

  const radio = result.radioRegions.map((region) => escape(region.name)).join(", ");
  const suggested = result.suggestedDefaultRegion;

  ui.result.innerHTML = `
    <h3>${latitude.toFixed(5)}, ${longitude.toFixed(5)}</h3>
    ${
      result.matches.length === 0
        ? "<p>No region covers this position.</p>"
        : `<ul class="match-list">${rows}</ul>
           <dl class="kv">
             <dt>Radio regions</dt><dd>${radio}</dd>
             <dt>Suggested default</dt><dd>${suggested ? escape(suggested.name) : "none"}</dd>
             <dt>Dataset</dt><dd>${escape(result.datasetVersion)}</dd>
           </dl>`
    }`;
  ui.result.hidden = false;
}

function searchRegions(query) {
  const db = state.database;
  if (db === null || query.trim() === "") return [];
  const needle = query.trim().toLowerCase();
  const found = [];
  for (const region of db.regions.values()) {
    if (
      region.code.toLowerCase().includes(needle) ||
      region.regionKey.toLowerCase().includes(needle) ||
      region.radioName.toLowerCase().includes(needle)
    ) {
      found.push(region);
      if (found.length >= 40) break;
    }
  }
  return found;
}

function zoomToRegion(region) {
  const bounds = state.database.handle.exec(
    "SELECT MIN(min_lon), MIN(min_lat), MAX(max_lon), MAX(max_lat) FROM geometry_parts " +
      "WHERE region_id = ?",
    [region.regionId],
  )[0];
  if (!bounds || bounds[0] === null) return;
  state.map.fitBounds(
    [
      [bounds[0], bounds[1]],
      [bounds[2], bounds[3]],
    ],
    { padding: 60, maxZoom: 11 },
  );
}

function escape(value) {
  return String(value).replace(/[&<>"']/g, (character) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[character],
  );
}

async function boot() {
  const style = {
    version: 8,
    sources: {
      land: { type: "geojson", data: new URL("basemap/land.geojson", BASE).href },
      admin0: { type: "geojson", data: new URL("basemap/admin0.geojson", BASE).href },
      admin1: { type: "geojson", data: new URL("basemap/admin1.geojson", BASE).href },
      regions: { type: "geojson", data: { type: "FeatureCollection", features: [] } },
    },
    layers: [
      { id: "ocean", type: "background", paint: { "background-color": "#0f1621" } },
      { id: "land", type: "fill", source: "land", paint: { "fill-color": "#1d2635" } },
      {
        id: "admin1-lines",
        type: "line",
        source: "admin1",
        paint: { "line-color": "#2f3d52", "line-width": 0.6 },
      },
      {
        id: "admin0-lines",
        type: "line",
        source: "admin0",
        paint: { "line-color": "#43536d", "line-width": 0.9 },
      },
      ...LAYERS.flatMap((layer) => [
        {
          id: `regions-fill-${layer.id}`,
          type: "fill",
          source: "regions",
          filter: ["==", ["get", "layer"], layer.id],
          paint: { "fill-color": layer.color, "fill-opacity": 0.14 },
        },
        {
          id: `regions-line-${layer.id}`,
          type: "line",
          source: "regions",
          filter: ["==", ["get", "layer"], layer.id],
          paint: { "line-color": layer.color, "line-width": 1.2 },
        },
      ]),
    ],
  };

  state.map = new maplibregl.Map({
    container: "map",
    style,
    center: [-122.2495, 37.5119],
    zoom: 7,
    hash: true,
    attributionControl: { customAttribution: "Basemap: Natural Earth (public domain)" },
  });
  state.map.addControl(new maplibregl.NavigationControl({ showCompass: false }), "top-right");
  state.map.addControl(new maplibregl.ScaleControl({ unit: "metric" }));

  state.map.on("load", () => {
    loadPlaces().catch(() => {});
    refreshRegions();
  });
  state.map.on("moveend", refreshRegions);
  state.map.on("click", (event) => runLookup(event.lngLat.lat, event.lngLat.lng));

  buildLayerToggles();
  wireControls();

  // The published database, when there is one. Until Phase 6 publishes it,
  // the file picker is how a local build gets opened.
  try {
    const response = await fetch(new URL("../world.regiondb", BASE));
    if (response.ok) {
      await loadDatabase(new Uint8Array(await response.arrayBuffer()));
      return;
    }
  } catch {
    /* fall through to the picker */
  }
  setStatus("No published database found. Choose a .regiondb file to inspect.", "warn");
}

async function loadPlaces() {
  const response = await fetch(new URL("basemap/places.json", BASE));
  const places = await response.json();
  const render = () => {
    for (const marker of state.placeMarkers) marker.remove();
    state.placeMarkers = [];
    const zoom = state.map.getZoom();
    const limit = zoom < 3 ? 40 : zoom < 6 ? 120 : 400;
    const bounds = state.map.getBounds();
    let shown = 0;
    for (const [name, longitude, latitude] of places) {
      if (shown >= limit) break;
      if (!bounds.contains([longitude, latitude])) continue;
      const element = document.createElement("span");
      element.className = "place-label";
      element.textContent = name;
      state.placeMarkers.push(
        new maplibregl.Marker({ element, anchor: "left" })
          .setLngLat([longitude, latitude])
          .addTo(state.map),
      );
      shown += 1;
    }
  };
  render();
  state.map.on("moveend", render);
}

function buildLayerToggles() {
  ui.layers.innerHTML = LAYERS.map(
    (layer) => `
      <label class="layer-toggle">
        <input type="checkbox" value="${layer.id}" checked />
        <span class="swatch" style="background:${layer.color}"></span>
        ${escape(layer.label)}
      </label>`,
  ).join("");
  ui.layers.addEventListener("change", (event) => {
    const input = event.target;
    if (input.checked) state.enabled.add(input.value);
    else state.enabled.delete(input.value);
    refreshRegions();
  });
}

function wireControls() {
  ui.coordinates.addEventListener("submit", (event) => {
    event.preventDefault();
    const data = new FormData(ui.coordinates);
    const latitude = Number.parseFloat(data.get("lat"));
    const longitude = Number.parseFloat(data.get("lon"));
    if (!Number.isFinite(latitude) || !Number.isFinite(longitude)) {
      setStatus("Enter a latitude and longitude in degrees.", "warn");
      return;
    }
    state.map.jumpTo({ center: [longitude, latitude], zoom: Math.max(state.map.getZoom(), 9) });
    runLookup(latitude, longitude);
  });

  ui.search.addEventListener("input", () => {
    const list = document.getElementById("search-results");
    const found = searchRegions(ui.search.value);
    list.innerHTML = found
      .map(
        (region) =>
          `<li><button type="button" data-region="${escape(region.regionKey)}">
             <code>${escape(region.regionKey)}</code> ${escape(region.radioName)}
           </button></li>`,
      )
      .join("");
    list.hidden = found.length === 0;
  });

  document.getElementById("search-results").addEventListener("click", (event) => {
    const button = event.target.closest("button[data-region]");
    if (button === null) return;
    for (const region of state.database.regions.values()) {
      if (region.regionKey === button.dataset.region) {
        zoomToRegion(region);
        return;
      }
    }
  });

  ui.file.addEventListener("change", async (event) => {
    const file = event.target.files?.[0];
    if (file === undefined) return;
    try {
      await loadDatabase(new Uint8Array(await file.arrayBuffer()));
    } catch (error) {
      setStatus(`Could not open that file: ${error.message}`, "warn");
    }
  });
}

boot().catch((error) => setStatus(error.message, "warn"));
