"""Command line entry point.

The commands are split along one line: `fetch` is the only one that touches the
network, `update` the only one that reads `regions/vendor/`, and everything
after that runs on the committed tree alone.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_DEFAULT_ROOT = Path("regions")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="regiondb-build", description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=REPO_DEFAULT_ROOT,
        help="source tree to operate on (default: regions)",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    fetch_command = commands.add_parser("fetch", help="download pinned upstream data")
    fetch_command.add_argument("--only", help="fetch a single source by id")

    update_command = commands.add_parser(
        "update", help="distill vendor data into committed extracts"
    )
    update_command.add_argument(
        "--check",
        action="store_true",
        help="re-derive the extracts and fail if the committed ones differ",
    )

    build_command = commands.add_parser("build", help="compile a source tree into a .regiondb")
    build_command.add_argument("--output", type=Path, help="database path to write")
    build_command.add_argument("--dataset-version", default=None, help="version to stamp")
    build_command.add_argument("--created-at", default=None, help="RFC 3339 build timestamp")
    build_command.add_argument("--report", type=Path, help="where to write build-report.json")

    validate_command = commands.add_parser("validate", help="check a database against the fixtures")
    validate_command.add_argument("--db", type=Path, required=True)
    validate_command.add_argument("--points", type=Path, help="known-points file to check")
    validate_command.add_argument(
        "--sample", type=int, default=0, help="random points to cross-check against exact lookup"
    )
    validate_command.add_argument("--seed", type=int, default=20260821)

    lookup_command = commands.add_parser("lookup", help="look up a position")
    lookup_command.add_argument("--db", type=Path, required=True)
    lookup_command.add_argument("--lat", type=float, required=True)
    lookup_command.add_argument("--lon", type=float, required=True)
    lookup_command.add_argument("--detailed", action="store_true")
    lookup_command.add_argument("--json", action="store_true")
    lookup_command.add_argument("--exhaustive", action="store_true", help="bypass the lookup cache")

    inspect_command = commands.add_parser("inspect", help="describe a region by code or key")
    inspect_command.add_argument("--db", type=Path, required=True)
    inspect_command.add_argument("code")

    export_command = commands.add_parser("export-geojson", help="dump geometry for inspection")
    export_command.add_argument("--db", type=Path, required=True)
    export_command.add_argument("--region", help="a single region key")
    export_command.add_argument("--layer", help="every region in a layer")
    export_command.add_argument("--output", type=Path)

    diff_command = commands.add_parser("diff", help="compare two build reports")
    diff_command.add_argument("old", type=Path)
    diff_command.add_argument("new", type=Path)

    conformance_command = commands.add_parser(
        "gen-conformance", help="regenerate the cross-implementation fixture"
    )
    conformance_command.add_argument("--db", type=Path, required=True)
    conformance_command.add_argument("--output", type=Path, required=True)
    conformance_command.add_argument("--points", type=Path)
    conformance_command.add_argument("--sample", type=int, default=0)
    conformance_command.add_argument("--seed", type=int, default=20260821)

    args = parser.parse_args(argv)
    handler = {
        "fetch": _fetch,
        "update": _update,
        "build": _build,
        "validate": _validate,
        "lookup": _lookup,
        "inspect": _inspect,
        "export-geojson": _export,
        "diff": _diff,
        "gen-conformance": _gen_conformance,
    }[args.command]
    return handler(args)


def _fetch(args) -> int:
    from . import fetch

    root = args.root
    for line in fetch.fetch(
        root / "upstream" / "sources.yaml",
        root / "upstream" / "lock.json",
        root / "vendor",
        only=args.only,
    ):
        print(line)
    return 0


def _update(args) -> int:
    from . import extract

    result = extract.update(args.root, check=args.check)
    for line in result.report:
        print(line)
    if args.check and result.differences:
        print("\nCommitted extracts differ from what the update pass produces:", file=sys.stderr)
        for path in result.differences:
            print(f"  {path}", file=sys.stderr)
        return 1
    return 0


def _build(args) -> int:
    from . import build as build_module
    from . import report as report_module

    output = args.output or (args.root / "dist" / "world.regiondb")
    version = args.dataset_version or "0.0.0-dev"
    outcome = build_module.build(
        args.root, output, dataset_version=version, created_at=args.created_at
    )
    report_path = args.report or output.with_name("build-report.json")
    report_module.write(report_path, outcome.report)
    print(report_module.summarize(outcome.report))
    print(f"  wrote {output} and {report_path}")
    return 0


def _validate(args) -> int:
    from . import validate as validate_module

    failures = validate_module.run(args.db, points=args.points, sample=args.sample, seed=args.seed)
    for failure in failures:
        print(failure, file=sys.stderr)
    if failures:
        print(f"{len(failures)} validation failures", file=sys.stderr)
        return 1
    print("validation passed")
    return 0


def _lookup(args) -> int:
    from .lookup import RegionDb

    with RegionDb(args.db) as database:
        result = database.lookup(args.lat, args.lon, exhaustive=args.exhaustive)

    if args.json:
        print(json.dumps(_lookup_json(result), indent=2))
        return 0

    print(f"{args.lat}, {args.lon}  [dataset {result.dataset_version}]")
    if args.detailed:
        for match in result.matches:
            membership = "core" if match.membership == 0 else "expanded"
            print(
                f"  {match.region_key:<28} {match.radio_name:<24} 0x{match.wire_code:04X}  "
                f"{match.layer} ({membership})"
            )
    print("  radio regions: " + (", ".join(item.name for item in result.radio_regions) or "none"))
    default = result.suggested_default_region
    print(f"  suggested default: {default.name if default else 'none'}")
    return 0


def _lookup_json(result) -> dict:
    return {
        "position": {"latitude": result.latitude, "longitude": result.longitude},
        "dataset_version": result.dataset_version,
        "matches": [
            {
                "key": match.region_key,
                "radio_name": match.radio_name,
                "wire_code": f"0x{match.wire_code:04X}",
                "kind": match.layer,
                "membership": "core" if match.membership == 0 else "expanded",
            }
            for match in result.matches
        ],
        "radio_regions": [item.name for item in result.radio_regions],
        "suggested_default_region": (
            result.suggested_default_region.name if result.suggested_default_region else None
        ),
    }


def _inspect(args) -> int:
    import sqlite3

    connection = sqlite3.connect(f"file:{args.db}?mode=ro", uri=True)
    namespace, _, code = args.code.partition(":")
    if code:
        where, parameters = "namespace = ? AND code = ? COLLATE NOCASE", (namespace, code)
    else:
        where, parameters = "code = ? COLLATE NOCASE", (args.code,)
    rows = connection.execute(
        f"SELECT id, namespace, code, radio_name, wire_code, layer, "
        f"priority, default_rank, expansion_m, site_lon, site_lat FROM regions "
        f"WHERE {where} ORDER BY priority",
        parameters,
    ).fetchall()
    if not rows:
        print(f"no region matches {args.code!r}", file=sys.stderr)
        return 1
    for row in rows:
        print(f"{row[1]}:{row[2]}")
        print(f"  radio name      {row[3] if row[3] is not None else row[2]}  0x{row[4]:04X}")
        print(f"  layer           {row[5]} (priority {row[6]}, default rank {row[7]})")
        print(f"  expansion       {row[8]} m")
        if row[9] is not None:
            print(f"  site            {row[10]}, {row[9]}")
        count = connection.execute(
            "SELECT COUNT(*) FROM geometry_parts WHERE region_id = ?", (row[0],)
        ).fetchone()[0]
        print(f"  core parts      {count}")
        for detail in connection.execute(
            "SELECT detail FROM provenance WHERE region_id = ? ORDER BY detail",
            (row[0],),
        ):
            print(f"  provenance      {detail[0]}")
    connection.close()
    return 0


def _export(args) -> int:
    import sqlite3

    from . import blob

    connection = sqlite3.connect(f"file:{args.db}?mode=ro", uri=True)
    if args.region:
        namespace, _, code = args.region.partition(":")
        if not code:
            print("region takes a namespaced key, as in iata-airport:MFR", file=sys.stderr)
            return 1
        where, parameters = "r.namespace = ? AND r.code = ?", (namespace, code)
    elif args.layer:
        where, parameters = "r.layer = ?", (args.layer,)
    else:
        print("give --region or --layer", file=sys.stderr)
        return 1

    features = []
    for namespace, code, expansion_m, payload in connection.execute(
        f"SELECT r.namespace, r.code, r.expansion_m, p.geometry FROM geometry_parts p "
        f"JOIN regions r ON r.id = p.region_id WHERE {where} "
        "ORDER BY r.namespace, r.code, p.id",
        parameters,
    ):
        rings = blob.decode(payload)
        coordinates = []
        for ring in rings:
            points = [[blob.from_e6(x), blob.from_e6(y)] for x, y in ring.points]
            points.append(points[0])
            coordinates.append(points)
        features.append(
            {
                "type": "Feature",
                "properties": {
                    "region_key": f"{namespace}:{code}",
                    # Only core geometry exists; the expansion margin is a
                    # number resolved at lookup time, exported here so a
                    # viewer can draw the fuzzy edge itself if it wants to.
                    "expansion_m": expansion_m,
                },
                "geometry": {"type": "Polygon", "coordinates": coordinates},
            }
        )
    connection.close()

    document = {"type": "FeatureCollection", "features": features}
    text = json.dumps(document, indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text + "\n")
        print(f"wrote {len(features)} features to {args.output}")
    else:
        print(text)
    return 0


def _diff(args) -> int:
    from . import report as report_module

    old = json.loads(args.old.read_text())
    new = json.loads(args.new.read_text())
    print(json.dumps(report_module.diff(old, new), indent=2))
    return 0


def _gen_conformance(args) -> int:
    from . import conformance

    count = conformance.generate(
        args.db, args.output, points=args.points, sample=args.sample, seed=args.seed
    )
    print(f"wrote {count} conformance cases to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
