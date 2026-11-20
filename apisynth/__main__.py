"""Command line: ``python -m apisynth <command>``

  generate   Generate synthetic request data (valid, boundary, invalid, hostile)
  endpoints  List the endpoints found in the sources
  infer      Print the JSON Schema inferred from live URLs / sample files
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional

from .core import Options, Sources, generate_cases, load_endpoints, select
from .output import FORMATS, write_all


def _add_sources(p: argparse.ArgumentParser) -> None:
    g = p.add_argument_group("sources (any combination, each repeatable)")
    g.add_argument("--openapi", "-s", action="append", default=[], metavar="FILE|URL",
                   help="OpenAPI 3.x / Swagger 2.0 spec (JSON or YAML)")
    g.add_argument("--postman", "-p", action="append", default=[], metavar="FILE|URL", help="Postman collection")
    g.add_argument("--url", "-u", action="append", default=[], metavar="URL[ -> METHOD /path]",
                   help="live API URL to GET; the response shape is inferred. Default target: POST <path without id>")
    g.add_argument("--sample", action="append", default=[], metavar="FILE[ -> METHOD /path]",
                   help="example JSON payload/response file to infer from")
    g.add_argument("-H", "--header", action="append", default=[], metavar="'Name: value'",
                   help="header for fetching specs/URLs, e.g. auth")
    f = p.add_argument_group("filters")
    f.add_argument("--include", "-i", action="append", default=[], metavar="PATTERN",
                   help="only endpoints matching, e.g. 'POST /users*' or '/orders*' or an operationId")
    f.add_argument("--exclude", "-x", action="append", default=[], metavar="PATTERN")
    f.add_argument("--tag", action="append", default=[], help="only endpoints with this OpenAPI tag")


def _sources(a: argparse.Namespace) -> Sources:
    headers = {}
    for h in a.header:
        k, _, v = h.partition(":")
        headers[k.strip()] = v.strip()
    return Sources(openapi=a.openapi, postman=a.postman, urls=a.url, samples=a.sample, headers=headers)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m apisynth", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("generate", help="generate synthetic request data")
    _add_sources(g)
    o = g.add_argument_group("generation")
    o.add_argument("-n", "--count", type=int, default=5, help="valid requests per endpoint (default 5)")
    o.add_argument("--seed", type=int, help="seed for reproducible data (default: random, printed)")
    o.add_argument("--no-invalid", action="store_true", help="skip negative (schema-violating) cases")
    o.add_argument("--no-boundary", action="store_true", help="skip exact-limit boundary cases")
    o.add_argument("--hostile", action="store_true", help="add SQL-injection/XSS/unicode strings (expect no 5xx)")
    o.add_argument("--optional-rate", type=float, default=0.7, help="chance an optional field is included (0-1)")
    o.add_argument("--max-invalid", type=int, default=200, help="cap on invalid cases per endpoint")
    o.add_argument("--prefer-examples", action="store_true", help="use schema examples when present")
    o.add_argument("--methods", help="comma list, e.g. POST,PUT,PATCH (default: endpoints with body or params)")
    w = g.add_argument_group("output")
    w.add_argument("-o", "--out", default="synthetic-data", help="output directory (default synthetic-data/)")
    w.add_argument("-f", "--format", default="json", help=f"comma list of {', '.join(FORMATS)} (default json)")
    w.add_argument("--name", help="dataset name (default from the first source)")
    w.add_argument("--base-url", help="base URL written into apitest/postman exports (default: spec servers)")
    w.add_argument("--strict", action="store_true", help="exit 1 if the self-check finds any problem")

    e = sub.add_parser("endpoints", help="list endpoints found in the sources")
    _add_sources(e)

    i = sub.add_parser("infer", help="print the JSON Schema inferred from --url / --sample / --postman")
    _add_sources(i)

    a = parser.parse_args(argv)
    src = _sources(a)
    if src.empty():
        parser.error("give at least one source: --openapi, --postman, --url or --sample")

    try:
        eps, spec_base = load_endpoints(src)
    except (ValueError, FileNotFoundError, OSError) as ex:
        print(f"error: {ex}", file=sys.stderr)
        return 2
    eps = select(eps, a.include, a.exclude, a.tag)
    if not eps:
        print("No endpoints matched.", file=sys.stderr)
        return 1

    if a.cmd == "endpoints":
        for ep in eps:
            body = "body" if ep.body_schema is not None else "    "
            params = ",".join(f"{p.location[0]}:{p.name}" for p in ep.params)
            print(f"{ep.method:7} {ep.path:40} {body}  {params:30} {ep.operation_id or ep.summary or ''}"
                  f"{'  (inferred)' if ep.inferred else ''}")
        print(f"\n{len(eps)} endpoint(s)")
        return 0

    if a.cmd == "infer":
        for ep in eps:
            print(f"# {ep.key}  ({ep.source})")
            print(json.dumps(ep.body_schema, indent=2))
        return 0

    formats = [f.strip().lower() for f in a.format.split(",") if f.strip()]
    bad = [f for f in formats if f not in FORMATS]
    if bad:
        parser.error(f"unknown format(s) {bad}; choose from {', '.join(FORMATS)}")
    opts = Options(count=a.count, seed=a.seed, invalid=not a.no_invalid, boundary=not a.no_boundary,
                   hostile=a.hostile, optional_rate=a.optional_rate, max_invalid=a.max_invalid,
                   prefer_examples=a.prefer_examples,
                   methods=[m.strip().upper() for m in a.methods.split(",")] if a.methods else None)
    results, problems, seed = generate_cases(eps, opts)
    if not results:
        print("No endpoints with request data to generate (use --methods GET to include parameter-less GETs).",
              file=sys.stderr)
        return 1
    name = a.name or _default_name(src)
    base_url = a.base_url or spec_base
    written = write_all(results, Path(a.out), formats, seed, name, base_url)

    print(f"{'endpoint':52} {'valid':>5} {'bound':>5} {'invalid':>7} {'hostile':>7}")
    for ep, cases in results:
        k = {kind: sum(1 for c in cases if c.kind == kind) for kind in ("valid", "boundary", "invalid", "hostile")}
        print(f"{ep.key[:52]:52} {k['valid']:>5} {k['boundary']:>5} {k['invalid']:>7} {k['hostile']:>7}")
    total = sum(len(c) for _, c in results)
    print(f"\n{total} case(s) for {len(results)} endpoint(s), seed {seed} -> {a.out}/ ({', '.join(formats)})")
    if problems:
        print(f"\nself-check: {len(problems)} case(s) don't match the schema as intended:", file=sys.stderr)
        for p in problems[:20]:
            print("  - " + p, file=sys.stderr)
        if a.strict:
            return 1
    else:
        print("self-check: every case validates (or fails) against the schema as intended")
    return 0


def _default_name(src: Sources) -> str:
    import re
    first = (src.openapi or src.postman or src.urls or src.samples)[0]
    stem = re.split(r"[/\\]", first.split("->")[0].strip().rstrip("/"))[-1]
    return re.sub(r"(\.postman_collection)?\.(json|ya?ml)$", "", stem) or "synthetic"


if __name__ == "__main__":
    sys.exit(main())
