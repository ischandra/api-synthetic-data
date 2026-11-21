"""Command line: ``python -m apisynth <command>``

  test       Test any API end to end: find its spec, generate data, call it, report bugs
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
    o.add_argument("--param", action="append", default=[], metavar="NAME=VALUE",
                   help="pin a path/query/header parameter in every case except those testing it, "
                        "e.g. --param userId=42 (the id of a record that exists)")
    o.add_argument("--methods", help="comma list, e.g. POST,PUT,PATCH (default: endpoints with body or params)")
    w = g.add_argument_group("output")
    w.add_argument("-o", "--out", default="synthetic-data", help="output directory (default synthetic-data/)")
    w.add_argument("-f", "--format", default="json", help=f"comma list of {', '.join(FORMATS)} (default json)")
    w.add_argument("--name", help="dataset name (default from the first source)")
    w.add_argument("--base-url", help="base URL written into apitest/postman exports (default: spec servers)")
    w.add_argument("--auth", default="auto",
                   help="auth in apitest/postman exports: auto (from the spec's security, default), none, bearer, "
                        "basic, apikey:<Header-Name>. Credentials stay variables ({{token}}, {{username}}...)")
    w.add_argument("--strict", action="store_true", help="exit 1 if the self-check finds any problem")

    t = sub.add_parser("test", help="test any API end to end: find its spec, generate data, call it, report",
                       description="Point it at an API: its base URL, a spec/Swagger UI URL, a Postman collection, "
                                   "or a file. It finds the spec, generates valid/boundary/invalid data, calls the "
                                   "API and reports bugs. Safe by default: never changes records it didn't create.")
    t.add_argument("targets", nargs="*", metavar="URL|FILE",
                   help="API base URL, spec or Swagger UI URL, Postman collection, or spec file")
    _add_sources(t)
    r = t.add_argument_group("calling the API")
    r.add_argument("--base-url", help="API base URL (default: from the spec, resolved against its location)")
    r.add_argument("--token", help="bearer / OAuth2 access token")
    r.add_argument("--api-key", help="API key value (header name from the spec, or --api-key-header)")
    r.add_argument("--api-key-header", help="API key header name when the spec doesn't say (default X-API-Key)")
    r.add_argument("--basic", metavar="USER:PASS", help="HTTP basic credentials")
    r.add_argument("--mode", choices=["safe", "read", "all"], default="safe",
                   help="safe (default): PUT/PATCH/DELETE only on records this run created; read: GET only; "
                        "all: may change existing records")
    r.add_argument("--rps", type=float, default=5.0, help="max requests per second (default 5)")
    r.add_argument("--timeout", type=float, default=30.0, help="per-request timeout in seconds")
    r.add_argument("--insecure", action="store_true", help="don't verify TLS certificates")
    r.add_argument("--param", action="append", default=[], metavar="NAME=VALUE",
                   help="use this value for a path/query parameter, e.g. --param userId=42")
    tg = t.add_argument_group("test data")
    tg.add_argument("-n", "--count", type=int, default=3, help="valid requests per endpoint (default 3)")
    tg.add_argument("--seed", type=int, help="seed for reproducible data (default: random, printed)")
    tg.add_argument("--hostile", action="store_true", help="also send SQL-injection/XSS/unicode strings "
                                                           "(only on APIs you're allowed to security-test)")
    tg.add_argument("--no-invalid", action="store_true")
    tg.add_argument("--no-boundary", action="store_true")
    tg.add_argument("--max-invalid", type=int, default=40, help="cap on invalid cases per endpoint (default 40)")
    rp = t.add_argument_group("report")
    rp.add_argument("-o", "--out", default="api-test-report", help="report directory (default api-test-report/)")
    rp.add_argument("--fail-on", default="server-error,validation-gap,valid-rejected",
                    help="bug categories that make the exit code 1 (comma list, or 'none')")
    rp.add_argument("-q", "--quiet", action="store_true", help="no per-endpoint progress")

    e = sub.add_parser("endpoints", help="list endpoints found in the sources")
    _add_sources(e)

    i = sub.add_parser("infer", help="print the JSON Schema inferred from --url / --sample / --postman")
    _add_sources(i)

    a = parser.parse_args(argv)
    if a.cmd == "test":
        return _test(a, parser)
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
                   prefer_examples=a.prefer_examples, params=_params(a.param, parser),
                   methods=[m.strip().upper() for m in a.methods.split(",")] if a.methods else None)
    results, problems, seed = generate_cases(eps, opts)
    if not results:
        print("No endpoints with request data to generate (use --methods GET to include parameter-less GETs).",
              file=sys.stderr)
        return 1
    name = a.name or _default_name(src)
    base_url = a.base_url or spec_base
    try:
        written = write_all(results, Path(a.out), formats, seed, name, base_url, a.auth)
    except ValueError as ex:
        parser.error(str(ex))

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


def _test(a: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    import time
    from datetime import datetime, timezone

    from .core import select as select_eps
    from .fetch import discover, is_url
    from .report import console, totals, write_reports
    from .runner import BUG_CATEGORIES, Credentials, Runner, Unreachable
    from .sources.openapi import load_openapi
    from .sources.postman import load_postman

    say = (lambda m: None) if a.quiet else (lambda m: print(m, flush=True))
    src = _sources(a)
    if not a.targets and src.empty():
        parser.error("give the API to test: a base URL, spec URL, Postman collection or file")
    eps, spec_base = [], None
    spec_label = []
    try:
        for target in a.targets:
            kind, location, doc = discover(target, src.headers)
            say(f"Found {kind} description: {location}")
            spec_label.append(location)
            if kind == "openapi":
                found, base = load_openapi(location, src.headers, raw=doc)
                eps += found
                spec_base = spec_base or base
            else:
                eps += load_postman(location, src.headers)
                var = {v.get("key"): v.get("value") for v in (doc.get("variable") or [])}
                if not spec_base and isinstance(var.get("baseUrl"), str) and is_url(var["baseUrl"]):
                    spec_base = var["baseUrl"]
        if not src.empty():
            more, base = load_endpoints(src)
            eps += more
            spec_base = spec_base or base
    except (ValueError, FileNotFoundError, OSError) as ex:
        print(f"error: {ex}", file=sys.stderr)
        return 2
    base_url = a.base_url or spec_base
    if not base_url and src.urls:
        from urllib.parse import urlsplit
        u = urlsplit(src.urls[0].split("->")[0].strip())
        base_url = f"{u.scheme}://{u.netloc}"
    if not base_url or not is_url(base_url):
        print("error: can't tell the API's base URL from the spec; pass --base-url https://...", file=sys.stderr)
        return 2
    eps = select_eps(eps, a.include, a.exclude, a.tag)
    if not eps:
        print("No endpoints matched.", file=sys.stderr)
        return 1

    params = _params(a.param, parser)
    opts = Options(count=a.count, seed=a.seed, invalid=not a.no_invalid, boundary=not a.no_boundary,
                   hostile=a.hostile, max_invalid=a.max_invalid, methods=None)
    # parameters are resolved at run time (created/discovered records), so generate without pinning
    results, problems, seed = generate_cases(eps, Options(**{**opts.__dict__, "methods": ["GET", "HEAD", "POST", "PUT",
                                                                                         "PATCH", "DELETE", "OPTIONS"]}))
    n_cases = sum(len(c) for _, c in results)
    say(f"Testing {len(results)} endpoint(s) at {base_url}: {n_cases} cases, seed {seed}, mode {a.mode}")
    if problems:
        say(f"warning: self-check found {len(problems)} generated case(s) that don't match the schema as intended")

    basic = tuple(a.basic.split(":", 1)) if a.basic and ":" in a.basic else None
    creds = Credentials(token=a.token, api_key=a.api_key, api_key_name=a.api_key_header, basic=basic)
    runner = Runner(base_url, creds, headers=src.headers, mode=a.mode, rps=a.rps, timeout=a.timeout,
                    pinned=params, verify_tls=not a.insecure, progress=say)
    started = time.time()
    try:
        outcomes = runner.run(results)
    except Unreachable as ex:
        print(f"error: {ex}. Check the URL/network, or pass --base-url if the spec's server is wrong.",
              file=sys.stderr)
        return 2

    hints = []
    t = totals(outcomes)
    if runner.missing_credentials:
        hints.append(f"The spec asks for {', '.join(sorted(runner.missing_credentials))} credentials that weren't "
                     f"given; protected endpoints may only show 401/403. Pass --token / --api-key / --basic.")
    if any(o.category == "missing-data" for o in outcomes):
        hints.append("Some cases were skipped because no suitable record existed; --param NAME=VALUE supplies one.")
    meta = {"title": (doc.get("info") or {}).get("title") if a.targets and isinstance(doc, dict) else "API",
            "target": " ".join(a.targets) or None, "spec": ", ".join(spec_label) or None, "base_url": base_url,
            "mode": a.mode, "seed": seed, "requests": runner.requests_sent,
            "started": datetime.fromtimestamp(started, timezone.utc).isoformat(timespec="seconds"),
            "duration_s": round(time.time() - started, 1), "hints": hints}
    print(console(outcomes, meta))
    paths = write_reports(outcomes, Path(a.out), meta)
    print(f"\nReports: {', '.join(str(p) for p in paths)}")
    fail_on = set() if a.fail_on.strip() == "none" else {x.strip() for x in a.fail_on.split(",") if x.strip()}
    unknown = fail_on - set(BUG_CATEGORIES)
    if unknown:
        parser.error(f"unknown --fail-on categories {sorted(unknown)}; choose from {', '.join(BUG_CATEGORIES)}")
    return 1 if any(o.verdict == "bug" and o.category in fail_on for o in outcomes) else 0


def _params(items: List[str], parser: argparse.ArgumentParser) -> dict:
    out = {}
    for item in items:
        if "=" not in item:
            parser.error(f"--param expects NAME=VALUE, got '{item}'")
        k, v = item.split("=", 1)
        try:
            out[k.strip()] = json.loads(v)  # 42 -> int, true -> bool, "x" -> str
        except ValueError:
            out[k.strip()] = v
    return out


def _default_name(src: Sources) -> str:
    import re
    first = (src.openapi or src.postman or src.urls or src.samples)[0]
    stem = re.split(r"[/\\]", first.split("->")[0].strip().rstrip("/"))[-1]
    return re.sub(r"(\.postman_collection)?\.(json|ya?ml)$", "", stem) or "synthetic"


if __name__ == "__main__":
    sys.exit(main())
