"""Writers: json (per endpoint), jsonl, csv, apitest YAML suite, Postman collection."""
from __future__ import annotations

import csv
import json
import re
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

from .model import Case, Endpoint

FORMATS = ("json", "jsonl", "csv", "apitest", "postman")
Result = Tuple[Endpoint, List[Case]]


def write_all(results: List[Result], out_dir: Path, formats: List[str], seed: int, name: str,
              base_url: Optional[str]) -> List[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    written: List[Path] = []
    if "json" in formats:
        written += write_json(results, out_dir, seed)
    if "jsonl" in formats:
        written.append(write_jsonl(results, out_dir / "cases.jsonl"))
    if "csv" in formats:
        written += write_csv(results, out_dir / "csv")
    if "apitest" in formats:
        written.append(write_apitest(results, out_dir / f"{_slug(name)}.api.yaml", name, base_url, seed))
    if "postman" in formats:
        written.append(write_postman(results, out_dir / f"{_slug(name)}.postman_collection.json", name, base_url))
    index = {
        "name": name, "seed": seed, "base_url": base_url,
        "endpoints": [{"endpoint": ep.key, "source": ep.source, "operationId": ep.operation_id,
                       "inferred": ep.inferred, "file": f"endpoints/{ep.slug}.json",
                       "counts": _counts(cases)} for ep, cases in results],
    }
    p = out_dir / "index.json"
    p.write_text(json.dumps(index, indent=2, ensure_ascii=False), encoding="utf-8")
    written.append(p)
    return written


def _counts(cases: List[Case]) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for c in cases:
        out[c.kind] = out.get(c.kind, 0) + 1
    return out


def _slug(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "-", s).strip("-").lower() or "synthetic"


def write_json(results: List[Result], out_dir: Path, seed: int) -> List[Path]:
    d = out_dir / "endpoints"
    d.mkdir(parents=True, exist_ok=True)
    paths = []
    for ep, cases in results:
        doc = {"endpoint": ep.key, "source": ep.source, "operationId": ep.operation_id, "summary": ep.summary,
               "contentType": ep.content_type if ep.body_schema is not None else None, "inferred": ep.inferred,
               "seed": seed}
        for kind in ("valid", "boundary", "invalid", "hostile"):
            sel = [c.to_dict() for c in cases if c.kind == kind]
            if sel:
                doc[kind] = sel
        p = d / f"{ep.slug}.json"
        p.write_text(json.dumps(doc, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
        paths.append(p)
    return paths


def write_jsonl(results: List[Result], path: Path) -> Path:
    with path.open("w", encoding="utf-8") as fh:
        for ep, cases in results:
            for c in cases:
                fh.write(json.dumps({"endpoint": ep.key, **c.to_dict()}, ensure_ascii=False, default=str) + "\n")
    return path


def _flatten(value: Any, prefix: str = "", out: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    out = {} if out is None else out
    if isinstance(value, dict) and value:
        for k, v in value.items():
            _flatten(v, f"{prefix}.{k}" if prefix else str(k), out)
    elif isinstance(value, list) and value and all(not isinstance(x, (dict, list)) for x in value):
        out[prefix or "value"] = "|".join("" if x is None else str(x) for x in value)
    elif isinstance(value, list) and value:
        for i, v in enumerate(value):
            _flatten(v, f"{prefix}[{i}]", out)
    else:
        out[prefix or "value"] = value
    return out


def write_csv(results: List[Result], out_dir: Path) -> List[Path]:
    """Valid data flattened to columns (data-driven tools); invalid cases with their rule."""
    out_dir.mkdir(parents=True, exist_ok=True)
    paths = []
    for ep, cases in results:
        rows = []
        for c in cases:
            if c.kind not in ("valid", "boundary"):
                continue
            row: Dict[str, Any] = {"case_id": c.id, "kind": c.kind}
            row.update({f"path.{k}": v for k, v in c.request.path_params.items()})
            row.update({f"query.{k}": v for k, v in c.request.query.items()})
            if c.request.has_body:
                row.update({f"body.{k}" if k != "value" else "body": v for k, v in _flatten(c.request.body).items()})
            rows.append(row)
        if rows:
            p = out_dir / f"{ep.slug}.valid.csv"
            _write_rows(p, rows)
            paths.append(p)
        bad = [{"case_id": c.id, "kind": c.kind, "category": c.category, "target": c.target, "expect": c.expect,
                "description": c.description, "url": c.request.url(),
                "body": json.dumps(c.request.body, ensure_ascii=False, default=str) if c.request.has_body else ""}
               for c in cases if c.kind in ("invalid", "hostile")]
        if bad:
            p = out_dir / f"{ep.slug}.negative.csv"
            _write_rows(p, bad)
            paths.append(p)
    return paths


def _write_rows(path: Path, rows: List[Dict[str, Any]]) -> None:
    cols: List[str] = []
    for r in rows:
        cols.extend(k for k in r if k not in cols)
    with path.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        for r in rows:
            w.writerow({k: ("" if r.get(k) is None else r.get(k)) for k in cols})


_EXPECT_STATUS = {"2xx": "2xx", "4xx": {"gte": 400, "lt": 500}, "not 5xx": {"lt": 500}}


def write_apitest(results: List[Result], path: Path, name: str, base_url: Optional[str], seed: int) -> Path:
    """Suite for the api-test-framework (pytest): one data-driven test per endpoint and kind."""
    tests = []
    for ep, cases in results:
        for kind, label in (("valid", "valid data"), ("boundary", "boundary values"),
                            ("invalid", "invalid data is rejected"), ("hostile", "hostile input does not crash")):
            sel = [c for c in cases if c.kind == kind]
            if not sel:
                continue
            t: Dict[str, Any] = {"name": f"{ep.key} - {label}", ep.method.lower(): "{{url}}"}
            if ep.body_schema is not None:
                if ep.content_type == "application/x-www-form-urlencoded":
                    t["form"] = "{{body}}"
                else:
                    t["json"] = "{{body}}"
            rows = []
            for c in sel:
                row: Dict[str, Any] = {"id": c.id, "url": c.request.url()}
                if ep.body_schema is not None:
                    row["body"] = c.request.body if c.request.has_body else None
                rows.append(row)
            t["cases"] = rows
            t["expect"] = {"status": _EXPECT_STATUS[sel[0].expect]}
            t["tags"] = ["generated", kind]
            tests.append(t)
    doc: Dict[str, Any] = {"name": f"{name} (synthetic)"}
    if base_url and re.match(r"(?i)^https?://", base_url):
        doc["base_url"] = base_url
    doc["defaults"] = {"headers": {"Accept": "application/json"}}
    doc["tests"] = tests
    header = (f"# Generated by apisynth (seed {seed}). Run with the api-test-framework:  pytest {path.name}\n"
              "# Add auth under defaults, e.g.  auth: {bearer: \"{{token}}\"}  or set baseUrl in your environment.\n"
              "# Invalid cases expect a 4xx; 'expect.status' can be tightened per test (e.g. 400 or 422).\n")
    path.write_text(header + yaml.safe_dump(doc, sort_keys=False, allow_unicode=True, width=120), encoding="utf-8")
    return path


def write_postman(results: List[Result], path: Path, name: str, base_url: Optional[str]) -> Path:
    folders = []
    for ep, cases in results:
        items = []
        for c in cases:
            req: Dict[str, Any] = {"method": ep.method, "header": [],
                                   "url": {"raw": "{{baseUrl}}" + c.request.url()}}
            if c.request.has_body:
                if ep.content_type == "application/x-www-form-urlencoded" and isinstance(c.request.body, dict):
                    req["body"] = {"mode": "urlencoded", "urlencoded": [
                        {"key": k, "value": "" if v is None else str(v)} for k, v in c.request.body.items()]}
                else:
                    req["body"] = {"mode": "raw", "raw": json.dumps(c.request.body, indent=2, ensure_ascii=False, default=str),
                                   "options": {"raw": {"language": "json"}}}
                    req["header"].append({"key": "Content-Type", "value": "application/json"})
            test = {
                "2xx": "pm.test('2xx', () => pm.expect(pm.response.code).to.be.within(200, 299));",
                "4xx": "pm.test('rejected with 4xx', () => pm.expect(pm.response.code).to.be.within(400, 499));",
                "not 5xx": "pm.test('no server error', () => pm.expect(pm.response.code).to.be.below(500));",
            }[c.expect]
            items.append({"name": f"[{c.kind}] {c.id}", "request": req,
                          "event": [{"listen": "test", "script": {"type": "text/javascript", "exec": [test]}}]})
        folders.append({"name": ep.key, "item": items})
    col = {"info": {"_postman_id": str(uuid.uuid5(uuid.NAMESPACE_URL, name)), "name": f"{name} (synthetic)",
                    "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
           "variable": [{"key": "baseUrl", "value": base_url or "http://localhost:8000"}],
           "item": folders}
    path.write_text(json.dumps(col, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    return path
