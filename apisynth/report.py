"""Test reports: console summary, Markdown, JSON and JUnit XML (for Jenkins/GitHub)."""
from __future__ import annotations

import json
import shlex
import xml.etree.ElementTree as ET
from collections import Counter, OrderedDict, defaultdict
from pathlib import Path
from typing import Any, Dict, List

from .runner import Outcome

TITLES = OrderedDict([
    ("server-error", "Server errors (5xx)"),
    ("validation-gap", "Validation gaps: invalid data accepted"),
    ("valid-rejected", "Valid data rejected"),
])
ATTENTION = OrderedDict([
    ("auth", "Not authorised (401/403): credentials missing or insufficient"),
    ("not-found", "Record not found (404) for a valid request"),
    ("missing-data", "Skipped: no existing record to use"),
    ("rate-limited", "Rate limited (429)"),
    ("request-error", "Network / request errors"),
    ("skipped", "Skipped for safety or by mode"),
])


def curl(req: Dict[str, Any]) -> str:
    if not req:
        return ""
    parts = ["curl", "-X", req.get("method", "GET"), shlex.quote(req.get("url", ""))]
    for k, v in (req.get("headers") or {}).items():
        if k.lower() not in ("user-agent", "accept-encoding", "connection", "content-length"):
            parts += ["-H", shlex.quote(f"{k}: {v}")]
    if req.get("body") is not None:
        parts += ["--data-raw", shlex.quote(json.dumps(req["body"], ensure_ascii=False, default=str))]
    return " ".join(parts)


def totals(outcomes: List[Outcome]) -> Dict[str, int]:
    c = Counter(o.verdict for o in outcomes)
    return {"cases": len(outcomes), "passed": c["pass"], "bugs": c["bug"], "attention": c["attention"],
            "skipped": c["skip"]}


def console(outcomes: List[Outcome], meta: Dict[str, Any]) -> str:
    t = totals(outcomes)
    lines = ["", f"Results: {t['passed']} passed, {t['bugs']} bugs, {t['attention']} need attention, "
                 f"{t['skipped']} skipped ({t['cases']} cases, {meta.get('requests', 0)} requests)"]
    by_cat = defaultdict(list)
    for o in outcomes:
        if o.verdict in ("bug", "attention", "skip"):
            by_cat[o.category].append(o)
    for cat, title in list(TITLES.items()) + list(ATTENTION.items()):
        items = by_cat.get(cat)
        if not items:
            continue
        lines.append(f"\n{title}: {len(items)}")
        per_ep = defaultdict(list)
        for o in items:
            per_ep[o.endpoint].append(o)
        for ep, os_ in per_ep.items():
            lines.append(f"  {ep}  ({len(os_)})")
            shown = os_ if cat in TITLES else os_[:1]
            for o in shown[:6]:
                lines.append(f"    - [{o.case.id}] {o.detail}")
            if len(shown) > 6:
                lines.append(f"    - ... {len(shown) - 6} more (see the report)")
    for hint in meta.get("hints", []):
        lines.append(f"\nNote: {hint}")
    return "\n".join(lines)


def write_reports(outcomes: List[Outcome], out_dir: Path, meta: Dict[str, Any]) -> List[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    paths = [_json(outcomes, out_dir / "report.json", meta), _junit(outcomes, out_dir / "junit.xml", meta),
             _markdown(outcomes, out_dir / "report.md", meta)]
    return paths


def _json(outcomes: List[Outcome], path: Path, meta: Dict[str, Any]) -> Path:
    path.write_text(json.dumps({"meta": meta, "totals": totals(outcomes), "results": [o.to_dict() for o in outcomes]},
                               indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    return path


def _junit(outcomes: List[Outcome], path: Path, meta: Dict[str, Any]) -> Path:
    root = ET.Element("testsuites", name=f"apisynth {meta.get('title', '')}".strip())
    per_ep: Dict[str, List[Outcome]] = OrderedDict()
    for o in outcomes:
        per_ep.setdefault(o.endpoint, []).append(o)
    for ep, os_ in per_ep.items():
        suite = ET.SubElement(root, "testsuite", name=ep, tests=str(len(os_)),
                              failures=str(sum(o.verdict == "bug" for o in os_)),
                              skipped=str(sum(o.verdict in ("skip", "attention") for o in os_)))
        for o in os_:
            tc = ET.SubElement(suite, "testcase", classname=ep, name=f"{o.case.kind}: {o.case.id}",
                               time=f"{(o.elapsed_ms or 0) / 1000:.3f}")
            if o.verdict == "bug":
                f = ET.SubElement(tc, "failure", message=o.detail, type=o.category)
                f.text = f"{curl(o.request)}\n\nResponse ({o.status}):\n{o.response}"
            elif o.verdict in ("skip", "attention"):
                ET.SubElement(tc, "skipped", message=f"{o.category}: {o.detail}")
    ET.ElementTree(root).write(path, encoding="utf-8", xml_declaration=True)
    return path


def _markdown(outcomes: List[Outcome], path: Path, meta: Dict[str, Any]) -> Path:
    t = totals(outcomes)
    md = [f"# API test report: {meta.get('title', 'API')}", ""]
    for k in ("target", "spec", "base_url", "mode", "seed", "started", "duration_s", "requests"):
        if meta.get(k) not in (None, ""):
            md.append(f"- **{k.replace('_', ' ')}**: {meta[k]}")
    md += ["", f"**{t['passed']} passed, {t['bugs']} bugs, {t['attention']} need attention, {t['skipped']} skipped** "
               f"out of {t['cases']} cases.", "", "| Endpoint | Cases | Passed | Bugs | Attention | Skipped |",
           "|---|---|---|---|---|---|"]
    per_ep: Dict[str, List[Outcome]] = OrderedDict()
    for o in outcomes:
        per_ep.setdefault(o.endpoint, []).append(o)
    for ep, os_ in per_ep.items():
        c = Counter(o.verdict for o in os_)
        md.append(f"| `{ep}` | {len(os_)} | {c['pass']} | {c['bug']} | {c['attention']} | {c['skip']} |")
    for cat, title in TITLES.items():
        items = [o for o in outcomes if o.category == cat]
        if not items:
            continue
        md += ["", f"## {title} ({len(items)})", ""]
        for o in items:
            md.append(f"- `{o.endpoint}` **{o.case.id}**: {o.detail}")
            md.append(f"  <details><summary>request / response</summary>\n\n  ```\n  {curl(o.request)}\n  ```\n"
                      f"  Response {o.status}: `{o.response[:300]}`\n  </details>")
    attention = [o for o in outcomes if o.verdict in ("attention", "skip")]
    if attention:
        md += ["", "## Needs attention (not API bugs)", ""]
        for cat, title in ATTENTION.items():
            items = [o for o in attention if o.category == cat]
            if items:
                eps = Counter(o.endpoint for o in items)
                md.append(f"- **{title}**: {len(items)} case(s) in " + ", ".join(f"`{e}` ({n})" for e, n in eps.items())
                          + f". Example: {items[0].detail}")
    for hint in meta.get("hints", []):
        md += ["", f"> {hint}"]
    path.write_text("\n".join(md) + "\n", encoding="utf-8")
    return path
