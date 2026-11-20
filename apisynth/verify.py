"""Self-check: validates generated cases against the endpoint's own schema.

* valid / boundary / hostile cases must PASS schema validation
* invalid cases must FAIL it (otherwise the case wouldn't test anything)

Formats the validator can't check (e.g. date-time without extra packages) are skipped.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from jsonschema import Draft202012Validator, FormatChecker

from .model import Case, Endpoint

_CHECKER = FormatChecker()


def _validator(ep: Endpoint, schema: Dict[str, Any]) -> Draft202012Validator:
    # Merge the schema into the root document so internal "#/components/..." refs resolve.
    root = {k: v for k, v in ep.doc.items() if k not in ("$schema", "$id")}
    return Draft202012Validator({**root, **schema}, format_checker=_CHECKER)


def _errors(ep: Endpoint, schema: Optional[Dict[str, Any]], value: Any) -> List[str]:
    if schema is None:
        return []
    return [e.message for e in _validator(ep, schema).iter_errors(value)]


def case_errors(ep: Endpoint, case: Case) -> List[str]:
    """Schema violations of a case's request (empty list = schema-valid)."""
    errs: List[str] = []
    rd = case.request
    buckets = {"path": rd.path_params, "query": rd.query, "header": rd.headers, "cookie": rd.headers}
    for p in ep.params:
        bucket = buckets[p.location]
        if p.name not in bucket:
            if p.required:
                errs.append(f"{p.location}.{p.name}: required parameter missing")
            continue
        errs += [f"{p.location}.{p.name}: {m}" for m in _errors(ep, p.schema, bucket[p.name])]
    if ep.body_schema is not None:
        if not rd.has_body:
            if ep.body_required:
                errs.append("body: required body missing")
        else:
            errs += [f"body: {m}" for m in _errors(ep, ep.body_schema, rd.body)]
    return errs


def verify(ep: Endpoint, cases: List[Case]) -> List[str]:
    """Returns human-readable problems; empty when every case does what it claims."""
    problems = []
    for c in cases:
        errs = case_errors(ep, c)
        if c.kind in ("valid", "boundary", "hostile") and errs:
            problems.append(f"{ep.key} {c.id}: expected schema-valid but {errs[0]}")
        elif c.kind == "invalid" and not errs:
            if c.category == "format" and not _format_checkable(c.description or ""):
                continue
            problems.append(f"{ep.key} {c.id}: expected schema-invalid but it validates ({c.description})")
    return problems


def _format_checkable(description: str) -> bool:
    m = re.search(r"is not a valid ([\w-]+)", description)
    return bool(m) and m.group(1) in _CHECKER.checkers
