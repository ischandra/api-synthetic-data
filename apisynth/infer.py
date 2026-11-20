"""Infers a JSON Schema from example JSON (API responses, Postman bodies, sample files).

* properties present (and non-null) in every sample become ``required``
* string formats are detected when every sample matches (email, uuid, date-time, date, uri, ipv4)
* low-cardinality string fields over many samples become ``enum``
* server-generated fields (id, createdAt, updatedAt, version, links...) are marked
  ``readOnly`` so they are left out of request payloads
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

_FORMATS = [
    ("email", re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")),
    ("uuid", re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")),
    ("date-time", re.compile(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]\d{2}:?\d{2})?$")),
    ("date", re.compile(r"^\d{4}-\d{2}-\d{2}$")),
    ("uri", re.compile(r"^https?://\S+$")),
    ("ipv4", re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")),
]
SERVER_FIELD = re.compile(
    r"^(id|_id|uuid|guid|(created|updated|modified|deleted|last_?modified)(_?(at|on|date|time|by|timestamp))?"
    r"|version|_?etag|_?links|href|self|_?meta(data)?)$", re.I)
RECORD_KEYS = ("items", "data", "results", "content", "records", "rows", "values", "list", "entries")


def _snake(name: str) -> str:
    return re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name).lower()


def _kind(v: Any) -> str:
    if isinstance(v, bool):
        return "boolean"
    if isinstance(v, int):
        return "integer"
    if isinstance(v, float):
        return "number"
    if isinstance(v, str):
        return "string"
    if isinstance(v, list):
        return "array"
    if isinstance(v, dict):
        return "object"
    return "null"


def infer_schema(samples: List[Any], name: Optional[str] = None, mark_server_fields: bool = True,
                 _root: bool = True) -> Dict[str, Any]:
    non_null = [s for s in samples if s is not None]
    nullable = len(non_null) < len(samples)
    if not non_null:
        return {"type": ["string", "null"]}
    kinds = {_kind(v) for v in non_null}
    if kinds == {"integer", "number"}:
        kinds = {"number"}

    if len(kinds) > 1:  # mixed types: use the most common one
        counts: Dict[str, int] = {}
        for v in non_null:
            counts[_kind(v)] = counts.get(_kind(v), 0) + 1
        winner = max(counts, key=counts.get)
        non_null = [v for v in non_null if _kind(v) == winner]
        kinds = {winner}

    kind = next(iter(kinds))
    schema: Dict[str, Any]
    if kind == "object":
        keys: List[str] = []
        for d in non_null:
            keys.extend(k for k in d if k not in keys)
        props = {k: infer_schema([d[k] for d in non_null if k in d], k, mark_server_fields, False) for k in keys}
        required = [k for k in keys if all(k in d and d[k] is not None for d in non_null)]
        if mark_server_fields:
            for k in keys:
                if SERVER_FIELD.match(_snake(k)):
                    props[k]["readOnly"] = True
        schema = {"type": "object", "properties": props}
        if required:
            schema["required"] = required
    elif kind == "array":
        items = [x for arr in non_null for x in arr]
        schema = {"type": "array", "items": infer_schema(items, name, mark_server_fields, False) if items else {}}
    elif kind == "string":
        schema = {"type": "string"}
        distinct = sorted(set(v for v in non_null if v != "__postman_variable__"))
        for fmt, rx in _FORMATS:
            if distinct and all(rx.match(v) for v in distinct):
                schema["format"] = fmt
                break
        if "format" not in schema and len(non_null) >= 8 and len(distinct) <= 4 \
                and all(re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,30}", v) for v in distinct):
            schema["enum"] = distinct
        if distinct:
            schema["examples"] = distinct[:5]
    else:
        schema = {"type": kind}
        if kind in ("integer", "number"):
            schema["examples"] = sorted(set(non_null))[:3]

    if nullable:
        schema["type"] = [schema["type"], "null"]
    return schema


def extract_records(doc: Any) -> List[Any]:
    """A response may be a record, a list of records, or an envelope like {"items": [...]}."""
    if isinstance(doc, list):
        return doc
    if isinstance(doc, dict):
        for k in RECORD_KEYS:
            v = doc.get(k)
            if isinstance(v, list) and v and all(isinstance(x, dict) for x in v):
                return v
        lists = [v for v in doc.values() if isinstance(v, list) and v and all(isinstance(x, dict) for x in v)]
        if len(lists) == 1 and len(doc) <= 4:
            return lists[0]
        return [doc]
    return [doc]
