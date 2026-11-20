"""Postman collection -> endpoints, with request shapes inferred from example bodies.

Requests with the same method + path are merged, so several examples of one endpoint
give better inference (e.g. which fields are optional)."""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Tuple

from ..fetch import load_document, source_name
from ..infer import infer_schema
from ..model import Endpoint, Param
from ..schema import convert_schema

# Representative values for Postman dynamic variables, so formats/types can be inferred.
_DYNAMIC = {
    "$guid": "6f1c2a3b-4d5e-4f60-8a7b-9c0d1e2f3a4b", "$randomUUID": "6f1c2a3b-4d5e-4f60-8a7b-9c0d1e2f3a4b",
    "$timestamp": 1700000000, "$isoTimestamp": "2024-01-01T10:00:00.000Z", "$randomInt": 42,
    "$randomBoolean": True, "$randomPrice": 19.99, "$randomEmail": "alex.doe@example.com",
    "$randomExampleEmail": "alex.doe@example.com", "$randomUrl": "https://www.example.com/page",
    "$randomIP": "192.0.2.10", "$randomDatePast": "2023-05-01T10:00:00.000Z",
    "$randomDateFuture": "2027-05-01T10:00:00.000Z", "$randomDateRecent": "2024-01-01T10:00:00.000Z",
    "$randomLatitude": 40.7128, "$randomLongitude": -74.006,
}


UNKNOWN = "__postman_variable__"  # never used as an example value
_VAR_HINTS = [(r"(?i)e-?mail", "user@example.com"), (r"(?i)(url|uri|link)$", "https://www.example.com"),
              (r"(?i)(date|day)$", "2024-01-01"), (r"(?i)(time|at|timestamp)$", "2024-01-01T10:00:00Z"),
              (r"(?i)(uuid|guid)$", "6f1c2a3b-4d5e-4f60-8a7b-9c0d1e2f3a4b")]


def _sample_for(name: str, in_string: bool) -> Any:
    name = name.strip()
    v = _DYNAMIC.get(name)
    if v is not None:
        return v
    if in_string or name.startswith("$"):
        return next((sample for rx, sample in _VAR_HINTS if re.search(rx, name)), UNKNOWN)
    return 0


def substitute_placeholders(raw: str) -> str:
    """Replaces {{var}} placeholders so the body becomes valid JSON for inference."""
    out: List[str] = []
    i, in_str = 0, False
    while i < len(raw):
        if raw.startswith("{{", i):
            end = raw.find("}}", i + 2)
            if end != -1:
                name = raw[i + 2:end].strip()
                whole = in_str and raw[i - 1] == '"' and raw[end + 2:end + 3] == '"'
                if whole:  # "{{var}}" -> typed sample replaces the quoted string
                    out.pop()
                    out.append(json.dumps(_sample_for(name, True)))
                    i = end + 3
                    in_str = False
                    continue
                v = _sample_for(name, in_str)
                out.append(str(v) if in_str else json.dumps(v))
                i = end + 2
                continue
        c = raw[i]
        if c == '"' and (i == 0 or raw[i - 1] != "\\"):
            in_str = not in_str
        out.append(c)
        i += 1
    return "".join(out)


def _path(url: Any) -> Tuple[str, List[Param], Dict[str, Any]]:
    """Returns (templated path, path params, query sample values)."""
    if isinstance(url, str):
        raw, variables, query = url, [], None
    else:
        url = url or {}
        raw = url.get("raw") or ""
        variables = url.get("variable") or []
        query = url.get("query")
        if not raw and url.get("path"):
            raw = "/" + "/".join(url["path"])
    raw = raw.split("#", 1)[0]
    path_part, _, qs = raw.partition("?")
    path_part = re.sub(r"^(https?://[^/]+|\{\{[^}]+\}\}(?=/|$))", "", path_part.strip())
    path_part = re.sub(r"^([^/{]*\.[a-z]{2,}|[A-Za-z0-9.-]+:\d+)(:\d+)?(?=/|$)", "", path_part)  # bare host[:port]
    params: List[Param] = []
    samples = {v.get("key"): v.get("value") for v in variables if v.get("key")}

    def colon(m: "re.Match[str]") -> str:
        params.append(Param(m.group(1), "path", True, _param_schema(samples.get(m.group(1)), m.group(1))))
        return "{" + m.group(1) + "}"

    def braces(m: "re.Match[str]") -> str:
        name = m.group(1).strip()
        params.append(Param(name, "path", True, _param_schema(None, name)))
        return "{" + name + "}"

    path = re.sub(r"(?<=/):([A-Za-z_][\w-]*)", colon, path_part)
    path = re.sub(r"(?<=/)\{\{\s*([^}]+?)\s*\}\}(?=/|$)", braces, path)
    if not path.startswith("/"):
        path = "/" + path
    q: Dict[str, Any] = {}
    if query is not None:
        for p in query:
            if p.get("key") and not p.get("disabled"):
                q[p["key"]] = p.get("value")
    elif qs:
        for part in qs.split("&"):
            k, _, v = part.partition("=")
            if k:
                q[k] = v
    return path, params, q


def _param_schema(sample: Any, name: str) -> Dict[str, Any]:
    decimal_name = re.search(r"(?i)price|amount|cost|rate|total|lat|lng|lon", name)
    if isinstance(sample, str) and re.fullmatch(r"-?\d+", sample):
        return {"type": "number" if decimal_name else "integer"}
    if isinstance(sample, str) and re.fullmatch(r"-?\d+\.\d+", sample):
        return {"type": "number"}
    if isinstance(sample, str) and sample.lower() in ("true", "false"):
        return {"type": "boolean"}
    if re.search(r"(?i)(^|_)id$|Id$", name) and not (isinstance(sample, str) and re.search(r"[A-Za-z-]", sample or "")):
        return {"type": "integer", "minimum": 1}
    if isinstance(sample, str) and sample and not sample.startswith("{{"):
        return {"type": "string", "examples": [sample]}
    return {"type": "string"}


def load_postman(src: str, headers: Optional[Dict[str, str]] = None) -> List[Endpoint]:
    doc = load_document(src, headers)
    if isinstance(doc, dict) and "collection" in doc and "item" not in doc:
        doc = doc["collection"]
    if not isinstance(doc, dict) or "item" not in doc:
        raise ValueError(f"{source_name(src)}: not a Postman collection")
    name = f"postman:{source_name(src)}"
    groups: Dict[str, Dict[str, Any]] = {}

    def walk(items: List[Dict[str, Any]], folder: List[str]) -> None:
        for it in items:
            if "item" in it:
                walk(it["item"], folder + [it.get("name", "")])
                continue
            req = it.get("request") or {}
            if isinstance(req, str):
                req = {"method": "GET", "url": req}
            method = str(req.get("method", "GET")).upper()
            path, pparams, query = _path(req.get("url"))
            g = groups.setdefault(f"{method} {path}", {"method": method, "path": path, "params": {}, "query": {},
                                                      "bodies": [], "content_type": "application/json",
                                                      "summary": it.get("name"), "tags": folder[-1:] if folder else []})
            for p in pparams:
                g["params"][p.name] = p
            for k, v in query.items():
                g["query"].setdefault(k, []).append(v)
            body = req.get("body") or {}
            mode = body.get("mode")
            if mode == "raw" and (body.get("raw") or "").strip():
                try:
                    g["bodies"].append(json.loads(substitute_placeholders(body["raw"])))
                except ValueError:
                    pass  # non-JSON raw bodies (XML, text) are not inferred
            elif mode in ("urlencoded", "formdata"):
                fields = {p["key"]: p.get("value", "") for p in body.get(mode) or []
                          if p.get("key") and not p.get("disabled") and p.get("type") != "file"}
                g["bodies"].append({k: json.loads(substitute_placeholders(json.dumps(v))) for k, v in fields.items()})
                g["content_type"] = "application/x-www-form-urlencoded" if mode == "urlencoded" else "multipart/form-data"
            elif mode == "graphql":
                g["bodies"].append({"query": (body.get("graphql") or {}).get("query", ""), "variables": {}})

    walk(doc["item"], [])
    endpoints = []
    for g in groups.values():
        ep = Endpoint(method=g["method"], path=g["path"], source=name, doc={}, summary=g["summary"],
                      tags=g["tags"], inferred=True, content_type=g["content_type"])
        ep.params = list(g["params"].values())
        for k, values in g["query"].items():
            sample = next((v for v in values if v not in (None, "")), None)
            ep.params.append(Param(k, "query", False, _param_schema(sample, k)))
        if g["bodies"]:
            # fields in a request body are client-sent by definition, so keep id/createdAt-style fields
            ep.body_schema = convert_schema(infer_schema(g["bodies"], mark_server_fields=False))
            ep.body_required = True
        endpoints.append(ep)
    return endpoints
