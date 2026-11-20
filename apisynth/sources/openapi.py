"""OpenAPI 3.0 / 3.1 and Swagger 2.0 -> endpoints."""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

from ..fetch import load_document, source_name
from ..model import Endpoint, Param
from ..schema import SpecError, convert_document, deref

METHODS = ("get", "put", "post", "delete", "options", "head", "patch", "trace")
_PARAM_SCHEMA_KEYS = ("type", "format", "enum", "minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum",
                      "minLength", "maxLength", "pattern", "items", "multipleOf", "minItems", "maxItems",
                      "uniqueItems", "default", "x-nullable")


def _media(content: Dict[str, Any]) -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
    if not content:
        return None, None
    order = list(content)
    for pref in ("application/json",):
        if pref in content:
            return pref, content[pref]
    for ct in order:
        if ct.endswith("+json"):
            return ct, content[ct]
    for pref in ("application/x-www-form-urlencoded", "multipart/form-data"):
        if pref in content:
            return pref, content[pref]
    return order[0], content[order[0]]


def default_base_url(raw: Dict[str, Any]) -> Optional[str]:
    if "swagger" in raw:
        host = raw.get("host")
        if not host:
            return raw.get("basePath") or None
        scheme = (raw.get("schemes") or ["https"])[0]
        return f"{scheme}://{host}{raw.get('basePath', '')}"
    servers = raw.get("servers") or []
    if servers and isinstance(servers[0], dict) and servers[0].get("url"):
        url = servers[0]["url"]
        for name, var in (servers[0].get("variables") or {}).items():
            url = url.replace("{" + name + "}", str(var.get("default", "")))
        return url
    return None


def load_openapi(src: str, headers: Optional[Dict[str, str]] = None) -> Tuple[List[Endpoint], Optional[str]]:
    """Returns (endpoints, default base URL from servers/host)."""
    raw = load_document(src, headers)
    if not isinstance(raw, dict) or not ("openapi" in raw or "swagger" in raw):
        raise SpecError(f"{source_name(src)}: not an OpenAPI/Swagger document (no 'openapi' or 'swagger' key)")
    doc = convert_document(raw)
    swagger2 = "swagger" in raw
    name = f"openapi:{source_name(src)}"
    endpoints: List[Endpoint] = []

    for path, item in (doc.get("paths") or {}).items():
        item = deref(doc, item)
        common = item.get("parameters") or []
        for method in METHODS:
            op = item.get(method)
            if not isinstance(op, dict):
                continue
            ep = Endpoint(method=method.upper(), path=path, source=name, doc=doc,
                          operation_id=op.get("operationId"), summary=op.get("summary"), tags=list(op.get("tags") or []))
            merged: Dict[Tuple[str, str], Dict[str, Any]] = {}
            for p in list(common) + list(op.get("parameters") or []):
                p = deref(doc, p)
                if isinstance(p, dict) and p.get("name") and p.get("in"):
                    merged[(p["name"], p["in"])] = p
            form_props: Dict[str, Any] = {}
            form_required: List[str] = []
            for (pname, loc), p in merged.items():
                if swagger2 and loc == "body":
                    ep.body_schema = p.get("schema") or {}
                    ep.body_required = bool(p.get("required"))
                    ep.content_type = (op.get("consumes") or raw.get("consumes") or ["application/json"])[0]
                    continue
                if swagger2 and loc == "formData":
                    form_props[pname] = {k: p[k] for k in _PARAM_SCHEMA_KEYS if k in p}
                    if p.get("required"):
                        form_required.append(pname)
                    continue
                schema = p.get("schema")
                if schema is None and "content" in p:
                    _, media = _media(p["content"])
                    schema = (media or {}).get("schema")
                if schema is None:
                    from ..schema import convert_schema
                    schema = convert_schema({k: p[k] for k in _PARAM_SCHEMA_KEYS if k in p}, oas30=True)
                ep.params.append(Param(name=pname, location=loc, required=bool(p.get("required")) or loc == "path",
                                       schema=schema or {"type": "string"}))
            if form_props:
                from ..schema import convert_schema
                ep.body_schema = convert_schema({"type": "object", "properties": form_props, "required": form_required})
                ep.body_required = bool(form_required)
                consumes = op.get("consumes") or raw.get("consumes") or []
                ep.content_type = "multipart/form-data" if "multipart/form-data" in consumes else "application/x-www-form-urlencoded"
            body = op.get("requestBody")
            if body is not None and not swagger2:
                body = deref(doc, body)
                ct, media = _media(body.get("content") or {})
                if media is not None:
                    ep.body_schema = media.get("schema") or {}
                    ep.content_type = ct or "application/json"
                    ep.body_required = bool(body.get("required"))
            endpoints.append(ep)
    return endpoints, default_base_url(raw)


def path_of(url: str) -> str:
    return urlsplit(url).path or "/"
