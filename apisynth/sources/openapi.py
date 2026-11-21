"""OpenAPI 3.0 / 3.1 and Swagger 2.0 -> endpoints."""
from __future__ import annotations

import copy
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlsplit

from ..fetch import is_url, load_document, source_name
from ..model import Endpoint, Param
from ..schema import SpecError, convert_document, deref, resolve_pointer

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


def default_base_url(raw: Dict[str, Any], src: Optional[str] = None) -> Optional[str]:
    """Base URL from servers/host. Relative server URLs (e.g. "/api/v3") resolve against the URL the
    spec was downloaded from, as the OpenAPI spec defines; no servers at all means the spec's origin."""
    spec_url = src if src and is_url(src) else None
    if "swagger" in raw:
        host = raw.get("host")
        base_path = raw.get("basePath", "")
        if not host:
            if spec_url:
                parts = urlsplit(spec_url)
                return f"{parts.scheme}://{parts.netloc}{base_path}"
            return base_path or None
        scheme = (raw.get("schemes") or [urlsplit(spec_url).scheme if spec_url else "https"])[0]
        return f"{scheme}://{host}{base_path}"
    servers = raw.get("servers") or []
    if servers and isinstance(servers[0], dict) and servers[0].get("url"):
        url = servers[0]["url"]
        for name, var in (servers[0].get("variables") or {}).items():
            url = url.replace("{" + name + "}", str(var.get("default", "")))
        if spec_url and not is_url(url):
            url = urljoin(spec_url, url)
        return url.rstrip("/") or url
    if spec_url:
        return urljoin(spec_url, "/").rstrip("/")
    return None


def bundle_external_refs(raw: Dict[str, Any], src: str, headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """Inlines $refs that point to other files/URLs (multi-file specs), relative to the referring file."""
    cache: Dict[str, Any] = {src: raw}

    def load(target: str) -> Any:
        if target not in cache:
            cache[target] = load_document(target, headers)
        return cache[target]

    def locate(base: str, loc: str) -> str:
        return urljoin(base, loc) if is_url(base) else str((Path(base).parent / loc).resolve())

    def walk(node: Any, base: str, depth: int) -> Any:
        if isinstance(node, dict):
            ref = node.get("$ref")
            if isinstance(ref, str) and (not ref.startswith("#") or base != src):
                if depth > 12:
                    return {}
                loc, _, frag = ref.partition("#")
                target = locate(base, loc) if loc else base
                try:
                    tdoc = load(target)
                    tnode = resolve_pointer(tdoc, "#" + frag) if frag else tdoc
                except (OSError, ValueError) as e:
                    raise SpecError(f"Cannot resolve $ref '{ref}' from {source_name(base)}: {e}") from e
                return walk(copy.deepcopy(tnode), target, depth + 1)
            return {k: walk(v, base, depth) for k, v in node.items()}
        if isinstance(node, list):
            return [walk(x, base, depth) for x in node]
        return node

    return walk(raw, src, 0)


_SWAGGER2_FLOWS = {"application": "clientCredentials", "password": "password", "accessCode": "authorizationCode",
                   "implicit": "implicit"}


def _scheme(name: str, sch: Dict[str, Any]) -> Dict[str, Any]:
    """Normalises an OpenAPI / Swagger security scheme."""
    t = str(sch.get("type", "")).lower()
    http = str(sch.get("scheme", "")).lower()
    if str(sch.get("x-amazon-apigateway-authtype", "")).lower() == "awssigv4":
        return {"name": name, "type": "awsv4"}
    if t == "http":
        if http in ("bearer", "basic", "digest"):
            return {"name": name, "type": http, "format": sch.get("bearerFormat")}
        return {"name": name, "type": f"http-{http}"}
    if t == "basic":
        return {"name": name, "type": "basic"}
    if t == "apikey":
        return {"name": name, "type": "apikey", "param": sch.get("name", "X-API-Key"), "in": sch.get("in", "header")}
    if t == "oauth2":
        flows = dict(sch.get("flows") or {})
        if sch.get("flow"):  # Swagger 2
            flows[_SWAGGER2_FLOWS.get(sch["flow"], sch["flow"])] = {"tokenUrl": sch.get("tokenUrl"),
                                                                      "authorizationUrl": sch.get("authorizationUrl")}
        return {"name": name, "type": "oauth2", "flows": flows}
    if t == "openidconnect":
        return {"name": name, "type": "openid", "url": sch.get("openIdConnectUrl")}
    if t == "mutualtls":
        return {"name": name, "type": "mtls"}
    return {"name": name, "type": t or "unknown"}


def _security_for(raw: Dict[str, Any], op: Dict[str, Any]) -> List[List[Dict[str, Any]]]:
    """Alternatives (OR) of scheme lists (AND); [] = no authentication."""
    reqs = op["security"] if "security" in op else raw.get("security")
    if not reqs:
        return []
    schemes = (raw.get("components") or {}).get("securitySchemes") or raw.get("securityDefinitions") or {}
    return [[{**_scheme(n, schemes.get(n) or {}), "scopes": list(req[n] or [])} for n in (req or {})]
            for req in reqs]


def _simple_auth(security: List[List[Dict[str, Any]]]) -> Optional[Dict[str, str]]:
    """First scheme, simplified for the apitest/postman exports."""
    for req in security:
        for s in req:
            if s["type"] in ("bearer", "oauth2", "openid"):
                return {"type": "bearer"}
            if s["type"] in ("basic", "digest"):
                return {"type": "basic"}
            if s["type"] == "apikey" and s.get("in") in ("header", "query"):
                return {"type": "apikey", "name": s["param"], "in": s["in"]}
    return None


def load_openapi(src: str, headers: Optional[Dict[str, str]] = None,
                 raw: Optional[Dict[str, Any]] = None) -> Tuple[List[Endpoint], Optional[str]]:
    """Returns (endpoints, default base URL from servers/host). ``raw`` skips re-downloading."""
    if raw is None:
        raw = load_document(src, headers)
    if not isinstance(raw, dict) or not ("openapi" in raw or "swagger" in raw):
        raise SpecError(f"{source_name(src)}: not an OpenAPI/Swagger document (no 'openapi' or 'swagger' key)")
    if any(isinstance(v, str) and not v.startswith("#") for v in _refs(raw)):
        raw = bundle_external_refs(raw, src, headers)
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
                          operation_id=op.get("operationId"), summary=op.get("summary"), tags=list(op.get("tags") or []),
                          security=_security_for(raw, op))
            ep.auth = _simple_auth(ep.security)
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
    return endpoints, default_base_url(raw, src)


def _refs(node: Any):
    if isinstance(node, dict):
        for k, v in node.items():
            if k == "$ref":
                yield v
            else:
                yield from _refs(v)
    elif isinstance(node, list):
        for x in node:
            yield from _refs(x)


def path_of(url: str) -> str:
    return urlsplit(url).path or "/"
