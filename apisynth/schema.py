"""OpenAPI / JSON Schema helpers.

Specs are normalised to a JSON Schema 2020-12 "request view" before generation:
  * OpenAPI 3.0 ``nullable`` / Swagger ``x-nullable``  ->  ``type: [T, "null"]``
  * boolean ``exclusiveMinimum/Maximum`` (3.0)          ->  numeric form
  * Swagger ``type: file``                             ->  ``string`` / ``binary``
  * ``readOnly`` properties are removed from ``properties`` and ``required``,
    because clients must not send them (ids, timestamps...)
"""
from __future__ import annotations

import copy
from typing import Any, Dict, List, Optional

_DICT_OF_SCHEMAS = ("properties", "patternProperties", "$defs", "definitions", "dependentSchemas")
_ONE_SCHEMA = ("items", "additionalProperties", "not", "contains", "propertyNames", "if", "then", "else",
               "additionalItems", "unevaluatedProperties", "unevaluatedItems")
_LIST_OF_SCHEMAS = ("allOf", "anyOf", "oneOf", "prefixItems")
_SKIP_WALK = ("example", "examples", "x-examples")


class SpecError(ValueError):
    pass


# ----------------------------------------------------------------- pointers

def _unescape(token: str) -> str:
    return token.replace("~1", "/").replace("~0", "~")


def escape(token: str) -> str:
    return token.replace("~", "~0").replace("/", "~1")


def resolve_pointer(root: Dict[str, Any], ref: str) -> Any:
    if not ref.startswith("#"):
        raise SpecError(f"External $ref not supported (bundle the spec first): {ref}")
    node: Any = root
    for raw in [t for t in ref[1:].split("/") if t]:
        tok = _unescape(raw)
        if isinstance(node, list):
            node = node[int(tok)]
        elif isinstance(node, dict) and tok in node:
            node = node[tok]
        else:
            raise SpecError(f"Unresolvable $ref: {ref}")
    return node


def deref(root: Dict[str, Any], schema: Any) -> Any:
    """Follows ``$ref`` chains; sibling keywords (allowed in 3.1) override the target."""
    seen = 0
    while isinstance(schema, dict) and "$ref" in schema:
        seen += 1
        if seen > 50:
            raise SpecError(f"$ref cycle at {schema['$ref']}")
        target = resolve_pointer(root, schema["$ref"])
        siblings = {k: v for k, v in schema.items() if k != "$ref"}
        schema = {**target, **siblings} if siblings and isinstance(target, dict) else target
    return schema


def ref_name(schema: Any) -> Optional[str]:
    if isinstance(schema, dict) and isinstance(schema.get("$ref"), str):
        return schema["$ref"].rsplit("/", 1)[-1]
    return None


# ------------------------------------------------------------- conversion

def convert_schema(s: Any, oas30: bool = True) -> Any:
    if not isinstance(s, dict):
        return s
    out: Dict[str, Any] = {}
    for k, v in s.items():
        if k in _DICT_OF_SCHEMAS and isinstance(v, dict):
            out[k] = {pk: convert_schema(pv, oas30) for pk, pv in v.items()}
        elif k in _ONE_SCHEMA and isinstance(v, dict):
            out[k] = convert_schema(v, oas30)
        elif k in _LIST_OF_SCHEMAS and isinstance(v, list):
            out[k] = [convert_schema(x, oas30) for x in v]
        else:
            out[k] = v

    if out.get("type") == "file":
        out["type"], out["format"] = "string", "binary"

    for kw, base in (("exclusiveMinimum", "minimum"), ("exclusiveMaximum", "maximum")):
        if isinstance(out.get(kw), bool):
            if out[kw] and base in out:
                out[kw] = out.pop(base)
            else:
                out.pop(kw)

    nullable = bool(out.pop("nullable", False)) | bool(out.pop("x-nullable", False))
    if nullable:
        t = out.get("type")
        if isinstance(t, str):
            out["type"] = [t, "null"]
            if isinstance(out.get("enum"), list) and None not in out["enum"]:
                out["enum"] = out["enum"] + [None]
        elif isinstance(t, list):
            if "null" not in t:
                out["type"] = t + ["null"]
        else:
            out = {"anyOf": [out, {"type": "null"}]}

    props = out.get("properties")
    if isinstance(props, dict):
        read_only = [p for p, ps in props.items() if isinstance(ps, dict) and ps.get("readOnly")]
        if read_only:
            out["properties"] = {p: ps for p, ps in props.items() if p not in read_only}
            if isinstance(out.get("required"), list):
                out["required"] = [r for r in out["required"] if r not in read_only]
            out["x-readOnly-removed"] = sorted(set(out.get("x-readOnly-removed", [])) | set(read_only))
    return out


def convert_document(root: Dict[str, Any]) -> Dict[str, Any]:
    """Deep-copies a spec and converts every schema in it to the request view."""
    doc = copy.deepcopy(root)
    oas30 = not str(doc.get("openapi", "")).startswith("3.1")
    comps = doc.get("components")
    if isinstance(comps, dict) and isinstance(comps.get("schemas"), dict):
        comps["schemas"] = {k: convert_schema(v, oas30) for k, v in comps["schemas"].items()}
    if isinstance(doc.get("definitions"), dict):
        doc["definitions"] = {k: convert_schema(v, oas30) for k, v in doc["definitions"].items()}

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            for k in list(node):
                if k in _SKIP_WALK or k.startswith("x-"):
                    continue
                if k == "schema" and isinstance(node[k], dict):
                    node[k] = convert_schema(node[k], oas30)
                else:
                    walk(node[k])
        elif isinstance(node, list):
            for x in node:
                walk(x)

    walk(doc.get("paths") or {})
    if isinstance(comps, dict):
        for section in ("parameters", "requestBodies"):
            walk(comps.get(section) or {})
    walk(doc.get("parameters") or {})  # Swagger 2 global parameters
    return doc


# ----------------------------------------------------------------- allOf

def merge_allof(root: Dict[str, Any], schema: Dict[str, Any], _depth: int = 0) -> Dict[str, Any]:
    """Flattens ``allOf`` into a single schema (properties/required merged, bounds tightened)."""
    if _depth > 20:
        raise SpecError("allOf nesting too deep")
    base = {k: v for k, v in schema.items() if k != "allOf"}
    parts: List[Dict[str, Any]] = []
    for part in schema.get("allOf") or []:
        p = deref(root, part)
        if isinstance(p, dict):
            parts.append(merge_allof(root, p, _depth + 1) if "allOf" in p else p)
    merged: Dict[str, Any] = {}
    for p in parts + [base]:
        for k, v in p.items():
            if k == "properties":
                merged.setdefault("properties", {}).update(v)
            elif k in ("required", "x-readOnly-removed"):
                merged[k] = list(dict.fromkeys(list(merged.get(k, [])) + list(v)))
            elif k in ("minimum", "exclusiveMinimum", "minLength", "minItems", "minProperties") and k in merged:
                merged[k] = max(merged[k], v)
            elif k in ("maximum", "exclusiveMaximum", "maxLength", "maxItems", "maxProperties") and k in merged:
                merged[k] = min(merged[k], v)
            elif k == "enum" and k in merged:
                merged[k] = [x for x in merged[k] if x in v]
            elif k not in merged:
                merged[k] = v
    if "x-readOnly-removed" in merged and "properties" in merged:
        for p in merged["x-readOnly-removed"]:
            merged["properties"].pop(p, None)
        merged["required"] = [r for r in merged.get("required", []) if r not in merged["x-readOnly-removed"]]
    return merged


def resolve(root: Dict[str, Any], schema: Any) -> Any:
    """deref + allOf flattening: the shape generators/mutators work on."""
    s = deref(root, schema)
    if isinstance(s, dict) and "allOf" in s:
        s = merge_allof(root, s)
    return s


def schema_types(s: Dict[str, Any]) -> List[str]:
    t = s.get("type")
    if isinstance(t, list):
        return list(t)
    if isinstance(t, str):
        return [t]
    if "properties" in s or "additionalProperties" in s or "required" in s:
        return ["object"]
    if "items" in s or "prefixItems" in s:
        return ["array"]
    if "enum" in s and s["enum"]:
        kinds = {_json_type(v) for v in s["enum"]}
        return sorted(kinds)
    if "const" in s:
        return [_json_type(s["const"])]
    if any(k in s for k in ("pattern", "format", "minLength", "maxLength")):
        return ["string"]
    if any(k in s for k in ("minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum", "multipleOf")):
        return ["number"]
    return []


def is_nullable(s: Dict[str, Any]) -> bool:
    if "null" in schema_types(s):
        return True
    if isinstance(s.get("enum"), list) and None in s["enum"]:
        return True
    return any(isinstance(b, dict) and b.get("type") == "null" for b in (s.get("anyOf") or []) + (s.get("oneOf") or []))


def _json_type(v: Any) -> str:
    if v is None:
        return "null"
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
    return "object"
