"""Negative-test data: each case breaks exactly ONE rule of the schema, so a failing
API response points at a specific validation gap.

Kinds:
  invalid   breaks a rule                         -> expect 4xx
  boundary  sits exactly on a limit (still valid) -> expect 2xx
  hostile   schema-valid but nasty strings        -> expect "not 5xx"
"""
from __future__ import annotations

import copy
import json
import math
import re
from typing import Any, Callable, Dict, List, Optional, Tuple

from .generate import SKIP_HEADERS, Generator
from .model import Case, Endpoint, RequestData
from .schema import is_nullable, resolve, schema_types

_INVALID_FORMATS = {
    "email": "not-an-email", "idn-email": "not-an-email", "uuid": "not-a-uuid", "date": "2023-02-30",
    "date-time": "not-a-timestamp", "time": "25:61:00", "uri": "not a uri", "url": "not a url", "iri": "not a uri",
    "hostname": "-invalid-.host_name", "ipv4": "999.1.1.1", "ipv6": "not:an:ipv6", "byte": "not base64!!",
}
_PATTERN_CANDIDATES = ["", "!!!", "invalid value", "0", "AAAA", "a", "ZZZ-9999-zzz", " ", "éé"]
_HOSTILE = [("sql-injection", "' OR '1'='1"), ("xss", "<script>alert(1)</script>"),
            ("unicode", "Zoë 李小龙 \U0001F600"), ("path-traversal", "../../etc/passwd")]

Path = List[Any]


def _target(path: Path) -> str:
    out = ""
    for p in path:
        out += f"[{p}]" if isinstance(p, int) else (f".{p}" if out else str(p))
    return out


def _set(obj: Any, path: Path, value: Any) -> Any:
    if not path:
        return value
    node = obj
    for p in path[:-1]:
        node = node[p]
    node[path[-1]] = value
    return obj


def _delete(obj: Any, path: Path) -> Any:
    node = obj
    for p in path[:-1]:
        node = node[p]
    del node[path[-1]]
    return obj


def _json_type(v: Any) -> str:
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "boolean"
    if isinstance(v, int):
        return "integer"
    if isinstance(v, float):
        return "integer" if v.is_integer() else "number"
    if isinstance(v, str):
        return "string"
    return "array" if isinstance(v, list) else "object"


def _allows(types: List[str], v: Any) -> bool:
    if not types:
        return True
    t = _json_type(v)
    return t in types or (t == "integer" and "number" in types)


class Mutator:
    def __init__(self, gen: Generator, boundary: bool = True, hostile: bool = False, max_cases: int = 200):
        self.gen = gen
        self.boundary = boundary
        self.hostile = hostile
        self.max_cases = max_cases

    def cases(self, ep: Endpoint) -> List[Case]:
        base = self.gen.request(ep, full=True)
        out: List[Case] = []
        self._hostile_i = 0
        note = " (rule inferred from examples)" if ep.inferred else ""

        def emit(kind: str, category: str, target: str, desc: str, mutate: Callable[[RequestData], None]) -> None:
            # Cases expected to SUCCEED get their own fresh data (same structure), so unique fields such as
            # emails don't collide with each other (409 Conflict). Invalid cases reuse the base request.
            rd = (self._fresh_like(ep, base) if kind != "invalid" else None) or copy.deepcopy(base)
            mutate(rd)
            expect = {"invalid": "4xx", "boundary": "2xx", "hostile": "not 5xx"}[kind]
            prefix = "" if kind == "invalid" else f"{kind}:"
            out.append(Case(id=f"{prefix}{category}:{target}", kind=kind, request=rd, expect=expect,
                            category=category, target=target, description=desc + (note if kind == "invalid" else "")))

        # ---- parameters
        for p in ep.params:
            if p.location == "header" and p.name.lower() in SKIP_HEADERS:
                continue
            bucket = {"path": "path_params", "query": "query", "header": "headers", "cookie": "headers"}[p.location]
            target = f"{p.location}.{p.name}"
            if p.required and p.location != "path":
                emit("invalid", "required", target, f"{target}: required parameter omitted",
                     lambda rd, b=bucket, n=p.name: getattr(rd, b).pop(n, None))
            current = getattr(base, bucket).get(p.name)
            if current is None:
                continue

            def setter(b=bucket, n=p.name):
                return lambda rd, v: getattr(rd, b).__setitem__(n, v)
            self._value_rules(ep.doc, p.schema or {"type": "string"}, current, target, setter(), emit, is_param=True)

        # ---- body
        if ep.body_schema is not None:
            s = resolve(ep.doc, ep.body_schema)
            if ep.body_required:
                emit("invalid", "required", "body", "Request body omitted",
                     lambda rd: (setattr(rd, "has_body", False), setattr(rd, "body", None)))
            types = schema_types(s) if isinstance(s, dict) else []
            if "object" in types and isinstance(base.body, dict):
                if (s.get("required") or []) and base.body:
                    emit("invalid", "required", "body.*", "Empty JSON object - every required property missing",
                         lambda rd: setattr(rd, "body", {}))
                emit("invalid", "type", "body", "Body is a JSON array instead of an object",
                     lambda rd: setattr(rd, "body", [rd.body]))
            elif "array" in types:
                emit("invalid", "type", "body", "Body is a JSON object instead of an array",
                     lambda rd: setattr(rd, "body", {"items": rd.body}))
            self._walk(ep.doc, ep.body_schema, base.body, [], emit, depth=0)

        # ---- de-duplicate and cap
        uniq: Dict[str, Case] = {}
        ids: Dict[str, int] = {}
        for c in out:
            key = c.kind + json.dumps(c.request.to_dict(), sort_keys=True, default=str) + str(c.request.has_body)
            if key in uniq:
                continue
            n = ids.get(c.id, 0) + 1
            ids[c.id] = n
            if n > 1:
                c.id = f"{c.id}#{n}"
            uniq[key] = c
        cases = list(uniq.values())
        invalid = [c for c in cases if c.kind == "invalid"][: self.max_cases]
        return invalid + [c for c in cases if c.kind != "invalid"]

    def _fresh_like(self, ep: Endpoint, base: RequestData) -> Optional[RequestData]:
        want = _shape(base)
        for _ in range(5):
            cand = self.gen.request(ep, full=True)
            if _shape(cand) == want:
                return cand
        return None

    # ---------------------------------------------------------- body walk

    def _walk(self, doc, schema, value, path: Path, emit, depth: int) -> None:
        if depth > 8:
            return
        s = resolve(doc, schema)
        if not isinstance(s, dict):
            return
        s = self._branch_for(doc, s, value)

        def body_setter(p=list(path)):
            return lambda rd, v: setattr(rd, "body", _set(rd.body, p, v))

        if path:
            self._value_rules(doc, s, value, "body." + _target(path), body_setter(), emit)

        types = schema_types(s)
        if isinstance(value, dict) and ("object" in types or not types):
            props = s.get("properties") or {}
            for req in s.get("required") or []:
                if req in value:
                    t = "body." + _target(path + [req])
                    emit("invalid", "required", t, f"{t}: required property removed",
                         lambda rd, p=path + [req]: setattr(rd, "body", _delete(rd.body, p)))
            if s.get("additionalProperties") is False and props:
                t = "body." + _target(path + ["unexpectedField"])
                emit("invalid", "additional-property", t, f"{t}: property not defined in the schema",
                     lambda rd, p=path + ["unexpectedField"]: setattr(rd, "body", _set(rd.body, p, "unexpected")))
            for name, ps in props.items():
                if name in value:
                    self._walk(doc, ps, value[name], path + [name], emit, depth + 1)
        elif isinstance(value, list) and "array" in types:
            t = "body." + _target(path) if path else "body"
            lo, hi = s.get("minItems"), s.get("maxItems")
            if lo:
                emit("invalid", "min-items", t, f"{t}: {lo - 1} item(s), minItems is {lo}",
                     lambda rd, p=list(path), n=lo - 1: setattr(rd, "body", _set(rd.body, p, _get(rd.body, p)[:n])))
            if hi is not None and value:
                emit("invalid", "max-items", t, f"{t}: {hi + 1} items, maxItems is {hi}",
                     lambda rd, p=list(path), n=hi + 1: setattr(rd, "body", _set(rd.body, p, _repeat(_get(rd.body, p), n))))
            if s.get("uniqueItems") and value:
                emit("invalid", "unique-items", t, f"{t}: duplicate items, uniqueItems is true",
                     lambda rd, p=list(path): setattr(rd, "body", _set(rd.body, p, _get(rd.body, p) + [copy.deepcopy(_get(rd.body, p)[0])])))
            if self.boundary and hi is not None and value and hi <= 50 and len(value) != hi:
                emit("boundary", "max-items", t, f"{t}: exactly maxItems ({hi}) items",
                     lambda rd, p=list(path), n=hi: setattr(rd, "body", _set(rd.body, p, _repeat(_get(rd.body, p), n, unique=bool(s.get('uniqueItems')), gen=self.gen, doc=doc, schema=s))))
            items = s.get("items")
            if value and isinstance(items, (dict, bool)):
                self._walk(doc, items, value[0], path + [0], emit, depth + 1)

    def _branch_for(self, doc, s: Dict[str, Any], value: Any) -> Dict[str, Any]:
        """For oneOf/anyOf, picks the branch the generated value most likely came from."""
        for key in ("oneOf", "anyOf"):
            branches = s.get(key)
            if not isinstance(branches, list) or not branches:
                continue
            best, score = None, -1
            for b in branches:
                rb = resolve(doc, b)
                if not isinstance(rb, dict):
                    continue
                if isinstance(value, dict):
                    sc = len(set(value) & set(rb.get("properties") or {}))
                else:
                    sc = 1 if _allows([t for t in schema_types(rb) if t != "null"], value) else 0
                if sc > score:
                    best, score = rb, sc
            if best is not None:
                siblings = {k: v for k, v in s.items() if k not in ("oneOf", "anyOf", "discriminator")}
                if siblings.get("properties"):
                    merged = dict(best)
                    merged["properties"] = {**siblings["properties"], **(best.get("properties") or {})}
                    merged["required"] = list(dict.fromkeys((siblings.get("required") or []) + (best.get("required") or [])))
                    return merged
                return best
        return s

    # ---------------------------------------------------- per-value rules

    def _value_rules(self, doc, schema, value, target: str, set_value, emit, is_param: bool = False) -> None:
        s = resolve(doc, schema)
        if not isinstance(s, dict):
            return
        s = self._branch_for(doc, s, value)
        types = [t for t in schema_types(s)]
        non_null = [t for t in types if t != "null"]
        enum = s.get("enum") if isinstance(s.get("enum"), list) else None

        def inv(category: str, desc: str, v: Any) -> None:
            emit("invalid", category, target, f"{target}: {desc}", lambda rd: set_value(rd, copy.deepcopy(v)))

        def bnd(category: str, desc: str, v: Any) -> None:
            if self.boundary:
                emit("boundary", category, target, f"{target}: {desc}", lambda rd: set_value(rd, copy.deepcopy(v)))

        # wrong type
        if non_null and not enum:
            wrong = {"string": 12345, "integer": "not-a-number", "number": "not-a-number", "boolean": "not-a-boolean",
                     "object": "not-an-object", "array": "not-an-array"}.get(non_null[0])
            if is_param and non_null[0] == "string":
                wrong = None  # every parameter arrives as text; a string param can't have the wrong type
            if wrong is not None and not _allows(non_null, wrong):
                inv("type", f"{json.dumps(wrong)} where {'/'.join(non_null)} is expected", wrong)
        # null
        if not is_param and types and not is_nullable(s):
            inv("null", "null for a non-nullable field", None)
        # enum
        if enum:
            bad = next(c for c in ("INVALID_ENUM_VALUE", 999999, "") if c not in enum)
            inv("enum", f"{json.dumps(bad)} is not one of {enum}", bad)
            return
        if "const" in s:
            inv("enum", f"value differs from const {json.dumps(s['const'])}", "not-the-constant" if s["const"] != "not-the-constant" else "x")
            return

        if isinstance(value, str) or (non_null and non_null[0] == "string"):
            self._string_rules(s, target, inv, bnd)
        elif non_null and non_null[0] in ("integer", "number"):
            self._number_rules(s, non_null[0] == "integer", value, inv, bnd)

        if self.hostile and isinstance(value, str) and not s.get("format") and not s.get("pattern"):
            label, text = _HOSTILE[self._hostile_i % len(_HOSTILE)]
            self._hostile_i += 1
            max_len = s.get("maxLength")
            min_len = int(s.get("minLength", 0))
            if max_len is not None:
                text = text[: int(max_len)]
            text = text + "x" * max(0, min_len - len(text))
            emit("hostile", label, target, f"{target}: {label} string (valid per schema; must not cause a 5xx)",
                 lambda rd, v=text: set_value(rd, v))

    def _string_rules(self, s, target, inv, bnd) -> None:
        min_len, max_len = s.get("minLength"), s.get("maxLength")
        pattern, fmt = s.get("pattern"), s.get("format")
        if min_len:
            inv("min-length", f"{min_len - 1} character(s), minLength is {min_len}", "a" * (int(min_len) - 1))
        if max_len is not None:
            inv("max-length", f"{max_len + 1} characters, maxLength is {max_len}", "a" * (int(max_len) + 1))
        if pattern:
            try:
                rx = re.compile(pattern)
                bad = next((c for c in _PATTERN_CANDIDATES if not rx.search(c)
                            and (not min_len or len(c) >= min_len) and (max_len is None or len(c) <= max_len)), None)
                if bad is not None:
                    inv("pattern", f"{json.dumps(bad)} does not match /{pattern}/", bad)
            except re.error:
                pass
        if fmt in _INVALID_FORMATS:
            bad = _INVALID_FORMATS[fmt]
            if max_len is not None:
                bad = bad[: int(max_len)]
            inv("format", f"{json.dumps(bad)} is not a valid {fmt}", bad)
        if not pattern and not fmt:
            if min_len:
                bnd("min-length", f"exactly minLength ({min_len}) characters", "a" * int(min_len))
            if max_len is not None and int(max_len) <= 10000:
                bnd("max-length", f"exactly maxLength ({max_len}) characters", "a" * int(max_len))

    def _number_rules(self, s, integer: bool, value, inv, bnd) -> None:
        mn, mx = s.get("minimum"), s.get("maximum")
        emn, emx = s.get("exclusiveMinimum"), s.get("exclusiveMaximum")
        m = s.get("multipleOf")
        step = 1 if integer else _step(m)
        if mn is not None:
            inv("minimum", f"{_num(mn - step)} is below minimum {_num(mn)}", _num(mn - step))
            bnd("minimum", f"exactly the minimum ({_num(mn)})", _num(mn))
        if emn is not None:
            inv("minimum", f"{_num(emn)} equals exclusiveMinimum", _num(emn))
        if mx is not None:
            inv("maximum", f"{_num(mx + step)} is above maximum {_num(mx)}", _num(mx + step))
            bnd("maximum", f"exactly the maximum ({_num(mx)})", _num(mx))
        if emx is not None:
            inv("maximum", f"{_num(emx)} equals exclusiveMaximum", _num(emx))
        if integer:
            base = value if isinstance(value, int) and not isinstance(value, bool) else (mn if mn is not None else 1)
            inv("not-integer", f"{base + 0.5} is not an integer", base + 0.5)
        if m and isinstance(value, (int, float)) and not isinstance(value, bool):
            bad = value + m / 2
            if not integer or float(bad).is_integer():
                bad = _num(bad)
                if abs(bad / m - round(bad / m)) > 1e-9:
                    inv("multiple-of", f"{bad} is not a multiple of {m}", bad)


def _step(m: Any) -> float:
    if m:
        return m
    return 0.01


def _num(v: Any) -> Any:
    if isinstance(v, float):
        v = round(v, 10)
        return int(v) if v.is_integer() and abs(v) < 1e15 else v
    return v


def _get(obj: Any, path: Path) -> Any:
    for p in path:
        obj = obj[p]
    return obj


def _repeat(items: List[Any], n: int, unique: bool = False, gen: Optional[Generator] = None, doc=None, schema=None) -> List[Any]:
    out = list(items[:n])
    seen = {json.dumps(x, sort_keys=True, default=str) for x in out}
    attempts = 0
    while len(out) < n and attempts < n * 30:
        attempts += 1
        if unique and gen is not None:
            v = gen.value(doc, (schema or {}).get("items", {}), depth=1, full=True)
            k = json.dumps(v, sort_keys=True, default=str)
            if k in seen:
                continue
            seen.add(k)
            out.append(v)
        else:
            out.append(copy.deepcopy(items[len(out) % len(items)]) if items else None)
    return out


def _paths(v: Any, prefix: str = "") -> List[str]:
    if isinstance(v, dict):
        out = [prefix + "{}"]
        for k, x in v.items():
            out += _paths(x, f"{prefix}.{k}")
        return out
    if isinstance(v, list):
        out = [prefix + "[]"]
        for x in v:
            out += _paths(x, prefix + "[]")
        return out
    return [prefix + ":" + _json_type(v)] if v is None or isinstance(v, (dict, list)) else [prefix]


def _shape(rd: RequestData) -> Tuple:
    """Structure of a request (keys and nesting, not values)."""
    return (tuple(sorted(rd.path_params)), tuple(sorted(rd.query)), tuple(sorted(rd.headers)), rd.has_body,
            frozenset(_paths(rd.body)) if rd.has_body else None)
