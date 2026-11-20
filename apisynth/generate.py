"""Schema-driven generation of *valid* request data."""
from __future__ import annotations

import base64
import copy
import datetime as dt
import json
import math
import random
import re
import string
import uuid
from typing import Any, Dict, List, Optional

from faker import Faker
from rstr.xeger import Xeger

from .model import Case, Endpoint, RequestData
from .schema import is_nullable, ref_name, resolve, schema_types
from .semantics import DOMAINS, Semantics

def _fits(v: str, pattern: str, min_len: int, max_len: Optional[int]) -> bool:
    try:
        return bool(re.search(pattern, v)) and len(v) >= min_len and (max_len is None or len(v) <= int(max_len))
    except re.error:
        return False


SKIP_HEADERS = {"authorization", "content-type", "accept", "content-length", "cookie", "user-agent"}


class Generator:
    """Seeded generator: the same seed + inputs always produce the same data."""

    def __init__(self, seed: Optional[int] = None, optional_rate: float = 0.7, max_depth: int = 5,
                 prefer_examples: bool = False):
        self.seed = seed if seed is not None else random.SystemRandom().randint(1, 2**31 - 1)
        self.rng = random.Random(self.seed)
        self.fake = Faker()
        self.fake.seed_instance(self.seed)
        self.sem = Semantics(self.rng, self.fake)
        self.xeger = Xeger(self.rng)
        self.optional_rate = optional_rate
        self.max_depth = max_depth
        self.prefer_examples = prefer_examples
        self._context: List[str] = []

    # ------------------------------------------------------------- requests

    def request(self, ep: Endpoint, full: bool = False) -> RequestData:
        """One valid request. ``full=True`` includes every optional field/param
        (used as the base for negative mutations)."""
        rd = RequestData(ep.method, ep.path)
        segs = [x for x in ep.path.split("/") if x and not x.startswith("{")]
        self._context = [segs[-1] if segs else ""]
        for p in ep.params:
            if p.location == "header" and p.name.lower() in SKIP_HEADERS:
                continue
            include = p.location == "path" or p.required or full or self.rng.random() < self.optional_rate / 2
            if not include:
                continue
            v = self.value(ep.doc, p.schema or {"type": "string"}, name=p.name, depth=1, full=full)
            {"path": rd.path_params, "query": rd.query, "header": rd.headers, "cookie": rd.headers}[p.location][p.name] = v
        if ep.body_schema is not None:
            rd.body = self.value(ep.doc, ep.body_schema, name=None, depth=0, full=full)
            rd.has_body = True
        return rd

    def valid_cases(self, ep: Endpoint, count: int) -> List[Case]:
        return [Case(id=f"valid-{i}", kind="valid", request=self.request(ep), expect="2xx",
                     description="Valid request with synthetic data") for i in range(1, count + 1)]

    # --------------------------------------------------------------- values

    def value(self, doc: Dict[str, Any], schema: Any, name: Optional[str] = None, depth: int = 0,
              full: bool = False) -> Any:
        s = resolve(doc, schema)
        if s is True or s is None or s == {}:
            return self._string({}, name)
        if not isinstance(s, dict):
            return None

        if self.prefer_examples:
            if "example" in s:
                return copy.deepcopy(s["example"])
            if isinstance(s.get("examples"), list) and s["examples"]:
                return copy.deepcopy(self.rng.choice(s["examples"]))
        if "const" in s:
            return copy.deepcopy(s["const"])
        if isinstance(s.get("enum"), list) and s["enum"]:
            options = [v for v in s["enum"] if v is not None] or s["enum"]
            return copy.deepcopy(self.rng.choice(options))

        for key in ("oneOf", "anyOf"):
            if isinstance(s.get(key), list) and s[key]:
                return self._choice(doc, s, key, name, depth, full)

        types = [t for t in schema_types(s) if t != "null"]
        if not types:
            return None if "null" in schema_types(s) else self._string(s, name)
        t = types[0] if len(types) == 1 else self.rng.choice(types)

        if t == "object":
            if depth > self.max_depth:
                return {}
            if name:
                self._context.append(name)
            try:
                return self._object(doc, s, depth, full)
            finally:
                if name:
                    self._context.pop()
        if t == "array":
            return [] if depth > self.max_depth else self._array(doc, s, name, depth, full)
        if t == "string":
            return self._string(s, name)
        if t == "integer":
            return self._number(s, name, integer=True)
        if t == "number":
            return self._number(s, name, integer=False)
        if t == "boolean":
            sv = self.sem.value_for(name, "boolean")
            return sv if sv is not None else self.rng.random() < 0.5
        return None

    def _choice(self, doc, s, key, name, depth, full):
        branches = [b for b in s[key] if not (isinstance(resolve(doc, b), dict) and resolve(doc, b).get("type") == "null")]
        branch = self.rng.choice(branches or s[key])
        siblings = {k: v for k, v in s.items() if k not in ("oneOf", "anyOf", "discriminator")}
        target = {"allOf": [siblings, branch]} if any(k in siblings for k in ("properties", "required", "type")) else branch
        value = self.value(doc, target, name, depth, full)
        disc = s.get("discriminator")
        if isinstance(disc, dict) and isinstance(value, dict) and disc.get("propertyName"):
            mapping = disc.get("mapping") or {}
            ref = branch.get("$ref") if isinstance(branch, dict) else None
            tag = next((k for k, v in mapping.items() if v == ref or v.rsplit("/", 1)[-1] == ref_name(branch)), None)
            value[disc["propertyName"]] = tag or ref_name(branch) or value.get(disc["propertyName"])
        return value

    def _object(self, doc, s, depth, full) -> Dict[str, Any]:
        props: Dict[str, Any] = s.get("properties") or {}
        required = list(s.get("required") or [])
        out: Dict[str, Any] = {}
        for p, ps in props.items():
            if p in required or full or self.rng.random() < self.optional_rate:
                out[p] = self.value(doc, ps, name=p, depth=depth + 1, full=full)
        for p in required:
            if p not in out:
                out[p] = self._string({}, p)
        extra = s.get("additionalProperties")
        if not props and isinstance(extra, dict):
            for _ in range(self.rng.randint(1, 2)):
                out[self.fake.word()] = self.value(doc, extra, depth=depth + 1, full=full)
        min_props = s.get("minProperties", 0)
        for p, ps in props.items():
            if len(out) >= min_props:
                break
            if p not in out:
                out[p] = self.value(doc, ps, name=p, depth=depth + 1, full=full)
        return out

    def _array(self, doc, s, name, depth, full) -> List[Any]:
        lo = int(s.get("minItems", 0))
        hi = s.get("maxItems")
        lo_eff = max(lo, 1)
        hi_eff = min(int(hi), max(lo_eff, 3)) if hi is not None else max(lo_eff, 3)  # typical sizes; limits are
        lo_eff = min(lo_eff, hi_eff)                                                  # covered by boundary cases
        n = self.rng.randint(lo_eff, hi_eff)
        prefix = s.get("prefixItems") or []
        items_schema = s.get("items", {})
        if isinstance(items_schema, list):  # draft-4 tuple form
            prefix, items_schema = items_schema, {}
        singular = name[:-1] if name and name.endswith("s") else name
        out: List[Any] = [self.value(doc, ps, singular, depth + 1, full) for ps in prefix]
        seen = {json.dumps(v, sort_keys=True, default=str) for v in out}
        attempts = 0
        while len(out) < max(n, len(prefix)) and attempts < n * 20:
            attempts += 1
            v = self.value(doc, items_schema, singular, depth + 1, full)
            key = json.dumps(v, sort_keys=True, default=str)
            prefer_unique = not isinstance(v, (dict, list)) and attempts < n * 10  # realistic: no ["eco","eco"]
            if key in seen and (s.get("uniqueItems") or prefer_unique):
                continue
            seen.add(key)
            out.append(v)
        return out

    def _string(self, s: Dict[str, Any], name: Optional[str]) -> str:
        min_len = int(s.get("minLength", 0))
        max_len = s.get("maxLength")
        pattern = s.get("pattern")
        if pattern:
            # prefer a realistic value when it (or a compact/code variant of it) fits the pattern
            for sv in (self.sem.value_for(name, "string"), self.sem.value_for(f"{name} code", "string")):
                if isinstance(sv, str):
                    for cand in (sv, re.sub(r"[\s().-]", "", sv)):
                        if _fits(cand, pattern, min_len, max_len):
                            return cand
            v = self._from_pattern(pattern, min_len, max_len)
            if v is not None:
                return v
        fmt = s.get("format")
        v = self._format(fmt, name) if fmt else None
        examples = s.get("examples") if isinstance(s.get("examples"), list) else []
        if "example" in s:
            examples = examples + [s["example"]]
        examples = [e for e in examples if isinstance(e, str) and e]
        if v is None:
            v = self.sem.value_for(name, "string", self._context[-1] if self._context else None)
            if isinstance(v, str) and examples:
                v = self._match_shape(v, examples, name)
        if v is None and examples:  # values the spec author / real responses show are the safest choice
            v = self.rng.choice(examples)
        if v is None:
            if min_len > 30:
                v = self.fake.text(max_nb_chars=max(min_len * 2, 60))
            else:
                v = self.fake.word() if not name else f"{self.fake.word()}-{self.rng.randint(1, 999)}"
        v = str(v)
        if max_len is not None and len(v) > int(max_len):
            v = v[: int(max_len)]
        if len(v) < min_len:
            v += "".join(self.rng.choice(string.ascii_lowercase) for _ in range(min_len - len(v)))
        return v

    def _match_shape(self, v: str, examples: List[str], name: Optional[str]) -> Optional[str]:
        """If every example has a distinctive shape (e.g. 2-letter code) the value must too."""
        for shape in (r"[A-Z]{2}", r"[A-Z]{3}", r"[A-Z][A-Z0-9_]*", r"\d+", r"[a-z][a-z0-9_-]*"):
            if all(re.fullmatch(shape, e) for e in examples):
                if re.fullmatch(shape, v):
                    return v
                alt = self.sem.value_for(f"{name} code", "string")
                if isinstance(alt, str) and re.fullmatch(shape, alt):
                    return alt
                return self.rng.choice(examples)
        return v

    def _from_pattern(self, pattern: str, min_len: int, max_len: Optional[int]) -> Optional[str]:
        try:
            rx = re.compile(pattern)
        except re.error:
            return None
        for _ in range(25):
            try:
                v = self.xeger.xeger(pattern)
            except Exception:  # unsupported construct
                return None
            if rx.search(v) and len(v) >= min_len and (max_len is None or len(v) <= int(max_len)):
                return v
        return None

    def _format(self, fmt: str, name: Optional[str]) -> Optional[str]:
        r, f = self.rng, self.fake
        now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
        if fmt == "date":
            sv = self.sem.value_for(name, "string")
            if isinstance(sv, str) and re.fullmatch(r"\d{4}-\d{2}-\d{2}", sv):
                return sv
            return (now.date() - dt.timedelta(days=r.randint(-365, 3 * 365))).isoformat()
        if fmt == "date-time":
            return (now - dt.timedelta(seconds=r.randint(-30 * 86400, 3 * 365 * 86400))).isoformat().replace("+00:00", "Z")
        if fmt == "time":
            return f"{r.randint(0, 23):02d}:{r.randint(0, 59):02d}:{r.randint(0, 59):02d}"
        if fmt in ("email", "idn-email"):
            return self.sem.value_for("email", "string")
        if fmt == "uuid":
            return str(uuid.UUID(int=r.getrandbits(128), version=4))
        if fmt in ("uri", "url", "iri", "uri-reference", "iri-reference"):
            return self.sem.value_for(name, "string") if name and re.search(r"(?i)url|uri|link|image|avatar", name) \
                else f"https://{f.word()}.{r.choice(DOMAINS)}/{f.word()}"
        if fmt in ("hostname", "idn-hostname"):
            return f"{f.word()}.{r.choice(DOMAINS)}"
        if fmt == "ipv4":
            return f"{r.choice(['192.0.2.', '198.51.100.', '203.0.113.'])}{r.randint(1, 254)}"
        if fmt == "ipv6":
            return "2001:db8::" + ":".join(f"{r.randint(0, 65535):x}" for _ in range(3))
        if fmt == "byte":
            return base64.b64encode(bytes(r.getrandbits(8) for _ in range(12))).decode()
        if fmt == "binary":
            return "synthetic-file-content"
        if fmt == "password":
            return f.password(length=14)
        if fmt in ("int32", "int64"):
            return str(r.randint(1, 100000))
        if fmt == "phone":
            return f"+1-{r.randint(201, 989)}-555-{r.randint(100, 199):04d}"
        return None

    def _number(self, s: Dict[str, Any], name: Optional[str], integer: bool) -> Any:
        mn, mx = s.get("minimum"), s.get("maximum")
        emn, emx = s.get("exclusiveMinimum"), s.get("exclusiveMaximum")
        m = s.get("multipleOf")
        if integer:
            lo = math.ceil(mn) if mn is not None else None
            if emn is not None:
                lo = max(lo if lo is not None else -math.inf, math.floor(emn) + 1)
            hi = math.floor(mx) if mx is not None else None
            if emx is not None:
                hi = min(hi if hi is not None else math.inf, math.ceil(emx) - 1)
        else:
            lo = mn if mn is not None else (emn if emn is not None else None)
            hi = mx if mx is not None else (emx if emx is not None else None)
            if emn is not None and mn is None:
                lo = emn + min(0.01, (hi - emn) / 10 if hi is not None else 0.01)
            if emx is not None and mx is None:
                hi = emx - min(0.01, (emx - lo) / 10 if lo is not None else 0.01)

        sv = self.sem.value_for(name, "integer" if integer else "number")
        if isinstance(sv, (int, float)) and not isinstance(sv, bool) and (lo is None or sv >= lo) \
                and (hi is None or sv <= hi) and not m:
            return int(sv) if integer else sv

        examples = [e for e in (s.get("examples") or []) + ([s["example"]] if "example" in s else [])
                    if isinstance(e, (int, float)) and not isinstance(e, bool)]
        if lo is None and hi is None and examples:  # stay in the magnitude real data shows
            e_lo, e_hi = min(examples), max(examples)
            lo, hi = (min(0, e_lo) if e_lo <= 0 else e_lo / 2), (e_hi * 1.5 if e_hi > 0 else e_hi + 10)
            if integer:
                lo, hi = math.floor(lo), max(math.ceil(hi), math.floor(lo) + 1)
        if lo is None and hi is None:
            lo, hi = (1, 1000) if integer else (1.0, 1000.0)
        elif lo is None:
            lo = hi - 1000 if hi < 1 else max(0 if integer else 0.0, hi - 1000)
        elif hi is None:
            hi = lo + 1000
        if lo > hi:
            lo, hi = hi, lo

        if m:
            k_lo, k_hi = math.ceil(lo / m - 1e-9), math.floor(hi / m + 1e-9)
            if k_lo <= k_hi:
                v = self.rng.randint(int(k_lo), int(k_hi)) * m
                if integer:
                    return int(round(v))
                decimals = max(0, -int(math.floor(math.log10(abs(m))))) if m < 1 else 0
                return round(v, decimals + 2)
        if integer:
            return self.rng.randint(int(lo), int(hi))
        v = round(self.rng.uniform(lo, hi), 2)
        return min(max(v, lo), hi)
