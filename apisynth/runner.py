"""Runs generated cases against a live API and judges every response.

Built to be pointed at *any* API, including ones you don't own:

* Order: POST (creates) -> GET -> PUT/PATCH -> DELETE, so later calls can use records created earlier.
* Real ids at run time: a path parameter such as ``{petId}`` is filled from records this run created
  (POST responses) or found in list endpoints (GET responses), or from ``--param``.
* Safe by default (mode "safe"): PUT/PATCH/DELETE - and POSTs to an existing record's sub-path - only touch
  records created by this run (or ids you pinned). Mode "read" sends only GET/HEAD; mode "all" lifts the rule.
* Polite: rate-limited, retries 429 responses honouring Retry-After, bounded timeouts.
* Verdicts separate API bugs (server errors, validation gaps, valid data rejected) from things that need your
  attention but aren't bugs (missing credentials, missing test data, rate limiting, network errors).
"""
from __future__ import annotations

import copy
import json
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

import requests

from .infer import extract_records
from .model import Case, Endpoint, RequestData

MODES = ("safe", "read", "all")
READ_METHODS = ("GET", "HEAD", "OPTIONS")
_PHASE = {"POST": 0, "GET": 1, "HEAD": 1, "OPTIONS": 1, "PUT": 2, "PATCH": 2, "DELETE": 3}
BUG_CATEGORIES = ("server-error", "validation-gap", "valid-rejected")
_SECRET = re.compile(r"(?i)(authorization|cookie|token|secret|passw(or)?d|api[-_]?key|credential)")


@dataclass
class Credentials:
    token: Optional[str] = None
    api_key: Optional[str] = None
    api_key_name: Optional[str] = None
    basic: Optional[Tuple[str, str]] = None

    def any(self) -> bool:
        return bool(self.token or self.api_key or self.basic)


@dataclass
class Outcome:
    endpoint: str
    case: Case
    verdict: str                 # pass | bug | attention | skip
    category: str                # ok | server-error | validation-gap | valid-rejected | auth | not-found | ...
    status: Optional[int] = None
    elapsed_ms: Optional[int] = None
    detail: str = ""
    request: Dict[str, Any] = field(default_factory=dict)
    response: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"endpoint": self.endpoint, "case": self.case.id, "kind": self.case.kind,
                "rule": self.case.description, "verdict": self.verdict, "category": self.category,
                "status": self.status, "elapsed_ms": self.elapsed_ms, "detail": self.detail,
                "request": self.request, "response": self.response}


def _id_keys(name: str) -> List[str]:
    """Record fields that may hold the value for path parameter ``name``."""
    snake = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name).lower()
    keys = [name, snake, re.sub(r"_([a-z])", lambda m: m.group(1).upper(), snake)]
    if re.search(r"(?i)(^|_)id$|Id$|ID$", name):
        keys += ["id", "_id", "uuid"]
    return list(dict.fromkeys(keys))


def _collection(path: str, name: str) -> str:
    """'/users/{userId}/orders/{orderId}', 'orderId' -> '/users/{userId}/orders'"""
    return path.split("/{" + name + "}", 1)[0] or "/"


def _mask_headers(h: Dict[str, Any]) -> Dict[str, Any]:
    return {k: ("***" if _SECRET.search(k) else v) for k, v in h.items()}


class Unreachable(RuntimeError):
    """The API can't be reached at all (DNS, refused connection, TLS) - stop instead of failing every case."""


class Runner:
    def __init__(self, base_url: str, creds: Optional[Credentials] = None, headers: Optional[Dict[str, str]] = None,
                 mode: str = "safe", rps: float = 5.0, timeout: float = 30.0, pinned: Optional[Dict[str, Any]] = None,
                 verify_tls: bool = True, progress: Optional[Callable[[str], None]] = None):
        if mode not in MODES:
            raise ValueError(f"mode must be one of {MODES}")
        self.base_url = base_url.rstrip("/")
        self.creds = creds or Credentials()
        self.headers = dict(headers or {})
        self.mode = mode
        self.min_interval = 1.0 / rps if rps > 0 else 0.0
        self.timeout = timeout
        self.pinned = dict(pinned or {})
        self.session = requests.Session()
        self.session.verify = verify_tls
        self.progress = progress or (lambda msg: None)
        self.created: Dict[str, List[Dict[str, Any]]] = {}     # collection path -> records this run created
        self.discovered: Dict[str, List[Dict[str, Any]]] = {}  # collection path -> records seen in GET responses
        self.missing_credentials: set = set()
        self.requests_sent = 0
        self.responses = 0
        self._consecutive_errors = 0
        self._last = 0.0

    # ----------------------------------------------------------------- public

    def run(self, results: List[Tuple[Endpoint, List[Case]]]) -> List[Outcome]:
        ordered = sorted(results, key=lambda r: (_PHASE.get(r[0].method, 1), r[0].path.count("{"), r[0].path))
        out: List[Outcome] = []
        for ep, cases in ordered:
            ep_out = [self._run_case(ep, c) for c in self._ordered_cases(cases)]
            out += ep_out
            counts = {v: sum(1 for o in ep_out if o.verdict == v) for v in ("pass", "bug", "attention", "skip")}
            self.progress(f"  {ep.key:50} {counts['pass']:3} ok  {counts['bug']:3} bugs  "
                          f"{counts['attention']:3} attention  {counts['skip']:3} skipped")
        return out

    @staticmethod
    def _ordered_cases(cases: List[Case]) -> List[Case]:
        # valid first (they create the records later calls reuse), then boundary, invalid, hostile
        rank = {"valid": 0, "boundary": 1, "invalid": 2, "hostile": 3}
        return sorted(cases, key=lambda c: rank.get(c.kind, 9))

    # -------------------------------------------------------------- per case

    def _run_case(self, ep: Endpoint, case: Case) -> Outcome:
        writes = ep.method not in READ_METHODS
        if self.mode == "read" and writes:
            return Outcome(ep.key, case, "skip", "skipped", detail="read-only mode (--mode read)")
        rd = copy.deepcopy(case.request)
        for p in [p for p in ep.params if p.location == "path"]:
            tests_this_param = case.target == f"path.{p.name}"
            if tests_this_param:
                if writes and self.mode == "safe" and case.kind != "invalid":
                    return Outcome(ep.key, case, "skip", "skipped",
                                   detail=f"a valid {p.name} value could match an existing record (safe mode)")
                continue
            value, why = self._resolve(ep, p.name, writes)
            if value is None:
                return Outcome(ep.key, case, "skip", "missing-data", detail=why)
            rd.path_params[p.name] = value

        if writes and ep.method != "POST" and not any(p.location == "path" for p in ep.params) \
                and self.mode == "safe" and isinstance(rd.body, dict):
            # e.g. PUT /pet {"id": ...}: the record is named in the body; aim it at one this run created
            if not self._aim_body_at_created(ep, rd):
                return Outcome(ep.key, case, "skip", "missing-data",
                               detail=f"{ep.method} identifies the record in the body; no record created by this run "
                                      f"to target (safe mode). Use --mode all to allow it")
        try:
            resp, req_info = self._send(ep, rd)
            self._consecutive_errors = 0
            self.responses += 1
        except requests.RequestException as e:
            self._consecutive_errors += 1
            if self.responses == 0 and self._consecutive_errors >= 3:
                raise Unreachable(f"Can't reach {self.base_url}: {type(e).__name__}: {e}") from e
            return Outcome(ep.key, case, "attention", "request-error", detail=f"{type(e).__name__}: {e}",
                           request=self._describe(ep, rd))
        out = self._judge(ep, case, resp)
        out.request = req_info
        out.response = resp.text[:500]
        if 200 <= resp.status_code < 300 and case.kind == "valid":
            self._remember(ep, rd, resp)
        return out

    def _resolve(self, ep: Endpoint, name: str, writes: bool) -> Tuple[Optional[Any], str]:
        if name in self.pinned:
            return self.pinned[name], "pinned"
        coll = _collection(ep.path, name)
        safe_write = writes and self.mode == "safe"
        pools = [self.created] if safe_write else [self.created, self.discovered]
        for pool in pools:
            for cpath in sorted(pool, key=lambda c: (c != coll, len(c))):
                if cpath == coll or (cpath.startswith(coll + "/") and "{" not in cpath[len(coll):]):
                    for rec in reversed(pool[cpath]):
                        for key in _id_keys(name):
                            v = rec.get(key) if isinstance(rec, dict) else None
                            if v not in (None, "") and not isinstance(v, (dict, list, bool)):
                                return v, "found"
        if safe_write:
            return None, (f"no {{{name}}} created by this run to {ep.method} (safe mode never changes records it "
                          f"didn't create): pass --param {name}=<value> or --mode all")
        return None, f"no existing {{{name}}} found in responses: pass --param {name}=<value>"

    def _aim_body_at_created(self, ep: Endpoint, rd: RequestData) -> bool:
        records = self.created.get(ep.path) or []
        id_fields = [k for k in rd.body if re.fullmatch(r"(?i)id|_id|uuid|[a-z]+_?id", k)]
        for rec in reversed(records):
            hits = {k: rec[k] for k in id_fields if k in rec and not isinstance(rec[k], (dict, list))}
            if hits:
                rd.body.update(hits)
                return True
        return False

    def _remember(self, ep: Endpoint, rd: RequestData, resp: requests.Response) -> None:
        try:
            body = resp.json()
        except ValueError:
            body = None
        records = [r for r in extract_records(body) if isinstance(r, dict)] if body is not None else []
        if ep.method == "POST":
            sent = rd.body if isinstance(rd.body, dict) else {}
            if not records and resp.headers.get("Location"):
                records = [{"id": resp.headers["Location"].rstrip("/").rsplit("/", 1)[-1]}]
            records = [{**sent, **r} for r in records] or ([sent] if sent and resp.status_code in (200, 201) else [])
            self.created.setdefault(ep.path, []).extend(records)
        elif ep.method in READ_METHODS and not any(p.location == "path" for p in ep.params):
            self.discovered.setdefault(ep.path, []).extend(records[:50])

    # ---------------------------------------------------------------- HTTP

    def _auth(self, ep: Endpoint, headers: Dict[str, str], query: Dict[str, Any]) -> Optional[Tuple[str, str]]:
        c = self.creds
        wanted = ep.auth
        have = {"bearer": bool(c.token), "apikey": bool(c.api_key), "basic": bool(c.basic)}
        if wanted and not have.get(wanted["type"]):
            if c.any():  # the spec offers this scheme first, but use whatever credentials were given
                wanted = None
            else:
                self.missing_credentials.add(wanted["type"])
                return None
        if wanted is None:
            if c.token:
                wanted = {"type": "bearer"}
            elif c.api_key:
                wanted = {"type": "apikey", "name": c.api_key_name or "X-API-Key", "in": "header"}
            elif c.basic:
                wanted = {"type": "basic"}
            else:
                return None
        if wanted["type"] == "bearer":
            headers.setdefault("Authorization", f"Bearer {c.token}")
        elif wanted["type"] == "apikey":
            name = c.api_key_name or wanted.get("name") or "X-API-Key"
            (query if wanted.get("in") == "query" else headers).setdefault(name, c.api_key)
        elif wanted["type"] == "basic":
            return c.basic
        return None

    def _send(self, ep: Endpoint, rd: RequestData) -> Tuple[requests.Response, Dict[str, Any]]:
        headers = {**self.headers, **{k: str(v) for k, v in rd.headers.items()}}
        extra_query: Dict[str, Any] = {}
        basic = self._auth(ep, headers, extra_query)
        url = self.base_url + rd.url()
        if extra_query:
            url += ("&" if "?" in url else "?") + "&".join(f"{k}={v}" for k, v in extra_query.items())
        kwargs: Dict[str, Any] = {"headers": headers, "timeout": self.timeout, "auth": basic}
        ct = ep.content_type or "application/json"
        if rd.has_body:
            if ct == "application/x-www-form-urlencoded" and isinstance(rd.body, dict):
                kwargs["data"] = {k: ("" if v is None else v if isinstance(v, str) else json.dumps(v))
                                  for k, v in rd.body.items()}
            elif ct.startswith("multipart/") and isinstance(rd.body, dict):
                kwargs["files"] = {k: (None, v if isinstance(v, str) else json.dumps(v)) for k, v in rd.body.items()}
            elif "json" in ct:
                kwargs["json"] = rd.body
            else:
                headers.setdefault("Content-Type", ct)
                kwargs["data"] = (rd.body if isinstance(rd.body, str) else json.dumps(rd.body)).encode()
        resp = self._request(ep.method, url, kwargs)
        info = {"method": ep.method, "url": url, "headers": _mask_headers(resp.request.headers),
                "body": rd.body if rd.has_body else None}
        return resp, info

    def _request(self, method: str, url: str, kwargs: Dict[str, Any]) -> requests.Response:
        for attempt in range(4):
            wait = self.min_interval - (time.monotonic() - self._last)
            if wait > 0:
                time.sleep(wait)
            self._last = time.monotonic()
            resp = self.session.request(method, url, **kwargs)
            self.requests_sent += 1
            if resp.status_code != 429 or attempt == 3:
                return resp
            retry_after = resp.headers.get("Retry-After", "")
            time.sleep(min(float(retry_after) if retry_after.isdigit() else 2 ** attempt, 30))
        return resp

    def _describe(self, ep: Endpoint, rd: RequestData) -> Dict[str, Any]:
        return {"method": ep.method, "url": self.base_url + rd.url(), "body": rd.body if rd.has_body else None}

    # -------------------------------------------------------------- verdicts

    def _judge(self, ep: Endpoint, case: Case, resp: requests.Response) -> Outcome:
        s = resp.status_code
        ms = round(resp.elapsed.total_seconds() * 1000)

        def o(verdict: str, category: str, detail: str) -> Outcome:
            return Outcome(ep.key, case, verdict, category, s, ms, detail)

        if s in (401, 403):
            need = f" (the spec asks for {', '.join(sorted(self.missing_credentials))} credentials)" \
                if self.missing_credentials else ""
            return o("attention", "auth", f"{s} {resp.reason}: not authorised{need}; pass --token / --api-key / --basic")
        if s == 429:
            return o("attention", "rate-limited", "429 Too Many Requests even after retries; lower --rps")
        if case.kind in ("valid", "boundary"):
            if s < 400:
                return o("pass", "ok", f"{s} {resp.reason}")
            if s >= 500:
                return o("bug", "server-error", f"{s} {resp.reason} for a valid request ({case.description})")
            if s == 404 and any(p.location == "path" for p in ep.params):
                return o("attention", "not-found", f"404: the record used may not exist; pass --param to choose one")
            return o("bug", "valid-rejected", f"{s} {resp.reason}: valid data per the spec was rejected "
                                               f"({case.description})")
        if case.kind == "invalid":
            if 400 <= s < 500:
                return o("pass", "ok", f"rejected with {s}")
            if s >= 500:
                return o("bug", "server-error", f"{s} {resp.reason} instead of a 4xx for invalid input: "
                                                 f"{case.description}")
            return o("bug", "validation-gap", f"invalid data accepted with {s}: {case.description}")
        # hostile
        if s >= 500:
            return o("bug", "server-error", f"{s} {resp.reason} on hostile input: {case.description}")
        return o("pass", "ok", f"handled with {s}")
