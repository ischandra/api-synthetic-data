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

from .auth import INVALID, SECRET_NAMES, AuthConfig, AuthError, AuthManager, Credentials, describe
from .infer import extract_records
from .model import Case, Endpoint, RequestData

MODES = ("safe", "read", "all")
READ_METHODS = ("GET", "HEAD", "OPTIONS")
_PHASE = {"POST": 0, "GET": 1, "HEAD": 1, "OPTIONS": 1, "PUT": 2, "PATCH": 2, "DELETE": 3}
BUG_CATEGORIES = ("auth-bypass", "server-error", "validation-gap", "valid-rejected")
_SECRET = re.compile(r"(?i)(authorization|cookie|token|secret|passw(or)?d|api[-_]?key|credential)")


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


def _mask_headers(h: Dict[str, Any], extra: Tuple[str, ...] = ()) -> Dict[str, Any]:
    return {k: ("***" if _SECRET.search(k) or k.lower() in extra else v) for k, v in h.items()}


def _mask_url(url: str, extra: Tuple[str, ...] = ()) -> str:
    from urllib.parse import parse_qsl, urlencode, urlsplit as _split, urlunsplit
    parts = _split(url)
    if not parts.query:
        return url
    q = [(k, "***" if SECRET_NAMES.search(k) or k.lower() in extra else v)
         for k, v in parse_qsl(parts.query, keep_blank_values=True)]
    return urlunsplit(parts._replace(query=urlencode(q, safe="*")))


class Unreachable(RuntimeError):
    """The API can't be reached at all (DNS, refused connection, TLS) - stop instead of failing every case."""


class Runner:
    def __init__(self, base_url: str, creds: Optional[Credentials] = None, headers: Optional[Dict[str, str]] = None,
                 mode: str = "safe", rps: float = 5.0, timeout: float = 30.0, pinned: Optional[Dict[str, Any]] = None,
                 verify_tls: bool = True, progress: Optional[Callable[[str], None]] = None, auth_tests: bool = True):
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
        self.auth = AuthManager(self.creds, self.session, self.base_url, timeout, self.headers)
        self.auth_tests = auth_tests
        self._secret_names = tuple(n.lower() for n in (self.creds.api_key_name,) if n)
        self.requests_sent = 0
        self.responses = 0
        self._consecutive_errors = 0
        self._last = 0.0

    @property
    def missing_credentials(self) -> set:
        return self.auth.missing

    # ----------------------------------------------------------------- public

    def run(self, results: List[Tuple[Endpoint, List[Case]]]) -> List[Outcome]:
        ordered = sorted(results, key=lambda r: (_PHASE.get(r[0].method, 1), r[0].path.count("{"), r[0].path))
        out: List[Outcome] = []
        for ep, cases in ordered:
            check_auth = self.auth_tests and self.auth.requires_auth(ep.security)
            ordered_cases = self._ordered_cases(cases)
            valid = [c for c in ordered_cases if c.kind == "valid"]
            ep_out: List[Outcome] = []
            if check_auth and ep.method == "DELETE":   # check before the record is gone
                ep_out += self._auth_tests(ep, valid[:1])
                check_auth = False
            valid_out = [self._run_case(ep, c) for c in valid]
            ep_out += valid_out
            if check_auth:
                # reuse a request that really succeeded, so a refusal can only be about the credentials
                ok = [c for c, o in zip(valid, valid_out) if o.verdict == "pass"]
                ep_out += self._auth_tests(ep, ok[:1] or valid[:1])
            ep_out += [self._run_case(ep, c) for c in ordered_cases if c.kind != "valid"]
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
        rd = self._prepare(ep, case)
        if isinstance(rd, Outcome):
            return rd
        try:
            resp, req_info = self._send(ep, rd)
            self._consecutive_errors = 0
            self.responses += 1
        except AuthError as e:
            return Outcome(ep.key, case, "attention", "auth", detail=f"could not authenticate: {e}",
                           request=self._describe(ep, rd))
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

    def _prepare(self, ep: Endpoint, case: Case):
        """The request to send (path params resolved, safety rules applied) - or a skip Outcome."""
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
        return rd

    # ------------------------------------------------- auth enforcement tests

    def _auth_tests(self, ep: Endpoint, cases: List[Case]) -> List[Outcome]:
        """A secured endpoint must refuse requests with no credentials and with invalid ones."""
        base = cases[0] if cases else None
        if base is None:
            return []
        variants = [("no-credentials", "a request with no credentials", True, False),
                    ("invalid-credentials", "a request with invalid credentials", False, True)]
        schemes = " or ".join(" + ".join(describe(x) for x in req) for req in (ep.security or []) if req)
        out = []
        for vid, desc, anonymous, corrupt in variants:
            case = Case(id=f"auth:{vid}", kind="auth", request=base.request, expect="401/403", category="auth",
                        target="auth", description=f"{desc} (endpoint requires {schemes})")
            rd = self._prepare(ep, case)
            if isinstance(rd, Outcome):
                out.append(rd)
                continue
            try:
                resp, info = self._send(ep, rd, anonymous=anonymous, corrupt=corrupt)
            except requests.exceptions.SSLError:
                out.append(Outcome(ep.key, case, "pass", "ok", detail="refused during the TLS handshake"))
                continue
            except requests.RequestException as e:
                out.append(Outcome(ep.key, case, "attention", "request-error", detail=f"{type(e).__name__}: {e}"))
                continue
            s = resp.status_code
            ms = round(resp.elapsed.total_seconds() * 1000)
            if s >= 500:
                o = Outcome(ep.key, case, "bug", "server-error", s, ms, f"{s} {resp.reason} for {desc}")
            elif s >= 400 or 300 <= s < 400:
                o = Outcome(ep.key, case, "pass", "ok", s, ms, f"refused with {s}")
            else:
                o = Outcome(ep.key, case, "bug", "auth-bypass", s, ms,
                            f"{desc} was accepted with {s}: authentication is not enforced (spec requires {schemes})")
            o.request, o.response = info, resp.text[:500]
            out.append(o)
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

    def _send(self, ep: Endpoint, rd: RequestData, anonymous: bool = False, corrupt: bool = False
              ) -> Tuple[requests.Response, Dict[str, Any]]:
        """``anonymous``: no credentials at all; ``corrupt``: wrong credentials (auth enforcement tests)."""
        resp, info = self._send_once(ep, rd, anonymous, corrupt)
        if resp.status_code == 401 and not (anonymous or corrupt) and self.auth.refreshable():
            self.auth.invalidate()  # expired token / session: authenticate again and retry once
            resp, info = self._send_once(ep, rd, anonymous, corrupt)
        return resp, info

    def _send_once(self, ep: Endpoint, rd: RequestData, anonymous: bool, corrupt: bool
                   ) -> Tuple[requests.Response, Dict[str, Any]]:
        headers = {**self.headers, **{k: str(v) for k, v in rd.headers.items()}}
        extra_query: Dict[str, str] = {}
        auth_obj = None
        session = self.session
        if anonymous or corrupt:
            # a clean session: no session cookies; keep the TLS client cert only for "invalid credentials"
            session = requests.Session()
            session.verify = self.session.verify
            if corrupt:
                session.cert = self.session.cert
            headers = {k: v for k, v in headers.items() if not SECRET_NAMES.search(k)}
        if not anonymous:
            auth_obj, _ = self.auth.apply(ep.security, headers, extra_query, corrupt=corrupt)
        url = self.base_url + rd.url()
        if extra_query:
            from urllib.parse import urlencode
            url += ("&" if "?" in url else "?") + urlencode(extra_query)
        kwargs: Dict[str, Any] = {"headers": headers, "timeout": self.timeout, "auth": auth_obj}
        if session.verify is not True:
            # requests lets REQUESTS_CA_BUNDLE override a session-level CA bundle; pass ours per request
            kwargs["verify"] = session.verify
        if anonymous or corrupt:
            kwargs["allow_redirects"] = False  # a redirect to a login page is a refusal, not a bypass
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
        resp = self._request(ep.method, url, kwargs, session)
        secret_q = tuple(k.lower() for k in extra_query) + self._secret_names
        info = {"method": ep.method, "url": _mask_url(url, secret_q),
                "headers": _mask_headers(resp.request.headers, secret_q), "body": rd.body if rd.has_body else None}
        return resp, info

    def _request(self, method: str, url: str, kwargs: Dict[str, Any],
                 session: Optional[requests.Session] = None) -> requests.Response:
        session = session or self.session
        for attempt in range(4):
            wait = self.min_interval - (time.monotonic() - self._last)
            if wait > 0:
                time.sleep(wait)
            self._last = time.monotonic()
            resp = session.request(method, url, **kwargs)
            self.requests_sent += 1
            if resp.status_code != 429 or attempt == 3:
                return resp
            retry_after = resp.headers.get("Retry-After", "")
            time.sleep(min(float(retry_after) if retry_after.isdigit() else 2 ** attempt, 30))
        return resp

    def _describe(self, ep: Endpoint, rd: RequestData) -> Dict[str, Any]:
        return {"method": ep.method, "url": _mask_url(self.base_url + rd.url(), self._secret_names),
                "body": rd.body if rd.has_body else None}

    # -------------------------------------------------------------- verdicts

    def _judge(self, ep: Endpoint, case: Case, resp: requests.Response) -> Outcome:
        s = resp.status_code
        ms = round(resp.elapsed.total_seconds() * 1000)

        def o(verdict: str, category: str, detail: str) -> Outcome:
            return Outcome(ep.key, case, verdict, category, s, ms, detail)

        if s in (401, 403):
            need = f" (the spec requires: {'; '.join(sorted(self.missing_credentials))})" if self.missing_credentials else ""
            return o("attention", "auth", f"{s} {resp.reason}: not authorised{need}")
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
