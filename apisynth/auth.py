"""Authentication for calling APIs.

Covers every scheme OpenAPI can describe, plus common real-world ones:

  http bearer / JWT ............ --token
  apiKey (header/query/cookie).. --api-key  (name and location from the spec)
  http basic / digest .......... --basic / --digest USER:PASS
  oauth2 ....................... client_credentials, password and refresh_token grants: the token is fetched
                                 from the spec's tokenUrl (or --token-url), cached and renewed on expiry / 401.
                                 authorizationCode / implicit need a browser: pass --token
  openIdConnect ................ token endpoint discovered from openIdConnectUrl
  mutualTLS .................... --cert / --cert-key / --ca-bundle
  AWS Signature V4 ............. --aws-sigv4 REGION/SERVICE (keys from --aws-* or the AWS_* env vars)
  login endpoint ............... --login "POST /auth/login": token taken from the response (or the session cookie kept)
  session cookie ............... --cookie "sid=..."

Security requirements are honoured as OpenAPI defines them: alternatives (OR) and combined schemes (AND); the
first alternative you have credentials for is used. Any secret may be given as ``env:VAR_NAME``.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import hmac
import json
import os
import re
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, quote, urljoin, urlsplit

import requests
from requests.auth import AuthBase, HTTPBasicAuth, HTTPDigestAuth

INVALID = "invalid-credential-apisynth"
SECRET_NAMES = re.compile(r"(?i)(authorization|cookie|token|secret|passw(or)?d|api[-_]?key|credential|signature|"
                          r"x-amz-security-token)")


class AuthError(RuntimeError):
    """Credentials could not be obtained (token endpoint / login failed)."""


def secret(value: Optional[str]) -> Optional[str]:
    """``env:NAME`` -> the value of environment variable NAME (keeps secrets out of command lines)."""
    if value and value.startswith("env:"):
        name = value[4:]
        if name not in os.environ:
            raise ValueError(f"environment variable {name} is not set")
        return os.environ[name]
    return value


def pair(value: Optional[str], flag: str) -> Optional[Tuple[str, str]]:
    value = secret(value)
    if not value:
        return None
    if ":" not in value:
        raise ValueError(f"{flag} expects USER:PASS")
    user, _, pwd = value.partition(":")
    return user, pwd


@dataclass
class AuthConfig:
    token: Optional[str] = None
    api_key: Optional[str] = None
    api_key_name: Optional[str] = None
    api_key_in: Optional[str] = None            # header | query | cookie (default: from the spec)
    basic: Optional[Tuple[str, str]] = None
    digest: Optional[Tuple[str, str]] = None
    # OAuth 2.0 / OpenID Connect
    token_url: Optional[str] = None
    client_id: Optional[str] = None
    client_secret: Optional[str] = None
    scope: Optional[str] = None
    audience: Optional[str] = None
    username: Optional[str] = None              # password grant / login endpoint
    password: Optional[str] = None
    refresh_token: Optional[str] = None
    client_auth: str = "basic"                  # client credentials at the token endpoint: basic | body
    # login endpoint
    login: Optional[str] = None                 # "POST /auth/login"
    login_body: Optional[str] = None            # JSON; default {"username": ..., "password": ...}
    login_token_path: Optional[str] = None      # e.g. $.data.token (default: common token fields)
    login_header: str = "Authorization: Bearer {token}"
    cookie: Optional[str] = None
    # mutual TLS
    cert: Optional[str] = None
    cert_key: Optional[str] = None
    ca_bundle: Optional[str] = None
    # AWS Signature V4
    aws_region: Optional[str] = None
    aws_service: Optional[str] = None
    aws_access_key: Optional[str] = None
    aws_secret_key: Optional[str] = None
    aws_session_token: Optional[str] = None

    @property
    def oauth_capable(self) -> bool:
        return bool((self.client_id and self.client_secret) or (self.username and self.password and self.token_url)
                    or self.refresh_token)

    @property
    def aws(self) -> bool:
        return bool(self.aws_region and self.aws_service and self.aws_access_key and self.aws_secret_key)

    def any(self) -> bool:
        return bool(self.token or self.api_key or self.basic or self.digest or self.oauth_capable or self.login
                    or self.cookie or self.cert or self.aws)


# Backwards-compatible name used by earlier versions / tests
Credentials = AuthConfig


def describe(scheme: Dict[str, Any]) -> str:
    t = scheme.get("type", "?")
    if t == "apikey":
        return f"API key '{scheme.get('param')}' in {scheme.get('in', 'header')}"
    if t == "oauth2":
        flows = ", ".join(scheme.get("flows") or {}) or "oauth2"
        return f"OAuth2 ({flows})"
    return {"bearer": "bearer token", "basic": "HTTP basic", "digest": "HTTP digest", "openid": "OpenID Connect",
            "mtls": "client certificate (mTLS)", "awsv4": "AWS Signature V4"}.get(t, t)


# ===================================================================== AWS SigV4

class SigV4Auth(AuthBase):
    """AWS Signature Version 4 (as used by API Gateway, Lambda URLs, OpenSearch, ...)."""

    def __init__(self, access_key: str, secret_key: str, region: str, service: str,
                 session_token: Optional[str] = None, now: Optional[_dt.datetime] = None):
        self.access_key, self.secret_key = access_key, secret_key
        self.region, self.service, self.session_token, self.now = region, service, session_token, now

    @staticmethod
    def _sign(key: bytes, msg: str) -> bytes:
        return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

    def __call__(self, r: requests.PreparedRequest) -> requests.PreparedRequest:
        t = self.now or _dt.datetime.now(_dt.timezone.utc)
        amz_date, date = t.strftime("%Y%m%dT%H%M%SZ"), t.strftime("%Y%m%d")
        parts = urlsplit(r.url)
        body = r.body or b""
        if isinstance(body, str):
            body = body.encode("utf-8")
        payload_hash = hashlib.sha256(body).hexdigest()
        r.headers["X-Amz-Date"] = amz_date
        if self.session_token:
            r.headers["X-Amz-Security-Token"] = self.session_token
        if self.service == "s3":
            r.headers["X-Amz-Content-SHA256"] = payload_hash
        host = parts.hostname or ""
        if parts.port and not ((parts.scheme == "https" and parts.port == 443) or (parts.scheme == "http" and parts.port == 80)):
            host += f":{parts.port}"
        signed = {"host": host}
        for name, value in r.headers.items():
            ln = name.lower()
            if ln.startswith("x-amz-") or ln == "content-type":
                signed[ln] = " ".join(str(value).split())
        names = sorted(signed)
        canonical_headers = "".join(f"{n}:{signed[n]}\n" for n in names)
        signed_headers = ";".join(names)
        path = parts.path or "/"
        canonical_uri = path if self.service == "s3" else quote(path, safe="/~")
        query = sorted((quote(k, safe="-_.~"), quote(v, safe="-_.~"))
                       for k, v in parse_qsl(parts.query, keep_blank_values=True))
        canonical_query = "&".join(f"{k}={v}" for k, v in query)
        canonical_request = "\n".join([r.method.upper(), canonical_uri, canonical_query, canonical_headers,
                                       signed_headers, payload_hash])
        scope = f"{date}/{self.region}/{self.service}/aws4_request"
        string_to_sign = "\n".join(["AWS4-HMAC-SHA256", amz_date, scope,
                                    hashlib.sha256(canonical_request.encode("utf-8")).hexdigest()])
        k = self._sign(("AWS4" + self.secret_key).encode("utf-8"), date)
        for part in (self.region, self.service, "aws4_request"):
            k = self._sign(k, part)
        signature = hmac.new(k, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()
        r.headers["Authorization"] = (f"AWS4-HMAC-SHA256 Credential={self.access_key}/{scope}, "
                                      f"SignedHeaders={signed_headers}, Signature={signature}")
        return r


# ================================================================== the manager

def _extract(doc: Any, path: Optional[str]) -> Optional[str]:
    if path:
        node = doc
        for tok in re.findall(r"[^.\[\]$]+", path):
            if isinstance(node, list) and tok.isdigit() and int(tok) < len(node):
                node = node[int(tok)]
            elif isinstance(node, dict) and tok in node:
                node = node[tok]
            else:
                return None
        return node if isinstance(node, str) else None
    for container in (doc, (doc or {}).get("data") if isinstance(doc, dict) else None,
                      (doc or {}).get("result") if isinstance(doc, dict) else None):
        if isinstance(container, dict):
            for k in ("access_token", "accessToken", "token", "jwt", "id_token", "idToken", "authToken", "sessionToken"):
                if isinstance(container.get(k), str):
                    return container[k]
    return None


class AuthManager:
    """Decides, per endpoint, which credentials to send and obtains tokens when needed."""

    def __init__(self, cfg: AuthConfig, session: requests.Session, base_url: str, timeout: float = 30.0,
                 extra_headers: Optional[Dict[str, str]] = None):
        self.cfg = cfg
        self.session = session
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.extra_headers = {k.lower() for k in (extra_headers or {})}
        self.missing: set = set()
        self._tokens: Dict[Tuple[str, str], Tuple[str, float]] = {}
        self._login_token: Optional[str] = None
        self._logged_in = False
        self._refresh_token = cfg.refresh_token
        self._last_grant: Optional[str] = None
        self._oidc: Dict[str, str] = {}
        self.used_refreshable = False
        self.failed: Optional[str] = None
        if cfg.cert:
            session.cert = (cfg.cert, cfg.cert_key) if cfg.cert_key else cfg.cert
        if cfg.ca_bundle:
            session.verify = cfg.ca_bundle

    # ------------------------------------------------------- choosing schemes

    def can(self, s: Dict[str, Any]) -> bool:
        c, t = self.cfg, s.get("type")
        if t == "bearer":
            return bool(c.token or c.login or (c.oauth_capable and c.token_url))
        if t == "oauth2":
            return bool(c.token or c.login or (c.oauth_capable and (c.token_url or self._flow_token_url(s))))
        if t == "openid":
            return bool(c.token or c.login or (c.oauth_capable and (c.token_url or s.get("url"))))
        if t == "apikey":
            # a session cookie (from --login or --cookie) is how "API key in cookie" schemes are usually satisfied
            return bool(c.api_key) or (s.get("in") == "cookie" and bool(c.login or c.cookie))
        if t == "basic":
            return bool(c.basic)
        if t == "digest":
            return bool(c.digest or c.basic)
        if t == "mtls":
            return bool(c.cert)
        if t == "awsv4":
            return c.aws
        return "authorization" in self.extra_headers  # unknown scheme: satisfied by a custom -H header

    def choose(self, security: Optional[List[List[Dict[str, Any]]]]) -> Optional[List[Dict[str, Any]]]:
        """The schemes to apply: [] = none needed, None = needed but no matching credentials."""
        if security is None:
            return self._default()
        if not security:
            return []
        anonymous = False
        for req in security:
            if not req:
                anonymous = True
                continue
            if all(self.can(s) for s in req):
                return req
        if anonymous:
            return []
        self.missing.add(" + ".join(describe(s) for s in security[0]))
        return None

    def requires_auth(self, security: Optional[List[List[Dict[str, Any]]]]) -> bool:
        return bool(security) and all(req for req in security)

    def _default(self) -> List[Dict[str, Any]]:
        """No security info (Postman without auth, live URLs): use whatever was configured."""
        c = self.cfg
        if c.aws:
            return [{"type": "awsv4"}]
        if c.token or c.login or c.oauth_capable:
            return [{"type": "bearer"}]
        if c.api_key:
            return [{"type": "apikey", "param": c.api_key_name or "X-API-Key", "in": c.api_key_in or "header"}]
        if c.basic:
            return [{"type": "basic"}]
        if c.digest:
            return [{"type": "digest"}]
        return []

    # ------------------------------------------------------ applying schemes

    def apply(self, security, headers: Dict[str, str], query: Dict[str, str], corrupt: bool = False
              ) -> Tuple[Optional[AuthBase], bool]:
        """Adds credentials to ``headers`` / ``query``. Returns (requests auth object, satisfied).
        ``corrupt=True`` sends deliberately wrong credentials of the same kind (auth enforcement tests)."""
        if self.failed and not corrupt:
            raise AuthError(self.failed)
        if corrupt:  # wrong credentials of the kind the endpoint asks for, whatever we were given
            schemes = next((req for req in (security or []) if req), None) or self._default() or [{"type": "bearer"}]
            satisfied = True
        else:
            schemes = self.choose(security)
            satisfied = schemes is not None
            schemes = schemes or []
        auth_obj: Optional[AuthBase] = None
        try:
            for s in schemes:
                auth_obj = self._apply_one(s, headers, query, corrupt) or auth_obj
        except AuthError as e:
            self.failed = str(e)  # don't hammer a failing token endpoint / login for every case
            raise
        if self.cfg.cookie and not corrupt:
            headers["Cookie"] = "; ".join(x for x in (headers.get("Cookie"), self.cfg.cookie) if x)
        return auth_obj, satisfied

    def _apply_one(self, s: Dict[str, Any], headers: Dict[str, str], query: Dict[str, str], corrupt: bool
                   ) -> Optional[AuthBase]:
        c, t = self.cfg, s.get("type")
        if t in ("bearer", "oauth2", "openid"):
            if corrupt:
                headers["Authorization"] = f"Bearer {INVALID}"
                return None
            # OAuth/OpenID endpoints get a fetched token when OAuth credentials are configured;
            # plain bearer endpoints prefer the static --token
            can_fetch = c.oauth_capable and bool(c.token_url or self._flow_token_url(s) or s.get("url"))
            order = ("oauth", "token", "login") if t != "bearer" else ("token", "login", "oauth")
            for way in order:
                if way == "token" and c.token:
                    headers["Authorization"] = f"Bearer {c.token}"
                    break
                if way == "login" and c.login:
                    hdr = self._login_header()
                    if hdr:  # None = cookie-based session, already on the session
                        headers[hdr[0]] = hdr[1]
                    break
                if way == "oauth" and (can_fetch or (t == "bearer" and c.oauth_capable and c.token_url)):
                    headers["Authorization"] = f"Bearer {self._oauth_token(s)}"
                    self.used_refreshable = True
                    break
        elif t == "apikey":
            if not c.api_key and not corrupt:
                if s.get("in") == "cookie" and c.login and not self._logged_in:
                    self._login()  # the session cookie lands on the session
                return None
            name = c.api_key_name or s.get("param") or "X-API-Key"
            where = c.api_key_in or s.get("in") or "header"
            value = INVALID if corrupt else c.api_key
            if where == "query":
                query[name] = value
            elif where == "cookie":
                headers["Cookie"] = "; ".join(x for x in (headers.get("Cookie"), f"{name}={value}") if x)
            else:
                headers[name] = value
        elif t == "basic":
            user, pwd = c.basic or ("apisynth", INVALID)
            return HTTPBasicAuth(user, INVALID if corrupt else pwd)
        elif t == "digest":
            user, pwd = c.digest or c.basic or ("apisynth", INVALID)
            return HTTPDigestAuth(user, INVALID if corrupt else pwd)
        elif t == "awsv4":
            return SigV4Auth(c.aws_access_key or "AKIAINVALIDAPISYNTH", INVALID if corrupt else c.aws_secret_key,
                             c.aws_region or "us-east-1", c.aws_service or "execute-api",
                             None if corrupt else c.aws_session_token)
        # mtls: applied on the session; unknown schemes: the user's -H header
        return None

    # ----------------------------------------------------------- tokens

    @staticmethod
    def _flow_token_url(s: Dict[str, Any]) -> Optional[str]:
        flows = s.get("flows") or {}
        for name in ("clientCredentials", "password", "authorizationCode"):
            if isinstance(flows.get(name), dict) and flows[name].get("tokenUrl"):
                return flows[name]["tokenUrl"]
        return None

    def _token_url(self, s: Dict[str, Any]) -> str:
        url = self.cfg.token_url or self._flow_token_url(s)
        if not url and s.get("type") == "openid" and s.get("url"):
            disc = s["url"]
            if disc not in self._oidc:
                r = self.session.get(urljoin(self.base_url + "/", disc), timeout=self.timeout, **self._tls())
                if r.status_code >= 400:
                    raise AuthError(f"OpenID discovery {disc} returned {r.status_code}")
                self._oidc[disc] = r.json().get("token_endpoint", "")
            url = self._oidc[disc]
        if not url:
            raise AuthError("no OAuth token URL: the spec doesn't give one; pass --token-url")
        return url if re.match(r"(?i)^https?://", url) else urljoin(self.base_url + "/", url)

    def _oauth_token(self, s: Dict[str, Any]) -> str:
        c = self.cfg
        scopes = c.scope or " ".join(s.get("scopes") or [])
        url = self._token_url(s)
        key = (url, scopes)
        cached = self._tokens.get(key)
        if cached and cached[1] > time.time():
            return cached[0]
        data: Dict[str, str] = {}
        # renew with the refresh_token grant when one was given or came from a password grant;
        # client_credentials simply asks again (refresh tokens aren't meant for that grant)
        if self._refresh_token and (c.refresh_token or self._last_grant in ("password", "refresh_token")):
            data = {"grant_type": "refresh_token", "refresh_token": self._refresh_token}
        elif c.username and c.password:
            data = {"grant_type": "password", "username": c.username, "password": c.password}
        elif c.client_id and c.client_secret:
            data = {"grant_type": "client_credentials"}
        else:
            raise AuthError("OAuth needs --client-id/--client-secret, --username/--password or --refresh-token")
        if scopes:
            data["scope"] = scopes
        if c.audience:
            data["audience"] = c.audience
        auth = None
        if c.client_id:
            if c.client_auth == "body":
                data.update({"client_id": c.client_id, "client_secret": c.client_secret or ""})
            else:
                auth = HTTPBasicAuth(c.client_id, c.client_secret or "")
        r = self.session.post(url, data=data, auth=auth, timeout=self.timeout, headers={"Accept": "application/json"},
                              **self._tls())
        try:
            body = r.json()
        except ValueError:
            body = {}
        if r.status_code >= 400 or not isinstance(body, dict) or not body.get("access_token"):
            raise AuthError(f"OAuth {data['grant_type']} token request to {url} failed: {r.status_code} "
                            f"{(body.get('error_description') or body.get('error') or r.text)[:200] if isinstance(body, dict) else r.text[:200]}")
        if body.get("refresh_token"):
            self._refresh_token = body["refresh_token"]
        self._last_grant = data["grant_type"]
        ttl = float(body.get("expires_in") or 3600)
        self._tokens[key] = (body["access_token"], time.time() + max(ttl - 30, ttl * 0.5, 1))
        return body["access_token"]

    def _login_header(self) -> Optional[Tuple[str, str]]:
        if not self._logged_in:
            self._login()
        if self._login_token is None:  # session-cookie login: the cookie is on the session already
            return None
        name, _, template = self.cfg.login_header.partition(":")
        return name.strip(), template.strip().replace("{token}", self._login_token)

    def _login(self) -> None:
        c = self.cfg
        method, _, path = c.login.strip().partition(" ")
        if not path:
            method, path = "POST", method
        url = path if re.match(r"(?i)^https?://", path) else self.base_url + "/" + path.lstrip("/")
        if c.login_body:
            body = json.loads(c.login_body)
        elif c.username is not None:
            body = {"username": c.username, "password": c.password}
        elif c.basic:
            body = {"username": c.basic[0], "password": c.basic[1]}
        else:
            raise AuthError("--login needs --login-body, or --username/--password")
        r = self.session.request(method.upper(), url, json=body, timeout=self.timeout, **self._tls())
        if r.status_code >= 400:
            raise AuthError(f"login {method.upper()} {path} failed: {r.status_code} {r.text[:200]}")
        try:
            doc = r.json()
        except ValueError:
            doc = None
        self._login_token = _extract(doc, c.login_token_path)
        if self._login_token is None and not self.session.cookies:
            raise AuthError(f"login {path} succeeded but returned no token "
                            f"{'at ' + c.login_token_path if c.login_token_path else ''} and set no cookie; "
                            "use --login-token-path")
        self._logged_in = True
        self.used_refreshable = True

    def _tls(self) -> Dict[str, Any]:
        # requests lets REQUESTS_CA_BUNDLE override a session-level CA bundle; pass ours per request
        return {} if self.session.verify is True else {"verify": self.session.verify}

    def refreshable(self) -> bool:
        return self.used_refreshable

    def invalidate(self) -> None:
        """After a 401: forget cached tokens / login so the next request re-authenticates."""
        self.used_refreshable = False
        self._tokens.clear()
        self._logged_in = False
        self._login_token = None
