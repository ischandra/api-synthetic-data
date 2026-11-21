"""OAuth 2.0 / OpenID Connect providers: discovery, client authentication and a headless
authorization-code + PKCE login.

Written for PingFederate / PingOne and equally usable with Okta, Microsoft Entra ID, Keycloak, Auth0, ...

PingFederate specifics handled:
  * discovery at {issuer}/.well-known/openid-configuration; when it isn't exposed, PingFederate's standard
    endpoints are assumed: /as/token.oauth2 and /as/authorization.oauth2
  * client authentication: client_secret_basic, client_secret_post, private_key_jwt (RS/PS/ES),
    client_secret_jwt (HS256), tls_client_auth (mTLS), or none (public clients with PKCE)
  * the HTML Form Adapter login page: fields pf.username / pf.pass, and the hidden pf.ok flag its
    JavaScript sets to "clicked" on submit (without it PingFederate treats the post as not submitted)
"""
from __future__ import annotations

import base64
import hashlib
import secrets
import time
import uuid
from html.parser import HTMLParser
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urljoin, urlsplit

import requests

PINGFED_TOKEN_PATH = "/as/token.oauth2"
PINGFED_AUTHZ_PATH = "/as/authorization.oauth2"
ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"


class ProviderError(RuntimeError):
    pass


# ------------------------------------------------------------------ discovery

def discover(session: requests.Session, issuer: str, timeout: float, tls: Dict[str, Any]) -> Dict[str, Any]:
    base = issuer.rstrip("/")
    url = base + "/.well-known/openid-configuration"
    try:
        r = session.get(url, timeout=timeout, **tls)
        meta = r.json() if r.status_code < 400 else None
    except (requests.RequestException, ValueError):
        meta = None
    if isinstance(meta, dict) and meta.get("token_endpoint"):
        return meta
    # PingFederate without discovery exposed (or an older version): its standard endpoint paths
    return {"issuer": issuer, "token_endpoint": base + PINGFED_TOKEN_PATH,
            "authorization_endpoint": base + PINGFED_AUTHZ_PATH, "_assumed": True}


# ------------------------------------------------------- client authentication

def client_assertion(client_id: str, audience: str, key_pem: Optional[bytes] = None, secret: Optional[str] = None,
                     alg: Optional[str] = None, kid: Optional[str] = None) -> str:
    """RFC 7523 client assertion for private_key_jwt (key_pem) or client_secret_jwt (secret)."""
    import jwt  # PyJWT

    now = int(time.time())
    claims = {"iss": client_id, "sub": client_id, "aud": audience, "jti": uuid.uuid4().hex, "iat": now, "exp": now + 120}
    headers = {"kid": kid} if kid else None
    if key_pem is not None:
        from cryptography.hazmat.primitives.asymmetric import ec, rsa
        from cryptography.hazmat.primitives.serialization import load_pem_private_key

        key = load_pem_private_key(key_pem, password=None)
        if alg is None:
            if isinstance(key, rsa.RSAPrivateKey):
                alg = "RS256"
            elif isinstance(key, ec.EllipticCurvePrivateKey):
                alg = {256: "ES256", 384: "ES384", 521: "ES512"}.get(key.curve.key_size, "ES256")
            else:
                raise ProviderError("unsupported private key type for private_key_jwt (use RSA or EC)")
        return jwt.encode(claims, key, algorithm=alg, headers=headers)
    if not secret:
        raise ProviderError("client_secret_jwt needs --client-secret")
    return jwt.encode(claims, secret, algorithm=alg or "HS256", headers=headers)


# --------------------------------------------------------- headless login

class _Forms(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.forms: List[Dict[str, Any]] = []
        self.title = ""
        self._in_title = False

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        a = {k: (v or "") for k, v in attrs}
        if tag == "form":
            self.forms.append({"action": a.get("action", ""), "method": (a.get("method") or "post").lower(),
                               "inputs": [], "buttons": []})
        elif tag == "input" and self.forms:
            t = a.get("type", "text").lower()
            if t in ("submit", "image", "button"):
                if a.get("name"):
                    self.forms[-1]["buttons"].append((a["name"], a.get("value", "")))
            elif a.get("name"):
                self.forms[-1]["inputs"].append({"name": a["name"], "type": t, "value": a.get("value", ""),
                                                 "checked": "checked" in a})
        elif tag == "button" and self.forms and a.get("name"):
            self.forms[-1]["buttons"].append((a["name"], a.get("value", "")))
        elif tag == "title":
            self._in_title = True

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title += data.strip()


def pkce_pair() -> Tuple[str, str]:
    verifier = secrets.token_urlsafe(64)[:96]
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


def authorization_code_login(session: requests.Session, authorize_url: str, client_id: str, redirect_uri: str,
                             scope: str, username: str, password: str, timeout: float, tls: Dict[str, Any],
                             user_field: Optional[str] = None, pass_field: Optional[str] = None,
                             max_steps: int = 15) -> Tuple[str, str]:
    """Drives the provider's login pages like a browser (without JavaScript) until it redirects to
    ``redirect_uri`` with a code. Returns (code, PKCE verifier). The redirect URI itself is never called."""
    verifier, challenge = pkce_pair()
    state = secrets.token_urlsafe(16)
    params = {"response_type": "code", "client_id": client_id, "redirect_uri": redirect_uri, "state": state,
              "code_challenge": challenge, "code_challenge_method": "S256"}
    if scope:
        params["scope"] = scope
    r = session.get(authorize_url, params=params, allow_redirects=False, timeout=timeout, **tls)
    logged_in = False
    for _ in range(max_steps):
        if r.status_code in (301, 302, 303, 307, 308):
            loc = urljoin(r.url, r.headers.get("Location", ""))
            if loc.split("?")[0].split("#")[0] == redirect_uri.split("?")[0]:
                parts = urlsplit(loc)
                q = {**parse_qs(parts.fragment), **parse_qs(parts.query)}
                if "error" in q:
                    raise ProviderError(f"authorization refused: {q['error'][0]} {q.get('error_description', [''])[0]}")
                if q.get("state", [None])[0] != state:
                    raise ProviderError("authorization response state doesn't match the request (possible CSRF)")
                if not q.get("code"):
                    raise ProviderError("redirect without an authorization code")
                return q["code"][0], verifier
            r = session.get(loc, allow_redirects=False, timeout=timeout, **tls)
            continue
        if r.status_code >= 400:
            raise ProviderError(f"authorization step {r.url.split('?')[0]} returned {r.status_code}")
        p = _Forms()
        p.feed(r.text)
        login = next((f for f in p.forms if any(i["type"] == "password" for i in f["inputs"])), None)
        form = login or (p.forms[0] if p.forms else None)
        if form is None:
            raise ProviderError(f"no form to submit at {r.url.split('?')[0]} (page '{p.title or 'untitled'}'). "
                                "MFA, captcha or JavaScript-only login pages can't be automated: get a token in a "
                                "browser and pass --token")
        data: Dict[str, str] = {}
        for i in form["inputs"]:
            if i["type"] in ("checkbox", "radio"):
                if i["checked"] or (i["type"] == "checkbox" and not login):  # consent pages: approve requested scopes
                    data[i["name"]] = i["value"] or "on"
            else:
                data[i["name"]] = i["value"]
        if login is not None:
            if logged_in:
                raise ProviderError(f"login failed: the login form came back (check --username/--password; "
                                    f"page '{p.title or 'untitled'}')")
            pwd = pass_field or next(i["name"] for i in form["inputs"] if i["type"] == "password")
            usr = user_field or next((i["name"] for i in form["inputs"]
                                      if i["type"] in ("text", "email") and i["name"] != pwd), None)
            if not usr:
                raise ProviderError("couldn't find the username field on the login form; pass --form-user-field")
            data[usr], data[pwd] = username, password
            logged_in = True
        if "pf.ok" in data:            # PingFederate HTML Form Adapter: set by its JavaScript on submit
            data["pf.ok"] = "clicked"
        data.pop("pf.cancel", None)
        if form["buttons"] and not any(b[0] in data for b in form["buttons"]):
            data.setdefault(*form["buttons"][0])
        action = urljoin(r.url, form["action"] or r.url)
        if form["method"] == "get":
            r = session.get(action, params=data, allow_redirects=False, timeout=timeout, **tls)
        else:
            r = session.post(action, data=data, allow_redirects=False, timeout=timeout, **tls)
    raise ProviderError(f"the login didn't reach the redirect URI within {max_steps} steps")
