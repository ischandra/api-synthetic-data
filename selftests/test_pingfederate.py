"""PingFederate-style OAuth/OIDC: discovery, every client authentication method, headless
authorization-code + PKCE through the HTML Form Adapter (pf.username / pf.pass / pf.ok) and consent.

The mock provider verifies everything independently: client assertions with the client's PUBLIC key (PyJWT),
audience/issuer/expiry/jti-replay, PKCE S256, single-use codes, registered redirect URIs and auth methods."""
import base64
import hashlib
import html
import json
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlencode, urlsplit

import pytest

from apisynth.__main__ import main

jwt = pytest.importorskip("jwt")
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, rsa  # noqa: E402

REDIRECT = "https://app.example.com/callback"
TOKEN_USES = 3


def _pem(key):
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


class PingFed:
    def __init__(self, discovery=True, methods=None):
        self.rsa = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.ec = ec.generate_private_key(ec.SECP256R1())
        self.discovery = discovery
        self.methods = methods or ["client_secret_basic", "client_secret_post", "private_key_jwt",
                                   "client_secret_jwt", "tls_client_auth", "none"]
        self.clients = {
            "cc-basic": {"auth": "client_secret_basic", "secret": "s3cret", "grants": ["client_credentials"]},
            "cc-post": {"auth": "client_secret_post", "secret": "s3cret", "grants": ["client_credentials"]},
            "cc-rsa": {"auth": "private_key_jwt", "key": self.rsa.public_key(), "kid": "k-rsa", "grants": ["client_credentials"]},
            "cc-ec": {"auth": "private_key_jwt", "key": self.ec.public_key(), "grants": ["client_credentials"]},
            "cc-hs": {"auth": "client_secret_jwt", "secret": "hs-secret-that-is-at-least-32-bytes-long!",
                      "grants": ["client_credentials"]},
            "web-app": {"auth": "client_secret_basic", "secret": "w3bsecret", "consent": True,
                        "grants": ["authorization_code", "refresh_token", "password"], "redirect": REDIRECT},
            "spa": {"auth": "none", "grants": ["authorization_code", "refresh_token"], "redirect": REDIRECT},
        }
        self.tokens, self.codes, self.pending, self.jtis, self.log = {}, {}, {}, set(), []
        self.origin = ""

    # --- token endpoint helpers
    def authenticate_client(self, headers, form):
        basic = headers.get("Authorization", "")
        if basic.startswith("Basic "):
            cid, _, sec = base64.b64decode(basic[6:]).decode().partition(":")
            c = self.clients.get(cid)
            ok = c and c["auth"] == "client_secret_basic" and c["secret"] == sec
            return (cid, "client_secret_basic") if ok else (None, "bad basic")
        if "client_assertion" in form:
            assertion = form["client_assertion"]
            if form.get("client_assertion_type") != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer":
                return None, "bad assertion type"
            cid = jwt.decode(assertion, options={"verify_signature": False}).get("iss")
            c = self.clients.get(cid)
            if not c or c["auth"] not in ("private_key_jwt", "client_secret_jwt"):
                return None, "client not registered for jwt auth"
            key = c["key"] if c["auth"] == "private_key_jwt" else c["secret"]
            algs = ["RS256", "PS256", "ES256"] if c["auth"] == "private_key_jwt" else ["HS256"]
            try:
                claims = jwt.decode(assertion, key, algorithms=algs, audience=self.origin + "/as/token.oauth2",
                                    issuer=cid, options={"require": ["exp", "iat", "jti", "sub"]})
            except jwt.PyJWTError as e:
                return None, f"assertion invalid: {e}"
            if claims["sub"] != cid or claims["jti"] in self.jtis:
                return None, "assertion replayed or wrong subject"
            if c.get("kid") and jwt.get_unverified_header(assertion).get("kid") != c["kid"]:
                return None, "wrong kid"
            self.jtis.add(claims["jti"])
            return cid, c["auth"]
        cid = form.get("client_id")
        c = self.clients.get(cid)
        if c and c["auth"] == "client_secret_post" and form.get("client_secret") == c["secret"]:
            return cid, "client_secret_post"
        if c and c["auth"] == "none" and "client_secret" not in form:
            return cid, "none"
        return None, "client authentication failed"

    def issue(self, cid, grant):
        tok = "pf-at-" + secrets.token_hex(8)
        self.tokens[tok] = TOKEN_USES
        self.log.append((cid, grant))
        out = {"access_token": tok, "token_type": "Bearer", "expires_in": 7200}
        if grant != "client_credentials":
            out["refresh_token"] = "pf-rt-" + secrets.token_hex(8)
        return out

    def login_page(self, resume, error=""):
        return (f"<html><head><title>Sign On</title></head><body><form method='POST' "
                f"action='/as/{resume}/resume/as/authorization.ping'>"
                f"<input type='text' name='pf.username' value=''/><input type='password' name='pf.pass'/>"
                f"<input type='hidden' name='pf.ok' value=''/><input type='hidden' name='pf.cancel' value=''/>"
                f"<input type='hidden' name='pf.adapterId' value='HTMLFormAdapter'/>"
                f"<a href='#' onclick='postOk()'>Sign On</a>{html.escape(error)}</form></body></html>")


def make_handler(pf):
    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        def reply(self, code, body=None, ctype="application/json", headers=None):
            data = (json.dumps(body) if ctype == "application/json" else body or "").encode()
            self.send_response(code)
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def form(self):
            n = int(self.headers.get("Content-Length") or 0)
            return {k: v[0] for k, v in parse_qs(self.rfile.read(n).decode(), keep_blank_values=True).items()}

        def do_GET(self):
            u = urlsplit(self.path)
            q = {k: v[0] for k, v in parse_qs(u.query).items()}
            if u.path == "/.well-known/openid-configuration":
                if not pf.discovery:
                    return self.reply(404, {"error": "not found"})
                return self.reply(200, {"issuer": pf.origin, "token_endpoint": pf.origin + "/as/token.oauth2",
                                        "authorization_endpoint": pf.origin + "/as/authorization.oauth2",
                                        "token_endpoint_auth_methods_supported": pf.methods})
            if u.path == "/openapi.json":
                return self.reply(200, SPEC)
            if u.path == "/as/authorization.oauth2":
                c = pf.clients.get(q.get("client_id"))
                if not c or q.get("redirect_uri") != c.get("redirect") or q.get("response_type") != "code":
                    return self.reply(400, "<html>invalid request</html>", "text/html")
                if q.get("code_challenge_method") != "S256" or not q.get("code_challenge"):
                    return self.reply(400, "<html>PKCE required</html>", "text/html")
                resume = secrets.token_hex(4)
                pf.pending[resume] = {**q, "user": None}
                return self.reply(200, pf.login_page(resume), "text/html")
            if u.path.startswith("/api/"):
                tok = self.headers.get("Authorization", "")[7:]
                if pf.tokens.get(tok, 0) <= 0:
                    return self.reply(401, {"error": "invalid_token"})
                pf.tokens[tok] -= 1
                page = q.get("page", "1")
                if not page.isdigit() or not 1 <= int(page) <= 9:
                    return self.reply(400, {"error": "page"})
                return self.reply(200, {"user": "alice", "page": int(page)})
            self.reply(404, {"error": "no route"})

        def do_POST(self):
            u = urlsplit(self.path)
            f = self.form()
            if u.path.endswith("/resume/as/authorization.ping"):
                resume = u.path.split("/")[2]
                p = pf.pending.get(resume)
                if not p:
                    return self.reply(400, "<html>expired</html>", "text/html")
                if p["user"] is None:
                    if f.get("pf.ok") != "clicked":              # what real PingFederate does without JavaScript
                        return self.reply(200, pf.login_page(resume), "text/html")
                    if (f.get("pf.username"), f.get("pf.pass")) != ("alice", "Passw0rd!"):
                        return self.reply(200, pf.login_page(resume, "Authentication failed"), "text/html")
                    p["user"] = "alice"
                    if pf.clients[p["client_id"]].get("consent"):
                        return self.reply(200, (
                            "<html><head><title>Approve access</title></head><body>"
                            f"<form method='POST' action='/as/{resume}/resume/as/authorization.ping'>"
                            "<input type='hidden' name='pf.oauth.authz.consent' value='1'/>"
                            "<input type='checkbox' name='scope' value='openid'/>"
                            "<input type='submit' name='allow' value='Allow'/></form></body></html>"), "text/html")
                elif f.get("pf.oauth.authz.consent") != "1" or f.get("allow") != "Allow":
                    return self.reply(400, "<html>consent required</html>", "text/html")
                code = "pf-code-" + secrets.token_hex(8)
                pf.codes[code] = p
                pf.log.append(("login", "pf.ok" if f.get("pf.ok") == "clicked" or p["user"] else ""))
                return self.reply(302, "", "text/html", {"Location": f"{p['redirect_uri']}?{urlencode({'code': code, 'state': p['state']})}"})
            if u.path == "/as/token.oauth2":
                cid, how = pf.authenticate_client(self.headers, f)
                if cid is None:
                    return self.reply(401, {"error": "invalid_client", "error_description": how})
                c = pf.clients[cid]
                g = f.get("grant_type")
                if g not in c["grants"]:
                    return self.reply(400, {"error": "unauthorized_client", "error_description": f"{g} not allowed"})
                if g == "authorization_code":
                    p = pf.codes.pop(f.get("code"), None)                      # single use
                    if not p or p["client_id"] != cid or f.get("redirect_uri") != p["redirect_uri"]:
                        return self.reply(400, {"error": "invalid_grant", "error_description": "bad code"})
                    want = base64.urlsafe_b64encode(hashlib.sha256(f.get("code_verifier", "").encode()).digest()).rstrip(b"=").decode()
                    if want != p["code_challenge"]:
                        return self.reply(400, {"error": "invalid_grant", "error_description": "PKCE verification failed"})
                if g == "password" and (f.get("username"), f.get("password")) != ("alice", "Passw0rd!"):
                    return self.reply(400, {"error": "invalid_grant", "error_description": "bad credentials"})
                if g == "refresh_token" and not f.get("refresh_token", "").startswith("pf-rt-"):
                    return self.reply(400, {"error": "invalid_grant"})
                return self.reply(200, pf.issue(cid, f"{g}/{how}"))
            self.reply(404, {"error": "no route"})

    return H


SPEC = {"openapi": "3.0.3", "info": {"title": "Ping-protected API", "version": "1"}, "servers": [{"url": "/api"}],
        "security": [{"ping": []}],
        "components": {"securitySchemes": {"ping": {"type": "openIdConnect",
                                                    "openIdConnectUrl": "/.well-known/openid-configuration"}}},
        "paths": {"/profile": {"get": {"parameters": [{"name": "page", "in": "query", "schema": {
            "type": "integer", "minimum": 1, "maximum": 9}}], "responses": {"200": {"description": "ok"}}}}}}


def serve(pf):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(pf))
    pf.origin = f"http://127.0.0.1:{srv.server_address[1]}"
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


@pytest.fixture
def pingfed():
    pf = PingFed()
    srv = serve(pf)
    yield pf
    srv.shutdown()


def run(tmp_path, pf, *args):
    out = tmp_path / "report"
    code = main(["test", pf.origin, "--issuer", pf.origin, *args, "-o", str(out), "-q", "--rps", "0",
                 "-n", "3", "--seed", "1"])
    text = (out / "report.json").read_text()
    return code, json.loads(text), text


def assert_all_authenticated(rep):
    valid = [r for r in rep["results"] if r["kind"] in ("valid", "boundary")]
    assert valid and all(r["status"] == 200 for r in valid), [(r["case"], r["status"], r["detail"]) for r in valid]
    checks = [r for r in rep["results"] if r["kind"] == "auth"]
    assert len(checks) == 2 and all(r["verdict"] == "pass" for r in checks)


@pytest.mark.parametrize("client,key_attr,kid", [("cc-rsa", "rsa", "k-rsa"), ("cc-ec", "ec", None)])
def test_private_key_jwt(tmp_path, pingfed, client, key_attr, kid):
    key = tmp_path / "client.pem"
    key.write_bytes(_pem(getattr(pingfed, key_attr)))
    args = ["--client-id", client, "--client-key", str(key)] + (["--client-key-id", kid] if kid else [])
    _, rep, text = run(tmp_path, pingfed, *args)
    assert_all_authenticated(rep)
    grants = [g for c, g in pingfed.log if c == client]
    assert grants and set(grants) == {"client_credentials/private_key_jwt"} and len(grants) >= 2  # renewed, new jti
    assert "eyJ" not in text  # no assertion/JWT in the report


def test_client_secret_jwt_basic_and_post(tmp_path, pingfed):
    for client, secret, how in (("cc-hs", "hs-secret-that-is-at-least-32-bytes-long!", "client_secret_jwt"),
                                ("cc-basic", "s3cret", "client_secret_basic")):
        extra = ["--client-auth", "client_secret_jwt"] if how == "client_secret_jwt" else []
        _, rep, text = run(tmp_path, pingfed, "--client-id", client, "--client-secret", secret, *extra)
        assert_all_authenticated(rep)
        assert {g for c, g in pingfed.log if c == client} == {f"client_credentials/{how}"}
        assert secret not in text


def test_auto_uses_post_when_provider_only_supports_it(tmp_path):
    pf = PingFed(methods=["client_secret_post"])
    srv = serve(pf)
    try:
        _, rep, _ = run(tmp_path, pf, "--client-id", "cc-post", "--client-secret", "s3cret")
        assert_all_authenticated(rep)
        assert {g for c, g in pf.log if c == "cc-post"} == {"client_credentials/client_secret_post"}
    finally:
        srv.shutdown()


@pytest.mark.parametrize("client,secret", [("web-app", "w3bsecret"), ("spa", None)])
def test_authorization_code_with_pkce_headless_login(tmp_path, pingfed, client, secret):
    args = ["--client-id", client, "--redirect-uri", REDIRECT, "--username", "alice", "--password", "Passw0rd!"]
    if secret:
        args += ["--client-secret", secret]
    _, rep, text = run(tmp_path, pingfed, *args)
    assert_all_authenticated(rep)
    grants = [g for c, g in pingfed.log if c == client]
    how = "client_secret_basic" if secret else "none"
    assert grants[0] == f"authorization_code/{how}"            # logged in once (with consent for web-app) ...
    assert f"refresh_token/{how}" in grants[1:]                 # ... then renewed with the refresh token
    assert "Passw0rd!" not in text and "pf-code-" not in text


def test_wrong_password_is_explained(tmp_path, pingfed):
    _, rep, _ = run(tmp_path, pingfed, "--client-id", "spa", "--redirect-uri", REDIRECT,
                    "--username", "alice", "--password", "wrong")
    valid = [r for r in rep["results"] if r["kind"] == "valid"]
    assert valid and all(r["category"] == "auth" and "login form came back" in r["detail"] for r in valid)


def test_password_grant_and_pingfederate_paths_without_discovery(tmp_path):
    pf = PingFed(discovery=False)                                # assumes /as/token.oauth2
    srv = serve(pf)
    try:
        _, rep, _ = run(tmp_path, pf, "--client-id", "web-app", "--client-secret", "w3bsecret",
                        "--username", "alice", "--password", "Passw0rd!")
        assert_all_authenticated(rep)
        assert [g for c, g in pf.log][0] == "password/client_secret_basic"
    finally:
        srv.shutdown()
