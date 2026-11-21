"""`apisynth test` against an API that implements every authentication scheme.

The server verifies credentials independently of apisynth's client code: digest from the RFC 2617 formulas,
AWS SigV4 with botocore, mutual TLS with a real TLS handshake against a test CA, OAuth2 with a token endpoint
whose tokens expire after a few uses. One endpoint is declared secured but doesn't check: it must be reported.
"""
import base64
import hashlib
import json
import re
import ssl
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import pytest

from apisynth.__main__ import main

SECRETS = ["static-token", "k123", "alice:pw", "csecret", "SECRETKEY", "sess-tok", "sess-cookie"]
TOKEN_USES = 3          # OAuth access tokens die after this many uses -> the client must renew them

SPEC = {
    "openapi": "3.1.0", "info": {"title": "Auth zoo", "version": "1"}, "servers": [{"url": "/api"}],
    "components": {"securitySchemes": {
        "bearerStatic": {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"},
        "oauthCC": {"type": "oauth2", "flows": {"clientCredentials": {"tokenUrl": "/oauth/token", "scopes": {"read": ""}}}},
        "oauthPwd": {"type": "oauth2", "flows": {"password": {"tokenUrl": "/oauth/token", "scopes": {}}}},
        "oidc": {"type": "openIdConnect", "openIdConnectUrl": "/.well-known/openid-configuration"},
        "keyHeader": {"type": "apiKey", "in": "header", "name": "X-API-Key"},
        "keyQuery": {"type": "apiKey", "in": "query", "name": "api_key"},
        "keyCookie": {"type": "apiKey", "in": "cookie", "name": "apikey"},
        "basicAuth": {"type": "http", "scheme": "basic"},
        "digestAuth": {"type": "http", "scheme": "digest"},
        "aws": {"type": "apiKey", "in": "header", "name": "Authorization", "x-amazon-apigateway-authtype": "awsSigv4"},
    }},
    "paths": {p: {"get": {"security": sec, "parameters": [], "responses": {"200": {"description": "ok"}}}} for p, sec in [
        ("/bearer", [{"bearerStatic": []}]),
        ("/oauth-cc", [{"oauthCC": ["read"]}]),
        ("/oidc", [{"oidc": []}]),
        ("/key-header", [{"keyHeader": []}]),
        ("/key-query", [{"keyQuery": []}]),
        ("/key-cookie", [{"keyCookie": []}]),
        ("/basic", [{"basicAuth": []}]),
        ("/digest", [{"digestAuth": []}]),
        ("/both", [{"keyHeader": [], "bearerStatic": []}]),       # AND
        ("/either", [{"digestAuth": []}, {"keyHeader": []}]),     # OR: use the one we have
        ("/aws", [{"aws": []}]),
        ("/leaky", [{"bearerStatic": []}]),                       # declared secured, but isn't
        ("/public", []),
    ]},
}
for _p in SPEC["paths"].values():   # a query parameter so cases are generated for every endpoint
    _p["get"]["parameters"] = [{"name": "page", "in": "query", "schema": {"type": "integer", "minimum": 1, "maximum": 9}}]


def _md5(s):
    return hashlib.md5(s.encode()).hexdigest()


class Zoo:
    def __init__(self):
        self.tokens = {}          # access token -> uses left
        self.issued = []          # grant types issued
        self.n = 0

    def issue(self, grant):
        self.n += 1
        tok = f"at-{self.n}"
        self.tokens[tok] = TOKEN_USES
        self.issued.append(grant)
        return {"access_token": tok, "token_type": "Bearer", "expires_in": 3600, "refresh_token": f"rt-{self.n}"}

    def oauth_ok(self, h):
        tok = h.get("Authorization", "")[7:]
        if self.tokens.get(tok, 0) <= 0:
            return False
        self.tokens[tok] -= 1
        return True


def handler(zoo, origin_holder):
    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        def send(self, code, body=None, headers=None):
            data = json.dumps(body if body is not None else {}).encode()
            self.send_response(code)
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def body(self):
            n = int(self.headers.get("Content-Length") or 0)
            return self.rfile.read(n) if n else b""

        def cookies(self):
            return dict(c.strip().split("=", 1) for c in (self.headers.get("Cookie") or "").split(";") if "=" in c)

        def basic_ok(self):
            h = self.headers.get("Authorization", "")
            return h.startswith("Basic ") and base64.b64decode(h[6:]).decode() == "alice:pw"

        def digest_ok(self):
            h = self.headers.get("Authorization", "")
            if not h.startswith("Digest "):
                return False
            p = dict(re.findall(r'(\w+)="?([^",]+)"?', h[7:]))
            ha1 = _md5(f"{p.get('username')}:apisynth:pw")
            ha2 = _md5(f"{self.command}:{p.get('uri')}")
            want = _md5(f"{ha1}:{p.get('nonce')}:{p.get('nc')}:{p.get('cnonce')}:{p.get('qop')}:{ha2}")
            return p.get("username") == "alice" and p.get("nonce") == "n0nce" and p.get("response") == want

        def aws_ok(self):
            h = self.headers.get("Authorization", "")
            m = re.match(r"AWS4-HMAC-SHA256 Credential=([^/]+)/(\d+)/([^/]+)/([^/]+)/aws4_request, "
                         r"SignedHeaders=([^,]+), Signature=(\w+)", h)
            if not m or m.group(1) != "AKIDTEST":
                return False
            from botocore.auth import SigV4Auth
            from botocore.awsrequest import AWSRequest
            from botocore.credentials import Credentials
            signed = m.group(5).split(";")
            req = AWSRequest(method=self.command, url=origin_holder[0] + self.path, data=b"",
                             headers={k: self.headers[k] for k in signed if k != "host"})
            req.context["timestamp"] = self.headers["X-Amz-Date"]
            signer = SigV4Auth(Credentials("AKIDTEST", "SECRETKEY"), m.group(4), m.group(3))
            want = signer.signature(signer.string_to_sign(req, signer.canonical_request(req)), req)
            return want == m.group(6)

        def do_GET(self):
            u = urlsplit(self.path)
            q = parse_qs(u.query)
            h = self.headers
            if u.path == "/openapi.json":
                return self.send(200, SPEC)
            if u.path == "/.well-known/openid-configuration":
                return self.send(200, {"issuer": "x", "token_endpoint": origin_holder[0] + "/oauth/token"})
            checks = {
                "/api/bearer": lambda: h.get("Authorization") == "Bearer static-token",
                "/api/oauth-cc": lambda: zoo.oauth_ok(h),
                "/api/oidc": lambda: zoo.oauth_ok(h),
                "/api/key-header": lambda: h.get("X-API-Key") == "k123",
                "/api/key-query": lambda: q.get("api_key") == ["k123"],
                "/api/key-cookie": lambda: self.cookies().get("apikey") == "k123",
                "/api/basic": self.basic_ok,
                "/api/digest": self.digest_ok,
                "/api/both": lambda: h.get("X-API-Key") == "k123" and h.get("Authorization") == "Bearer static-token",
                "/api/either": lambda: self.digest_ok() or h.get("X-API-Key") == "k123",
                "/api/aws": self.aws_ok,
                "/api/leaky": lambda: True,                                      # the bug
                "/api/public": lambda: True,
                "/api/login-token": lambda: h.get("Authorization") == "Bearer sess-tok",
                "/api/session": lambda: self.cookies().get("sid") == "sess-cookie",
                "/api/mtls": lambda: True,                                       # enforced by the TLS layer
            }
            ok = checks.get(u.path)
            if ok is None:
                return self.send(404, {"error": "no route"})
            page = q.get("page", ["1"])[0]
            if not ok():
                challenge = {"WWW-Authenticate": 'Digest realm="apisynth", qop="auth", nonce="n0nce", opaque="op"'} \
                    if u.path in ("/api/digest", "/api/either") else {}
                return self.send(401, {"error": "unauthorized"}, challenge)
            if not page.isdigit() or not 1 <= int(page) <= 9:
                return self.send(400, {"error": "page"})
            return self.send(200, {"ok": True, "path": u.path})

        def do_POST(self):
            u = urlsplit(self.path)
            raw = self.body()
            if u.path == "/oauth/token":
                form = {k: v[0] for k, v in parse_qs(raw.decode()).items()}
                basic = self.headers.get("Authorization", "")
                client = base64.b64decode(basic[6:]).decode() if basic.startswith("Basic ") else \
                    f"{form.get('client_id')}:{form.get('client_secret')}"
                g = form.get("grant_type")
                if g == "client_credentials" and client == "cid:csecret":
                    return self.send(200, zoo.issue(g))
                if g == "password" and form.get("username") == "alice" and form.get("password") == "pw":
                    return self.send(200, zoo.issue(g))
                if g == "refresh_token" and form.get("refresh_token", "").startswith("rt-"):
                    return self.send(200, zoo.issue(g))
                return self.send(400, {"error": "invalid_grant", "error_description": f"bad {g}"})
            if u.path in ("/login", "/login-cookie"):
                try:
                    b = json.loads(raw or b"{}")
                except ValueError:
                    b = {}
                if b.get("username") != "alice" or b.get("password") != "pw":
                    return self.send(401, {"error": "bad login"})
                if u.path == "/login":
                    return self.send(200, {"data": {"jwt": "sess-tok"}})
                return self.send(200, {"ok": True}, {"Set-Cookie": "sid=sess-cookie; Path=/; HttpOnly"})
            self.send(404, {"error": "no route"})

    return H


@pytest.fixture
def zoo_api():
    zoo, origin = Zoo(), []
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler(zoo, origin))
    origin.append(f"http://127.0.0.1:{srv.server_address[1]}")
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield origin[0], zoo
    srv.shutdown()


def run(tmp_path, *args):
    out = tmp_path / "report"
    code = main(["test", *args, "-o", str(out), "-q", "--rps", "0", "-n", "2", "--no-boundary", "--seed", "1"])
    text = (out / "report.json").read_text()
    return code, json.loads(text), text


def by_endpoint(rep):
    res = {}
    for r in rep["results"]:
        res.setdefault(r["endpoint"].split()[1], []).append(r)
    return res


ALL_CREDS = ["--token", "static-token", "--api-key", "k123", "--basic", "alice:pw", "--digest", "alice:pw",
             "--client-id", "cid", "--client-secret", "env:ZOO_CLIENT_SECRET",
             "--aws-sigv4", "us-east-1/execute-api", "--aws-access-key", "AKIDTEST", "--aws-secret-key", "SECRETKEY"]


def test_every_scheme_authenticates_and_the_leak_is_reported(tmp_path, zoo_api, monkeypatch):
    pytest.importorskip("botocore")
    origin, zoo = zoo_api
    monkeypatch.setenv("ZOO_CLIENT_SECRET", "csecret")   # secrets can come from the environment
    code, rep, text = run(tmp_path, origin, *ALL_CREDS)
    eps = by_endpoint(rep)
    # every secured endpoint: all valid requests got through with the right scheme
    for path in ("/bearer", "/oauth-cc", "/oidc", "/key-header", "/key-query", "/key-cookie", "/basic", "/digest",
                 "/both", "/either", "/aws", "/public"):
        valid = [r for r in eps[path] if r["kind"] == "valid"]
        assert valid and all(r["status"] == 200 for r in valid), (path, [(r["case"], r["status"], r["detail"]) for r in valid])
    # enforcement checks: refused everywhere except the leaky endpoint, which is a reported bug
    for path, rs in eps.items():
        checks = [r for r in rs if r["kind"] == "auth"]
        if path == "/public":
            assert not checks
        elif path == "/leaky":
            assert {r["category"] for r in checks} == {"auth-bypass"} and len(checks) == 2
        else:
            assert len(checks) == 2 and all(r["verdict"] == "pass" for r in checks), (path, checks)
    assert code == 1  # the leak is a bug
    # OAuth: tokens died after a few uses and were renewed (client_credentials simply asks again)
    assert set(zoo.issued) == {"client_credentials"} and len(zoo.issued) >= 3
    # no secret ends up in the report
    for s in SECRETS + [base64.b64encode(b"alice:pw").decode()]:
        assert s not in text, s


def test_password_grant(tmp_path, zoo_api):
    origin, zoo = zoo_api
    spec = json.loads(json.dumps(SPEC))
    spec["paths"]["/oauth-cc"]["get"]["security"] = [{"oauthPwd": []}]
    f = tmp_path / "spec.json"
    f.write_text(json.dumps(spec))
    code, rep, _ = run(tmp_path, str(f), "--base-url", origin + "/api", "--include", "GET /oauth-cc",
                       "--username", "alice", "--password", "pw", "--client-id", "cid", "--client-secret", "csecret")
    assert all(r["status"] == 200 for r in rep["results"] if r["kind"] == "valid")
    # renewed with the refresh token from the password grant once the first token died
    assert zoo.issued[0] == "password" and "refresh_token" in zoo.issued[1:]
    assert all(r["category"] != "auth" for r in rep["results"] if r["kind"] != "auth")


def test_login_endpoint_token_and_session_cookie(tmp_path, zoo_api):
    origin, _ = zoo_api
    spec = json.loads(json.dumps(SPEC))
    spec["components"]["securitySchemes"]["session"] = {"type": "apiKey", "in": "cookie", "name": "sid"}
    spec["paths"] = {"/login-token": {"get": {"security": [{"bearerStatic": []}], "responses": {"200": {"description": "ok"}},
                                             "parameters": SPEC["paths"]["/bearer"]["get"]["parameters"]}},
                     "/session": {"get": {"security": [{"session": []}], "responses": {"200": {"description": "ok"}},
                                          "parameters": SPEC["paths"]["/bearer"]["get"]["parameters"]}}}
    f = tmp_path / "spec.json"
    f.write_text(json.dumps(spec))
    # token in the login response ($.data.jwt is found automatically)
    _, rep, text = run(tmp_path, str(f), "--base-url", origin + "/api", "--include", "GET /login-token",
                       "--login", f"POST {origin}/login", "--username", "alice", "--password", "pw")
    assert all(r["status"] == 200 for r in rep["results"] if r["kind"] == "valid")
    assert all(r["verdict"] == "pass" for r in rep["results"] if r["kind"] == "auth")
    assert "sess-tok" not in text
    # session cookie set by the login response
    _, rep, _ = run(tmp_path, str(f), "--base-url", origin + "/api", "--include", "GET /session",
                    "--login", f"POST {origin}/login-cookie", "--login-body", '{"username": "alice", "password": "pw"}')
    assert all(r["status"] == 200 for r in rep["results"] if r["kind"] == "valid")
    assert all(r["verdict"] == "pass" for r in rep["results"] if r["kind"] == "auth")


def test_failed_token_request_is_explained_once(tmp_path, zoo_api):
    origin, zoo = zoo_api
    code, rep, _ = run(tmp_path, origin, "--include", "GET /oauth-cc", "--client-id", "cid", "--client-secret", "WRONG")
    valid = [r for r in rep["results"] if r["kind"] == "valid"]
    assert valid and all(r["category"] == "auth" and "token request" in r["detail"] for r in valid)
    assert zoo.issued == []


def test_missing_credentials_are_named(tmp_path, zoo_api):
    origin, _ = zoo_api
    code, rep, _ = run(tmp_path, origin, "--include", "GET /digest", "--include", "GET /key-query")
    hints = " ".join(rep["meta"]["hints"])
    assert "HTTP digest" in hints and "API key 'api_key' in query" in hints
    assert code == 0


# ------------------------------------------------------------------ mutual TLS

def _openssl(*args, cwd):
    subprocess.run(["openssl", *args], cwd=cwd, check=True, capture_output=True)


@pytest.fixture
def mtls_api(tmp_path):
    import shutil
    if not shutil.which("openssl"):
        pytest.skip("openssl not available")
    d = tmp_path / "pki"
    d.mkdir()
    _openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out", "ca.pem", "-days", "1",
             "-subj", "/CN=apisynth test CA", "-addext", "basicConstraints=critical,CA:TRUE",
             "-addext", "keyUsage=critical,keyCertSign,cRLSign", cwd=d)
    for name, ext in (("server", "subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\n"
                                 "keyUsage=critical,digitalSignature,keyEncipherment\nauthorityKeyIdentifier=keyid"),
                      ("client", "extendedKeyUsage=clientAuth\nkeyUsage=critical,digitalSignature\n"
                                 "authorityKeyIdentifier=keyid")):
        _openssl("req", "-newkey", "rsa:2048", "-nodes", "-keyout", f"{name}.key", "-out", f"{name}.csr",
                 "-subj", f"/CN={name}", cwd=d)
        (d / f"{name}.ext").write_text(ext + "\n")
        _openssl("x509", "-req", "-in", f"{name}.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial",
                 "-out", f"{name}.pem", "-days", "1", "-extfile", f"{name}.ext", cwd=d)
    zoo, origin = Zoo(), []
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler(zoo, origin))
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH, cafile=str(d / "ca.pem"))
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_cert_chain(str(d / "server.pem"), str(d / "server.key"))
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    origin.append(f"https://127.0.0.1:{srv.server_address[1]}")
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield origin[0], d
    srv.shutdown()


def test_mutual_tls(tmp_path, mtls_api):
    origin, d = mtls_api
    spec = {"openapi": "3.1.0", "info": {"title": "mtls", "version": "1"}, "servers": [{"url": "/api"}],
            "components": {"securitySchemes": {"m": {"type": "mutualTLS"}}},
            "paths": {"/mtls": {"get": {"security": [{"m": []}], "parameters": SPEC["paths"]["/bearer"]["get"]["parameters"],
                                        "responses": {"200": {"description": "ok"}}}}}}
    f = tmp_path / "spec.json"
    f.write_text(json.dumps(spec))
    _, rep, _ = run(tmp_path, str(f), "--base-url", origin + "/api", "--cert", str(d / "client.pem"),
                    "--cert-key", str(d / "client.key"), "--ca-bundle", str(d / "ca.pem"))
    valid = [r for r in rep["results"] if r["kind"] == "valid"]
    assert valid and all(r["status"] == 200 for r in valid)
    no_cert = next(r for r in rep["results"] if r["case"] == "auth:no-credentials")
    assert no_cert["verdict"] == "pass" and "TLS handshake" in no_cert["detail"]
