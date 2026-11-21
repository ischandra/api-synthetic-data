import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"


@pytest.fixture(scope="session")
def http_server():
    """Serves the example spec/collection and a fake 'live' API over HTTP."""
    routes = {
        "/openapi.yaml": ("application/yaml", (EXAMPLES / "shop-api.openapi.yaml").read_bytes()),
        "/collection.json": ("application/json", (EXAMPLES / "inventory.postman_collection.json").read_bytes()),
        "/api/employees": ("application/json", (EXAMPLES / "employees-response.json").read_bytes()),
        "/api/employees/101": ("application/json", json.dumps(
            json.loads((EXAMPLES / "employees-response.json").read_text())["data"][0]).encode()),
    }

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            if self.path.startswith("/secure") and self.headers.get("Authorization") != "Bearer t0k":
                self.send_response(401)
                self.end_headers()
                return
            ct, body = routes.get(self.path.replace("/secure", ""), (None, None))
            if body is None:
                self.send_response(404)
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Type", ct)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


WIDGET_SPEC = {
    "openapi": "3.0.3", "info": {"title": "Widgets (buggy test API)", "version": "1"},
    "servers": [{"url": "/api"}],
    "security": [{"bearer": []}],
    "components": {
        "securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}},
        "schemas": {"Widget": {"type": "object", "required": ["name", "size"], "properties": {
            "id": {"type": "integer", "readOnly": True},
            "name": {"type": "string", "minLength": 1, "maxLength": 50},
            "size": {"type": "integer", "minimum": 1, "maximum": 10},
            "color": {"type": "string", "enum": ["red", "green", "blue"]}}}}},
    "paths": {
        "/widgets": {
            "get": {"security": [], "parameters": [{"name": "limit", "in": "query",
                                                    "schema": {"type": "integer", "minimum": 1, "maximum": 100}}],
                    "responses": {"200": {"description": "ok"}}},
            "post": {"requestBody": {"required": True, "content": {"application/json": {
                "schema": {"$ref": "#/components/schemas/Widget"}}}}, "responses": {"201": {"description": "ok"}}}},
        "/widgets/{widgetId}": {
            "parameters": [{"name": "widgetId", "in": "path", "required": True,
                            "schema": {"type": "integer", "minimum": 1}}],
            "get": {"security": [], "responses": {"200": {"description": "ok"}}},
            "put": {"requestBody": {"required": True, "content": {"application/json": {
                "schema": {"$ref": "#/components/schemas/Widget"}}}}, "responses": {"200": {"description": "ok"}}},
            "delete": {"responses": {"204": {"description": "ok"}}}},
    },
}


@pytest.fixture
def widget_api():
    """A small REST API with two known bugs, an auth requirement and a pre-existing record:
      bug 1: POST /api/widgets without the optional 'color' crashes (500)
      bug 2: 'size' above its maximum (10) is accepted
    Yields (origin_url, store) so tests can check nothing pre-existing was changed."""
    import re as _re

    store = {"widgets": {1: {"id": 1, "name": "Pre-existing", "size": 5, "color": "red"}}, "next": 2,
             "log": []}

    def validate(b, partial=False):
        if not isinstance(b, dict):
            return "body must be an object"
        if not partial or "name" in b:
            if not isinstance(b.get("name"), str) or not 1 <= len(b["name"]) <= 50:
                return "name invalid"
        if not partial or "size" in b:
            s = b.get("size")
            if not isinstance(s, int) or isinstance(s, bool) or s < 1:   # BUG 2: no upper bound check
                return "size invalid"
        if "color" in b and b["color"] not in ("red", "green", "blue"):
            return "color invalid"
        return None

    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        def send(self, code, body=None):
            data = b"" if body is None else json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def body(self):
            n = int(self.headers.get("Content-Length") or 0)
            try:
                return json.loads(self.rfile.read(n) or b"null")
            except ValueError:
                return ...

        def authed(self):
            return self.headers.get("Authorization") == "Bearer t0k"

        def route(self):
            path, _, qs = self.path.partition("?")
            m = _re.fullmatch(r"/api/widgets/([^/]+)", path)
            return path, (m.group(1) if m else None), dict(p.split("=", 1) for p in qs.split("&") if "=" in p)

        def do_GET(self):
            path, wid, q = self.route()
            store["log"].append(("GET", self.path))
            if path == "/openapi.json":
                return self.send(200, WIDGET_SPEC)
            if path == "/api/widgets":
                lim = q.get("limit", "20")
                if not lim.isdigit() or not 1 <= int(lim) <= 100:
                    return self.send(400, {"error": "limit"})
                return self.send(200, {"items": list(store["widgets"].values())[: int(lim)]})
            if wid is not None:
                if not wid.isdigit():
                    return self.send(400, {"error": "id"})
                w = store["widgets"].get(int(wid))
                return self.send(200, w) if w else self.send(404, {"error": "not found"})
            self.send(404, {"error": "no route"})

        def do_POST(self):
            path, _, _ = self.route()
            b = self.body()
            store["log"].append(("POST", self.path))
            if path != "/api/widgets":
                return self.send(404, {"error": "no route"})
            if not self.authed():
                return self.send(401, {"error": "auth"})
            if b is ...:
                return self.send(400, {"error": "json"})
            err = validate(b)
            if err:
                return self.send(400, {"error": err})
            if "color" not in b:                                          # BUG 1: crash on optional field
                return self.send(500, {"error": "NullPointerException"})
            w = {"id": store["next"], "name": b["name"], "size": b["size"], "color": b["color"]}
            store["widgets"][w["id"]] = w
            store["next"] += 1
            return self.send(201, w)

        def do_PUT(self):
            _, wid, _ = self.route()
            b = self.body()
            store["log"].append(("PUT", self.path))
            if not self.authed():
                return self.send(401, {"error": "auth"})
            if wid is None or not wid.isdigit():
                return self.send(400, {"error": "id"})
            if int(wid) not in store["widgets"]:
                return self.send(404, {"error": "not found"})
            err = validate(b) if b is not ... else "json"
            if err:
                return self.send(400, {"error": err})
            store["widgets"][int(wid)].update({k: b[k] for k in ("name", "size", "color") if k in b})
            return self.send(200, store["widgets"][int(wid)])

        def do_DELETE(self):
            _, wid, _ = self.route()
            store["log"].append(("DELETE", self.path))
            if not self.authed():
                return self.send(401, {"error": "auth"})
            if wid is None or not wid.isdigit():
                return self.send(400, {"error": "id"})
            if store["widgets"].pop(int(wid), None) is None:
                return self.send(404, {"error": "not found"})
            return self.send(204)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}", store
    srv.shutdown()
