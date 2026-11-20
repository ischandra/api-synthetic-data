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
