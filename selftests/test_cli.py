import csv
import json
import subprocess
import sys

import yaml

from conftest import EXAMPLES, ROOT


def run(*args, cwd=None):
    return subprocess.run([sys.executable, "-m", "apisynth", *args], cwd=cwd or ROOT, capture_output=True, text=True,
                          env={"PYTHONPATH": str(ROOT), "PATH": "/usr/bin:/bin"})


def test_generate_all_formats_from_urls(tmp_path, http_server):
    out = tmp_path / "out"
    r = run("generate", "--openapi", f"{http_server}/openapi.yaml", "--postman", f"{http_server}/collection.json",
            "--url", f"{http_server}/api/employees/101", "--seed", "11", "-n", "2", "--hostile",
            "-f", "json,jsonl,csv,apitest,postman", "-o", str(out), "--name", "demo", "--strict")
    assert r.returncode == 0, r.stdout + r.stderr
    assert "self-check: every case validates" in r.stdout
    index = json.loads((out / "index.json").read_text())
    keys = [e["endpoint"] for e in index["endpoints"]]
    assert "POST /customers" in keys and "POST /products" in keys and "POST /api/employees" in keys
    assert index["base_url"] == "http://localhost:8000/api/v1"
    emp = json.loads((out / "endpoints" / "POST_api_employees.json").read_text())
    assert emp["inferred"] and "id" not in emp["valid"][0]["request"]["body"]
    lines = (out / "cases.jsonl").read_text().splitlines()
    assert len(lines) > 100 and all(json.loads(l)["endpoint"] for l in lines)
    rows = list(csv.DictReader((out / "csv" / "POST_customers.valid.csv").open()))
    assert rows and "body.address.city" in rows[0]
    suite_text = (out / "demo.api.yaml").read_text()
    suite = yaml.safe_load(suite_text)
    assert "base_url" not in suite  # must stay overridable by --env / --base-url
    assert suite["variables"]["baseUrl"] == "http://localhost:8000/api/v1"
    assert any(t["expect"]["status"] == {"gte": 400, "lt": 500} for t in suite["tests"])
    by_name = {t["name"]: t for t in suite["tests"]}
    assert by_name["POST /customers - valid data"]["auth"] == {"bearer": "{{token}}"}  # spec: global bearer
    assert "auth" not in by_name["POST /auth/token - valid data"]                    # spec: security: []
    assert "--var token=..." in suite_text
    col = json.loads((out / "demo.postman_collection.json").read_text())
    assert col["info"]["schema"].startswith("https://schema.getpostman.com") and col["item"]
    folders = {f["name"]: f for f in col["item"]}
    assert folders["POST /customers"]["item"][0]["request"]["auth"]["type"] == "bearer"
    assert folders["POST /auth/token"]["item"][0]["request"]["auth"]["type"] == "noauth"


def test_auth_override(tmp_path):
    r = run("generate", "--openapi", str(EXAMPLES / "shop-api.openapi.yaml"), "--include", "POST /orders",
            "-f", "apitest", "-o", str(tmp_path), "--auth", "apikey:X-API-Key", "-n", "1", "--name", "x")
    assert r.returncode == 0, r.stderr
    t = yaml.safe_load((tmp_path / "x.api.yaml").read_text())["tests"][0]
    assert t["auth"] == {"api_key": {"name": "X-API-Key", "value": "{{apiKey}}", "in": "header"}}
    bad = run("generate", "--openapi", str(EXAMPLES / "shop-api.openapi.yaml"), "-f", "apitest", "-o", str(tmp_path),
              "--auth", "magic")
    assert bad.returncode == 2 and "Unknown auth" in bad.stderr


def test_headers_used_for_fetching(tmp_path, http_server):
    denied = run("endpoints", "--openapi", f"{http_server}/secure/openapi.yaml")
    assert denied.returncode == 2 and "401" in denied.stderr
    ok = run("endpoints", "--openapi", f"{http_server}/secure/openapi.yaml", "-H", "Authorization: Bearer t0k")
    assert ok.returncode == 0 and "createCustomer" in ok.stdout


def test_filters_and_infer(tmp_path):
    r = run("generate", "--openapi", str(EXAMPLES / "shop-api.openapi.yaml"), "--include", "POST /orders",
            "--no-invalid", "--no-boundary", "-n", "3", "-o", str(tmp_path), "--seed", "1")
    assert r.returncode == 0, r.stderr
    d = json.loads((tmp_path / "endpoints" / "POST_orders.json").read_text())
    assert len(d["valid"]) == 3 and "invalid" not in d and "boundary" not in d
    assert len(json.loads((tmp_path / "index.json").read_text())["endpoints"]) == 1
    inf = run("infer", "--sample", str(EXAMPLES / "employees-response.json"))
    assert inf.returncode == 0 and '"format": "email"' in inf.stdout


def test_errors_are_friendly(tmp_path):
    r = run("generate", "--openapi", str(tmp_path / "missing.yaml"))
    assert r.returncode == 2 and "File not found" in r.stderr
    (tmp_path / "x.yaml").write_text("hello: world\n")
    r = run("generate", "--openapi", str(tmp_path / "x.yaml"))
    assert r.returncode == 2 and "not an OpenAPI" in r.stderr
