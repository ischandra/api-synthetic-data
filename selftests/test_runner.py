"""The `test` command end to end against a local API with known bugs."""
import json
import xml.etree.ElementTree as ET

import pytest

from apisynth.__main__ import main


def run_test(tmp_path, *args):
    out = tmp_path / "report"
    code = main(["test", *args, "-o", str(out), "-q", "--rps", "0"])
    return code, json.loads((out / "report.json").read_text()), out


@pytest.mark.parametrize("seed", ["11", "22"])
def test_finds_the_known_bugs_on_every_run(tmp_path, widget_api, seed):
    origin, store = widget_api
    before = dict(store["widgets"][1])
    code, rep, out = run_test(tmp_path, origin, "--token", "t0k", "--seed", seed)   # just the API's URL
    assert code == 1                                                                 # bugs -> exit 1
    assert rep["meta"]["base_url"] == origin + "/api"                                # relative server resolved
    res = rep["results"]
    bug = lambda cat, ep: [r for r in res if r["verdict"] == "bug" and r["category"] == cat and r["endpoint"] == ep]  # noqa
    # bug 1, found every run: required-only payload (no optional color) -> 500
    assert any(r["case"] == "valid-1" for r in bug("server-error", "POST /widgets"))
    # bug 2: size above maximum accepted
    assert any("size" in r["case"] and "maximum" in r["case"] for r in bug("validation-gap", "POST /widgets"))
    # correct behaviour is not reported as bugs
    assert not [r for r in res if r["verdict"] == "bug" and r["endpoint"].startswith("GET")]
    assert not bug("valid-rejected", "PUT /widgets/{widgetId}") and not bug("server-error", "DELETE /widgets/{widgetId}")
    # ids were created and reused: GET/PUT/DELETE valid cases actually ran
    for ep in ("GET /widgets/{widgetId}", "PUT /widgets/{widgetId}", "DELETE /widgets/{widgetId}"):
        assert any(r["endpoint"] == ep and r["kind"] == "valid" and r["verdict"] == "pass" for r in res), ep
    # safe mode: the pre-existing record was never modified or deleted
    assert store["widgets"].get(1) == before
    assert not [m for m in store["log"] if m[0] in ("PUT", "DELETE") and m[1].rstrip("/").endswith("/1")]
    junit = ET.parse(out / "junit.xml").getroot()
    assert sum(int(s.get("failures")) for s in junit.iter("testsuite")) == sum(r["verdict"] == "bug" for r in res)
    assert "Server errors (5xx)" in (out / "report.md").read_text()


def test_without_credentials_reports_auth_not_bugs(tmp_path, widget_api):
    origin, _ = widget_api
    code, rep, _ = run_test(tmp_path, origin + "/openapi.json", "--seed", "3")
    res = rep["results"]
    posts = [r for r in res if r["endpoint"] == "POST /widgets" and r["kind"] != "auth"]
    assert posts and all(r["category"] in ("auth", "skipped") for r in posts)
    # the API does enforce auth, so the enforcement checks pass
    checks = [r for r in res if r["endpoint"] == "POST /widgets" and r["kind"] == "auth"]
    assert {r["case"] for r in checks} == {"auth:no-credentials", "auth:invalid-credentials"}
    assert all(r["verdict"] == "pass" and r["status"] == 401 for r in checks)
    assert any("bearer token" in h for h in rep["meta"]["hints"])
    assert code == 0  # nothing that could be judged was a bug


def test_read_mode_sends_only_gets(tmp_path, widget_api):
    origin, store = widget_api
    store["log"].clear()
    code, rep, _ = run_test(tmp_path, origin, "--mode", "read", "--token", "t0k", "--seed", "4")
    assert {m[0] for m in store["log"]} == {"GET"}
    assert all(r["verdict"] == "skip" for r in rep["results"] if not r["endpoint"].startswith("GET"))
    # in read mode ids come from list endpoints: the pre-existing widget is used for GET /widgets/{id}
    assert any(r["endpoint"] == "GET /widgets/{widgetId}" and r["verdict"] == "pass" for r in rep["results"])


def test_mode_all_and_pinned_param_may_touch_existing_records(tmp_path, widget_api):
    origin, store = widget_api
    run_test(tmp_path, origin, "--mode", "all", "--token", "t0k", "--param", "widgetId=1", "--seed", "5",
             "--include", "DELETE *")
    assert 1 not in store["widgets"]  # explicitly allowed by the user


@pytest.fixture
def empty_server():
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            self.send_response(404)
            self.end_headers()

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def test_no_spec_found_is_a_clear_error(tmp_path, empty_server, capsys):
    code = main(["test", empty_server + "/api", "-o", str(tmp_path), "-q"])
    assert code == 2 and "No OpenAPI/Swagger spec found" in capsys.readouterr().err


def test_unreachable_api_stops_early(tmp_path, capsys):
    from conftest import EXAMPLES
    code = main(["test", str(EXAMPLES / "shop-api.openapi.yaml"), "--base-url", "http://127.0.0.1:9",
                 "-o", str(tmp_path), "-q", "--rps", "0"])
    assert code == 2 and "Can't reach http://127.0.0.1:9" in capsys.readouterr().err



def test_body_identified_updates_only_target_created_records(tmp_path, widget_api):
    """PUT /widgets {"id": ...}: in safe mode the body id must be one this run created."""
    import copy
    from conftest import WIDGET_SPEC
    origin, store = widget_api
    spec = copy.deepcopy(WIDGET_SPEC)
    spec["components"]["schemas"]["Widget"]["properties"]["id"] = {"type": "integer", "minimum": 1}
    spec["paths"]["/widgets"]["put"] = {"requestBody": {"required": True, "content": {"application/json": {
        "schema": {"$ref": "#/components/schemas/Widget"}}}}, "responses": {"200": {"description": "ok"}}}
    f = tmp_path / "spec.json"
    f.write_text(json.dumps(spec))
    from apisynth.core import Options, Sources, generate_cases, load_endpoints
    from apisynth.runner import Credentials, Runner
    eps, _ = load_endpoints(Sources(openapi=[str(f)]))
    results, _, _ = generate_cases([e for e in eps if e.path == "/widgets"], Options(seed=2, count=3))
    runner = Runner(origin + "/api", Credentials(token="t0k"), rps=0)
    outs = runner.run(results)
    created_ids = {r["id"] for r in runner.created.get("/widgets", [])}
    puts = [o for o in outs if o.endpoint == "PUT /widgets" and o.verdict != "skip"]
    assert puts and all(o.request["body"]["id"] in created_ids for o in puts if isinstance(o.request.get("body"), dict)
                        and "id" in o.request["body"])
    assert store["widgets"][1]["name"] == "Pre-existing"
