import json

from apisynth.infer import extract_records, infer_schema
from apisynth.schema import convert_schema
from apisynth.sources.postman import _path, substitute_placeholders


def test_infer_formats_required_nullable_and_server_fields():
    s = infer_schema([
        {"id": 1, "email": "a@example.com", "joined": "2024-01-01", "at": "2024-01-01T10:00:00Z", "site": "https://x.example.com",
         "ip": "192.0.2.1", "uid": "6f1c2a3b-4d5e-4f60-8a7b-9c0d1e2f3a4b", "n": 1, "tags": ["a"], "opt": "x", "maybe": None},
        {"id": 2, "email": "b@example.org", "joined": "2024-02-01", "at": "2024-02-01T10:00:00Z", "site": "https://y.example.com",
         "ip": "192.0.2.2", "uid": "7f1c2a3b-4d5e-4f60-8a7b-9c0d1e2f3a4b", "n": 2.5, "tags": [], "maybe": 3},
    ])
    p = s["properties"]
    assert p["email"]["format"] == "email" and p["joined"]["format"] == "date" and p["at"]["format"] == "date-time"
    assert p["site"]["format"] == "uri" and p["ip"]["format"] == "ipv4" and p["uid"]["format"] == "uuid"
    assert p["n"]["type"] == "number" and p["maybe"]["type"] == ["integer", "null"]
    assert "opt" not in s["required"] and "email" in s["required"] and "maybe" not in s["required"]
    assert p["id"]["readOnly"] is True
    req_view = convert_schema(s)
    assert "id" not in req_view["properties"] and "id" not in req_view["required"]


def test_infer_enum_from_many_samples():
    s = infer_schema([{"status": st} for st in ["OPEN", "CLOSED", "OPEN", "PENDING"] * 3])
    assert s["properties"]["status"]["enum"] == ["CLOSED", "OPEN", "PENDING"]


def test_extract_records():
    assert extract_records({"items": [{"a": 1}], "total": 1}) == [{"a": 1}]
    assert extract_records([{"a": 1}, {"a": 2}]) == [{"a": 1}, {"a": 2}]
    assert extract_records({"a": 1}) == [{"a": 1}]
    assert extract_records({"page": 1, "users": [{"a": 1}]}) == [{"a": 1}]


def test_postman_placeholders_become_valid_json():
    raw = '{"email": "{{$randomEmail}}", "n": {{$randomInt}}, "ok": {{flag}}, "msg": "Hi {{name}}!", "who": "{{userEmail}}", "x": "{{other}}"}'
    doc = json.loads(substitute_placeholders(raw))
    assert doc["email"] == "alex.doe@example.com" and doc["n"] == 42 and doc["ok"] == 0
    assert doc["msg"].startswith("Hi ") and doc["who"] == "user@example.com" and doc["x"] == "__postman_variable__"
    assert "examples" not in infer_schema([doc])["properties"]["x"]


def test_postman_paths():
    path, params, q = _path({"raw": "{{baseUrl}}/users/:id/orders/{{orderId}}?page=2", "variable": [{"key": "id", "value": "7"}],
                             "query": [{"key": "page", "value": "2"}, {"key": "off", "value": "1", "disabled": True}]})
    assert path == "/users/{id}/orders/{orderId}"
    assert [(p.name, p.schema["type"]) for p in params] == [("id", "integer"), ("orderId", "integer")]
    assert q == {"page": "2"}
    assert _path("https://api.example.com/v1/items?x=1")[0] == "/v1/items"
    assert _path("localhost:8080/v1/items")[0] == "/v1/items"
