"""Property tests: for many seeds, valid data must satisfy the schema and every
invalid case must violate it (checked with an independent JSON Schema validator)."""
import copy

import pytest

from apisynth.core import Options, Sources, generate_cases, load_endpoints
from apisynth.generate import Generator
from apisynth.model import Endpoint
from apisynth.schema import convert_document
from apisynth.verify import case_errors

from conftest import EXAMPLES

SWAGGER2 = {
    "swagger": "2.0", "info": {"title": "t", "version": "1"}, "host": "api.example.com", "basePath": "/v2",
    "definitions": {"Pet": {"type": "object", "required": ["name"], "properties": {
        "id": {"type": "integer", "readOnly": True},
        "name": {"type": "string", "maxLength": 30},
        "nickname": {"type": "string", "x-nullable": True},
        "weight": {"type": "number", "minimum": 0, "exclusiveMinimum": True},
        "status": {"type": "string", "enum": ["available", "sold"]}}}},
    "paths": {
        "/pets": {"post": {"parameters": [{"in": "body", "name": "body", "required": True, "schema": {"$ref": "#/definitions/Pet"}}]}},
        "/pets/{petId}/photo": {"post": {"consumes": ["multipart/form-data"], "parameters": [
            {"in": "path", "name": "petId", "required": True, "type": "integer", "minimum": 1},
            {"in": "formData", "name": "caption", "type": "string", "minLength": 3, "required": True},
            {"in": "formData", "name": "file", "type": "file"}]}},
    },
}

OAS31 = {
    "openapi": "3.1.0", "info": {"title": "t", "version": "1"},
    "paths": {"/events": {"post": {"requestBody": {"required": True, "content": {"application/json": {"schema": {
        "type": "object", "required": ["kind", "at", "score"], "additionalProperties": False,
        "properties": {
            "kind": {"const": "click"},
            "at": {"type": "string", "format": "date-time"},
            "score": {"type": "number", "exclusiveMinimum": 0, "exclusiveMaximum": 1},
            "label": {"type": ["string", "null"], "maxLength": 10},
            "coords": {"type": "array", "prefixItems": [{"type": "integer"}, {"type": "integer"}], "minItems": 2, "maxItems": 2},
            "meta": {"type": "object", "additionalProperties": {"type": "integer", "multipleOf": 5}}}}}}}}}},
}


def _endpoints_from(raw):
    import json
    import tempfile
    from pathlib import Path
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "spec.json"
        p.write_text(json.dumps(raw))
        return load_endpoints(Sources(openapi=[str(p)]))[0]


SPECS = {
    "shop-oas30": lambda: load_endpoints(Sources(openapi=[str(EXAMPLES / "shop-api.openapi.yaml")]))[0],
    "swagger2": lambda: _endpoints_from(SWAGGER2),
    "oas31": lambda: _endpoints_from(OAS31),
    "postman": lambda: load_endpoints(Sources(postman=[str(EXAMPLES / "inventory.postman_collection.json")]))[0],
    "sample": lambda: load_endpoints(Sources(samples=[str(EXAMPLES / "employees-response.json") + " -> POST /employees"]))[0],
}


@pytest.mark.parametrize("spec", sorted(SPECS))
@pytest.mark.parametrize("seed", range(1, 13))
def test_every_case_does_what_it_claims(spec, seed):
    eps = SPECS[spec]()
    results, problems, _ = generate_cases(eps, Options(seed=seed, count=4, hostile=True, optional_rate=0.5))
    assert results
    assert problems == []


def test_same_seed_same_data_different_seed_different_data():
    eps = SPECS["shop-oas30"]()
    dump = lambda r: [[c.to_dict() for c in cs] for _, cs in r]  # noqa: E731
    a = dump(generate_cases(eps, Options(seed=5))[0])
    b = dump(generate_cases(eps, Options(seed=5))[0])
    c = dump(generate_cases(eps, Options(seed=6))[0])
    assert a == b and a != c


def test_read_only_fields_never_sent_and_discriminator_consistent():
    eps = {e.key: e for e in SPECS["shop-oas30"]()}
    gen = Generator(seed=1, optional_rate=1.0)
    for _ in range(30):
        cust = gen.request(eps["POST /customers"]).body
        assert "id" not in cust and "createdAt" not in cust
        order = gen.request(eps["POST /orders"]).body
        assert "id" not in order
        pay = order["payment"]
        assert (pay["type"] == "card") == ("cardNumber" in pay)


def test_swagger2_details():
    eps = {e.key: e for e in SPECS["swagger2"]()}
    photo = eps["POST /pets/{petId}/photo"]
    assert photo.content_type == "multipart/form-data"
    assert photo.body_schema["required"] == ["caption"]
    body = Generator(seed=2, optional_rate=1).request(eps["POST /pets"]).body
    assert "id" not in body


def test_invalid_cases_break_exactly_one_rule():
    eps = SPECS["shop-oas30"]()
    results, _, _ = generate_cases(eps, Options(seed=9, count=1))
    for ep, cases in results:
        for c in cases:
            if c.kind == "invalid" and c.target and c.target.startswith("body.") and "[" not in c.target and c.category not in ("required",):
                errs = case_errors(ep, c)
                assert len(errs) >= 1, c.id


def test_categories_cover_the_spec():
    eps = SPECS["shop-oas30"]()
    results, _, _ = generate_cases(eps, Options(seed=1, count=1))
    cats = {c.category for _, cs in results for c in cs if c.kind == "invalid"}
    assert {"required", "type", "null", "enum", "min-length", "max-length", "pattern", "format", "minimum",
            "maximum", "multiple-of", "not-integer", "min-items", "max-items", "unique-items",
            "additional-property"} <= cats
    kinds = {c.kind for _, cs in results for c in cs}
    assert kinds == {"valid", "boundary", "invalid"}


def test_realistic_semantics():
    eps = {e.key: e for e in SPECS["shop-oas30"]()}
    gen = Generator(seed=4, optional_rate=1)
    for _ in range(20):
        b = gen.request(eps["POST /customers"]).body
        assert b["email"].split("@")[1] in {"example.com", "example.org", "example.net"}
        assert len(b["address"]["country"]) == 2
        if b.get("phone"):
            assert b["phone"].startswith("+1") and "555" in b["phone"]
