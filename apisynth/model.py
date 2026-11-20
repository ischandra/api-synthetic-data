"""Endpoint descriptions shared by every source (OpenAPI, Postman, live URLs, samples)."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class Param:
    name: str
    location: str                    # path | query | header | cookie
    required: bool = False
    schema: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Endpoint:
    method: str
    path: str                        # /users/{id}
    source: str                      # e.g. "openapi:orders.yaml"
    doc: Dict[str, Any] = field(default_factory=dict)   # root document $refs resolve against
    params: List[Param] = field(default_factory=list)
    body_schema: Optional[Dict[str, Any]] = None
    body_required: bool = False
    content_type: str = "application/json"
    operation_id: Optional[str] = None
    summary: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    inferred: bool = False           # schema guessed from examples rather than declared
    body_pointer: Optional[str] = None  # JSON pointer of the body schema inside doc (for validation)

    @property
    def key(self) -> str:
        return f"{self.method} {self.path}"

    @property
    def slug(self) -> str:
        s = re.sub(r"[{}]", "", self.path).strip("/") or "root"
        return f"{self.method}_{re.sub(r'[^A-Za-z0-9]+', '_', s).strip('_')}"


@dataclass
class RequestData:
    method: str
    path: str
    path_params: Dict[str, Any] = field(default_factory=dict)
    query: Dict[str, Any] = field(default_factory=dict)
    headers: Dict[str, Any] = field(default_factory=dict)
    body: Any = None
    has_body: bool = False

    def url(self) -> str:
        from urllib.parse import quote, urlencode

        def sub(m: "re.Match[str]") -> str:
            name = m.group(1)
            if name not in self.path_params:
                return m.group(0)
            return quote(str(_text(self.path_params[name])), safe="")

        path = re.sub(r"\{([^}/]+)\}", sub, self.path)
        q = {k: (v if isinstance(v, list) else _text(v)) for k, v in self.query.items() if v is not None}
        return path + ("?" + urlencode(q, doseq=True) if q else "")

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {"method": self.method, "path": self.path, "url": self.url()}
        if self.path_params:
            d["path_params"] = self.path_params
        if self.query:
            d["query"] = self.query
        if self.headers:
            d["headers"] = self.headers
        if self.has_body:
            d["body"] = self.body
        return d


@dataclass
class Case:
    id: str
    kind: str                         # valid | invalid | hostile
    request: RequestData
    expect: str                       # "2xx" | "4xx" | "not 5xx"
    category: Optional[str] = None    # required | type | null | enum | length | pattern | format | range | ...
    target: Optional[str] = None      # e.g. body.address.zip / query.limit
    description: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {"id": self.id, "kind": self.kind}
        for k in ("category", "target", "description"):
            if getattr(self, k):
                d[k] = getattr(self, k)
        d["expect"] = self.expect
        d["request"] = self.request.to_dict()
        return d


def _text(v: Any) -> Any:
    if isinstance(v, bool):
        return "true" if v else "false"
    if v is None:
        return ""
    return v
