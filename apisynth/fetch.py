"""Loads JSON/YAML documents from files or URLs."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

_URL = re.compile(r"(?i)^https?://")


def is_url(s: str) -> bool:
    return bool(_URL.match(s))


def get_json(url: str, headers: Optional[Dict[str, str]] = None, timeout: float = 30) -> Any:
    import requests

    resp = requests.get(url, headers=headers or {}, timeout=timeout)
    if resp.status_code >= 400:
        raise ValueError(f"GET {url} returned {resp.status_code} {resp.reason}")
    try:
        return resp.json()
    except ValueError:
        return yaml.safe_load(resp.text)


def load_document(src: str, headers: Optional[Dict[str, str]] = None) -> Any:
    if is_url(src):
        return get_json(src, headers)
    p = Path(src)
    if not p.is_file():
        raise FileNotFoundError(f"File not found: {src}")
    text = p.read_text(encoding="utf-8")
    if p.suffix.lower() == ".json":
        return json.loads(text)
    return yaml.safe_load(text)


def source_name(src: str) -> str:
    return src if is_url(src) else Path(src).name


# Where APIs usually publish their spec (tried relative to the given URL, then to its origin).
SPEC_PATHS = ["openapi.json", "openapi.yaml", "swagger.json", "v3/api-docs", "v2/api-docs", "api-docs",
              "swagger/v1/swagger.json", "api/openapi.json", "api/v3/openapi.json", "api/v1/openapi.json",
              "api/swagger.json", "docs/openapi.json", "openapi/v1.json", "api-docs.json", "swagger.yaml"]


def kind_of(doc: Any) -> Optional[str]:
    if isinstance(doc, dict):
        if "openapi" in doc or "swagger" in doc:
            return "openapi"
        if "item" in doc and "info" in doc or ("collection" in doc and "item" in (doc.get("collection") or {})):
            return "postman"
    return None


def discover(target: str, headers: Optional[Dict[str, str]] = None, timeout: float = 15,
             verify: Any = True, cert: Any = None) -> Tuple[str, str, Any]:
    """Finds an API description from whatever the user passed: a spec/collection file or URL, a Swagger UI
    page, or just the API's base URL. Returns (kind, location, document)."""
    import requests
    from urllib.parse import urljoin, urlsplit

    if not is_url(target):
        doc = load_document(target)
        k = kind_of(doc)
        if not k:
            raise ValueError(f"{target}: not an OpenAPI/Swagger spec or Postman collection")
        return k, target, doc

    tried: List[str] = []

    def probe(url: str) -> Optional[Tuple[str, str, Any]]:
        if url in tried:
            return None
        tried.append(url)
        try:
            r = requests.get(url, headers=headers or {}, timeout=timeout, verify=verify, cert=cert)
        except requests.RequestException:
            return None
        if r.status_code >= 400 or not r.content:
            return None
        try:
            doc = r.json()
        except ValueError:
            if "<html" in r.text[:2000].lower():
                for m in re.finditer(r"""(?:url|spec-url|specUrl)["']?\s*[:=]\s*["']([^"']+\.(?:json|ya?ml)[^"']*)["']""", r.text):
                    found = probe(urljoin(url, m.group(1)))  # spec referenced by a Swagger UI / Redoc page
                    if found:
                        return found
                return None
            try:
                doc = yaml.safe_load(r.text)
            except yaml.YAMLError:
                return None
        k = kind_of(doc)
        return (k, url, doc) if k else None

    found = probe(target)
    if found:
        return found
    parts = urlsplit(target)
    origin = f"{parts.scheme}://{parts.netloc}/"
    bases = [target.rstrip("/") + "/"] + ([origin] if origin != target.rstrip("/") + "/" else [])
    for base in bases:
        for path in SPEC_PATHS:
            found = probe(urljoin(base, path))
            if found:
                return found
    raise ValueError(f"No OpenAPI/Swagger spec found at {target} (tried {len(tried)} locations, e.g. "
                     f"{', '.join(tried[1:4])}). Pass the spec or Postman collection URL/file directly, "
                     f"or use --url <endpoint returning a record> to infer from live data.")
