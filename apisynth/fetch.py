"""Loads JSON/YAML documents from files or URLs."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, Optional

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
