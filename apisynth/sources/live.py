"""Live API URLs and sample JSON files -> endpoints, by inferring the record shape.

``GET https://api.example.com/users/42`` returns a user, so the tool infers the user
shape and, by default, generates payloads for ``POST /users`` (trailing id removed).
Use ``"<url> -> PUT /users/{id}"`` to choose the target endpoint yourself."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlsplit

from ..fetch import get_json, is_url
from ..infer import extract_records, infer_schema
from ..model import Endpoint, Param
from ..schema import convert_schema

_ID_SEGMENT = re.compile(r"^(\d+|[0-9a-fA-F-]{32,36}|[0-9a-f]{24})$")


def split_target(arg: str) -> Tuple[str, Optional[str]]:
    """``"https://x/users/1 -> PUT /users/{id}"`` -> (url, "PUT /users/{id}")"""
    if "->" in arg:
        src, _, target = arg.partition("->")
        return src.strip(), target.strip()
    return arg.strip(), None


def _default_target(path: str) -> Tuple[str, str]:
    segs = [s for s in path.split("/") if s]
    if segs and _ID_SEGMENT.match(segs[-1]):
        segs = segs[:-1]
    return "POST", "/" + "/".join(segs)


def _endpoint(records: List, target: Optional[str], default_path: str, source: str) -> Endpoint:
    if target:
        m = re.fullmatch(r"(?i)(get|post|put|patch|delete)\s+(\S+)", target)
        if not m:
            raise ValueError(f"Target must look like 'POST /users', got '{target}'")
        method, path = m.group(1).upper(), m.group(2)
    else:
        method, path = _default_target(default_path)
    ep = Endpoint(method=method, path=path, source=source, doc={}, inferred=True,
                  body_schema=convert_schema(infer_schema(records)), body_required=True)
    for name in re.findall(r"\{([^}/]+)\}", path):
        ep.params.append(Param(name, "path", True, {"type": "string"}))
    return ep


def load_live(args: List[str], headers: Optional[Dict[str, str]] = None) -> List[Endpoint]:
    eps = []
    for arg in args:
        url, target = split_target(arg)
        if not is_url(url):
            raise ValueError(f"Not an http(s) URL: {url}")
        records = extract_records(get_json(url, headers))
        eps.append(_endpoint(records, target, urlsplit(url).path, f"live:{url}"))
    return eps


def load_samples(args: List[str]) -> List[Endpoint]:
    eps = []
    for arg in args:
        file, target = split_target(arg)
        p = Path(file)
        records = extract_records(json.loads(p.read_text(encoding="utf-8")))
        default = "/" + re.sub(r"[^a-z0-9]+", "-", p.stem.lower()).strip("-")
        eps.append(_endpoint(records, target, default, f"sample:{p.name}"))
    return eps
