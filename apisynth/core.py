"""High-level API: load sources -> generate cases -> (verify) -> write."""
from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .generate import Generator
from .model import Case, Endpoint
from .negative import Mutator
from .sources.live import load_live, load_samples
from .sources.openapi import load_openapi
from .sources.postman import load_postman
from .verify import verify


@dataclass
class Sources:
    openapi: List[str] = field(default_factory=list)
    postman: List[str] = field(default_factory=list)
    urls: List[str] = field(default_factory=list)
    samples: List[str] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)

    def empty(self) -> bool:
        return not (self.openapi or self.postman or self.urls or self.samples)


def load_endpoints(src: Sources) -> Tuple[List[Endpoint], Optional[str]]:
    """All endpoints from all sources, plus a default base URL (from the first spec's servers)."""
    eps: List[Endpoint] = []
    base_url: Optional[str] = None
    for s in src.openapi:
        found, base = load_openapi(s, src.headers)
        eps += found
        base_url = base_url or base
    for s in src.postman:
        eps += load_postman(s, src.headers)
    if src.urls:
        eps += load_live(src.urls, src.headers)
    if src.samples:
        eps += load_samples(src.samples)
    return eps, base_url


def select(eps: List[Endpoint], include: List[str], exclude: List[str], tags: List[str]) -> List[Endpoint]:
    def match(ep: Endpoint, patterns: List[str]) -> bool:
        return any(fnmatch.fnmatchcase(ep.key, p) or fnmatch.fnmatchcase(ep.key, f"* {p}")
                   or (ep.operation_id and fnmatch.fnmatchcase(ep.operation_id, p)) for p in patterns)
    out = [e for e in eps if (not include or match(e, include)) and not match(e, exclude)]
    if tags:
        out = [e for e in out if set(tags) & set(e.tags)]
    return out


@dataclass
class Options:
    count: int = 5
    seed: Optional[int] = None
    invalid: bool = True
    boundary: bool = True
    hostile: bool = False
    optional_rate: float = 0.7
    max_invalid: int = 200
    prefer_examples: bool = False
    methods: Optional[List[str]] = None   # default: endpoints with a body or params


def generate_cases(eps: List[Endpoint], opts: Options) -> Tuple[List[Tuple[Endpoint, List[Case]]], List[str], int]:
    """Returns ([(endpoint, cases)], verification problems, seed used)."""
    gen = Generator(seed=opts.seed, optional_rate=opts.optional_rate, prefer_examples=opts.prefer_examples)
    mut = Mutator(gen, boundary=opts.boundary, hostile=opts.hostile, max_cases=opts.max_invalid)
    results = []
    problems: List[str] = []
    for ep in eps:
        if opts.methods and ep.method not in opts.methods:
            continue
        if not opts.methods and ep.body_schema is None and not ep.params:
            continue  # nothing to generate (e.g. GET /health)
        cases = gen.valid_cases(ep, opts.count)
        if opts.invalid or opts.boundary or opts.hostile:
            extra = mut.cases(ep)
            cases += [c for c in extra if (c.kind == "invalid" and opts.invalid) or c.kind in ("boundary", "hostile")]
        problems += verify(ep, cases)
        results.append((ep, cases))
    return results, problems, gen.seed
