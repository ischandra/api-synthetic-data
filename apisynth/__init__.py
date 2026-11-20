"""apisynth - synthetic request data generated from your API definitions.

Sources: OpenAPI/Swagger specs, Postman collections, live API URLs, sample JSON.
Output: valid, boundary, invalid (one rule broken per case) and hostile request data.
"""
__version__ = "0.1.0"

_EXPORTS = {
    "Generator": "generate", "Mutator": "negative", "infer_schema": "infer", "verify": "verify",
    "Sources": "core", "Options": "core", "load_endpoints": "core", "generate_cases": "core",
    "load_openapi": "sources.openapi", "load_postman": "sources.postman",
    "load_live": "sources.live", "load_samples": "sources.live",
}
__all__ = list(_EXPORTS)


def __getattr__(name):
    if name in _EXPORTS:
        import importlib
        return getattr(importlib.import_module(f".{_EXPORTS[name]}", __name__), name)
    raise AttributeError(f"module 'apisynth' has no attribute '{name}'")
