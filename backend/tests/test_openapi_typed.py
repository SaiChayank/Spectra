"""Every core API route documents a real 200/201 response schema.

The frontend generates its TypeScript types from ``frontend/contract/openapi.json``,
so an untyped route (``{}``) silently becomes ``unknown``.  Only the frozen
experimental modules (pqc/tee/bio/twin/edge, model harden/robustness/evasion/
intel) and the Prometheus text route are allowed to stay untyped.
"""

from __future__ import annotations

from spectra.api.app import app

UNTYPED_ALLOWED = ("/api/pqc", "/api/tee", "/api/bio", "/api/twin", "/api/edge",
                   "/api/metrics", "/api/model/harden", "/api/model/robustness",
                   "/api/model/evasion", "/api/model/intel")


def _typed(op: dict) -> bool:
    resp = op["responses"].get("200") or op["responses"].get("201") or {}
    schema = resp.get("content", {}).get("application/json", {}).get("schema", {})
    return bool(schema.get("$ref") or schema.get("properties"))


def test_core_routes_have_typed_responses():
    untyped = [f"{method.upper()} {path}"
               for path, ops in app.openapi()["paths"].items()
               if path.startswith("/api/") and not path.startswith(UNTYPED_ALLOWED)
               for method, op in ops.items() if not _typed(op)]
    assert not untyped, f"routes without a response_model: {untyped}"


def test_response_model_mismatch_fails_open_in_production(client, caplog):
    """Outside the test suite a model mismatch logs and returns the data, never a 500."""
    from pydantic import BaseModel

    from spectra.api.app import app

    class Strict(BaseModel):
        n: int

    def bad() -> dict:
        return {"n": "not-a-number", "extra": 1}

    app.router.routes.insert(0, __import__("fastapi").routing.APIRoute(
        "/api/_t_mismatch", bad, response_model=Strict))
    app.state.strict_responses = False
    try:
        res = client.get("/api/_t_mismatch")
        assert res.status_code == 200 and res.json() == {"n": "not-a-number", "extra": 1}
        assert any(r.getMessage() == "response model mismatch" for r in caplog.records)
    finally:
        app.state.strict_responses = True
        app.router.routes.pop(0)
