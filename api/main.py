"""REST API for threat queries."""
from __future__ import annotations
import logging, os
from typing import Any
logger = logging.getLogger(__name__)

def create_app():
    try:
        from fastapi import FastAPI
    except ImportError:
        raise RuntimeError("fastapi not installed")
    app = FastAPI(title="CTI API")
    @app.get("/health")
    def health():
        return {"status": "ok"}
    @app.get("/threats")
    def threats(q: str = ""):
        return {"query": q, "results": []}
    return app

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(create_app(), host="0.0.0.0", port=int(os.getenv("API_PORT", "8000")))
