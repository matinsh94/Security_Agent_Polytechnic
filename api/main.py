"""REST API for querying threats, CVEs, IOCs, and campaign correlations."""
from __future__ import annotations
import os, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from scripts.state_manager import StateManager
from scripts.correlation_engine import CorrelationEngine

def create_app():
    try:
        from fastapi import FastAPI, HTTPException
    except ImportError:
        raise RuntimeError("fastapi not installed")
    from fastapi import Header
    token_env = os.getenv("API_TOKEN")

    def _auth(x_api_token: str | None = Header(default=None)):
        if token_env and x_api_token != token_env:
            raise HTTPException(status_code=401, detail="unauthorized")
        return True
    db_path = Path(os.getenv("DATABASE_PATH", "data/agent_state.db"))
    sm = StateManager(db_path=db_path)

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.get("/threats")
    def threats(limit: int = 50):
        try:
            rows = sm.get_vulnerabilities(limit=limit)
        except Exception:
            rows = []
        return {"results": rows}

    @app.get("/cves/{cve_id}")
    def cve(cve_id: str):
        try:
            info = sm.get_threat_analysis_by_cve(cve_id)
        except Exception:
            info = None
        if not info:
            raise HTTPException(status_code=404, detail="not found")
        return info

    @app.get("/iocs")
    def iocs(ioc_type: str = "ipv4", limit: int = 100):
        try:
            rows = sm.get_iocs_by_type(ioc_type)
        except Exception:
            rows = []
        return {"results": rows[:limit]}

    @app.get("/campaigns")
    def campaigns():
        try:
            rows = sm.get_correlation_clusters()
        except Exception:
            rows = []
        return {"results": rows}

    return app

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(create_app(), host="0.0.0.0", port=int(os.getenv("API_PORT", "8000")))
