"""
Vervet API - FastAPI application entry point.
Provides REST endpoints for network log analysis and threat hunting.
"""
import os
import sys
import logging

from fastapi import APIRouter, Depends, FastAPI
from api.dependencies.auth import api_key_auth
from fastapi.middleware.cors import CORSMiddleware
from api.config import settings
from api.routers import analysis, logs, ingest, data, hunt, dns_threat, export, sessions, scoring, intel, reports, analytics, capture, workflow, search, packets, baseline, anomalies, cases, bundles, rules, sigma, hosts, hunt_hypotheses, annotations, trends
from api.routers import tls, webhooks, http_analysis, lateral, integrations, live_ops
from api.routers import settings as settings_router
from api.services.log_store import log_store
from api.services.demo_data import DemoDataService

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Production safety check: refuse to start without an API key in production
# ---------------------------------------------------------------------------
_env = os.environ.get("VERVET_ENV", "development").lower()
if _env == "production" and not settings.api_key:
    logger.critical(
        "FATAL: VERVET_ENV is 'production' but VERVET_API_KEY is not set. "
        "Refusing to start without authentication. "
        "Set VERVET_API_KEY to a secure random value."
    )
    sys.exit(1)

if not settings.api_key:
    logger.warning(
        "VERVET_API_KEY is not set — authentication is disabled (dev mode). "
        "Set VERVET_ENV=production and VERVET_API_KEY for production use."
    )


from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(application):
    """Startup: load demo data if enabled."""
    import os, traceback
    raw_env = os.environ.get("VERVET_DEMO_MODE", "unset")
    demo = getattr(settings, "demo_mode", False)
    print(f"[STARTUP] Demo check: env={raw_env}, settings.demo_mode={demo}", flush=True)
    if demo or str(raw_env).lower() in ("true", "1", "yes"):
        try:
            svc = DemoDataService()
            print(f"[STARTUP] Demo data dir: {svc.data_dir}, exists: {svc.data_dir.exists()}", flush=True)
            if svc.data_dir.exists():
                print(f"[STARTUP] Demo files: {list(svc.data_dir.iterdir())}", flush=True)
            stats = svc.load_into_store(log_store)
            print(f"[STARTUP] Demo loaded: {stats}", flush=True)

            from api.services.trend_tracker import TrendTracker
            tracker = TrendTracker()
            if not tracker.list_snapshots():
                tracker.seed_demo_trends()
        except Exception:
            print(f"[STARTUP] Failed to load demo data:\n{traceback.format_exc()}", flush=True)
    yield

# Initialize FastAPI app
app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="Network threat hunting and analysis platform for Zeek (Bro) and Suricata logs",
    lifespan=lifespan,
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


api_router = APIRouter(dependencies=[Depends(api_key_auth)])


@api_router.get("/api/status")
async def root():
    """API status endpoint."""
    return {
        "name": settings.app_name,
        "version": settings.app_version,
        "status": "operational",
        "demo_mode": getattr(settings, "demo_mode", False),
    }


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "healthy"}


# Include routers
api_router.include_router(logs.router, prefix=f"{settings.api_prefix}/logs", tags=["logs"])
api_router.include_router(
    analysis.router, prefix=f"{settings.api_prefix}/analysis", tags=["analysis"]
)
api_router.include_router(ingest.router, prefix=f"{settings.api_prefix}/ingest", tags=["ingest"])
api_router.include_router(data.router, prefix=f"{settings.api_prefix}/data", tags=["data"])
api_router.include_router(hunt.router, prefix=f"{settings.api_prefix}/hunt", tags=["hunt"])
api_router.include_router(dns_threat.router, prefix=f"{settings.api_prefix}/hunt", tags=["dns-threats"])
api_router.include_router(export.router, prefix=f"{settings.api_prefix}/export", tags=["export"])
api_router.include_router(sessions.router, prefix=f"{settings.api_prefix}/sessions", tags=["sessions"])
api_router.include_router(scoring.router, prefix=f"{settings.api_prefix}/scoring", tags=["scoring"])
api_router.include_router(intel.router, prefix=f"{settings.api_prefix}/intel", tags=["intel"])
api_router.include_router(reports.router, prefix=f"{settings.api_prefix}/reports", tags=["reports"])
api_router.include_router(cases.router, prefix=f"{settings.api_prefix}/cases", tags=["cases"])
api_router.include_router(bundles.router, prefix=f"{settings.api_prefix}/cases", tags=["bundles"])
api_router.include_router(analytics.router, prefix=f"{settings.api_prefix}/analytics", tags=["analytics"])
api_router.include_router(trends.router, prefix=f"{settings.api_prefix}/trends", tags=["trends"])
api_router.include_router(capture.router, prefix=f"{settings.api_prefix}/capture", tags=["capture"])
api_router.include_router(workflow.router, prefix=f"{settings.api_prefix}/workflow", tags=["workflow"])
api_router.include_router(settings_router.router, prefix=f"{settings.api_prefix}/settings", tags=["settings"])
api_router.include_router(search.router, prefix=f"{settings.api_prefix}/search", tags=["search"])
api_router.include_router(packets.router, prefix=f"{settings.api_prefix}/packets", tags=["packets"])
api_router.include_router(baseline.router, prefix=f"{settings.api_prefix}/baseline", tags=["baseline"])
api_router.include_router(anomalies.router, prefix=f"{settings.api_prefix}/anomalies", tags=["anomalies"])
api_router.include_router(hunt_hypotheses.router, prefix=f"{settings.api_prefix}/hypotheses", tags=["hypotheses"])
api_router.include_router(annotations.router, prefix=f"{settings.api_prefix}/annotations", tags=["annotations"])
api_router.include_router(rules.router, prefix=f"{settings.api_prefix}/rules", tags=["rules"])
api_router.include_router(sigma.router, prefix=f"{settings.api_prefix}/sigma", tags=["sigma"])
api_router.include_router(hosts.router, prefix=f"{settings.api_prefix}/hosts", tags=["hosts"])
api_router.include_router(tls.router)
api_router.include_router(webhooks.router)
api_router.include_router(http_analysis.router)
api_router.include_router(lateral.router)
api_router.include_router(integrations.router)
api_router.include_router(live_ops.router, prefix=f"{settings.api_prefix}/live", tags=["live-operations"])


app.include_router(api_router)


## Demo data loading is handled via lifespan context manager above


# Serve frontend static files in production
_frontend_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "web", "dist")
if os.path.isdir(_frontend_dir):
    from fastapi.responses import FileResponse

    @app.get("/{full_path:path}")
    async def serve_frontend(full_path: str):
        """Serve frontend SPA — all non-API routes fall through to index.html."""
        from pathlib import Path
        base = Path(_frontend_dir).resolve()
        candidate = base / full_path
        # Check boundary before touching the filesystem (no info leak via timing)
        try:
            candidate.relative_to(base)
        except ValueError:
            return FileResponse(os.path.join(_frontend_dir, "index.html"))
        # Reject symlinks that could escape the boundary
        for parent in [candidate, *candidate.parents]:
            if parent == base:
                break
            if parent.is_symlink():
                return FileResponse(os.path.join(_frontend_dir, "index.html"))
        if full_path and candidate.is_file():
            return FileResponse(candidate)
        return FileResponse(os.path.join(_frontend_dir, "index.html"))


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)
