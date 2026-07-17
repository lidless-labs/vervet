"""
Vervet API - FastAPI application entry point.
Provides REST endpoints for network log analysis and threat hunting.
"""
import os
import sys
import logging

from fastapi import FastAPI
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
    demo = getattr(settings, "demo_mode", False) or str(raw_env).lower() in ("true", "1", "yes")
    print(f"[STARTUP] Demo check: env={raw_env}, demo_active={demo}", flush=True)
    if demo:
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
    elif settings.data_dir:
        # Durable mode: mirror ingested logs to <data_dir>/vervet.db and reload
        # whatever was ingested before the last restart.
        try:
            from api.services.persistence import LogPersistence

            db_path = os.path.join(settings.data_dir, "vervet.db")
            log_store.attach_persistence(LogPersistence(db_path))
            log_store.rehydrate()
            print(
                f"[STARTUP] Persistence at {db_path}; "
                f"rehydrated {log_store.total_records} record(s)",
                flush=True,
            )
        except Exception:
            print(f"[STARTUP] Failed to init persistence:\n{traceback.format_exc()}", flush=True)
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


@app.get("/api/status")
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
app.include_router(logs.router, prefix=f"{settings.api_prefix}/logs", tags=["logs"])
app.include_router(
    analysis.router, prefix=f"{settings.api_prefix}/analysis", tags=["analysis"]
)
app.include_router(ingest.router, prefix=f"{settings.api_prefix}/ingest", tags=["ingest"])
app.include_router(data.router, prefix=f"{settings.api_prefix}/data", tags=["data"])
app.include_router(hunt.router, prefix=f"{settings.api_prefix}/hunt", tags=["hunt"])
app.include_router(dns_threat.router, prefix=f"{settings.api_prefix}/hunt", tags=["dns-threats"])
app.include_router(export.router, prefix=f"{settings.api_prefix}/export", tags=["export"])
app.include_router(sessions.router, prefix=f"{settings.api_prefix}/sessions", tags=["sessions"])
app.include_router(scoring.router, prefix=f"{settings.api_prefix}/scoring", tags=["scoring"])
app.include_router(intel.router, prefix=f"{settings.api_prefix}/intel", tags=["intel"])
app.include_router(reports.router, prefix=f"{settings.api_prefix}/reports", tags=["reports"])
app.include_router(cases.router, prefix=f"{settings.api_prefix}/cases", tags=["cases"])
app.include_router(bundles.router, prefix=f"{settings.api_prefix}/cases", tags=["bundles"])
app.include_router(analytics.router, prefix=f"{settings.api_prefix}/analytics", tags=["analytics"])
app.include_router(trends.router, prefix=f"{settings.api_prefix}/trends", tags=["trends"])
app.include_router(capture.router, prefix=f"{settings.api_prefix}/capture", tags=["capture"])
app.include_router(workflow.router, prefix=f"{settings.api_prefix}/workflow", tags=["workflow"])
app.include_router(settings_router.router, prefix=f"{settings.api_prefix}/settings", tags=["settings"])
app.include_router(search.router, prefix=f"{settings.api_prefix}/search", tags=["search"])
app.include_router(packets.router, prefix=f"{settings.api_prefix}/packets", tags=["packets"])
app.include_router(baseline.router, prefix=f"{settings.api_prefix}/baseline", tags=["baseline"])
app.include_router(anomalies.router, prefix=f"{settings.api_prefix}/anomalies", tags=["anomalies"])
app.include_router(hunt_hypotheses.router, prefix=f"{settings.api_prefix}/hypotheses", tags=["hypotheses"])
app.include_router(annotations.router, prefix=f"{settings.api_prefix}/annotations", tags=["annotations"])
app.include_router(rules.router, prefix=f"{settings.api_prefix}/rules", tags=["rules"])
app.include_router(sigma.router, prefix=f"{settings.api_prefix}/sigma", tags=["sigma"])
app.include_router(hosts.router, prefix=f"{settings.api_prefix}/hosts", tags=["hosts"])
app.include_router(tls.router)
app.include_router(webhooks.router)
app.include_router(http_analysis.router)
app.include_router(lateral.router)
app.include_router(integrations.router)
app.include_router(live_ops.router, prefix=f"{settings.api_prefix}/live", tags=["live-operations"])


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
