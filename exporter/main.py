"""
NetPol Exporter — FastAPI service.

Exposes a cached cluster snapshot at GET /snapshot.
The Streamlit app fetches this snapshot instead of calling the K8s API directly,
so it does not need cluster RBAC — that stays here with the ServiceAccount.

Cache behaviour:
  - On startup: snapshot is built in the background; /snapshot returns 503 until ready.
  - After startup: the cache is refreshed in the background on the first request
    that finds a stale entry, so callers never block on a full K8s fetch.
"""
import asyncio
import logging
import os
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import JSONResponse

from exporter.k8s_fetch import build_snapshot
from exporter.models import ClusterSnapshot

logging.basicConfig(
    level=logging.DEBUG if os.getenv("DEBUG", "false").lower() == "true" else logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

CACHE_TTL = int(os.getenv("CACHE_TTL", "60"))
_cache: dict = {"snapshot": None, "ts": 0.0, "refreshing": False}


async def _refresh_cache() -> None:
    """Build a fresh snapshot in the background and update the cache."""
    if _cache["refreshing"]:
        return
    _cache["refreshing"] = True
    try:
        loop = asyncio.get_event_loop()
        snapshot = await loop.run_in_executor(None, build_snapshot)
        _cache["snapshot"] = snapshot
        _cache["ts"] = time.time()
        logger.info("Snapshot ready (%d namespaces, %d pods, %d policies)",
                    len(snapshot.namespaces), len(snapshot.pods), len(snapshot.network_policies))
    except Exception:
        logger.exception("Failed to build snapshot")
    finally:
        _cache["refreshing"] = False


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Building initial cluster snapshot on startup")
    asyncio.create_task(_refresh_cache())
    yield


app = FastAPI(title="NetPol Exporter", lifespan=lifespan)


@app.get("/snapshot", response_model=ClusterSnapshot)
async def snapshot():
    if _cache["snapshot"] is None:
        # Still building on startup — tell the caller to retry
        return JSONResponse(
            status_code=503,
            content={"detail": "Snapshot not yet ready, please retry in a few seconds"},
            headers={"Retry-After": "5"},
        )

    age = time.time() - _cache["ts"]
    if age > CACHE_TTL:
        logger.info("Cache stale (age=%.0fs) — refreshing in background", age)
        asyncio.create_task(_refresh_cache())

    logger.debug("Serving snapshot (age=%.0fs)", age)
    return _cache["snapshot"]


@app.get("/health")
async def health():
    return {"status": "ok", "snapshot_ready": _cache["snapshot"] is not None}
