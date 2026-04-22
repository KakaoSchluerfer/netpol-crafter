"""
NetPol Exporter — FastAPI service.

Endpoints:
  GET  /get_cluster_data  — returns the cached cluster snapshot
  POST /snapshot          — triggers a background rebuild of the cache
  GET  /health            — liveness/readiness probe

Cache is persisted to {cwd}/cache/snapshot.json so a pod restart can serve
stale data immediately while a fresh rebuild runs in the background.
"""
import asyncio
import logging
import os
import time
from contextlib import asynccontextmanager
from pathlib import Path

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
CACHE_DIR = Path.cwd() / "cache"
CACHE_FILE = CACHE_DIR / "snapshot.json"

_cache: dict = {"snapshot": None, "ts": 0.0, "refreshing": False}


# ── Disk persistence ──────────────────────────────────────────────────────────

def _load_from_disk() -> ClusterSnapshot | None:
    try:
        if CACHE_FILE.exists():
            snapshot = ClusterSnapshot.model_validate_json(CACHE_FILE.read_text())
            logger.info("Loaded snapshot from disk: %s", CACHE_FILE)
            return snapshot
    except Exception:
        logger.warning("Disk cache unreadable, will rebuild from cluster", exc_info=True)
    return None


def _save_to_disk(snapshot: ClusterSnapshot) -> None:
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        CACHE_FILE.write_text(snapshot.model_dump_json())
        logger.debug("Snapshot saved to %s", CACHE_FILE)
    except Exception:
        logger.warning("Failed to save snapshot to disk", exc_info=True)


# ── Background refresh ────────────────────────────────────────────────────────

async def _refresh_cache() -> None:
    if _cache["refreshing"]:
        logger.debug("Refresh already in progress, skipping")
        return
    _cache["refreshing"] = True
    try:
        loop = asyncio.get_event_loop()
        snapshot = await loop.run_in_executor(None, build_snapshot)
        _cache["snapshot"] = snapshot
        _cache["ts"] = time.time()
        _save_to_disk(snapshot)
        logger.info("Snapshot ready (%d namespaces, %d pods, %d policies)",
                    len(snapshot.namespaces), len(snapshot.pods), len(snapshot.network_policies))
    except Exception:
        logger.exception("Failed to build snapshot")
    finally:
        _cache["refreshing"] = False


# ── App lifecycle ─────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    disk_snapshot = _load_from_disk()
    if disk_snapshot is not None:
        _cache["snapshot"] = disk_snapshot
        _cache["ts"] = time.time()
        logger.info("Serving disk cache while rebuilding fresh snapshot in background")
    else:
        logger.info("No disk cache found — building initial snapshot")
    asyncio.create_task(_refresh_cache())
    yield


app = FastAPI(title="NetPol Exporter", lifespan=lifespan)


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.get("/get_cluster_data", response_model=ClusterSnapshot)
async def get_cluster_data():
    """Return the cached cluster snapshot."""
    if _cache["snapshot"] is None:
        return JSONResponse(
            status_code=503,
            content={"detail": "Snapshot not yet ready, please retry in a few seconds"},
            headers={"Retry-After": "5"},
        )
    age = time.time() - _cache["ts"]
    logger.debug("Serving snapshot (age=%.0fs)", age)
    return _cache["snapshot"]


@app.post("/snapshot", status_code=202)
async def trigger_snapshot():
    """Trigger an asynchronous rebuild of the cluster snapshot."""
    if _cache["refreshing"]:
        return {"status": "rebuild already in progress"}
    asyncio.create_task(_refresh_cache())
    logger.info("Snapshot rebuild triggered via POST /snapshot")
    return {"status": "rebuild triggered"}


@app.get("/health")
async def health():
    return {"status": "ok", "snapshot_ready": _cache["snapshot"] is not None}
