"""
NetPol Exporter — FastAPI service.

Exposes a cached cluster snapshot at GET /snapshot.
The Streamlit app fetches this snapshot instead of calling the K8s API directly,
so it does not need cluster RBAC — that stays here with the ServiceAccount.
"""
import asyncio
import logging
import os
import time

from fastapi import FastAPI

from exporter.k8s_fetch import build_snapshot
from exporter.models import ClusterSnapshot

logging.basicConfig(
    level=logging.DEBUG if os.getenv("DEBUG", "false").lower() == "true" else logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

CACHE_TTL = int(os.getenv("CACHE_TTL", "60"))
_cache: dict = {"snapshot": None, "ts": 0.0}

app = FastAPI(title="NetPol Exporter")


@app.get("/snapshot", response_model=ClusterSnapshot)
async def snapshot():
    now = time.time()
    age = now - _cache["ts"]
    if _cache["snapshot"] is None or age > CACHE_TTL:
        logger.info("Cache miss (age=%.0fs) — rebuilding snapshot", age)
        loop = asyncio.get_event_loop()
        _cache["snapshot"] = await loop.run_in_executor(None, build_snapshot)
        _cache["ts"] = time.time()
        logger.info("Snapshot rebuilt successfully")
    else:
        logger.debug("Cache hit (age=%.0fs)", age)
    return _cache["snapshot"]


@app.get("/health")
async def health():
    return {"status": "ok"}
