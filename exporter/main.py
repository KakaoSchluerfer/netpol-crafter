import asyncio
import os
import time

from fastapi import FastAPI

from exporter.k8s_fetch import build_snapshot
from exporter.models import ClusterSnapshot

CACHE_TTL = int(os.getenv("CACHE_TTL", "60"))
_cache: dict = {"snapshot": None, "ts": 0.0}

app = FastAPI(title="NetPol Exporter")


@app.get("/snapshot", response_model=ClusterSnapshot)
async def snapshot():
    now = time.time()
    if _cache["snapshot"] is None or now - _cache["ts"] > CACHE_TTL:
        loop = asyncio.get_event_loop()
        _cache["snapshot"] = await loop.run_in_executor(None, build_snapshot)
        _cache["ts"] = time.time()
    return _cache["snapshot"]


@app.get("/health")
async def health():
    return {"status": "ok"}
