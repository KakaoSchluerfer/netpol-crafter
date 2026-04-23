"""HTTP client for the pharos-exporter REST API (used by the Streamlit app).

The _SnapshotRefresher (a st.cache_resource singleton) keeps the latest snapshot
in memory, refreshes it from the exporter every REFRESH_INTERVAL seconds in a
background daemon thread, and persists successful fetches to disk so a Streamlit
restart serves data immediately without waiting for the exporter.
"""
from __future__ import annotations

import logging
import os
import threading
import time
from pathlib import Path

import requests
import streamlit as st

from exporter.models import (
    AdminNetworkPolicyModel,
    ClusterSnapshot,
    NamespaceModel,
    NetworkPolicyModel,
    PodModel,
    RouteModel,
    ServiceModel,
    ServicePortModel,
)
from k8s import fixtures as _fix

logger = logging.getLogger(__name__)

_TEST_MODE = os.getenv("TEST_MODE", "false").lower() == "true"
REFRESH_INTERVAL = int(os.getenv("SNAPSHOT_REFRESH_INTERVAL", "60"))
_CACHE_FILE = Path(__file__).resolve().parent.parent / "cache" / "builder_snapshot.json"


# ── Disk persistence ──────────────────────────────────────────────────────────

def _save_to_disk(snapshot: ClusterSnapshot) -> None:
    try:
        _CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        _CACHE_FILE.write_text(snapshot.model_dump_json())
        logger.info("Builder snapshot saved to disk: %s", _CACHE_FILE)
    except Exception:
        logger.error("Failed to save builder snapshot to disk", exc_info=True)


def _load_from_disk() -> ClusterSnapshot | None:
    try:
        if _CACHE_FILE.exists():
            snapshot = ClusterSnapshot.model_validate_json(_CACHE_FILE.read_text())
            logger.info("Builder snapshot loaded from disk: %s", _CACHE_FILE)
            return snapshot
    except Exception:
        logger.warning("Builder disk cache unreadable, will fetch from exporter", exc_info=True)
    return None


# ── Background refresher ──────────────────────────────────────────────────────

class _SnapshotRefresher:
    """Singleton (via st.cache_resource) that holds the latest snapshot and
    refreshes it from the exporter every REFRESH_INTERVAL seconds."""

    def __init__(self, exporter_url: str) -> None:
        self._url = exporter_url
        self._snapshot: ClusterSnapshot | None = _load_from_disk()
        self._lock = threading.RLock()
        thread = threading.Thread(target=self._loop, daemon=True, name="snapshot-refresher")
        thread.start()
        logger.info("Snapshot refresher started (interval=%ds, cache=%s)", REFRESH_INTERVAL, _CACHE_FILE)

    def _loop(self) -> None:
        while True:
            try:
                self._fetch()
            except Exception as exc:
                logger.warning("Snapshot refresh failed: %s", exc)
            time.sleep(REFRESH_INTERVAL)

    def _fetch(self) -> None:
        resp = requests.get(f"{self._url}/get_cluster_data", timeout=30)
        resp.raise_for_status()
        snapshot = ClusterSnapshot.model_validate(resp.json())
        with self._lock:
            self._snapshot = snapshot
        _save_to_disk(snapshot)
        logger.info("Snapshot refreshed: %d namespaces, %d pods, %d policies",
                    len(snapshot.namespaces), len(snapshot.pods), len(snapshot.network_policies))

    def get(self) -> ClusterSnapshot | None:
        with self._lock:
            return self._snapshot


@st.cache_resource(show_spinner=False)
def _get_refresher(exporter_url: str) -> _SnapshotRefresher:
    """One refresher singleton per exporter URL, shared across all Streamlit sessions."""
    return _SnapshotRefresher(exporter_url)


# ── Public API ────────────────────────────────────────────────────────────────

def fetch_snapshot(exporter_url: str) -> ClusterSnapshot:
    if _TEST_MODE:
        logger.debug("TEST_MODE: returning fixture snapshot")
        return _build_fixture_snapshot()

    refresher = _get_refresher(exporter_url)
    snapshot = refresher.get()

    if snapshot is None:
        # Refresher just started and the first background fetch hasn't completed.
        # Block once so the caller gets real data rather than an error.
        logger.info("No cached snapshot yet — fetching synchronously from %s", exporter_url)
        resp = requests.get(f"{exporter_url}/get_cluster_data", timeout=30)
        resp.raise_for_status()
        snapshot = ClusterSnapshot.model_validate(resp.json())

    return snapshot


# ── Snapshot accessors ────────────────────────────────────────────────────────

def snapshot_namespaces(s: ClusterSnapshot) -> list[str]:
    return sorted(ns.name for ns in s.namespaces)


def snapshot_ns_labels(s: ClusterSnapshot) -> dict[str, dict[str, str]]:
    return {ns.name: ns.labels for ns in s.namespaces}


def snapshot_all_pods(s: ClusterSnapshot) -> list[dict]:
    return [p.model_dump() for p in s.pods]


def snapshot_pods_in_ns(s: ClusterSnapshot, namespace: str) -> list[dict]:
    return [p.model_dump() for p in s.pods if p.namespace == namespace]


def snapshot_services_in_ns(s: ClusterSnapshot, namespace: str) -> list[dict]:
    return [svc.model_dump() for svc in s.services if svc.namespace == namespace]


def snapshot_all_services(s: ClusterSnapshot) -> list[dict]:
    return [svc.model_dump() for svc in s.services]


def snapshot_routes_in_ns(s: ClusterSnapshot, namespace: str) -> list[dict]:
    return [r.model_dump() for r in s.routes if r.namespace == namespace]


def snapshot_all_routes(s: ClusterSnapshot) -> list[dict]:
    return [r.model_dump() for r in s.routes]


def snapshot_policies(s: ClusterSnapshot) -> list[dict]:
    """Convert to format expected by collect_edges: {metadata: {name, namespace}, spec: {...}}"""
    return [
        {"metadata": {"name": p.name, "namespace": p.namespace}, "spec": p.spec}
        for p in s.network_policies
    ]


def snapshot_anps(s: ClusterSnapshot) -> list[dict]:
    return [
        {"name": a.name, "priority": a.priority, "spec": a.spec}
        for a in s.admin_network_policies
    ]


# ── Fixture snapshot (TEST_MODE) ──────────────────────────────────────────────

def _build_fixture_snapshot() -> ClusterSnapshot:
    pods = [
        PodModel(
            name=p["name"], namespace=p["namespace"],
            labels=p.get("labels", {}), workload_labels=p.get("workload_labels", {}),
            phase=p.get("phase", "Running"),
        )
        for p in _fix.get_all_pods()
    ]

    services = [
        ServiceModel(
            name=s["name"], namespace=s["namespace"],
            labels=s.get("labels", {}), selector=s.get("selector", {}),
            ports=[ServicePortModel(**pt) for pt in s.get("ports", [])],
            type=s.get("type", "ClusterIP"),
        )
        for ns in _fix.get_namespaces()
        for s in _fix.get_services(ns)
    ]

    routes = [
        RouteModel(
            name=r["name"], namespace=r["namespace"],
            host=r.get("host", ""), path=r.get("path", "/"),
            to=r.get("to", {}), labels=r.get("labels", {}),
            tls=r.get("tls", False),
        )
        for ns in _fix.get_namespaces()
        for r in _fix.get_routes(ns)
    ]

    ns_labels_map = _fix.get_all_namespace_labels()
    namespaces = [NamespaceModel(name=ns, labels=lbls) for ns, lbls in ns_labels_map.items()]

    network_policies = [
        NetworkPolicyModel(
            name=pol.get("metadata", {}).get("name", ""),
            namespace=pol.get("metadata", {}).get("namespace", ""),
            spec=pol.get("spec", {}),
        )
        for pol in _fix.get_network_policies()
    ]

    anps = [
        AdminNetworkPolicyModel(name=a["name"], priority=a.get("priority", 0), spec=a.get("spec", {}))
        for a in _fix.get_admin_network_policies()
    ]

    return ClusterSnapshot(
        cluster_name="test-fixture",
        namespaces=namespaces, pods=pods, services=services, routes=routes,
        network_policies=network_policies, admin_network_policies=anps,
        baseline_admin_network_policy=_fix.get_baseline_admin_network_policy(),
    )
