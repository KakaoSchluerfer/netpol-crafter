"""HTTP client for the netpol-exporter REST API (used by the Streamlit app)."""
from __future__ import annotations

import logging
import os

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


@st.cache_data(ttl=60, show_spinner=False)
def fetch_snapshot(exporter_url: str) -> ClusterSnapshot:
    if _TEST_MODE:
        logger.debug("TEST_MODE: building fixture snapshot")
        return _build_fixture_snapshot()
    logger.info("Fetching cluster snapshot from %s", exporter_url)
    resp = requests.get(f"{exporter_url}/snapshot", timeout=30)
    resp.raise_for_status()
    snapshot = ClusterSnapshot.model_validate(resp.json())
    logger.debug("Snapshot: %d namespaces, %d pods, %d policies",
                 len(snapshot.namespaces), len(snapshot.pods), len(snapshot.network_policies))
    return snapshot


def _build_fixture_snapshot() -> ClusterSnapshot:
    """Build a ClusterSnapshot from the existing fixture data."""
    pods = []
    for p in _fix.get_all_pods():
        pods.append(PodModel(
            name=p["name"],
            namespace=p["namespace"],
            labels=p.get("labels", {}),
            workload_labels=p.get("workload_labels", {}),
            phase=p.get("phase", "Running"),
        ))

    services = []
    for ns in _fix.get_namespaces():
        for s in _fix.get_services(ns):
            ports = [ServicePortModel(**pt) for pt in s.get("ports", [])]
            services.append(ServiceModel(
                name=s["name"],
                namespace=s["namespace"],
                labels=s.get("labels", {}),
                selector=s.get("selector", {}),
                ports=ports,
                type=s.get("type", "ClusterIP"),
            ))

    routes = []
    for ns in _fix.get_namespaces():
        for r in _fix.get_routes(ns):
            routes.append(RouteModel(
                name=r["name"],
                namespace=r["namespace"],
                host=r.get("host", ""),
                path=r.get("path", "/"),
                to=r.get("to", {}),
                labels=r.get("labels", {}),
                tls=r.get("tls", False),
            ))

    ns_labels_map = _fix.get_all_namespace_labels()
    namespaces = [
        NamespaceModel(name=ns, labels=lbls)
        for ns, lbls in ns_labels_map.items()
    ]

    network_policies = []
    for pol in _fix.get_network_policies():
        meta = pol.get("metadata", {})
        network_policies.append(NetworkPolicyModel(
            name=meta.get("name", ""),
            namespace=meta.get("namespace", ""),
            spec=pol.get("spec", {}),
        ))

    anps = [
        AdminNetworkPolicyModel(
            name=a["name"],
            priority=a.get("priority", 0),
            spec=a.get("spec", {}),
        )
        for a in _fix.get_admin_network_policies()
    ]

    return ClusterSnapshot(
        cluster_name="test-fixture",
        namespaces=namespaces,
        pods=pods,
        services=services,
        routes=routes,
        network_policies=network_policies,
        admin_network_policies=anps,
        baseline_admin_network_policy=_fix.get_baseline_admin_network_policy(),
    )


# ── Snapshot accessors (same signatures as k8s.resources functions) ───────────

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


def snapshot_routes_in_ns(s: ClusterSnapshot, namespace: str) -> list[dict]:
    return [r.model_dump() for r in s.routes if r.namespace == namespace]


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
