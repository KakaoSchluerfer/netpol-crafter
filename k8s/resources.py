"""
All Kubernetes / OpenShift resource-fetching logic lives here.

Design notes:
  • Every public function accepts an ApiClient so callers can inject test doubles.
  • Results are plain dicts/lists – no kubernetes model objects leak outside this module.
  • @st.cache_data(ttl=60) caches each call for 60 s, shared across sessions.
    The user can force-refresh via the UI "Refresh" button which calls
    st.cache_data.clear() for the relevant functions.
  • Routes use the OpenShift CustomObjectsApi (group=route.openshift.io/v1).
    On vanilla Kubernetes the call returns an empty list gracefully.
"""
from __future__ import annotations

import logging
import os
from typing import Any

import streamlit as st
from kubernetes import client as k8s_client
from kubernetes.client.exceptions import ApiException

from k8s import fixtures as _fix

logger = logging.getLogger(__name__)

_TEST_MODE = os.getenv("TEST_MODE", "false").lower() == "true"

# Labels injected by controllers – they identify a *single replica*, not the workload.
# Stripped when building podSelector so the selector matches the whole Deployment/SS.
EXCLUDED_LABEL_KEYS: frozenset[str] = frozenset(
    {
        "pod-template-hash",
        "controller-revision-hash",
        "statefulset.kubernetes.io/pod-name",
        "deployment.kubernetes.io/revision",
        "apps.kubernetes.io/pod-index",
    }
)


# ── Label helpers ────────────────────────────────────────────────────────────

def extract_workload_labels(pod_labels: dict[str, str]) -> dict[str, str]:
    """Remove controller-injected ephemeral labels; return workload-stable labels."""
    return {k: v for k, v in pod_labels.items() if k not in EXCLUDED_LABEL_KEYS}


def _safe_labels(labels: dict | None) -> dict[str, str]:
    return labels or {}


# ── Namespaces ────────────────────────────────────────────────────────────────

@st.cache_data(ttl=60, show_spinner=False)
def list_namespaces(_api_client: k8s_client.ApiClient) -> list[str]:
    """Return sorted list of namespace names visible to the ServiceAccount."""
    if _TEST_MODE:
        return _fix.get_namespaces()
    core = k8s_client.CoreV1Api(_api_client)
    ns_list = core.list_namespace(_request_timeout=10)
    return sorted(ns.metadata.name for ns in ns_list.items)


@st.cache_data(ttl=60, show_spinner=False)
def get_namespace_labels(
    _api_client: k8s_client.ApiClient, namespace: str
) -> dict[str, str]:
    """
    Return all labels on the namespace object.
    kubernetes.io/metadata.name is always present on K8s >= 1.21 and is the
    canonical way to select a specific namespace in namespaceSelector.
    """
    if _TEST_MODE:
        return _fix.get_namespace_labels(namespace)
    core = k8s_client.CoreV1Api(_api_client)
    ns = core.read_namespace(namespace, _request_timeout=10)
    labels = _safe_labels(ns.metadata.labels)
    # Guarantee the metadata.name label is present even on older clusters
    labels.setdefault("kubernetes.io/metadata.name", namespace)
    return labels


@st.cache_data(ttl=60, show_spinner=False)
def get_all_namespace_labels(
    _api_client: k8s_client.ApiClient,
) -> dict[str, dict[str, str]]:
    """Return {namespace_name: {label_key: label_value}} for all visible namespaces."""
    if _TEST_MODE:
        return _fix.get_all_namespace_labels()
    core = k8s_client.CoreV1Api(_api_client)
    ns_list = core.list_namespace(_request_timeout=10)
    result: dict[str, dict[str, str]] = {}
    for ns in ns_list.items:
        labels = _safe_labels(ns.metadata.labels)
        labels.setdefault("kubernetes.io/metadata.name", ns.metadata.name)
        result[ns.metadata.name] = labels
    return result


# ── Pods ──────────────────────────────────────────────────────────────────────

@st.cache_data(ttl=60, show_spinner=False)
def list_all_pods(_api_client: k8s_client.ApiClient) -> list[dict[str, Any]]:
    """Return pod metadata for all running/pending pods across all namespaces."""
    if _TEST_MODE:
        return _fix.get_all_pods()
    core = k8s_client.CoreV1Api(_api_client)
    pod_list = core.list_pod_for_all_namespaces(_request_timeout=10)
    result = []
    for pod in pod_list.items:
        labels = _safe_labels(pod.metadata.labels)
        result.append({
            "name": pod.metadata.name,
            "namespace": pod.metadata.namespace,
            "labels": labels,
            "workload_labels": extract_workload_labels(labels),
            "phase": (pod.status.phase or "Unknown") if pod.status else "Unknown",
        })
    return result


@st.cache_data(ttl=60, show_spinner=False)
def list_pods_in_namespace(
    _api_client: k8s_client.ApiClient, namespace: str
) -> list[dict[str, Any]]:
    """
    Return pod metadata for every running/pending pod in the namespace.
    Each dict:  { name, namespace, labels, workload_labels }
    workload_labels has controller-injected keys stripped – safe for podSelector.
    """
    if _TEST_MODE:
        return _fix.get_pods(namespace)
    core = k8s_client.CoreV1Api(_api_client)
    pod_list = core.list_namespaced_pod(namespace, _request_timeout=10)
    result = []
    for pod in pod_list.items:
        labels = _safe_labels(pod.metadata.labels)
        result.append(
            {
                "name": pod.metadata.name,
                "namespace": pod.metadata.namespace,
                "labels": labels,
                "workload_labels": extract_workload_labels(labels),
                "phase": (pod.status.phase or "Unknown") if pod.status else "Unknown",
            }
        )
    return result


# ── Services ──────────────────────────────────────────────────────────────────

@st.cache_data(ttl=60, show_spinner=False)
def list_services_in_namespace(
    _api_client: k8s_client.ApiClient, namespace: str
) -> list[dict[str, Any]]:
    """
    Return service metadata.  The `selector` field maps to pods and is useful
    for pre-populating the target pod selector from a chosen Service.
    """
    if _TEST_MODE:
        return _fix.get_services(namespace)
    core = k8s_client.CoreV1Api(_api_client)
    svc_list = core.list_namespaced_service(namespace, _request_timeout=10)
    result = []
    for svc in svc_list.items:
        ports = []
        for p in svc.spec.ports or []:
            ports.append(
                {
                    "port": p.port,
                    "protocol": p.protocol or "TCP",
                    "target_port": str(p.target_port) if p.target_port else "",
                    "name": p.name or "",
                }
            )
        result.append(
            {
                "name": svc.metadata.name,
                "namespace": svc.metadata.namespace,
                "labels": _safe_labels(svc.metadata.labels),
                "selector": _safe_labels(svc.spec.selector),
                "ports": ports,
                "type": svc.spec.type or "ClusterIP",
            }
        )
    return result


# ── OpenShift Routes ──────────────────────────────────────────────────────────

@st.cache_data(ttl=60, show_spinner=False)
def list_routes_in_namespace(
    _api_client: k8s_client.ApiClient, namespace: str
) -> list[dict[str, Any]]:
    """
    Fetch OpenShift Route objects via CustomObjectsApi.
    Returns an empty list on vanilla Kubernetes (404 / no CRD) without raising.
    """
    if _TEST_MODE:
        return _fix.get_routes(namespace)
    custom = k8s_client.CustomObjectsApi(_api_client)
    try:
        response = custom.list_namespaced_custom_object(
            group="route.openshift.io",
            version="v1",
            namespace=namespace,
            plural="routes",
            _request_timeout=10,
        )
    except ApiException as exc:
        if exc.status in (404, 403):
            # Not an OpenShift cluster, or ServiceAccount lacks access to Routes
            logger.info("Routes unavailable in %s (status=%s)", namespace, exc.status)
            return []
        raise

    result = []
    for route in response.get("items", []):
        meta = route.get("metadata", {})
        spec = route.get("spec", {})
        result.append(
            {
                "name": meta.get("name", ""),
                "namespace": meta.get("namespace", namespace),
                "host": spec.get("host", ""),
                "path": spec.get("path", "/"),
                "to": spec.get("to", {}),
                "labels": meta.get("labels", {}),
                "tls": bool(spec.get("tls")),
            }
        )
    return result


# ── Network Policy List ───────────────────────────────────────────────────────

@st.cache_data(ttl=60, show_spinner=False)
def list_network_policies(_api_client: k8s_client.ApiClient) -> list[dict[str, Any]]:
    """Return all NetworkPolicy objects across all namespaces as plain dicts."""
    if _TEST_MODE or _api_client is None:
        return _fix.get_network_policies()
    networking = k8s_client.NetworkingV1Api(_api_client)
    raw = networking.list_network_policy_for_all_namespaces(_request_timeout=10)
    # Convert K8s model objects to plain dicts via the API client serializer
    from kubernetes.client import ApiClient
    temp_client = ApiClient()
    result = []
    for pol in raw.items:
        d = temp_client.sanitize_for_serialization(pol)
        result.append(d)
    return result


@st.cache_data(ttl=60, show_spinner=False)
def list_admin_network_policies(_api_client) -> list[dict[str, Any]]:
    """Return AdminNetworkPolicy objects (cluster-scoped). Empty list if unavailable."""
    if _TEST_MODE or _api_client is None:
        return _fix.get_admin_network_policies()
    custom = k8s_client.CustomObjectsApi(_api_client)
    try:
        result = custom.list_cluster_custom_object(
            group="policy.networking.k8s.io", version="v1alpha1",
            plural="adminnetworkpolicies", _request_timeout=10,
        )
        return sorted(result.get("items", []), key=lambda x: x.get("spec", {}).get("priority", 0))
    except ApiException as exc:
        if exc.status in (404, 403):
            return []
        raise


@st.cache_data(ttl=60, show_spinner=False)
def list_baseline_admin_network_policy(_api_client) -> dict[str, Any] | None:
    """Return the single BaselineAdminNetworkPolicy spec, or None."""
    if _TEST_MODE or _api_client is None:
        return _fix.get_baseline_admin_network_policy()
    custom = k8s_client.CustomObjectsApi(_api_client)
    try:
        result = custom.list_cluster_custom_object(
            group="policy.networking.k8s.io", version="v1alpha1",
            plural="baselineadminnetworkpolicies", _request_timeout=10,
        )
        items = result.get("items", [])
        return items[0] if items else None
    except ApiException as exc:
        if exc.status in (404, 403):
            return None
        raise


@st.cache_data(ttl=60, show_spinner=False)
def list_all_routes(_api_client) -> list[dict[str, Any]]:
    """Return all routes across all namespaces."""
    if _TEST_MODE or _api_client is None:
        routes = []
        for ns in _fix.get_namespaces():
            routes.extend(_fix.get_routes(ns))
        return routes
    custom = k8s_client.CustomObjectsApi(_api_client)
    try:
        response = custom.list_cluster_custom_object(
            group="route.openshift.io", version="v1", plural="routes",
            _request_timeout=10,
        )
    except ApiException as exc:
        if exc.status in (404, 403):
            return []
        raise
    result = []
    for route in response.get("items", []):
        meta = route.get("metadata", {})
        spec = route.get("spec", {})
        result.append({
            "name": meta.get("name", ""),
            "namespace": meta.get("namespace", ""),
            "host": spec.get("host", ""),
            "path": spec.get("path", "/"),
            "to": spec.get("to", {}),
            "labels": meta.get("labels", {}),
            "tls": bool(spec.get("tls")),
        })
    return result


@st.cache_data(ttl=60, show_spinner=False)
def list_all_services(_api_client) -> list[dict[str, Any]]:
    """Return all services across all namespaces."""
    if _TEST_MODE or _api_client is None:
        svcs = []
        for ns in _fix.get_namespaces():
            svcs.extend(_fix.get_services(ns))
        return svcs
    core = k8s_client.CoreV1Api(_api_client)
    svc_list = core.list_service_for_all_namespaces(_request_timeout=10)
    result = []
    for svc in svc_list.items:
        ports = []
        for p in svc.spec.ports or []:
            ports.append({
                "port": p.port,
                "protocol": p.protocol or "TCP",
                "target_port": str(p.target_port) if p.target_port else "",
                "name": p.name or "",
            })
        result.append({
            "name": svc.metadata.name,
            "namespace": svc.metadata.namespace,
            "labels": _safe_labels(svc.metadata.labels),
            "selector": _safe_labels(svc.spec.selector),
            "ports": ports,
            "type": svc.spec.type or "ClusterIP",
        })
    return result


# ── Network Policy Apply ──────────────────────────────────────────────────────

def apply_network_policy(
    api_client: k8s_client.ApiClient, policy_dict: dict
) -> dict[str, str]:
    """
    Create or replace (server-side upsert) a NetworkPolicy.
    Returns { "action": "created"|"replaced", "name": "<name>", "namespace": "<ns>" }

    Raises ApiException on permission errors so the caller can surface them in the UI.
    In TEST_MODE simulates a successful create without touching any cluster.
    """
    namespace = policy_dict["metadata"]["namespace"]
    name = policy_dict["metadata"]["name"]
    if _TEST_MODE:
        return {"action": "created (simulated)", "name": name, "namespace": namespace}
    networking = k8s_client.NetworkingV1Api(api_client)
    namespace = policy_dict["metadata"]["namespace"]
    name = policy_dict["metadata"]["name"]

    try:
        networking.read_namespaced_network_policy(name, namespace, _request_timeout=10)
        networking.replace_namespaced_network_policy(
            name, namespace, body=policy_dict, _request_timeout=10
        )
        return {"action": "replaced", "name": name, "namespace": namespace}
    except ApiException as exc:
        if exc.status == 404:
            networking.create_namespaced_network_policy(
                namespace, body=policy_dict, _request_timeout=10
            )
            return {"action": "created", "name": name, "namespace": namespace}
        raise
