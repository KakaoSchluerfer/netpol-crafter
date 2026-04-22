"""
In-cluster data fetcher for the netpol-exporter.

Uses K8S_IN_CLUSTER env var (default "true") to decide incluster vs kubeconfig.
"""
from __future__ import annotations

import logging
import os
from typing import Any

from kubernetes import client as k8s_client
from kubernetes import config as k8s_config
from kubernetes.client.exceptions import ApiException

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
logger = logging.getLogger(__name__)

_EXCLUDED_LABEL_KEYS = frozenset({
    "pod-template-hash",
    "controller-revision-hash",
    "statefulset.kubernetes.io/pod-name",
    "deployment.kubernetes.io/revision",
    "apps.kubernetes.io/pod-index",
})


def _safe_labels(labels) -> dict:
    return labels or {}


def extract_workload_labels(labels: dict) -> dict:
    return {k: v for k, v in labels.items() if k not in _EXCLUDED_LABEL_KEYS}

_IN_CLUSTER = os.getenv("K8S_IN_CLUSTER", "true").lower() == "true"
_CLUSTER_NAME = os.getenv("CLUSTER_NAME", "default")


def _build_api_client() -> k8s_client.ApiClient:
    if _IN_CLUSTER:
        k8s_config.load_incluster_config()
        cfg = k8s_client.Configuration.get_default_copy()
    else:
        try:
            k8s_config.load_kube_config()
        except Exception:
            k8s_config.load_incluster_config()
        cfg = k8s_client.Configuration.get_default_copy()
    return k8s_client.ApiClient(configuration=cfg)


def _fetch_namespaces(core: k8s_client.CoreV1Api) -> list[NamespaceModel]:
    ns_list = core.list_namespace(_request_timeout=10)
    result = []
    for ns in ns_list.items:
        labels = _safe_labels(ns.metadata.labels)
        labels.setdefault("kubernetes.io/metadata.name", ns.metadata.name)
        result.append(NamespaceModel(name=ns.metadata.name, labels=labels))
    return result


def _fetch_pods(core: k8s_client.CoreV1Api) -> list[PodModel]:
    pod_list = core.list_pod_for_all_namespaces(_request_timeout=10)
    result = []
    for pod in pod_list.items:
        labels = _safe_labels(pod.metadata.labels)
        result.append(PodModel(
            name=pod.metadata.name,
            namespace=pod.metadata.namespace,
            labels=labels,
            workload_labels=extract_workload_labels(labels),
            phase=(pod.status.phase or "Unknown") if pod.status else "Unknown",
        ))
    return result


def _fetch_services(core: k8s_client.CoreV1Api) -> list[ServiceModel]:
    svc_list = core.list_service_for_all_namespaces(_request_timeout=10)
    result = []
    for svc in svc_list.items:
        ports = []
        for p in svc.spec.ports or []:
            ports.append(ServicePortModel(
                port=p.port,
                protocol=p.protocol or "TCP",
                target_port=str(p.target_port) if p.target_port else "",
                name=p.name or "",
            ))
        result.append(ServiceModel(
            name=svc.metadata.name,
            namespace=svc.metadata.namespace,
            labels=_safe_labels(svc.metadata.labels),
            selector=_safe_labels(svc.spec.selector),
            ports=ports,
            type=svc.spec.type or "ClusterIP",
        ))
    return result


def _fetch_routes(custom: k8s_client.CustomObjectsApi) -> list[RouteModel]:
    try:
        response = custom.list_cluster_custom_object(
            group="route.openshift.io", version="v1", plural="routes",
            _request_timeout=10,
        )
    except ApiException as exc:
        if exc.status in (404, 403):
            logger.info("Routes unavailable (status=%s) – not an OpenShift cluster?", exc.status)
            return []
        raise
    result = []
    for route in response.get("items", []):
        meta = route.get("metadata", {})
        spec = route.get("spec", {})
        result.append(RouteModel(
            name=meta.get("name", ""),
            namespace=meta.get("namespace", ""),
            host=spec.get("host", ""),
            path=spec.get("path", "/"),
            to=spec.get("to", {}),
            labels=meta.get("labels", {}),
            tls=bool(spec.get("tls")),
        ))
    return result


def _fetch_network_policies(networking: k8s_client.NetworkingV1Api) -> list[NetworkPolicyModel]:
    raw = networking.list_network_policy_for_all_namespaces(_request_timeout=10)
    from kubernetes.client import ApiClient as _ApiClient
    temp = _ApiClient()
    result = []
    for pol in raw.items:
        d = temp.sanitize_for_serialization(pol)
        meta = d.get("metadata", {})
        result.append(NetworkPolicyModel(
            name=meta.get("name", ""),
            namespace=meta.get("namespace", ""),
            spec=d.get("spec", {}),
        ))
    return result


def _fetch_anps(custom: k8s_client.CustomObjectsApi) -> list[AdminNetworkPolicyModel]:
    try:
        result = custom.list_cluster_custom_object(
            group="policy.networking.k8s.io", version="v1alpha1",
            plural="adminnetworkpolicies", _request_timeout=10,
        )
        items = sorted(result.get("items", []), key=lambda x: x.get("spec", {}).get("priority", 0))
        return [
            AdminNetworkPolicyModel(
                name=item.get("metadata", {}).get("name", ""),
                priority=item.get("spec", {}).get("priority", 0),
                spec=item.get("spec", {}),
            )
            for item in items
        ]
    except ApiException as exc:
        if exc.status in (404, 403):
            return []
        raise


def _fetch_banp(custom: k8s_client.CustomObjectsApi) -> dict[str, Any] | None:
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


def _build_fixture_snapshot() -> ClusterSnapshot:
    """Return a ClusterSnapshot built from fixture data (TEST_MODE)."""
    import sys, os as _os
    # Add repo root to path so k8s.fixtures is importable without Streamlit
    repo_root = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
    if repo_root not in sys.path:
        sys.path.insert(0, repo_root)
    import importlib.util as _ilu
    _spec = _ilu.spec_from_file_location("k8s_fixtures", _os.path.join(repo_root, "k8s", "fixtures.py"))
    _fix_mod = _ilu.module_from_spec(_spec)
    _spec.loader.exec_module(_fix_mod)
    _fix = _fix_mod

    ns_labels_map = _fix.get_all_namespace_labels()
    namespaces = [
        NamespaceModel(name=ns, labels=lbls)
        for ns, lbls in ns_labels_map.items()
    ]
    pods = []
    for p in _fix.get_all_pods():
        pods.append(PodModel(
            name=p["name"], namespace=p["namespace"],
            labels=p.get("labels", {}),
            workload_labels=p.get("workload_labels", {}),
            phase=p.get("phase", "Running"),
        ))
    services = []
    for ns in _fix.get_namespaces():
        for s in _fix.get_services(ns):
            ports = [ServicePortModel(**pt) for pt in s.get("ports", [])]
            services.append(ServiceModel(
                name=s["name"], namespace=s["namespace"],
                labels=s.get("labels", {}), selector=s.get("selector", {}),
                ports=ports, type=s.get("type", "ClusterIP"),
            ))
    routes = []
    for ns in _fix.get_namespaces():
        for r in _fix.get_routes(ns):
            routes.append(RouteModel(
                name=r["name"], namespace=r["namespace"],
                host=r.get("host", ""), path=r.get("path", "/"),
                to=r.get("to", {}), labels=r.get("labels", {}),
                tls=r.get("tls", False),
            ))
    network_policies = []
    for pol in _fix.get_network_policies():
        meta = pol.get("metadata", {})
        network_policies.append(NetworkPolicyModel(
            name=meta.get("name", ""), namespace=meta.get("namespace", ""),
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
        cluster_name=_CLUSTER_NAME,
        namespaces=namespaces, pods=pods, services=services,
        routes=routes, network_policies=network_policies,
        admin_network_policies=anps,
        baseline_admin_network_policy=_fix.get_baseline_admin_network_policy(),
    )


def build_snapshot() -> ClusterSnapshot:
    """Fetch all cluster data and return a ClusterSnapshot.

    All K8s API calls run in parallel via a thread pool so the total time is
    bounded by the slowest individual call rather than their sum.
    """
    if os.getenv("TEST_MODE", "false").lower() == "true":
        return _build_fixture_snapshot()

    from concurrent.futures import ThreadPoolExecutor

    api_client = _build_api_client()
    core = k8s_client.CoreV1Api(api_client)
    networking = k8s_client.NetworkingV1Api(api_client)
    custom = k8s_client.CustomObjectsApi(api_client)

    logger.info("Fetching cluster data in parallel")
    with ThreadPoolExecutor(max_workers=7) as pool:
        f_ns   = pool.submit(_fetch_namespaces, core)
        f_pods = pool.submit(_fetch_pods, core)
        f_svcs = pool.submit(_fetch_services, core)
        f_rts  = pool.submit(_fetch_routes, custom)
        f_nps  = pool.submit(_fetch_network_policies, networking)
        f_anps = pool.submit(_fetch_anps, custom)
        f_banp = pool.submit(_fetch_banp, custom)

    return ClusterSnapshot(
        cluster_name=_CLUSTER_NAME,
        namespaces=f_ns.result(),
        pods=f_pods.result(),
        services=f_svcs.result(),
        routes=f_rts.result(),
        network_policies=f_nps.result(),
        admin_network_policies=f_anps.result(),
        baseline_admin_network_policy=f_banp.result(),
    )
