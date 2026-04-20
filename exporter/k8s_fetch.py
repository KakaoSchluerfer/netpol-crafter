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
from k8s.resources import extract_workload_labels, _safe_labels

logger = logging.getLogger(__name__)

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


def build_snapshot() -> ClusterSnapshot:
    """Fetch all cluster data and return a ClusterSnapshot."""
    api_client = _build_api_client()
    core = k8s_client.CoreV1Api(api_client)
    networking = k8s_client.NetworkingV1Api(api_client)
    custom = k8s_client.CustomObjectsApi(api_client)

    namespaces = _fetch_namespaces(core)
    pods = _fetch_pods(core)
    services = _fetch_services(core)
    routes = _fetch_routes(custom)
    network_policies = _fetch_network_policies(networking)
    anps = _fetch_anps(custom)
    banp = _fetch_banp(custom)

    return ClusterSnapshot(
        cluster_name=_CLUSTER_NAME,
        namespaces=namespaces,
        pods=pods,
        services=services,
        routes=routes,
        network_policies=network_policies,
        admin_network_policies=anps,
        baseline_admin_network_policy=banp,
    )
