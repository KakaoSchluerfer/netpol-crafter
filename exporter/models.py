from __future__ import annotations
from typing import Any, Optional
from pydantic import BaseModel


class ServicePortModel(BaseModel):
    port: int
    protocol: str = "TCP"
    target_port: str = ""
    name: str = ""


class NamespaceModel(BaseModel):
    name: str
    labels: dict[str, str] = {}


class PodModel(BaseModel):
    name: str
    namespace: str
    labels: dict[str, str] = {}
    workload_labels: dict[str, str] = {}
    phase: str = "Unknown"


class ServiceModel(BaseModel):
    name: str
    namespace: str
    labels: dict[str, str] = {}
    selector: dict[str, str] = {}
    ports: list[ServicePortModel] = []
    type: str = "ClusterIP"


class RouteModel(BaseModel):
    name: str
    namespace: str
    host: str = ""
    path: str = "/"
    to: dict[str, Any] = {}
    labels: dict[str, str] = {}
    tls: bool = False


class NetworkPolicyModel(BaseModel):
    name: str
    namespace: str
    spec: dict[str, Any] = {}


class AdminNetworkPolicyModel(BaseModel):
    name: str
    priority: int = 0
    spec: dict[str, Any] = {}


class ClusterSnapshot(BaseModel):
    cluster_name: str
    namespaces: list[NamespaceModel] = []
    pods: list[PodModel] = []
    services: list[ServiceModel] = []
    routes: list[RouteModel] = []
    network_policies: list[NetworkPolicyModel] = []
    admin_network_policies: list[AdminNetworkPolicyModel] = []
    baseline_admin_network_policy: Optional[dict[str, Any]] = None
