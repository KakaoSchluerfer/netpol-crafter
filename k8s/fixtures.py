"""
Realistic banking-context fixture data for TEST_MODE.

Simulates a mid-size bank's OpenShift cluster with the following namespaces:
  payments          – PCI-DSS scoped payment rails
  fraud-detection   – real-time ML fraud scoring
  account-services  – customer account management
  api-gateway       – edge routing & rate limiting
  monitoring        – Prometheus / Grafana / Alertmanager
  infra             – Vault, cert-manager, external-secrets
  staging           – pre-production mirror of payments + account-services

Each namespace has labels, pods (with realistic workload labels), services
(with selectors matching those pods), and OpenShift Routes where applicable.
"""
from __future__ import annotations
from typing import Any

# ── Namespaces ────────────────────────────────────────────────────────────────

NAMESPACES: list[str] = [
    "payments",
    "fraud-detection",
    "account-services",
    "api-gateway",
    "monitoring",
    "infra",
    "staging",
]

NAMESPACE_LABELS: dict[str, dict[str, str]] = {
    "payments": {
        "kubernetes.io/metadata.name": "payments",
        "environment": "production",
        "team": "core-banking",
        "compliance": "pci-dss",
        "cost-centre": "payments-ops",
    },
    "fraud-detection": {
        "kubernetes.io/metadata.name": "fraud-detection",
        "environment": "production",
        "team": "risk-engineering",
        "compliance": "pci-dss",
    },
    "account-services": {
        "kubernetes.io/metadata.name": "account-services",
        "environment": "production",
        "team": "core-banking",
    },
    "api-gateway": {
        "kubernetes.io/metadata.name": "api-gateway",
        "environment": "production",
        "team": "platform",
    },
    "monitoring": {
        "kubernetes.io/metadata.name": "monitoring",
        "environment": "production",
        "team": "platform",
    },
    "infra": {
        "kubernetes.io/metadata.name": "infra",
        "environment": "production",
        "team": "platform",
    },
    "staging": {
        "kubernetes.io/metadata.name": "staging",
        "environment": "staging",
        "team": "core-banking",
    },
}

# ── Pods ──────────────────────────────────────────────────────────────────────

def _pod(
    name: str,
    namespace: str,
    workload_labels: dict[str, str],
    extra_labels: dict[str, str] | None = None,
    phase: str = "Running",
) -> dict[str, Any]:
    labels = {**workload_labels, **(extra_labels or {})}
    return {
        "name": name,
        "namespace": namespace,
        "labels": labels,
        "workload_labels": workload_labels,
        "phase": phase,
    }


PODS: dict[str, list[dict[str, Any]]] = {
    "payments": [
        _pod("payment-api-7d8b9c4f6-xk2p4", "payments",
             {"app": "payment-api", "version": "v2.4.1", "tier": "api"},
             {"pod-template-hash": "7d8b9c4f6"}),
        _pod("payment-api-7d8b9c4f6-rn8wz", "payments",
             {"app": "payment-api", "version": "v2.4.1", "tier": "api"},
             {"pod-template-hash": "7d8b9c4f6"}),
        _pod("payment-processor-6b8f9d5c7-mnp2q", "payments",
             {"app": "payment-processor", "version": "v1.9.0", "tier": "worker"},
             {"pod-template-hash": "6b8f9d5c7"}),
        _pod("payment-db-0", "payments",
             {"app": "payment-db", "tier": "database"},
             {"statefulset.kubernetes.io/pod-name": "payment-db-0"}),
        _pod("payment-db-1", "payments",
             {"app": "payment-db", "tier": "database"},
             {"statefulset.kubernetes.io/pod-name": "payment-db-1"}),
    ],
    "fraud-detection": [
        _pod("fraud-scorer-5c9d8e6f7-abc12", "fraud-detection",
             {"app": "fraud-scorer", "model-version": "v3.2", "tier": "inference"},
             {"pod-template-hash": "5c9d8e6f7"}),
        _pod("fraud-scorer-5c9d8e6f7-def34", "fraud-detection",
             {"app": "fraud-scorer", "model-version": "v3.2", "tier": "inference"},
             {"pod-template-hash": "5c9d8e6f7"}),
        _pod("fraud-api-6f8c7d9e0-xyz89", "fraud-detection",
             {"app": "fraud-api", "version": "v1.3.0", "tier": "api"},
             {"pod-template-hash": "6f8c7d9e0"}),
        _pod("feature-store-7a9b8c0d1-uvw56", "fraud-detection",
             {"app": "feature-store", "version": "v0.8.1", "tier": "data"},
             {"pod-template-hash": "7a9b8c0d1"}),
    ],
    "account-services": [
        _pod("account-api-4b7c9f8e5-pqr34", "account-services",
             {"app": "account-api", "version": "v3.1.2", "tier": "api"},
             {"pod-template-hash": "4b7c9f8e5"}),
        _pod("account-api-4b7c9f8e5-stu67", "account-services",
             {"app": "account-api", "version": "v3.1.2", "tier": "api"},
             {"pod-template-hash": "4b7c9f8e5"}),
        _pod("account-db-0", "account-services",
             {"app": "account-db", "tier": "database"},
             {"statefulset.kubernetes.io/pod-name": "account-db-0"}),
        _pod("notification-worker-3c6d8f9a2-lmn90", "account-services",
             {"app": "notification-worker", "version": "v1.0.4", "tier": "worker"},
             {"pod-template-hash": "3c6d8f9a2"}),
    ],
    "api-gateway": [
        _pod("gateway-7a8b9c0d1-lmn56", "api-gateway",
             {"app": "gateway", "version": "v4.2.0", "tier": "edge"},
             {"pod-template-hash": "7a8b9c0d1"}),
        _pod("gateway-7a8b9c0d1-opq78", "api-gateway",
             {"app": "gateway", "version": "v4.2.0", "tier": "edge"},
             {"pod-template-hash": "7a8b9c0d1"}),
        _pod("rate-limiter-8b9c0d1e2-rst90", "api-gateway",
             {"app": "rate-limiter", "version": "v2.0.1", "tier": "edge"},
             {"pod-template-hash": "8b9c0d1e2"}),
    ],
    "monitoring": [
        _pod("prometheus-0", "monitoring",
             {"app": "prometheus", "tier": "metrics"}),
        _pod("grafana-6d9f8c7b0-abc23", "monitoring",
             {"app": "grafana", "version": "v10.2.0", "tier": "dashboard"},
             {"pod-template-hash": "6d9f8c7b0"}),
        _pod("alertmanager-0", "monitoring",
             {"app": "alertmanager", "tier": "alerting"}),
    ],
    "infra": [
        _pod("vault-0", "infra",
             {"app": "vault", "tier": "secrets"}),
        _pod("vault-1", "infra",
             {"app": "vault", "tier": "secrets"}),
        _pod("cert-manager-5e8f9a0b3-def45", "infra",
             {"app": "cert-manager", "version": "v1.14.0"},
             {"pod-template-hash": "5e8f9a0b3"}),
        _pod("external-secrets-4d7e8f9b2-ghi67", "infra",
             {"app": "external-secrets", "version": "v0.9.11"},
             {"pod-template-hash": "4d7e8f9b2"}),
    ],
    "staging": [
        _pod("payment-api-9e0f1a2b3-jkl89", "staging",
             {"app": "payment-api", "version": "v2.5.0-rc1", "tier": "api", "environment": "staging"},
             {"pod-template-hash": "9e0f1a2b3"}),
        _pod("account-api-8d9e0f1a2-mno12", "staging",
             {"app": "account-api", "version": "v3.2.0-rc1", "tier": "api", "environment": "staging"},
             {"pod-template-hash": "8d9e0f1a2"}),
    ],
}

# ── Services ──────────────────────────────────────────────────────────────────

def _svc(
    name: str,
    namespace: str,
    selector: dict[str, str],
    ports: list[tuple[int, str, str]],  # (port, protocol, name)
    svc_type: str = "ClusterIP",
    labels: dict[str, str] | None = None,
) -> dict[str, Any]:
    return {
        "name": name,
        "namespace": namespace,
        "labels": labels or {"app": name},
        "selector": selector,
        "ports": [{"port": p, "protocol": proto, "target_port": str(p), "name": n}
                  for p, proto, n in ports],
        "type": svc_type,
    }


SERVICES: dict[str, list[dict[str, Any]]] = {
    "payments": [
        _svc("payment-api",       "payments", {"app": "payment-api"},
             [(8080, "TCP", "http"), (8443, "TCP", "https")]),
        _svc("payment-processor", "payments", {"app": "payment-processor"},
             [(9090, "TCP", "grpc")]),
        _svc("payment-db",        "payments", {"app": "payment-db"},
             [(5432, "TCP", "postgres")]),
    ],
    "fraud-detection": [
        _svc("fraud-api",     "fraud-detection", {"app": "fraud-api"},
             [(8080, "TCP", "http")]),
        _svc("fraud-scorer",  "fraud-detection", {"app": "fraud-scorer"},
             [(50051, "TCP", "grpc")]),
        _svc("feature-store", "fraud-detection", {"app": "feature-store"},
             [(6379, "TCP", "redis")]),
    ],
    "account-services": [
        _svc("account-api",          "account-services", {"app": "account-api"},
             [(8080, "TCP", "http")]),
        _svc("account-db",           "account-services", {"app": "account-db"},
             [(5432, "TCP", "postgres")]),
        _svc("notification-worker",  "account-services", {"app": "notification-worker"},
             [(8080, "TCP", "http")]),
    ],
    "api-gateway": [
        _svc("gateway",      "api-gateway", {"app": "gateway"},
             [(80, "TCP", "http"), (443, "TCP", "https")], svc_type="LoadBalancer"),
        _svc("rate-limiter", "api-gateway", {"app": "rate-limiter"},
             [(8081, "TCP", "http")]),
    ],
    "monitoring": [
        _svc("prometheus",    "monitoring", {"app": "prometheus"},    [(9090, "TCP", "http")]),
        _svc("grafana",       "monitoring", {"app": "grafana"},       [(3000, "TCP", "http")]),
        _svc("alertmanager",  "monitoring", {"app": "alertmanager"},  [(9093, "TCP", "http")]),
    ],
    "infra": [
        _svc("vault", "infra", {"app": "vault"},
             [(8200, "TCP", "http"), (8201, "TCP", "cluster")]),
        _svc("cert-manager", "infra", {"app": "cert-manager"}, [(9402, "TCP", "metrics")]),
    ],
    "staging": [
        _svc("payment-api",  "staging", {"app": "payment-api"},  [(8080, "TCP", "http")]),
        _svc("account-api",  "staging", {"app": "account-api"},  [(8080, "TCP", "http")]),
    ],
}

# ── OpenShift Routes ──────────────────────────────────────────────────────────

ROUTES: dict[str, list[dict[str, Any]]] = {
    "payments": [
        {
            "name": "payment-api",
            "namespace": "payments",
            "host": "payments.apps.ocp.bank.internal",
            "path": "/",
            "to": {"kind": "Service", "name": "payment-api"},
            "labels": {"app": "payment-api"},
            "tls": True,
        },
    ],
    "api-gateway": [
        {
            "name": "gateway-public",
            "namespace": "api-gateway",
            "host": "api.bank.internal",
            "path": "/",
            "to": {"kind": "Service", "name": "gateway"},
            "labels": {"app": "gateway"},
            "tls": True,
        },
    ],
    "monitoring": [
        {
            "name": "grafana",
            "namespace": "monitoring",
            "host": "grafana.apps.ocp.bank.internal",
            "path": "/",
            "to": {"kind": "Service", "name": "grafana"},
            "labels": {"app": "grafana"},
            "tls": True,
        },
    ],
    "staging": [
        {
            "name": "payment-api-staging",
            "namespace": "staging",
            "host": "payments-staging.apps.ocp.bank.internal",
            "path": "/",
            "to": {"kind": "Service", "name": "payment-api"},
            "labels": {"app": "payment-api"},
            "tls": True,
        },
    ],
}


# ── Public accessors (match the signature of the real resource functions) ─────

def get_namespaces() -> list[str]:
    return list(NAMESPACES)


def get_namespace_labels(namespace: str) -> dict[str, str]:
    return dict(NAMESPACE_LABELS.get(namespace, {
        "kubernetes.io/metadata.name": namespace,
    }))


def get_pods(namespace: str) -> list[dict[str, Any]]:
    return list(PODS.get(namespace, []))


def get_services(namespace: str) -> list[dict[str, Any]]:
    return list(SERVICES.get(namespace, []))


def get_routes(namespace: str) -> list[dict[str, Any]]:
    return list(ROUTES.get(namespace, []))
