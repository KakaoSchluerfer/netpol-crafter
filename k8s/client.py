"""
Kubernetes / OpenShift API client factory.

In TEST_MODE every function returns None; resources.py falls through to fixtures.
"""
from __future__ import annotations

import os
from typing import Any, Optional

import streamlit as st
from kubernetes import client as k8s_client
from kubernetes import config as k8s_config


@st.cache_resource(show_spinner=False)
def _cached_cluster_client(
    name: str,
    api_server: str,
    token: str,
    ca_cert_path: str,
    in_cluster: bool,
) -> k8s_client.ApiClient:
    """One cached ApiClient per cluster (keyed by name)."""
    if in_cluster:
        k8s_config.load_incluster_config()
        cfg = k8s_client.Configuration.get_default_copy()
    else:
        cfg = k8s_client.Configuration()
        cfg.host = api_server
        if token:
            cfg.api_key["authorization"] = token
            cfg.api_key_prefix["authorization"] = "Bearer"
        if ca_cert_path:
            cfg.ssl_ca_cert = ca_cert_path
            cfg.verify_ssl = True
        else:
            cfg.verify_ssl = True  # trust system CAs when no custom bundle given
    return k8s_client.ApiClient(configuration=cfg)


def get_cluster_client(cluster: dict[str, Any]) -> Optional[k8s_client.ApiClient]:
    """Return a cached ApiClient for a cluster config dict. Returns None in TEST_MODE."""
    if os.getenv("TEST_MODE", "false").lower() == "true":
        return None
    return _cached_cluster_client(
        name=cluster["name"],
        api_server=cluster.get("api_server", ""),
        token=cluster.get("token", ""),
        ca_cert_path=cluster.get("ca_cert_path", ""),
        in_cluster=cluster.get("in_cluster", False),
    )


def build_user_token_client(access_token: str, config: Any) -> Optional[k8s_client.ApiClient]:
    """Build an ApiClient authenticated with the user's OCP OAuth access token."""
    if os.getenv("TEST_MODE", "false").lower() == "true":
        return None
    return _cached_cluster_client(
        name=f"__user_{access_token[:16]}",  # cache key, prefix only for privacy
        api_server=config.ocp_api_server,
        token=access_token,
        ca_cert_path=config.ocp_ca_cert_path,
        in_cluster=False,
    )


# ── Backward-compat helpers ───────────────────────────────────────────────────

def get_api_client(
    in_cluster: bool,
    api_server: str = "",
    ca_cert_path: str = "",
) -> k8s_client.ApiClient:
    """Legacy single-cluster helper (used by existing callers that pass explicit args)."""
    return _cached_cluster_client(
        name=f"__legacy_{api_server or 'in-cluster'}",
        api_server=api_server,
        token="",
        ca_cert_path=ca_cert_path,
        in_cluster=in_cluster,
    )


def build_api_client_from_config(config: Any) -> Optional[k8s_client.ApiClient]:
    """
    Backward-compat stub. The crafter now uses the exporter REST API;
    this function is kept to avoid import errors in older callers.
    """
    return None
