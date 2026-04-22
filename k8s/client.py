"""
Kubernetes API client factory.

build_user_token_client() — used by the Network Policy Map to make API calls
    on behalf of the logged-in user (respects their RBAC).

get_cluster_client() — used when a full cluster config dict is available.

TLS: set ssl_ca_cert to the path of your cluster CA bundle.
     verify_ssl is always True — never disable TLS verification in production.
"""
from __future__ import annotations

import logging
import os
from typing import Any, Optional

import streamlit as st
from kubernetes import client as k8s_client
from kubernetes import config as k8s_config

logger = logging.getLogger(__name__)


@st.cache_resource(show_spinner=False)
def _cached_client(
    cache_key: str,
    api_server: str,
    token: str,
    ca_cert_path: str,
    in_cluster: bool,
) -> k8s_client.ApiClient:
    """One cached ApiClient per unique (api_server, token-prefix) combination."""
    if in_cluster:
        logger.debug("Loading in-cluster kubeconfig")
        k8s_config.load_incluster_config()
        cfg = k8s_client.Configuration.get_default_copy()
    else:
        cfg = k8s_client.Configuration()
        cfg.host = api_server
        cfg.verify_ssl = True
        if token:
            cfg.api_key["authorization"] = token
            cfg.api_key_prefix["authorization"] = "Bearer"
        if ca_cert_path:
            cfg.ssl_ca_cert = ca_cert_path
            logger.debug("Using custom CA bundle: %s", ca_cert_path)
        else:
            logger.debug("Using system CAs for %s", api_server)
    return k8s_client.ApiClient(configuration=cfg)


def build_user_token_client(access_token: str, config: Any) -> Optional[k8s_client.ApiClient]:
    """Build an ApiClient authenticated with the user's OCP OAuth access token."""
    if os.getenv("TEST_MODE", "false").lower() == "true":
        return None
    # Use only the first 16 chars of the token as a cache key — never log the full token.
    cache_key = f"user_{access_token[:16]}"
    return _cached_client(
        cache_key=cache_key,
        api_server=config.ocp_api_server,
        token=access_token,
        ca_cert_path=config.ocp_ca_cert_path,
        in_cluster=False,
    )


def get_cluster_client(cluster: dict[str, Any]) -> Optional[k8s_client.ApiClient]:
    """Build a cached ApiClient from a cluster config dict. Returns None in TEST_MODE."""
    if os.getenv("TEST_MODE", "false").lower() == "true":
        return None
    cache_key = f"cluster_{cluster['name']}"
    return _cached_client(
        cache_key=cache_key,
        api_server=cluster.get("api_server", ""),
        token=cluster.get("token", ""),
        ca_cert_path=cluster.get("ca_cert_path", ""),
        in_cluster=cluster.get("in_cluster", False),
    )
