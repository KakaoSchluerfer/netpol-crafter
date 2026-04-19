"""
Shared cluster-selector sidebar widget.

Usage:
    from ui.cluster_selector import render_cluster_selector

    cluster, api_client = render_cluster_selector(config.clusters)
    if cluster is None:
        st.stop()
"""
from __future__ import annotations

from typing import Any, Optional

import streamlit as st

from k8s.client import get_cluster_client


def render_cluster_selector(
    clusters: tuple | list,
    session_key: str = "selected_cluster",
) -> tuple[Optional[dict], Any]:
    """
    Render a cluster selectbox in the sidebar and return (cluster_dict, api_client).

    - When only one cluster is configured the selectbox is hidden and that cluster
      is used automatically (no unnecessary noise in the UI).
    - The selection is persisted in st.session_state[session_key] across reruns.
    - Returns (None, None) if clusters list is empty.
    """
    clusters = list(clusters)
    if not clusters:
        st.sidebar.error("No clusters configured. Set CLUSTERS_JSON in the environment.")
        return None, None

    if len(clusters) == 1:
        selected = clusters[0]
    else:
        display_names = [c.get("display_name") or c["name"] for c in clusters]
        by_display = {(c.get("display_name") or c["name"]): c for c in clusters}

        chosen = st.sidebar.selectbox(
            "Cluster",
            options=display_names,
            key=session_key,
            help="Select which OpenShift/Kubernetes cluster to inspect.",
        )
        selected = by_display[chosen]

    client = get_cluster_client(selected)
    return selected, client
