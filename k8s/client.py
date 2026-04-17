"""
Kubernetes / OpenShift API client factory.

Supports two modes controlled by K8S_IN_CLUSTER:
  • True  → load_incluster_config()  (Pod with mounted ServiceAccount token)
  • False → load_kube_config()       (developer workstation, respects KUBECONFIG)

The returned ApiClient is lightweight; callers create typed API stubs from it
(CoreV1Api, NetworkingV1Api, CustomObjectsApi) on demand.  Those stubs share the
underlying urllib3 connection pool and are safe to use concurrently.
"""
from kubernetes import client as k8s_client
from kubernetes import config as k8s_config

import streamlit as st

from config import AppConfig


@st.cache_resource(show_spinner=False)
def get_api_client(
    in_cluster: bool,
    api_server: str = "",
    ca_cert_path: str = "",
) -> k8s_client.ApiClient:
    """
    Build and return a shared ApiClient (cached for the lifetime of the process).
    Uses @st.cache_resource so a single connection pool is reused across Streamlit
    sessions rather than opening a new TCP connection per user request.
    """
    if in_cluster:
        k8s_config.load_incluster_config()
    else:
        k8s_config.load_kube_config()

    configuration = k8s_client.Configuration.get_default_copy()

    if api_server:
        configuration.host = api_server
    if ca_cert_path:
        configuration.ssl_ca_cert = ca_cert_path
        configuration.verify_ssl = True

    configuration.assert_hostname = True

    return k8s_client.ApiClient(configuration=configuration)


def build_api_client_from_config(config: AppConfig) -> k8s_client.ApiClient:
    return get_api_client(
        in_cluster=config.k8s_in_cluster,
        api_server=config.k8s_api_server,
        ca_cert_path=config.k8s_ca_cert_path,
    )
