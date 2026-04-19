"""
Central configuration – reads from environment variables (or .env via python-dotenv).
All required variables raise KeyError on startup if absent; no silent defaults for secrets.
"""
import json
import os
from dataclasses import dataclass, field
from typing import Any

from dotenv import load_dotenv

load_dotenv()


@dataclass(frozen=True)
class AppConfig:
    # ── OIDC ─────────────────────────────────────────────────────────────────
    oidc_client_id: str
    oidc_client_secret: str
    azure_tenant_id: str
    oidc_redirect_uri: str
    oidc_scopes: str

    # ── Kubernetes – multi-cluster ────────────────────────────────────────────
    # Each dict: {name, display_name?, api_server, token, ca_cert_path, in_cluster?}
    # Populated from CLUSTERS_JSON env var, or synthesised from legacy K8S_* vars.
    clusters: tuple  # tuple[dict[str, Any], ...] (frozen-dataclass-safe)

    # ── GitHub ────────────────────────────────────────────────────────────────
    # Option A – GitHub App (recommended for production)
    github_app_id: str            # numeric App ID as string
    github_app_private_key: str   # PEM content (newlines preserved)
    github_app_installation_id: str
    # Option B – Personal Access Token (dev / small teams)
    github_token: str
    # Repo config
    github_repo: str              # "org/repo-name"
    github_base_branch: str       # target branch for PRs, default "main"
    github_policies_path: str     # path prefix inside repo, default "policies"

    # ── App ───────────────────────────────────────────────────────────────────
    app_secret_key: str
    debug: bool
    test_mode: bool

    @property
    def oidc_authority(self) -> str:
        return f"https://login.microsoftonline.com/{self.azure_tenant_id}/v2.0"

    @property
    def oidc_discovery_url(self) -> str:
        return f"{self.oidc_authority}/.well-known/openid-configuration"

    @property
    def github_configured(self) -> bool:
        has_app = bool(self.github_app_id and self.github_app_private_key and self.github_app_installation_id)
        return bool(self.github_repo) and (has_app or bool(self.github_token))


def _read_github_private_key() -> str:
    """
    Read the GitHub App private key from a file path or inline env var.
    Inline values may use literal '\\n' for newlines (common in CI secrets).
    """
    key_path = os.getenv("GITHUB_APP_PRIVATE_KEY_PATH", "")
    if key_path:
        with open(key_path) as fh:
            return fh.read()
    raw = os.getenv("GITHUB_APP_PRIVATE_KEY", "")
    # Replace escaped newlines written by some secret managers
    return raw.replace("\\n", "\n")


def _parse_clusters() -> tuple:
    """
    Build the clusters tuple from env vars.

    Priority:
      1. CLUSTERS_JSON  – full multi-cluster JSON array (production)
      2. Legacy K8S_* vars – synthesised as a single cluster named by K8S_CLUSTER_NAME
         (backward-compatible with existing single-cluster deployments)

    Each cluster dict:
      name         – unique identifier used as a cache key
      display_name – label shown in the UI (defaults to name)
      api_server   – https://api.cluster.example.com:6443
      token        – SA bearer token (leave empty if in_cluster=true)
      ca_cert_path – path to a PEM CA bundle (mounted as a secret volume)
      in_cluster   – true to use the pod's own mounted ServiceAccount token
    """
    raw_json = os.getenv("CLUSTERS_JSON", "").strip()
    if raw_json:
        clusters = json.loads(raw_json)
        for c in clusters:
            c.setdefault("display_name", c["name"])
            c.setdefault("token", "")
            c.setdefault("ca_cert_path", "")
            c.setdefault("in_cluster", False)
        return tuple(clusters)

    # Fallback: single cluster from legacy vars
    name = os.getenv("K8S_CLUSTER_NAME", "default")
    return (
        {
            "name": name,
            "display_name": name,
            "api_server": os.getenv("K8S_API_SERVER", ""),
            "token": os.getenv("K8S_SA_TOKEN", ""),
            "ca_cert_path": os.getenv("K8S_CA_CERT_PATH", ""),
            "in_cluster": os.getenv("K8S_IN_CLUSTER", "false").lower() == "true",
        },
    )


def get_config() -> AppConfig:
    _required = ("OIDC_CLIENT_ID", "OIDC_CLIENT_SECRET", "AZURE_TENANT_ID", "APP_SECRET_KEY")
    _missing = [k for k in _required if not os.environ.get(k)]
    if _missing:
        raise EnvironmentError(
            f"Missing required environment variables: {', '.join(_missing)}. "
            "Copy .env.example to .env and fill in the values."
        )

    return AppConfig(
        oidc_client_id=os.environ["OIDC_CLIENT_ID"],
        oidc_client_secret=os.environ["OIDC_CLIENT_SECRET"],
        azure_tenant_id=os.environ["AZURE_TENANT_ID"],
        oidc_redirect_uri=os.getenv("OIDC_REDIRECT_URI", "http://localhost:8501"),
        oidc_scopes=os.getenv("OIDC_SCOPES", "openid profile email"),
        clusters=_parse_clusters(),
        github_app_id=os.getenv("GITHUB_APP_ID", ""),
        github_app_private_key=_read_github_private_key(),
        github_app_installation_id=os.getenv("GITHUB_APP_INSTALLATION_ID", ""),
        github_token=os.getenv("GITHUB_TOKEN", ""),
        github_repo=os.getenv("GITHUB_REPO", ""),
        github_base_branch=os.getenv("GITHUB_BASE_BRANCH", "main"),
        github_policies_path=os.getenv("GITHUB_POLICIES_PATH", "policies"),
        app_secret_key=os.environ["APP_SECRET_KEY"],
        debug=os.getenv("DEBUG", "false").lower() == "true",
        test_mode=os.getenv("TEST_MODE", "false").lower() == "true",
    )
