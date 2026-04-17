"""
Central configuration – reads from environment variables (or .env via python-dotenv).
All required variables raise KeyError on startup if absent; no silent defaults for secrets.
"""
import os
from dataclasses import dataclass

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

    # ── Kubernetes ────────────────────────────────────────────────────────────
    k8s_in_cluster: bool
    k8s_api_server: str
    k8s_ca_cert_path: str

    # ── App ───────────────────────────────────────────────────────────────────
    app_secret_key: str
    debug: bool

    @property
    def oidc_authority(self) -> str:
        return f"https://login.microsoftonline.com/{self.azure_tenant_id}/v2.0"

    @property
    def oidc_discovery_url(self) -> str:
        return f"{self.oidc_authority}/.well-known/openid-configuration"


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
        k8s_in_cluster=os.getenv("K8S_IN_CLUSTER", "false").lower() == "true",
        k8s_api_server=os.getenv("K8S_API_SERVER", ""),
        k8s_ca_cert_path=os.getenv("K8S_CA_CERT_PATH", ""),
        app_secret_key=os.environ["APP_SECRET_KEY"],
        debug=os.getenv("DEBUG", "false").lower() == "true",
    )
