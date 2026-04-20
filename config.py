"""
Central configuration – reads from environment variables (or .env via python-dotenv).
Required variables raise EnvironmentError on startup if absent.
"""
import os
from dataclasses import dataclass
from dotenv import load_dotenv

load_dotenv()


@dataclass(frozen=True)
class AppConfig:
    # ── OpenShift OAuth ───────────────────────────────────────────────────────
    ocp_api_server: str        # https://api.cluster:6443
    ocp_client_id: str         # registered OAuthClient name
    ocp_client_secret: str     # OAuthClient secret
    ocp_redirect_uri: str      # app callback URL
    ocp_ca_cert_path: str      # path to CA bundle (empty = system CAs)

    # ── Exporter ──────────────────────────────────────────────────────────────
    exporter_url: str          # http://netpol-exporter:8080

    # ── Cluster display ───────────────────────────────────────────────────────
    cluster_name: str          # display name for sidebar

    # ── App ───────────────────────────────────────────────────────────────────
    app_secret_key: str
    debug: bool
    test_mode: bool

    # ── Backward compat properties used by auth/oidc.py ──────────────────────

    @property
    def oidc_authority(self) -> str:
        return self.ocp_api_server

    @property
    def oidc_discovery_url(self) -> str:
        return f"{self.ocp_api_server}/.well-known/oauth-authorization-server"

    # Kept so any code that reads these via config doesn't break
    @property
    def oidc_client_id(self) -> str:
        return self.ocp_client_id

    @property
    def oidc_client_secret(self) -> str:
        return self.ocp_client_secret

    @property
    def oidc_redirect_uri(self) -> str:
        return self.ocp_redirect_uri


def get_config() -> AppConfig:
    test_mode = os.getenv("TEST_MODE", "false").lower() == "true"

    _required = ["APP_SECRET_KEY"]
    if not test_mode:
        _required.append("OCP_API_SERVER")

    _missing = [k for k in _required if not os.environ.get(k)]
    if _missing:
        raise EnvironmentError(
            f"Missing required environment variables: {', '.join(_missing)}. "
            "Copy .env.example to .env and fill in the values."
        )

    return AppConfig(
        ocp_api_server=os.getenv("OCP_API_SERVER", "https://api.test-cluster:6443"),
        ocp_client_id=os.getenv("OCP_CLIENT_ID", "netpol-crafter"),
        ocp_client_secret=os.getenv("OCP_CLIENT_SECRET", ""),
        ocp_redirect_uri=os.getenv("OCP_REDIRECT_URI", "http://localhost:8501"),
        ocp_ca_cert_path=os.getenv("OCP_CA_CERT_PATH", ""),
        exporter_url=os.getenv("EXPORTER_URL", "http://netpol-exporter:8080"),
        cluster_name=os.getenv("CLUSTER_NAME", "default"),
        app_secret_key=os.environ["APP_SECRET_KEY"],
        debug=os.getenv("DEBUG", "false").lower() == "true",
        test_mode=test_mode,
    )
