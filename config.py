"""
Central configuration — reads from environment variables (or .env via python-dotenv).
Missing required variables raise EnvironmentError on startup.
"""
import logging
import os

from dataclasses import dataclass
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class AppConfig:
    # OpenShift OAuth
    ocp_api_server: str     # https://api.cluster:6443
    ocp_client_id: str      # registered OAuthClient name
    ocp_client_secret: str  # OAuthClient secret
    ocp_redirect_uri: str   # app callback URL
    ocp_ca_cert_path: str   # path to PEM CA bundle; empty = use system CAs

    # Exporter
    exporter_url: str       # http://pharos-exporter:8080

    # Display
    cluster_name: str

    # Application
    app_secret_key: str
    debug: bool
    test_mode: bool

    @property
    def ocp_discovery_url(self) -> str:
        return f"{self.ocp_api_server}/.well-known/oauth-authorization-server"


def get_config() -> AppConfig:
    test_mode = os.getenv("TEST_MODE", "false").lower() == "true"

    required = ["APP_SECRET_KEY"]
    if not test_mode:
        required.append("OCP_API_SERVER")

    missing = [k for k in required if not os.environ.get(k)]
    if missing:
        raise EnvironmentError(
            f"Missing required environment variables: {', '.join(missing)}. "
            "Copy .env.example to .env and fill in the values."
        )

    config = AppConfig(
        ocp_api_server=os.getenv("OCP_API_SERVER", "https://api.test-cluster:6443"),
        ocp_client_id=os.getenv("OCP_CLIENT_ID", "pharos-frontend"),
        ocp_client_secret=os.getenv("OCP_CLIENT_SECRET", ""),
        ocp_redirect_uri=os.getenv("OCP_REDIRECT_URI", "http://localhost:8501"),
        ocp_ca_cert_path=os.getenv("OCP_CA_CERT_PATH", ""),
        exporter_url=os.getenv("EXPORTER_URL", "http://pharos-exporter:8080"),
        cluster_name=os.getenv("CLUSTER_NAME", "default"),
        app_secret_key=os.environ["APP_SECRET_KEY"],
        debug=os.getenv("DEBUG", "false").lower() == "true",
        test_mode=test_mode,
    )
    logger.debug(
        "Config loaded — cluster=%s test_mode=%s ca_cert=%s",
        config.cluster_name,
        config.test_mode,
        config.ocp_ca_cert_path or "(system CAs)",
    )
    return config
