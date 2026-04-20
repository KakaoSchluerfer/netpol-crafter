"""
OpenShift OAuth authentication.

Flow (Authorization Code, server-side app):
  1. generate_auth_url()  → redirect browser to OpenShift OAuth authorize endpoint
  2. OpenShift calls back with ?code=&state=
  3. exchange_code()      → POST to /token endpoint
  4. get_user_info()      → GET /apis/user.openshift.io/v1/users/~
  5. Caller stores token claims in st.session_state – NEVER in a cookie or log.

State is a cryptographically random token stored in st.session_state["oauth_state"]
and echoed back by OpenShift; we validate it on callback to prevent CSRF.

OpenShift OAuth discovery:
  GET {ocp_api_server}/.well-known/oauth-authorization-server
  Returns: {"authorization_endpoint": "...", "token_endpoint": "..."}

The OAuthClient must be pre-registered on the cluster.
"""
import hmac
import secrets
from typing import Optional
from urllib.parse import urlencode

import requests

from config import AppConfig


class OIDCAuthenticator:
    def __init__(self, config: AppConfig) -> None:
        self._client_id = config.ocp_client_id
        self._client_secret = config.ocp_client_secret
        self._redirect_uri = config.ocp_redirect_uri
        self._discovery_url = config.oidc_discovery_url
        self._api_server = config.ocp_api_server
        self._ca_cert_path = config.ocp_ca_cert_path
        self._app_secret = config.app_secret_key.encode()
        self._metadata: Optional[dict] = None

    # ── TLS helper ───────────────────────────────────────────────────────────

    def _verify(self):
        """Return the CA cert path (verify=path) or True (system CAs) for requests."""
        return self._ca_cert_path if self._ca_cert_path else True

    # ── OAuth discovery ──────────────────────────────────────────────────────

    def _get_metadata(self) -> dict:
        if self._metadata is None:
            resp = requests.get(self._discovery_url, timeout=10, verify=self._verify())
            resp.raise_for_status()
            self._metadata = resp.json()
        return self._metadata

    @property
    def authorization_endpoint(self) -> str:
        return self._get_metadata()["authorization_endpoint"]

    @property
    def token_endpoint(self) -> str:
        return self._get_metadata()["token_endpoint"]

    # ── Auth URL ─────────────────────────────────────────────────────────────

    def generate_auth_url(self) -> tuple[str, str]:
        """
        Returns (authorization_url, state).
        Caller MUST store `state` in st.session_state["oauth_state"] before redirecting.
        """
        state = secrets.token_urlsafe(32)
        params = urlencode({
            "response_type": "code",
            "client_id": self._client_id,
            "redirect_uri": self._redirect_uri,
            "state": state,
        })
        url = f"{self.authorization_endpoint}?{params}"
        return url, state

    # ── Token exchange ────────────────────────────────────────────────────────

    def exchange_code(self, code: str, state: str, expected_state: str) -> dict:
        """
        Exchange an authorization code for tokens.
        Raises ValueError on state mismatch (CSRF guard).
        Raises requests.HTTPError on token endpoint failure.
        """
        if not hmac.compare_digest(state, expected_state):
            raise ValueError(
                "OAuth state mismatch – possible CSRF attempt. Login aborted."
            )

        resp = requests.post(
            self.token_endpoint,
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": self._redirect_uri,
            },
            auth=(self._client_id, self._client_secret),
            timeout=15,
            verify=self._verify(),
        )
        resp.raise_for_status()
        return resp.json()

    # ── User info ─────────────────────────────────────────────────────────────

    def get_user_info(self, access_token: str) -> dict:
        """
        Fetch user info from /apis/user.openshift.io/v1/users/~.

        OpenShift returns:
          {"metadata": {"name": "john.doe"}, "fullName": "John Doe", ...}

        We normalise to the keys expected by app.py / display_name():
          name               → fullName
          preferred_username → metadata.name
          email              → metadata.name  (OCP has no email field in user API)
        """
        resp = requests.get(
            f"{self._api_server}/apis/user.openshift.io/v1/users/~",
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=10,
            verify=self._verify(),
        )
        resp.raise_for_status()
        raw = resp.json()

        username = raw.get("metadata", {}).get("name", "")
        full_name = raw.get("fullName", "") or username

        return {
            "name": full_name,
            "preferred_username": username,
            "email": username,
            # preserve raw data for callers that want it
            "_raw": raw,
        }

    # ── Convenience ───────────────────────────────────────────────────────────

    @staticmethod
    def display_name(user_info: dict) -> str:
        return (
            user_info.get("name")
            or user_info.get("preferred_username")
            or user_info.get("email")
            or "Unknown User"
        )
