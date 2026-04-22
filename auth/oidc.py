"""
OpenShift OAuth — authorization code flow.

Flow:
  1. generate_auth_url()  → redirect browser to OpenShift OAuth /authorize
  2. OpenShift calls back → ?code=<code>&state=<state>
  3. exchange_code()      → POST to /token endpoint
  4. get_user_info()      → GET /apis/user.openshift.io/v1/users/~

CSRF protection: a random `state` token is stored in session and validated on callback.

TLS: pass OCP_CA_CERT_PATH to use a custom CA bundle instead of system CAs.
     Never set verify=False — that removes TLS protection entirely.
"""
import hashlib
import hmac
import logging
import time
from typing import Optional
from urllib.parse import urlencode

import requests

from config import AppConfig

logger = logging.getLogger(__name__)


class OIDCAuthenticator:
    def __init__(self, config: AppConfig) -> None:
        self._client_id = config.ocp_client_id
        self._client_secret = config.ocp_client_secret
        self._redirect_uri = config.ocp_redirect_uri
        self._discovery_url = config.ocp_discovery_url
        self._api_server = config.ocp_api_server
        self._ca_cert = config.ocp_ca_cert_path or True  # path or True = system CAs
        self._app_secret = config.app_secret_key.encode()
        self._metadata: Optional[dict] = None

    # ── OAuth discovery ───────────────────────────────────────────────────────

    def _get_metadata(self) -> dict:
        if self._metadata is None:
            logger.debug("Fetching OAuth metadata from %s", self._discovery_url)
            resp = requests.get(self._discovery_url, timeout=10, verify=self._ca_cert)
            resp.raise_for_status()
            self._metadata = resp.json()
            logger.debug("OAuth endpoints: authorize=%s token=%s",
                         self._metadata.get("authorization_endpoint"),
                         self._metadata.get("token_endpoint"))
        return self._metadata

    @property
    def authorization_endpoint(self) -> str:
        return self._get_metadata()["authorization_endpoint"]

    @property
    def token_endpoint(self) -> str:
        return self._get_metadata()["token_endpoint"]

    # ── Auth URL ──────────────────────────────────────────────────────────────

    def generate_auth_url(self) -> tuple[str, str]:
        """
        Return (authorization_url, state).

        The state is a stateless HMAC token: `<timestamp>.<mac>`. It can be
        verified from the app secret alone — no server-side session storage
        needed, so it survives the Streamlit WebSocket reconnect that happens
        when OCP redirects the browser back after login.
        """
        ts = str(int(time.time()))
        mac = hmac.new(self._app_secret, ts.encode(), hashlib.sha256).hexdigest()[:24]
        state = f"{ts}.{mac}"
        params = urlencode({
            "response_type": "code",
            "client_id": self._client_id,
            "redirect_uri": self._redirect_uri,
            "state": state,
        })
        url = f"{self.authorization_endpoint}?{params}"
        logger.debug("Generated auth URL for client_id=%s", self._client_id)
        return url, state

    def _verify_state(self, state: str) -> bool:
        """Verify an HMAC state token. Valid for 10 minutes."""
        try:
            ts_str, mac = state.rsplit(".", 1)
            expected = hmac.new(self._app_secret, ts_str.encode(), hashlib.sha256).hexdigest()[:24]
            if not hmac.compare_digest(mac, expected):
                return False
            return abs(time.time() - int(ts_str)) < 600
        except Exception:
            return False

    # ── Token exchange ────────────────────────────────────────────────────────

    def exchange_code(self, code: str, state: str) -> dict:
        """
        Exchange an authorization code for tokens.
        Raises ValueError on invalid/expired CSRF state.
        Raises requests.HTTPError on token endpoint failure.
        """
        if not self._verify_state(state):
            raise ValueError("Invalid or expired OAuth state — possible CSRF attempt. Login aborted.")

        logger.debug("Posting to token endpoint: %s", self.token_endpoint)
        resp = requests.post(
            self.token_endpoint,
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": self._redirect_uri,
            },
            auth=(self._client_id, self._client_secret),
            timeout=15,
            verify=self._ca_cert,
        )
        resp.raise_for_status()
        logger.info("Token exchange successful")
        return resp.json()

    # ── User info ─────────────────────────────────────────────────────────────

    def get_user_info(self, access_token: str) -> dict:
        """
        Fetch the authenticated user's identity from OpenShift.
        Returns a normalized dict with: name, preferred_username, email.
        """
        url = f"{self._api_server}/apis/user.openshift.io/v1/users/~"
        logger.debug("Fetching user info from %s", url)
        resp = requests.get(
            url,
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=10,
            verify=self._ca_cert,
        )
        resp.raise_for_status()
        raw = resp.json()

        username = raw.get("metadata", {}).get("name", "")
        full_name = raw.get("fullName", "") or username
        logger.info("Got user info: username=%s full_name=%s", username, full_name)

        return {
            "name": full_name,
            "preferred_username": username,
            "email": username,  # OCP user API has no email field
        }

    @staticmethod
    def display_name(user_info: dict) -> str:
        return (
            user_info.get("name")
            or user_info.get("preferred_username")
            or user_info.get("email")
            or "Unknown User"
        )
