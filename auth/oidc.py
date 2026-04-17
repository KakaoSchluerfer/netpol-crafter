"""
OIDC authentication against Azure AD / Entra ID.

Flow (Authorization Code, no PKCE – server-side app):
  1. generate_auth_url()  → redirect browser to Azure AD
  2. Azure AD calls back with ?code=&state=
  3. exchange_code()      → POST to /token endpoint
  4. get_user_info()      → GET /userinfo endpoint
  5. Caller stores token claims in st.session_state – NEVER in a cookie or log.

State is a cryptographically random token stored in st.session_state["oauth_state"]
and echoed back by Azure AD; we validate it on callback to prevent CSRF.
"""
import hashlib
import hmac
import secrets
import time
from typing import Optional

import requests
from authlib.integrations.requests_client import OAuth2Session

from config import AppConfig


class OIDCAuthenticator:
    def __init__(self, config: AppConfig) -> None:
        self._client_id = config.oidc_client_id
        self._client_secret = config.oidc_client_secret
        self._redirect_uri = config.oidc_redirect_uri
        self._scopes = config.oidc_scopes
        self._discovery_url = config.oidc_discovery_url
        self._app_secret = config.app_secret_key.encode()
        self._metadata: Optional[dict] = None

    # ── OIDC discovery ───────────────────────────────────────────────────────

    def _get_metadata(self) -> dict:
        if self._metadata is None:
            resp = requests.get(self._discovery_url, timeout=10)
            resp.raise_for_status()
            self._metadata = resp.json()
        return self._metadata

    @property
    def authorization_endpoint(self) -> str:
        return self._get_metadata()["authorization_endpoint"]

    @property
    def token_endpoint(self) -> str:
        return self._get_metadata()["token_endpoint"]

    @property
    def userinfo_endpoint(self) -> str:
        return self._get_metadata()["userinfo_endpoint"]

    # ── Auth URL ─────────────────────────────────────────────────────────────

    def generate_auth_url(self) -> tuple[str, str]:
        """
        Returns (authorization_url, state).
        Caller MUST store `state` in st.session_state["oauth_state"] before redirecting.
        """
        state = secrets.token_urlsafe(32)
        session = OAuth2Session(
            client_id=self._client_id,
            redirect_uri=self._redirect_uri,
            scope=self._scopes,
        )
        url, returned_state = session.create_authorization_url(
            self.authorization_endpoint,
            state=state,
            response_type="code",
        )
        return url, returned_state

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

        session = OAuth2Session(
            client_id=self._client_id,
            client_secret=self._client_secret,
            redirect_uri=self._redirect_uri,
            state=state,
        )
        token = session.fetch_token(
            self.token_endpoint,
            code=code,
            grant_type="authorization_code",
        )
        return dict(token)

    # ── User info ─────────────────────────────────────────────────────────────

    def get_user_info(self, access_token: str) -> dict:
        """Fetch profile claims from the /userinfo endpoint."""
        resp = requests.get(
            self.userinfo_endpoint,
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=10,
        )
        resp.raise_for_status()
        return resp.json()

    # ── Convenience ───────────────────────────────────────────────────────────

    @staticmethod
    def display_name(user_info: dict) -> str:
        return (
            user_info.get("name")
            or user_info.get("preferred_username")
            or user_info.get("email")
            or "Unknown User"
        )
