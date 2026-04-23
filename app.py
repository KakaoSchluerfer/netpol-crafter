"""
Pharos — application entry point.

Auth flow:
  1. App loads → if ?code= callback, exchange for token and store in session
  2. st.navigation() builds the sidebar:
       unauthenticated → only Sign In page visible
       authenticated   → Policy Builder, Network Map, How-To Guide
"""
import logging
import traceback

import streamlit as st

# Must be the first Streamlit call in the script.
st.set_page_config(
    page_title="Pharos",
    page_icon="sources/images/favicon.ico",
    layout="wide",
    initial_sidebar_state="expanded",
)

logger = logging.getLogger(__name__)


def _configure_logging(debug: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if debug else logging.INFO,
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def main() -> None:
    from config import get_config
    from auth.oidc import OIDCAuthenticator
    from ui.auth_page import render_login_page
    from ui.policy_builder import render_policy_builder

    try:
        config = get_config()
    except EnvironmentError as exc:
        st.error(str(exc))
        st.stop()

    _configure_logging(config.debug)

    # ── Test mode: skip OAuth entirely ───────────────────────────────────────
    if config.test_mode and not st.session_state.get("authenticated"):
        st.session_state.update({
            "authenticated": True,
            "user": {
                "name": "Test Engineer",
                "preferred_username": "test.engineer",
                "email": "test.engineer@bank.internal",
                "sub": "test-user-fixture-001",
            },
            "access_token": "test-token-not-real",
        })
        logger.info("Test mode: auto-authenticated as fixture user")

    authenticator = OIDCAuthenticator(config)

    # ── OAuth2 callback ───────────────────────────────────────────────────────
    params = st.query_params
    if "code" in params and "state" in params and not st.session_state.get("authenticated"):
        code: str = params["code"]
        returned_state: str = params["state"]
        try:
            logger.info("Exchanging OAuth authorization code")
            token = authenticator.exchange_code(code, returned_state)
            user_info = authenticator.get_user_info(token["access_token"])
        except ValueError as exc:
            logger.warning("OAuth state validation failed: %s", exc)
            st.error(f"🚫 {exc}")
            st.stop()
        except Exception as exc:
            logger.error("Authentication failed: %s", exc, exc_info=True)
            st.error(f"Authentication failed: {exc}")
            if config.debug:
                st.code(traceback.format_exc())
            st.stop()

        st.session_state.update({
            "authenticated": True,
            "user": {
                "name": user_info.get("name"),
                "preferred_username": user_info.get("preferred_username"),
                "email": user_info.get("email"),
                "sub": user_info.get("sub"),
            },
            "access_token": token["access_token"],
        })
        logger.info("Authenticated: %s", user_info.get("preferred_username"))
        st.query_params.clear()
        st.rerun()

    # ── Navigation ───────────────────────────────────────────────────────────
    # st.navigation() controls which pages appear in the sidebar.
    # Unauthenticated users only see the Sign In page; all others are hidden.
    if st.session_state.get("authenticated"):
        pages = [
            st.Page(
                lambda: render_policy_builder(config),
                title="Policy Builder",
                icon="🔒",
                default=True,
            ),
            st.Page("pages/Network_Policy_Map.py", title="Network Policy Map", icon="🗺"),
            st.Page("pages/How_To_Guide.py", title="How-To Guide", icon="📖"),
        ]
    else:
        pages = [
            st.Page(
                lambda: render_login_page(authenticator),
                title="Sign In",
                icon="🔐",
                default=True,
            )
        ]

    pg = st.navigation(pages, position="sidebar")
    pg.run()


main()
