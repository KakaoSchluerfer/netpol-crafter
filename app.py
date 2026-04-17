"""
NetPol Crafter – Streamlit entry point.

Start with:
    streamlit run app.py

Auth state machine:
  ┌─────────────────────────────────────────────────────────┐
  │  App loads                                              │
  │     ↓                                                   │
  │  ?code= in query params?                                │
  │     ├─ YES → exchange_code() → store in session_state   │
  │     │        → clear params  → rerun                    │
  │     └─ NO  ↓                                            │
  │  session_state["authenticated"]?                        │
  │     ├─ YES → render_policy_builder()                    │
  │     └─ NO  → render_login_page()                        │
  └─────────────────────────────────────────────────────────┘
"""
import traceback

import streamlit as st

st.set_page_config(
    page_title="NetPol Crafter",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded",
)


def main() -> None:
    # Lazy imports keep the first paint fast and avoid importing heavy deps
    # (kubernetes, authlib) before we know we need them.
    from config import get_config
    from auth.oidc import OIDCAuthenticator
    from ui.auth_page import render_login_page
    from ui.policy_builder import render_policy_builder

    try:
        config = get_config()
    except EnvironmentError as exc:
        st.error(str(exc))
        st.stop()

    # ── Test mode: skip OIDC entirely ────────────────────────────────────────
    if config.test_mode and not st.session_state.get("authenticated"):
        st.session_state["authenticated"] = True
        st.session_state["user"] = {
            "name": "Test Engineer",
            "email": "test.engineer@bank.internal",
            "preferred_username": "test.engineer",
            "sub": "test-user-fixture-001",
        }
        st.session_state["access_token"] = "test-token-not-real"

    authenticator = OIDCAuthenticator(config)

    # ── OAuth2 callback handling ──────────────────────────────────────────────
    params = st.query_params
    if "code" in params and "state" in params and not st.session_state.get("authenticated"):
        code: str = params["code"]
        returned_state: str = params["state"]
        expected_state: str = st.session_state.get("oauth_state", "")

        try:
            token = authenticator.exchange_code(code, returned_state, expected_state)
            user_info = authenticator.get_user_info(token["access_token"])
        except ValueError as exc:
            # CSRF state mismatch
            st.error(f"🚫 {exc}")
            st.session_state.pop("oauth_state", None)
            st.stop()
        except Exception as exc:
            st.error(f"Authentication failed: {exc}")
            if config.debug:
                st.code(traceback.format_exc())
            st.stop()

        # Mark session as authenticated – never log the token itself
        st.session_state["authenticated"] = True
        st.session_state["user"] = {
            "name": user_info.get("name"),
            "email": user_info.get("email") or user_info.get("preferred_username"),
            "preferred_username": user_info.get("preferred_username"),
            "sub": user_info.get("sub"),
        }
        # Token stored only for potential k8s impersonation; never written to disk
        st.session_state["access_token"] = token["access_token"]
        st.session_state.pop("oauth_state", None)

        # Clear the OAuth params from the browser URL bar before rendering the app
        st.query_params.clear()
        st.rerun()

    # ── Route to login or app ─────────────────────────────────────────────────
    if not st.session_state.get("authenticated"):
        render_login_page(authenticator)
        return

    render_policy_builder(config)


if __name__ == "__main__":
    main()
