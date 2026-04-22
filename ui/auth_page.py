"""
Login page — shown only when the user is not authenticated.

Note: st.set_page_config() must NOT be called here; it is called once in app.py.
"""
import logging

import streamlit as st
import streamlit.components.v1 as components

from auth.oidc import OIDCAuthenticator

logger = logging.getLogger(__name__)


def render_login_page(authenticator: OIDCAuthenticator) -> None:
    col_l, col_c, col_r = st.columns([1, 2, 1])
    with col_c:
        st.markdown("## 🔐 NetPol Crafter")
        st.markdown(
            "**OpenShift Network Policy builder** — authenticate with your "
            "OpenShift account to continue."
        )
        st.divider()

        if st.button(
            "Sign in with OpenShift",
            use_container_width=True,
            type="primary",
            help="Redirects to OpenShift OAuth for authentication",
        ):
            _start_oidc_redirect(authenticator)

        st.markdown(
            "<p style='text-align:center; color:grey; font-size:0.8em;'>"
            "Access is governed by your OpenShift cluster permissions.<br>"
            "All activity is subject to corporate security policy.</p>",
            unsafe_allow_html=True,
        )


def _start_oidc_redirect(authenticator: OIDCAuthenticator) -> None:
    """Generate auth URL, store CSRF state, then navigate the browser to OpenShift OAuth."""
    try:
        auth_url, state = authenticator.generate_auth_url()
    except Exception as exc:
        logger.error("Failed to reach identity provider: %s", exc)
        st.error(f"Could not reach the identity provider: {exc}")
        return

    st.session_state["oauth_state"] = state
    logger.debug("Starting OIDC redirect, state stored in session")

    # JavaScript navigation — Streamlit cannot do a full-page redirect natively.
    components.html(
        f"<script>window.top.location.href = {repr(auth_url)};</script>",
        height=0,
    )
    st.info("Redirecting to OpenShift OAuth…")
    st.stop()
