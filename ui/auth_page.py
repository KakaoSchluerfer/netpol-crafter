"""
Login page — shown only when the user is not authenticated.

Note: st.set_page_config() must NOT be called here; it is called once in app.py.
"""
import logging

import streamlit as st

from auth.oidc import OIDCAuthenticator

logger = logging.getLogger(__name__)


def render_login_page(authenticator: OIDCAuthenticator) -> None:
    col_l, col_c, col_r = st.columns([1, 2, 1])
    with col_c:
        _, logo_col, _ = st.columns([1, 2, 1])
        with logo_col:
            st.image("sources/images/pharos.png", use_container_width=True)
        st.markdown(
            "<h3 style='text-align:center;margin-top:0'>OpenShift Network Policy builder</h3>"
            "<p style='text-align:center;color:grey'>Authenticate with your OpenShift account to continue.</p>",
            unsafe_allow_html=True,
        )
        st.divider()

        try:
            auth_url, _ = authenticator.generate_auth_url()
        except Exception as exc:
            logger.error("Failed to reach identity provider: %s", exc)
            st.error(f"Could not reach the identity provider: {exc}")
            return

        logger.debug("Rendering login page, auth URL generated")

        # st.link_button renders a real <a href> — no JavaScript iframe tricks.
        # This is important because window.top.location.href in an iframe is
        # blocked by browser security policies in many environments.
        _, btn_col, _ = st.columns([1, 2, 1])
        with btn_col:
            st.link_button(
                "Sign in with OpenShift",
                auth_url,
                use_container_width=True,
                type="primary",
                help="Redirects to OpenShift OAuth for authentication",
            )

        st.markdown(
            "<p style='text-align:center; color:grey; font-size:0.8em;'>"
            "Access is governed by your OpenShift cluster permissions.<br>"
            "All activity is subject to corporate security policy.</p>",
            unsafe_allow_html=True,
        )
