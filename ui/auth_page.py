"""
Login page rendered when no authenticated session exists.

OAuth redirect flow:
  1. User clicks "Sign in with OpenShift"
  2. We store the nonce state in st.session_state["oauth_state"]
  3. A JavaScript redirect sends the browser to OpenShift OAuth
  4. OpenShift calls back with ?code=&state= → handled in app.py before this page renders
"""
import streamlit as st
import streamlit.components.v1 as components

from auth.oidc import OIDCAuthenticator


def render_login_page(authenticator: OIDCAuthenticator) -> None:
    st.set_page_config(
        page_title="NetPol Crafter – Sign In",
        page_icon="🔐",
        layout="centered",
    )

    # ── Centered login card ───────────────────────────────────────────────────
    col_l, col_c, col_r = st.columns([1, 2, 1])
    with col_c:
        st.markdown("## 🔐 NetPol Crafter")
        st.markdown(
            "**OpenShift Network Policy builder** – authenticate with your "
            "OpenShift account to continue."
        )
        st.divider()

        if st.button(
            "Sign in with OpenShift",
            width="stretch",
            type="primary",
            help="Redirects to OpenShift OAuth for authentication",
        ):
            _trigger_oidc_redirect(authenticator)

        st.markdown(
            "<p style='text-align:center; color:grey; font-size:0.8em;'>"
            "Access is governed by your OpenShift cluster permissions.<br>"
            "All activity is subject to corporate security policy.</p>",
            unsafe_allow_html=True,
        )


def _trigger_oidc_redirect(authenticator: OIDCAuthenticator) -> None:
    """Generate auth URL, stash state, then redirect the browser via JavaScript."""
    try:
        auth_url, state = authenticator.generate_auth_url()
    except Exception as exc:
        st.error(f"Could not reach the identity provider: {exc}")
        return

    st.session_state["oauth_state"] = state

    # Use a JS meta-refresh so the browser navigates away (full page redirect).
    # We cannot use st.experimental_rerun() here because we need the browser
    # to leave the Streamlit origin and visit OpenShift OAuth.
    components.html(
        f"""
        <script>
          // Intentional top-level navigation to OpenShift OAuth
          window.top.location.href = {repr(auth_url)};
        </script>
        """,
        height=0,
    )
    st.info("Redirecting to OpenShift OAuth…")
    st.stop()
