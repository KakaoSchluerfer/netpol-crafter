"""
Login page rendered when no authenticated session exists.

OIDC redirect flow:
  1. User clicks "Sign in with Microsoft"
  2. We store the nonce state in st.session_state["oauth_state"]
  3. A JavaScript redirect sends the browser to Azure AD
  4. Azure AD calls back with ?code=&state= → handled in app.py before this page renders
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
            "corporate Microsoft account to continue."
        )
        st.divider()

        if st.button(
            "Sign in with Microsoft",
            use_container_width=True,
            type="primary",
            help="Redirects to your Azure AD / Entra ID tenant for authentication",
        ):
            _trigger_oidc_redirect(authenticator)

        st.markdown(
            "<p style='text-align:center; color:grey; font-size:0.8em;'>"
            "Access is governed by your Active Directory group membership.<br>"
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
    # to leave the Streamlit origin and visit Azure AD.
    components.html(
        f"""
        <script>
          // Intentional top-level navigation to Azure AD
          window.top.location.href = {repr(auth_url)};
        </script>
        """,
        height=0,
    )
    st.info("Redirecting to Microsoft login…")
    st.stop()
