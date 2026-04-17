"""
Main policy builder UI.

Session state keys owned by this module:
  ingress_rules  – list of rule dicts
  egress_rules   – list of rule dicts
  confirm_apply  – bool, gating the two-step apply confirmation

Each rule dict schema:
  {
    "ns":           str | None,   # selected source/dest namespace name
    "ns_labels":    dict,         # labels of that namespace (for namespaceSelector)
    "pod_labels":   dict,         # workload labels of selected pod (for podSelector)
    "ports":        list[dict],   # [{"protocol": "TCP", "port": 8080}, ...]
  }
"""
from __future__ import annotations

import traceback
from typing import Any

import streamlit as st
import yaml

from config import AppConfig
from k8s.client import build_api_client_from_config
from k8s import (
    list_namespaces,
    list_pods_in_namespace,
    list_services_in_namespace,
    list_routes_in_namespace,
    get_namespace_labels,
    apply_network_policy,
)

# ── Constants ─────────────────────────────────────────────────────────────────

_PROTOCOLS = ["TCP", "UDP", "SCTP"]

_EMPTY_RULE: dict = {
    "ns": None,
    "ns_labels": {},
    "pod_labels": {},
    "ports": [],
}


# ── State helpers ─────────────────────────────────────────────────────────────

def _init_state() -> None:
    st.session_state.setdefault("ingress_rules", [])
    st.session_state.setdefault("egress_rules", [])
    st.session_state.setdefault("confirm_apply", False)


def _add_rule(key: str) -> None:
    import copy
    st.session_state[key].append(copy.deepcopy(_EMPTY_RULE))


def _remove_rule(key: str, idx: int) -> None:
    st.session_state[key].pop(idx)


# ── YAML generation ───────────────────────────────────────────────────────────

def _build_peer(rule: dict) -> dict:
    """Translate a rule dict into a NetworkPolicy peer (from/to entry)."""
    peer: dict = {}

    if rule.get("ns_labels"):
        peer["namespaceSelector"] = {"matchLabels": rule["ns_labels"]}

    if rule.get("pod_labels"):
        peer["podSelector"] = {"matchLabels": rule["pod_labels"]}

    # An empty peer means "any source/dest" – represent as empty podSelector
    if not peer:
        peer["podSelector"] = {}

    return peer


def _build_port_entries(ports: list[dict]) -> list[dict]:
    result = []
    for p in ports:
        entry: dict = {"protocol": p.get("protocol", "TCP")}
        if p.get("port"):
            entry["port"] = int(p["port"])
        result.append(entry)
    return result


def build_network_policy_dict(
    name: str,
    namespace: str,
    pod_selector_labels: dict,
    ingress_rules: list[dict],
    egress_rules: list[dict],
) -> dict:
    spec: dict[str, Any] = {
        "podSelector": (
            {"matchLabels": pod_selector_labels} if pod_selector_labels else {}
        ),
        "policyTypes": [],
    }

    if ingress_rules:
        spec["policyTypes"].append("Ingress")
        spec["ingress"] = []
        for rule in ingress_rules:
            entry: dict[str, Any] = {"from": [_build_peer(rule)]}
            if rule.get("ports"):
                entry["ports"] = _build_port_entries(rule["ports"])
            spec["ingress"].append(entry)

    if egress_rules:
        spec["policyTypes"].append("Egress")
        spec["egress"] = []
        for rule in egress_rules:
            entry = {"to": [_build_peer(rule)]}
            if rule.get("ports"):
                entry["ports"] = _build_port_entries(rule["ports"])
            spec["egress"].append(entry)

    return {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {"name": name, "namespace": namespace},
        "spec": spec,
    }


def _to_yaml(policy_dict: dict) -> str:
    return yaml.dump(policy_dict, default_flow_style=False, sort_keys=False)


# ── Rule editor sub-component ─────────────────────────────────────────────────

def _render_rule_editor(
    api_client: Any,
    rule: dict,
    rule_idx: int,
    rules_key: str,
    all_namespaces: list[str],
    direction: str,  # "Ingress" or "Egress"
) -> None:
    """Render the editor for a single ingress or egress rule."""
    peer_label = "Source" if direction == "Ingress" else "Destination"

    col_ns, col_pod = st.columns(2)

    with col_ns:
        ns_options = ["(any namespace)"] + all_namespaces
        current_ns = rule.get("ns") or "(any namespace)"
        selected_ns = st.selectbox(
            f"{peer_label} Namespace",
            ns_options,
            index=ns_options.index(current_ns) if current_ns in ns_options else 0,
            key=f"{rules_key}_{rule_idx}_ns",
        )

        if selected_ns != "(any namespace)":
            rule["ns"] = selected_ns
            with st.spinner("Fetching namespace labels…"):
                rule["ns_labels"] = get_namespace_labels(api_client, selected_ns)
            st.caption(
                "Labels: "
                + ", ".join(f"`{k}={v}`" for k, v in rule["ns_labels"].items())
            )
        else:
            rule["ns"] = None
            rule["ns_labels"] = {}

    with col_pod:
        pod_options = ["(any pod)"]
        pod_map: dict[str, dict] = {}

        if selected_ns and selected_ns != "(any namespace)":
            with st.spinner("Fetching pods…"):
                pods = list_pods_in_namespace(api_client, selected_ns)
            for pod in pods:
                pod_map[pod["name"]] = pod
            pod_options += sorted(pod_map.keys())

        selected_pod = st.selectbox(
            f"{peer_label} Pod (optional)",
            pod_options,
            key=f"{rules_key}_{rule_idx}_pod",
        )

        if selected_pod != "(any pod)" and selected_pod in pod_map:
            wl_labels = pod_map[selected_pod]["workload_labels"]
            rule["pod_labels"] = wl_labels
            if wl_labels:
                st.caption(
                    "Selector labels: "
                    + ", ".join(f"`{k}={v}`" for k, v in wl_labels.items())
                )
            else:
                st.warning("Pod has no workload labels – selector will match all pods.")
        else:
            rule["pod_labels"] = {}

    # ── Ports ─────────────────────────────────────────────────────────────────
    st.markdown("**Ports** *(leave empty to allow all ports)*")

    port_col1, port_col2, port_col3 = st.columns([2, 2, 1])
    new_protocol = port_col1.selectbox(
        "Protocol", _PROTOCOLS, key=f"{rules_key}_{rule_idx}_proto"
    )
    new_port = port_col2.text_input(
        "Port (number or name)", key=f"{rules_key}_{rule_idx}_port_input"
    )
    if port_col3.button("＋ Add Port", key=f"{rules_key}_{rule_idx}_add_port"):
        if new_port:
            rule["ports"].append({"protocol": new_protocol, "port": new_port})

    if rule["ports"]:
        for pidx, p in enumerate(rule["ports"]):
            p_col, del_col = st.columns([5, 1])
            p_col.code(f"{p['protocol']}:{p['port']}", language=None)
            if del_col.button("✕", key=f"{rules_key}_{rule_idx}_del_port_{pidx}"):
                rule["ports"].pop(pidx)
                st.rerun()


# ── Main render ───────────────────────────────────────────────────────────────

def render_policy_builder(config: AppConfig) -> None:
    _init_state()

    user_info = st.session_state.get("user", {})
    api_client = build_api_client_from_config(config)

    # ── Sidebar ───────────────────────────────────────────────────────────────
    with st.sidebar:
        st.markdown("### 👤 Signed in as")
        from auth.oidc import OIDCAuthenticator  # local import avoids circular
        # We only need the static method here
        st.markdown(f"**{OIDCAuthenticator.display_name(user_info)}**")
        st.caption(user_info.get("email", ""))
        st.divider()

        if st.button("🔄 Refresh cluster data", use_container_width=True):
            st.cache_data.clear()
            st.success("Cache cleared – data will reload on next interaction.")

        st.divider()
        if st.button("🚪 Sign out", use_container_width=True, type="secondary"):
            for key in list(st.session_state.keys()):
                del st.session_state[key]
            st.rerun()

        st.divider()
        st.markdown(
            "<p style='font-size:0.75em;color:grey'>"
            "Cluster data is cached for 60 s.<br>"
            "YAML is generated locally – no data is transmitted until you click Apply."
            "</p>",
            unsafe_allow_html=True,
        )

    # ── Page header ───────────────────────────────────────────────────────────
    st.title("🔒 NetPol Crafter")
    st.markdown(
        "Build an OpenShift **NetworkPolicy** from cluster resources. "
        "The tool fetches live labels so your selectors are always accurate."
    )
    st.divider()

    # ── Load namespace list (shared across sections) ───────────────────────────
    with st.spinner("Loading namespaces…"):
        try:
            all_namespaces = list_namespaces(api_client)
        except Exception as exc:
            st.error(f"Cannot list namespaces: {exc}")
            if config.debug:
                st.code(traceback.format_exc())
            st.stop()

    # ═══════════════════════════════════════════════════════════════════════════
    # SECTION 1 – Policy Metadata
    # ═══════════════════════════════════════════════════════════════════════════
    st.subheader("1 · Policy metadata")
    meta_col1, meta_col2 = st.columns(2)
    policy_name = meta_col1.text_input(
        "Policy name",
        placeholder="e.g. allow-frontend-to-api",
        help="Must be a valid DNS subdomain name (lowercase, hyphens, no dots).",
    )
    target_namespace = meta_col2.selectbox(
        "Target namespace",
        [""] + all_namespaces,
        format_func=lambda x: "(select namespace)" if x == "" else x,
    )

    # ═══════════════════════════════════════════════════════════════════════════
    # SECTION 2 – Target Pod Selector
    # ═══════════════════════════════════════════════════════════════════════════
    st.subheader("2 · Target pod selector")
    st.markdown(
        "Select the pods **this policy protects**. "
        "Leaving the pod unselected applies the policy to *all pods* in the namespace."
    )

    target_pod_labels: dict[str, str] = {}

    if target_namespace:
        target_col1, target_col2 = st.columns(2)

        with target_col1:
            with st.spinner("Loading pods…"):
                target_pods = list_pods_in_namespace(api_client, target_namespace)
            target_pod_options = ["(all pods)"] + [p["name"] for p in target_pods]
            target_pod_map = {p["name"]: p for p in target_pods}

            selected_target_pod = st.selectbox(
                "Target pod", target_pod_options
            )

        with target_col2:
            if selected_target_pod != "(all pods)" and selected_target_pod in target_pod_map:
                target_pod_labels = target_pod_map[selected_target_pod]["workload_labels"]
                st.markdown("**Derived podSelector labels:**")
                for k, v in target_pod_labels.items():
                    st.code(f"{k}: {v}", language=None)
                if not target_pod_labels:
                    st.warning(
                        "This pod has no workload labels. "
                        "The policy will match ALL pods in the namespace."
                    )

            # Optional: pre-fill from a Service
            with st.expander("💡 Pre-fill from a Service definition"):
                with st.spinner("Loading services…"):
                    services = list_services_in_namespace(api_client, target_namespace)
                svc_map = {s["name"]: s for s in services}
                selected_svc = st.selectbox(
                    "Service", ["(none)"] + sorted(svc_map.keys()), key="target_svc"
                )
                if selected_svc != "(none)":
                    svc = svc_map[selected_svc]
                    if svc["selector"]:
                        target_pod_labels = svc["selector"]
                        st.success(
                            f"Using selector from Service **{selected_svc}**: "
                            + str(svc["selector"])
                        )
                    else:
                        st.warning("This Service has no pod selector (headless or external).")

        # Routes info panel (read-only – useful context)
        with st.expander("📡 OpenShift Routes in this namespace"):
            with st.spinner("Loading routes…"):
                routes = list_routes_in_namespace(api_client, target_namespace)
            if routes:
                for route in routes:
                    tls_badge = "🔒" if route["tls"] else "🔓"
                    st.markdown(
                        f"{tls_badge} **{route['name']}** → `{route['host']}{route['path']}`"
                    )
            else:
                st.info("No Routes found (or this is not an OpenShift cluster).")
    else:
        st.info("Select a target namespace above to continue.")

    # ═══════════════════════════════════════════════════════════════════════════
    # SECTION 3 – Ingress Rules
    # ═══════════════════════════════════════════════════════════════════════════
    st.subheader("3 · Ingress rules")
    st.markdown("Define *who can send traffic **in*** to the target pods.")

    if not st.session_state["ingress_rules"]:
        st.info("No ingress rules defined. Click below to add one, or leave empty to deny all ingress.")

    for idx in range(len(st.session_state["ingress_rules"])):
        rule = st.session_state["ingress_rules"][idx]
        with st.expander(f"Ingress rule #{idx + 1}", expanded=True):
            _render_rule_editor(
                api_client, rule, idx, "ingress_rules", all_namespaces, "Ingress"
            )
            if st.button(
                "🗑 Remove this rule", key=f"del_ingress_{idx}", type="secondary"
            ):
                _remove_rule("ingress_rules", idx)
                st.rerun()

    if st.button("＋ Add ingress rule", key="add_ingress"):
        _add_rule("ingress_rules")
        st.rerun()

    # ═══════════════════════════════════════════════════════════════════════════
    # SECTION 4 – Egress Rules
    # ═══════════════════════════════════════════════════════════════════════════
    st.subheader("4 · Egress rules")
    st.markdown("Define *where the target pods can send traffic **out*** to.")

    if not st.session_state["egress_rules"]:
        st.info("No egress rules defined. Click below to add one, or leave empty to deny all egress.")

    for idx in range(len(st.session_state["egress_rules"])):
        rule = st.session_state["egress_rules"][idx]
        with st.expander(f"Egress rule #{idx + 1}", expanded=True):
            _render_rule_editor(
                api_client, rule, idx, "egress_rules", all_namespaces, "Egress"
            )
            if st.button(
                "🗑 Remove this rule", key=f"del_egress_{idx}", type="secondary"
            ):
                _remove_rule("egress_rules", idx)
                st.rerun()

    if st.button("＋ Add egress rule", key="add_egress"):
        _add_rule("egress_rules")
        st.rerun()

    # ═══════════════════════════════════════════════════════════════════════════
    # SECTION 5 – YAML Preview & Apply
    # ═══════════════════════════════════════════════════════════════════════════
    st.divider()
    st.subheader("5 · YAML preview & apply")

    ready = policy_name and target_namespace
    if not ready:
        st.warning("Fill in a policy name and target namespace to generate YAML.")
        return

    policy_dict = build_network_policy_dict(
        name=policy_name,
        namespace=target_namespace,
        pod_selector_labels=target_pod_labels,
        ingress_rules=st.session_state["ingress_rules"],
        egress_rules=st.session_state["egress_rules"],
    )
    yaml_str = _to_yaml(policy_dict)

    st.code(yaml_str, language="yaml")

    btn_col1, btn_col2 = st.columns([1, 4])
    btn_col1.download_button(
        label="⬇ Download YAML",
        data=yaml_str,
        file_name=f"{policy_name}.yaml",
        mime="text/yaml",
    )

    st.markdown("---")
    st.markdown("#### Apply to cluster")
    st.warning(
        "⚠️ Applying a NetworkPolicy immediately affects live traffic. "
        "Review the YAML carefully before proceeding.",
        icon="⚠️",
    )

    if not st.session_state["confirm_apply"]:
        if st.button("🚀 Apply to cluster", type="primary"):
            st.session_state["confirm_apply"] = True
            st.rerun()
    else:
        st.error(
            f"**Confirm:** Create/replace `{policy_name}` in namespace `{target_namespace}`?"
        )
        confirm_col1, confirm_col2 = st.columns(2)

        if confirm_col1.button("✅ Yes, apply now", type="primary"):
            st.session_state["confirm_apply"] = False
            with st.spinner("Applying NetworkPolicy…"):
                try:
                    result = apply_network_policy(api_client, policy_dict)
                    st.success(
                        f"✅ Policy **{result['name']}** {result['action']} "
                        f"in namespace **{result['namespace']}**."
                    )
                except Exception as exc:
                    st.error(f"Apply failed: {exc}")
                    if config.debug:
                        st.code(traceback.format_exc())

        if confirm_col2.button("❌ Cancel"):
            st.session_state["confirm_apply"] = False
            st.rerun()
