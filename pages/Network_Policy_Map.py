"""
Network Policy Map — visual connection diagram.

Shows which workloads can communicate based on active NetworkPolicies.
Data is served from the exporter's cached snapshot — no direct K8s calls here.
Note: st.set_page_config() must NOT be called here; it lives in app.py.
"""
from __future__ import annotations

import logging

import yaml
import streamlit as st

from config import get_config
from k8s.exporter_client import (
    fetch_snapshot,
    snapshot_namespaces,
    snapshot_ns_labels,
    snapshot_all_pods,
    snapshot_all_routes,
    snapshot_all_services,
    snapshot_policies,
    snapshot_anps,
)
from ui.netpol_viz import ns_palette, build_workloads, cluster_map_dot, check_route_reachability, route_diagram_dot

logger = logging.getLogger(__name__)


def main() -> None:
    if not st.session_state.get("authenticated"):
        st.warning("Please sign in to access this page.")
        st.stop()

    try:
        config = get_config()
    except EnvironmentError as exc:
        st.error(str(exc))
        st.stop()

    st.title(f"🗺 Network Policy Map — {config.cluster_name}")
    st.caption(
        "Directed graph of allowed pod-to-pod traffic derived from active "
        "NetworkPolicies. Data is served from the exporter cache."
    )

    with st.spinner("Loading cluster data…"):
        try:
            snapshot = fetch_snapshot(config.exporter_url)
        except Exception as exc:
            st.error(f"Could not load cluster data: {exc}")
            st.stop()

    all_namespaces = snapshot_namespaces(snapshot)
    all_pods       = snapshot_all_pods(snapshot)
    ns_labels      = snapshot_ns_labels(snapshot)
    policies       = snapshot_policies(snapshot)
    anps           = snapshot_anps(snapshot)
    all_routes     = snapshot_all_routes(snapshot)
    all_services   = snapshot_all_services(snapshot)

    logger.debug("Snapshot: %d namespaces, %d pods, %d policies, %d ANPs",
                 len(all_namespaces), len(all_pods), len(policies), len(anps))

    # Build workload-name index once: {namespace: [app, ...]}
    _all_workloads = build_workloads(all_pods)
    ns_to_apps: dict[str, list[str]] = {}
    for w in _all_workloads.values():
        ns_to_apps.setdefault(w["namespace"], set()).add(w["app"])
    ns_to_apps = {ns: sorted(apps) for ns, apps in ns_to_apps.items()}

    # ── Sidebar ───────────────────────────────────────────────────────────────
    st.sidebar.header("Cluster")
    st.sidebar.markdown(f"**{config.cluster_name}**")
    st.sidebar.divider()

    st.sidebar.header("Filters")
    selected_ns = st.sidebar.multiselect(
        "Namespaces", options=all_namespaces, default=[],
        help="Select one or more namespaces, then pick workloads within each.",
    )

    # Per-namespace workload filter — shown immediately below the namespace picker
    ns_selected_apps: dict[str, list[str]] = {}
    if selected_ns:
        st.sidebar.markdown("**Workloads**")
        for ns in selected_ns:
            apps = ns_to_apps.get(ns, [])
            ns_selected_apps[ns] = st.sidebar.multiselect(
                ns,
                options=apps,
                default=[],
                key=f"wl_{ns}",
                placeholder="Select workloads…" if apps else "No workloads found",
                disabled=not apps,
            )

    show_external = st.sidebar.checkbox("Show external IP blocks", value=True)
    show_anps = st.sidebar.checkbox(
        "Show AdminNetworkPolicies",
        value=False,
        help="Overlay ANP edges (purple=Allow, red=Deny) on the cluster map.",
    )

    st.sidebar.markdown("**Default NetworkPolicies**")
    _DEFAULT_POLICY_NAMES = [
        "allow-all-within-namespace",
        "default-deny-all-ingress-and-egress",
    ]
    show_default_policies = {
        name: st.sidebar.checkbox(name, value=False, key=f"defpol_{name}")
        for name in _DEFAULT_POLICY_NAMES
    }

    # Only include namespaces where the user picked at least one workload
    active_ns = [ns for ns in selected_ns if ns_selected_apps.get(ns)]

    st.sidebar.divider()
    st.sidebar.subheader("Legend")
    for ns in active_ns:
        border, _, fill = ns_palette(ns)
        st.sidebar.markdown(
            f'<span style="display:inline-block;width:14px;height:14px;'
            f'background:{fill};border:2px solid {border};border-radius:3px;'
            f'margin-right:6px;vertical-align:middle"></span>**{ns}**',
            unsafe_allow_html=True,
        )

    if not selected_ns:
        st.info("Select at least one namespace in the sidebar.")
        return
    if not active_ns:
        st.info("Select at least one workload per namespace in the sidebar.")
        return

    # Filter pods to only those matching the per-namespace workload selection
    def _app_of(pod: dict) -> str:
        labels = pod.get("workload_labels") or pod.get("labels") or {}
        return labels.get("app") or labels.get("name") or pod["name"].rsplit("-", 2)[0]

    filtered_pods = [
        p for p in all_pods
        if p["namespace"] in active_ns
        and _app_of(p) in ns_selected_apps[p["namespace"]]
    ]

    # Apply default-policy filter once so all downstream code uses the same list
    visible_policies = [
        p for p in policies
        if p.get("metadata", {}).get("name") not in _DEFAULT_POLICY_NAMES
        or show_default_policies.get(p.get("metadata", {}).get("name"), False)
    ]

    # ── Route reachability ────────────────────────────────────────────────────
    route_results = check_route_reachability(
        [r for r in all_routes if r["namespace"] in active_ns],
        [s for s in all_services if s["namespace"] in active_ns],
        filtered_pods,
        [p for p in visible_policies if p.get("metadata", {}).get("namespace") in active_ns],
        ns_labels,
    )

    # ── Compute ───────────────────────────────────────────────────────────────
    dot, edges, external_nodes = cluster_map_dot(
        visible_policies, filtered_pods, ns_labels, active_ns, show_external,
        anps=anps, route_results=route_results, show_anps=show_anps,
    )
    workloads = build_workloads(filtered_pods)
    active_policies = [
        p for p in visible_policies if p.get("metadata", {}).get("namespace") in active_ns
    ]

    # ── Metrics ───────────────────────────────────────────────────────────────
    n_reachable = sum(1 for r in route_results if r["reachable"])
    n_blocked = len(route_results) - n_reachable
    c1, c2, c3, c4, c5, c6 = st.columns(6)
    c1.metric("Namespaces", len(active_ns))
    c2.metric("Workloads", len(workloads))
    c3.metric("NetworkPolicies", len(active_policies))
    c4.metric("Allowed flows", len(edges))
    c5.metric("Routes reachable", n_reachable)
    c6.metric("Routes blocked", n_blocked,
              delta=None if n_blocked == 0 else f"-{n_blocked}", delta_color="inverse")
    st.divider()

    if not workloads:
        st.warning("No pods found in the selected namespaces.")
        return

    tab_graph, tab_flows, tab_routes, tab_policies, tab_dot = st.tabs(
        ["📊 Diagram", "🔗 Allowed Flows", "🛣️ Routes", "📋 Policies", "⟨/⟩ DOT source"]
    )

    with tab_graph:
        if not edges and not external_nodes:
            st.info("No allowed flows found. Either no NetworkPolicies are configured, or all traffic is denied.")
        st.graphviz_chart(dot, use_container_width=True)

    with tab_flows:
        if not edges:
            st.info("No allowed flows to display.")
        else:
            rows = []
            for (src, dst), annotations in sorted(edges.items()):
                ports_set = sorted({pl for pl, _ in annotations})
                policy_names = sorted({pn for _, pn in annotations})
                src_w = workloads.get(src, {})
                dst_w = workloads.get(dst, {})
                rows.append({
                    "From workload": src_w.get("app", src),
                    "From namespace": src_w.get("namespace", src),
                    "To workload": dst_w.get("app", dst) if dst in workloads else dst,
                    "To namespace": dst_w.get("namespace", "") if dst in workloads else "external",
                    "Ports": " / ".join(ports_set),
                    "Policy": ", ".join(policy_names),
                })
            st.dataframe(rows, use_container_width=True, hide_index=True)

    with tab_routes:
        if not route_results:
            st.info("No routes found in selected namespaces.")
        else:
            blocked = [r for r in route_results if not r["reachable"]]
            reachable = [r for r in route_results if r["reachable"]]
            col_ok, col_bl = st.columns(2)
            with col_ok:
                st.success(f"**{len(reachable)} reachable** — router ingress allowed")
            with col_bl:
                if blocked:
                    st.error(f"**{len(blocked)} blocked** — no NetworkPolicy allows ingress from the OpenShift router")
                else:
                    st.success("**0 blocked**")

            st.markdown("#### Route flow diagram")
            rdot = route_diagram_dot(route_results, workloads, active_ns)
            if rdot:
                st.graphviz_chart(rdot, use_container_width=True)

            st.markdown("#### Details")
            rows = [
                {
                    "Status": "✅ Reachable" if r["reachable"] else "🚫 Blocked",
                    "TLS": "🔒" if r.get("tls") else "",
                    "Route": r["route_name"],
                    "Namespace": r["namespace"],
                    "Host": r["host"],
                    "Target Service": r["target_svc"],
                    "Reason": r["reason"],
                }
                for r in sorted(route_results, key=lambda x: (x["namespace"], x["route_name"]))
            ]
            st.dataframe(rows, hide_index=True, use_container_width=True)

    with tab_policies:
        if not active_policies:
            st.info("No NetworkPolicies found in the selected namespaces.")
        for pol in sorted(active_policies, key=lambda p: (
            p.get("metadata", {}).get("namespace", ""),
            p.get("metadata", {}).get("name", ""),
        )):
            meta = pol.get("metadata", {})
            spec = pol.get("spec", {})
            ns = meta.get("namespace", "")
            name = meta.get("name", "")
            types = spec.get("policyTypes", [])
            with st.expander(f"**{name}** · `{ns}` · {' + '.join(types)}"):
                col_a, col_b = st.columns(2)
                with col_a:
                    st.markdown("**Target selector**")
                    sel = spec.get("podSelector") or {}
                    st.code(
                        yaml.dump({"podSelector": sel}, default_flow_style=False).strip()
                        if sel else "podSelector: {}  # all pods in namespace",
                        language="yaml",
                    )
                with col_b:
                    st.markdown("**Policy types**")
                    for t in types:
                        st.badge(t)
                if spec.get("ingress") is not None:
                    st.markdown("**Ingress rules**")
                    st.code(yaml.dump(spec["ingress"], default_flow_style=False).strip(), language="yaml")
                if spec.get("egress") is not None:
                    st.markdown("**Egress rules**")
                    st.code(yaml.dump(spec["egress"], default_flow_style=False).strip(), language="yaml")

    with tab_dot:
        st.code(dot, language="dot")
        st.download_button("⬇ Download .dot", dot, file_name="netpol-map.dot", mime="text/plain")


main()
