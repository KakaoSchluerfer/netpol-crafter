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
)
from ui.netpol_viz import (
    ns_palette, build_workloads, compute_cluster_data, build_dot,
    check_route_reachability, route_diagram_dot,
    cidr_label, merge_edge_ports, is_intra_namespace_only, detect_policy_issues,
)

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
    all_routes     = snapshot_all_routes(snapshot)
    all_services   = snapshot_all_services(snapshot)

    logger.debug("Snapshot: %d namespaces, %d pods, %d policies",
                 len(all_namespaces), len(all_pods), len(policies))

    _DEFAULT_POLICY_NAMES = frozenset({
        "allow-all-within-namespace",
        "default-deny-all-ingress-and-egress",
    })

    # Build lookup indexes once
    _all_workloads = build_workloads(all_pods)
    ns_to_apps: dict[str, list[str]] = {}
    for w in _all_workloads.values():
        ns_to_apps.setdefault(w["namespace"], set()).add(w["app"])
    ns_to_apps = {ns: sorted(apps) for ns, apps in ns_to_apps.items()}

    ns_to_policies: dict[str, list[str]] = {}
    ns_intra_policies: dict[str, set[str]] = {}
    for p in policies:
        ns = p.get("metadata", {}).get("namespace", "")
        name = p.get("metadata", {}).get("name", "")
        if ns and name:
            ns_to_policies.setdefault(ns, []).append(name)
            if is_intra_namespace_only(p):
                ns_intra_policies.setdefault(ns, set()).add(name)
    ns_to_policies = {ns: sorted(names) for ns, names in ns_to_policies.items()}

    # External endpoints (ipBlock CIDRs) referenced by each namespace's policies
    ns_to_ext_cidrs: dict[str, list[str]] = {}
    for p in policies:
        ns = p.get("metadata", {}).get("namespace", "")
        spec = p.get("spec", {})
        for rule in (spec.get("ingress") or []) + (spec.get("egress") or []):
            for peer in (rule.get("from") or []) + (rule.get("to") or []):
                ip_block = peer.get("ipBlock")
                if ip_block:
                    cidr = ip_block.get("cidr", "0.0.0.0/0")
                    ns_to_ext_cidrs.setdefault(ns, set()).add(cidr)  # type: ignore[arg-type]
    ns_to_ext_cidrs = {ns: sorted(cidrs) for ns, cidrs in ns_to_ext_cidrs.items()}

    # ── Sidebar ───────────────────────────────────────────────────────────────
    st.sidebar.header("Cluster")
    st.sidebar.markdown(f"**{config.cluster_name}**")
    st.sidebar.divider()

    st.sidebar.header("Filters")
    selected_ns = st.sidebar.multiselect(
        "Namespaces", options=all_namespaces, default=[],
        help="Select namespaces, then choose workloads and policies within each.",
    )

    # Per-namespace workload + policy + external endpoint selectors
    ns_selected_apps: dict[str, list[str]] = {}
    ns_selected_policies: dict[str, set[str]] = {}
    ns_selected_ext: dict[str, set[str]] = {}

    for ns in selected_ns:
        st.sidebar.markdown(f"**{ns}**")

        apps = ns_to_apps.get(ns, [])
        ns_selected_apps[ns] = st.sidebar.multiselect(
            "Workloads",
            options=apps,
            default=[],
            key=f"wl_{ns}",
            placeholder="Select workloads…" if apps else "No workloads found",
            disabled=not apps,
        )

        pol_names = ns_to_policies.get(ns, [])
        _hidden = _DEFAULT_POLICY_NAMES | ns_intra_policies.get(ns, set())
        default_pol_selection = [n for n in pol_names if n not in _hidden]
        ns_selected_policies[ns] = set(st.sidebar.multiselect(
            "Network Policies",
            options=pol_names,
            default=default_pol_selection,
            key=f"pol_{ns}",
            placeholder="Select policies…" if pol_names else "No policies found",
            disabled=not pol_names,
        ))

        ext_cidrs = ns_to_ext_cidrs.get(ns, [])
        if ext_cidrs:
            _ext_labels = {c: cidr_label(c) for c in ext_cidrs}
            ns_selected_ext[ns] = set(st.sidebar.multiselect(
                "External Endpoints",
                options=ext_cidrs,
                default=[],
                format_func=lambda c, _lbl=_ext_labels: _lbl[c],
                key=f"ext_{ns}",
                placeholder="Select external endpoints…",
            ))
        else:
            ns_selected_ext[ns] = set()

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

    # Only pass policies the user explicitly selected — this is the sole source of
    # truth for which flows are visible in the diagram and the flows table.
    visible_policies = [
        p for p in policies
        if p.get("metadata", {}).get("name") in ns_selected_policies.get(
            p.get("metadata", {}).get("namespace", ""), set()
        )
    ]

    # ── Aggregate selected external endpoints across all active namespaces ────
    selected_ext: set[str] = set()
    for ns in active_ns:
        selected_ext.update(ns_selected_ext.get(ns, set()))

    # ── Compute cluster data ──────────────────────────────────────────────────
    workloads, edges_all, ext_nodes_all, _, _ = compute_cluster_data(
        visible_policies, filtered_pods, ns_labels, active_ns, show_external=True,
    )

    # ── Apply external endpoints filter ──────────────────────────────────────
    external_nodes = {c: e for c, e in ext_nodes_all.items() if c in selected_ext}
    kept_eids = set(external_nodes.values())
    edges = {
        (src, dst): v for (src, dst), v in edges_all.items()
        if not (src.startswith("ext_") and src not in kept_eids)
        and not (dst.startswith("ext_") and dst not in kept_eids)
    }

    # ── Route reachability ────────────────────────────────────────────────────
    route_results = check_route_reachability(
        [r for r in all_routes if r["namespace"] in active_ns],
        [s for s in all_services if s["namespace"] in active_ns],
        filtered_pods,
        [p for p in visible_policies if p.get("metadata", {}).get("namespace") in active_ns],
        ns_labels,
    )

    # ── Render DOT (skip when too many flows to keep the diagram readable) ────
    _FLOW_LIMIT = 100
    _too_many = len(edges) > _FLOW_LIMIT
    dot = (
        ""
        if _too_many
        else build_dot(
            workloads, ns_labels, edges, external_nodes, active_ns,
            route_results=route_results,
        )
    )
    active_policies = [
        p for p in visible_policies
        if p.get("metadata", {}).get("namespace") in active_ns
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

    tab_graph, tab_flows, tab_routes, tab_policies, tab_issues, tab_dot = st.tabs(
        ["📊 Diagram", "🔗 Allowed Flows", "🛣️ Routes", "📋 Policies", "⚠️ Issues", "⟨/⟩ DOT source"]
    )

    with tab_graph:
        if _too_many:
            st.warning(
                f"**{len(edges)} flows detected** — too many to render clearly. "
                f"Please narrow the workload or policy selection to fewer than {_FLOW_LIMIT} flows."
            )
        elif not edges and not external_nodes:
            st.info("No allowed flows found. Either no NetworkPolicies are configured, or all traffic is denied.")
        else:
            st.graphviz_chart(dot, use_container_width=True)

    with tab_flows:
        if not edges:
            st.info("No allowed flows to display.")
        else:
            rows = []
            for (src, dst), annotations in sorted(edges.items()):
                policy_names = sorted({pn for _, pn in annotations})
                src_w = workloads.get(src, {})
                dst_w = workloads.get(dst, {})
                rows.append({
                    "From workload": src_w.get("app", src),
                    "From namespace": src_w.get("namespace", src),
                    "To workload": dst_w.get("app", dst) if dst in workloads else dst,
                    "To namespace": dst_w.get("namespace", "") if dst in workloads else "external",
                    "Ports": merge_edge_ports(annotations),
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
                st.markdown("**Full YAML**")
                st.code(
                    yaml.dump({
                        "apiVersion": "networking.k8s.io/v1",
                        "kind": "NetworkPolicy",
                        "metadata": {"name": name, "namespace": ns},
                        "spec": spec,
                    }, default_flow_style=False, sort_keys=False),
                    language="yaml",
                )

    with tab_issues:
        flagged = []
        for pol in active_policies:
            issues = detect_policy_issues(pol)
            if issues:
                meta = pol.get("metadata", {})
                flagged.append({
                    "policy": pol,
                    "name": meta.get("name", ""),
                    "namespace": meta.get("namespace", ""),
                    "issues": issues,
                })

        if not flagged:
            st.success("No policy issues detected in the selected namespaces.")
        else:
            st.warning(
                f"**{len(flagged)} policy issue(s) detected.** "
                + ("Unrestricted rules produce no edges in the diagram."
                   if not _too_many
                   else "Review and fix these policies to improve visibility.")
            )
            for item in sorted(flagged, key=lambda x: (x["namespace"], x["name"])):
                pol = item["policy"]
                spec = pol.get("spec", {})
                _ns = item["namespace"]
                _name = item["name"]
                with st.expander(f"**{_name}** · `{_ns}`"):
                    for issue in item["issues"]:
                        st.error(issue, icon="⚠️")
                    if spec.get("ingress") is not None:
                        st.markdown("**Ingress rules**")
                        st.code(yaml.dump(spec["ingress"], default_flow_style=False).strip(),
                                language="yaml")
                    if spec.get("egress") is not None:
                        st.markdown("**Egress rules**")
                        st.code(yaml.dump(spec["egress"], default_flow_style=False).strip(),
                                language="yaml")
                    st.markdown("**Full YAML**")
                    st.code(
                        yaml.dump({
                            "apiVersion": "networking.k8s.io/v1",
                            "kind": "NetworkPolicy",
                            "metadata": {"name": _name, "namespace": _ns},
                            "spec": spec,
                        }, default_flow_style=False, sort_keys=False),
                        language="yaml",
                    )

    with tab_dot:
        if _too_many:
            st.info("DOT source is not generated when flow count exceeds the render limit.")
        else:
            st.code(dot, language="dot")
            st.download_button("⬇ Download .dot", dot, file_name="netpol-map.dot", mime="text/plain")


main()
