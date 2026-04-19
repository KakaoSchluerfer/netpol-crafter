"""
Network Policy Map — visual connection diagram.

Shows which workloads (resolved by label) can communicate with each other
based on the NetworkPolicies active in the cluster.

How it works:
  1. Fetch all NetworkPolicies and all pods across selected namespaces.
  2. Run a label-matching engine: for each policy rule, find which workloads
     satisfy the selector (matchLabels + matchExpressions).
  3. Render a Graphviz directed graph: nodes = workloads, edges = allowed flows.
"""
from __future__ import annotations

import yaml

import streamlit as st

from config import get_config
from k8s.client import build_api_client_from_config
from k8s import (
    list_network_policies,
    list_all_pods,
    get_all_namespace_labels,
    list_namespaces,
)

st.set_page_config(page_title="Network Policy Map", layout="wide")

# ── Colour palette per namespace ──────────────────────────────────────────────
# (border_hex, bg_hex, node_fill_hex)
_NS_PALETTE: dict[str, tuple[str, str, str]] = {
    "payments":         ("#1B5E20", "#E8F5E9", "#A5D6A7"),
    "fraud-detection":  ("#BF360C", "#FBE9E7", "#FFAB91"),
    "account-services": ("#0D47A1", "#E3F2FD", "#90CAF9"),
    "api-gateway":      ("#4A148C", "#F3E5F5", "#CE93D8"),
    "monitoring":       ("#E65100", "#FFF3E0", "#FFCC80"),
    "infra":            ("#37474F", "#ECEFF1", "#B0BEC5"),
    "staging":          ("#880E4F", "#FCE4EC", "#F48FB1"),
}
_DEFAULT_PALETTE = ("#455A64", "#F5F5F5", "#CFD8DC")


def _ns_palette(ns: str) -> tuple[str, str, str]:
    return _NS_PALETTE.get(ns, _DEFAULT_PALETTE)


# ── Label-matching engine ─────────────────────────────────────────────────────

def _selector_matches(labels: dict[str, str], selector: dict | None) -> bool:
    """Return True if *labels* satisfy a Kubernetes LabelSelector dict."""
    if not selector:
        return True  # empty / null selector matches everything
    for k, v in (selector.get("matchLabels") or {}).items():
        if labels.get(k) != v:
            return False
    for expr in selector.get("matchExpressions") or []:
        key, op = expr["key"], expr["operator"]
        vals = set(expr.get("values") or [])
        pval = labels.get(key)
        if op == "In" and pval not in vals:
            return False
        if op == "NotIn" and pval in vals:
            return False
        if op == "Exists" and key not in labels:
            return False
        if op == "DoesNotExist" and key in labels:
            return False
    return True


# ── Workload deduplication ────────────────────────────────────────────────────

def _workload_key(pod: dict) -> str:
    """Stable identifier: namespace + primary app label."""
    ns = pod["namespace"]
    labels = pod.get("workload_labels") or pod.get("labels") or {}
    app = labels.get("app") or labels.get("name") or pod["name"].rsplit("-", 2)[0]
    return f"{ns}||{app}"


def _build_workloads(pods: list[dict]) -> dict[str, dict]:
    """Collapse individual pod replicas into {workload_key: workload_info}."""
    workloads: dict[str, dict] = {}
    for pod in pods:
        key = _workload_key(pod)
        if key not in workloads:
            labels = pod.get("workload_labels") or pod.get("labels") or {}
            app = labels.get("app") or labels.get("name") or pod["name"].rsplit("-", 2)[0]
            workloads[key] = {
                "key": key,
                "namespace": pod["namespace"],
                "app": app,
                "labels": labels,
            }
    return workloads


def _find_peers(
    workloads: dict[str, dict],
    ns_labels: dict[str, dict[str, str]],
    visible_ns: set[str],
    restrict_ns: str | None,
    ns_selector: dict | None,
    pod_selector: dict | None,
) -> list[str]:
    """Return workload keys matching a peer specification."""
    matches = []
    for key, w in workloads.items():
        ns = w["namespace"]
        if ns not in visible_ns:
            continue
        ns_lbls = ns_labels.get(ns, {"kubernetes.io/metadata.name": ns})

        if restrict_ns is not None:
            if ns != restrict_ns:
                continue
        elif ns_selector is not None:
            if not _selector_matches(ns_lbls, ns_selector):
                continue

        if not _selector_matches(w["labels"], pod_selector):
            continue
        matches.append(key)
    return matches


# ── Edge collection ───────────────────────────────────────────────────────────

def _format_ports(ports: list[dict] | None) -> str:
    if not ports:
        return "all ports"
    parts = []
    for p in ports:
        proto = p.get("protocol", "TCP")
        port = p.get("port", "")
        parts.append(f"{proto}:{port}" if port else proto)
    return " / ".join(parts)


def _collect_edges(
    policies: list[dict],
    workloads: dict[str, dict],
    ns_labels: dict[str, dict[str, str]],
    visible_ns: set[str],
    show_external: bool,
) -> tuple[dict[tuple[str, str], list[tuple[str, str]]], dict[str, str]]:
    """
    Returns:
      edges: {(src_key, dst_key): [(ports_label, policy_name), ...]}
      external_nodes: {cidr: node_id}
    """
    edges: dict[tuple[str, str], list[tuple[str, str]]] = {}
    external_nodes: dict[str, str] = {}

    def add(src: str, dst: str, ports: str, name: str) -> None:
        edges.setdefault((src, dst), []).append((ports, name))

    for pol in policies:
        meta = pol.get("metadata", {})
        spec = pol.get("spec", {})
        pol_ns = meta.get("namespace", "")
        pol_name = meta.get("name", "unknown")
        if pol_ns not in visible_ns:
            continue

        targets = _find_peers(
            workloads, ns_labels, visible_ns,
            restrict_ns=pol_ns,
            ns_selector=None,
            pod_selector=spec.get("podSelector"),
        )

        for rule in spec.get("ingress", []):
            ports_lbl = _format_ports(rule.get("ports"))
            peers = rule.get("from") or []
            if not peers:
                for src in workloads:
                    for tgt in targets:
                        if src != tgt:
                            add(src, tgt, ports_lbl, pol_name)
                continue
            for peer in peers:
                ip_block = peer.get("ipBlock")
                if ip_block:
                    if show_external:
                        cidr = ip_block.get("cidr", "0.0.0.0/0")
                        eid = "ext_" + cidr.replace("/", "_").replace(".", "_")
                        external_nodes[cidr] = eid
                        for tgt in targets:
                            add(eid, tgt, ports_lbl, pol_name)
                else:
                    sources = _find_peers(
                        workloads, ns_labels, visible_ns,
                        restrict_ns=None,
                        ns_selector=peer.get("namespaceSelector"),
                        pod_selector=peer.get("podSelector"),
                    )
                    for src in sources:
                        for tgt in targets:
                            if src != tgt:
                                add(src, tgt, ports_lbl, pol_name)

        for rule in spec.get("egress", []):
            ports_lbl = _format_ports(rule.get("ports"))
            peers = rule.get("to") or []
            if not peers:
                for dst in workloads:
                    for src in targets:
                        if src != dst:
                            add(src, dst, ports_lbl, pol_name)
                continue
            for peer in peers:
                ip_block = peer.get("ipBlock")
                if ip_block:
                    if show_external:
                        cidr = ip_block.get("cidr", "0.0.0.0/0")
                        eid = "ext_" + cidr.replace("/", "_").replace(".", "_")
                        external_nodes[cidr] = eid
                        for src in targets:
                            add(src, eid, ports_lbl, pol_name)
                else:
                    dests = _find_peers(
                        workloads, ns_labels, visible_ns,
                        restrict_ns=None,
                        ns_selector=peer.get("namespaceSelector"),
                        pod_selector=peer.get("podSelector"),
                    )
                    for dst in dests:
                        for src in targets:
                            if src != dst:
                                add(src, dst, ports_lbl, pol_name)

    return edges, external_nodes


# ── Graphviz DOT builder ──────────────────────────────────────────────────────

def _esc(text: str) -> str:
    """Escape text for use inside graphviz HTML-like labels."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _nid(key: str) -> str:
    """Quoted graphviz node ID."""
    return '"' + key.replace('"', '\\"') + '"'


def _build_dot(
    workloads: dict[str, dict],
    ns_labels: dict[str, dict[str, str]],
    edges: dict[tuple[str, str], list[tuple[str, str]]],
    external_nodes: dict[str, str],
    selected_ns: list[str],
) -> str:
    lines: list[str] = [
        "digraph netpol {",
        '  graph [rankdir=LR, fontname="Helvetica Neue", pad=0.6, nodesep=0.5, ranksep=1.2, compound=true]',
        '  node  [fontname="Helvetica Neue", fontsize=10, shape=box, style="filled,rounded", margin="0.18,0.12"]',
        '  edge  [fontname="Helvetica Neue", fontsize=9, arrowsize=0.75, arrowhead=vee]',
        "",
    ]

    by_ns: dict[str, list[str]] = {}
    for key, w in workloads.items():
        by_ns.setdefault(w["namespace"], []).append(key)

    for ns in selected_ns:
        if ns not in by_ns:
            continue
        border, bg, node_fill = _ns_palette(ns)
        ns_lbls = ns_labels.get(ns, {})
        ns_meta = " · ".join(
            f"{k}={_esc(v)}"
            for k, v in ns_lbls.items()
            if k != "kubernetes.io/metadata.name"
        )
        safe_cluster = ns.replace("-", "_")

        lines += [
            f"  subgraph cluster_{safe_cluster} {{",
            f'    label=<<B>{_esc(ns)}</B><BR/><FONT POINT-SIZE="8" COLOR="{border}">{_esc(ns_meta)}</FONT>>',
            f'    style=filled',
            f'    color="{border}"',
            f'    fillcolor="{bg}"',
            f'    fontname="Helvetica Neue"',
            f'    fontsize=13',
            f'    fontcolor="{border}"',
            "",
        ]

        for key in sorted(by_ns[ns]):
            w = workloads[key]
            app = w["app"]
            secondary = [
                f"{k}={_esc(str(v))}"
                for k, v in sorted(w["labels"].items())
                if k != "app"
            ][:3]
            sec_html = "<BR/>".join(secondary)
            lbl = (
                f'<<B>{_esc(app)}</B><BR/><FONT POINT-SIZE="8">{sec_html}</FONT>>'
                if sec_html
                else f'<<B>{_esc(app)}</B>>'
            )
            lines.append(
                f'    {_nid(key)} [label={lbl}, fillcolor="{node_fill}", color="{border}"]'
            )

        lines += ["  }", ""]

    for cidr, eid in external_nodes.items():
        lines.append(
            f'  {_nid(eid)} [label=<<B>External</B><BR/><FONT POINT-SIZE="9">{_esc(cidr)}</FONT>>, '
            f'shape=diamond, style="filled,dashed", fillcolor="#F5F5F5", color="#9E9E9E", fontcolor="#616161"]'
        )
    if external_nodes:
        lines.append("")

    seen: set[tuple[str, str]] = set()
    for (src, dst), annotations in sorted(edges.items()):
        if (src, dst) in seen:
            continue
        seen.add((src, dst))

        ports_set = sorted({pl for pl, _ in annotations})
        policy_names = sorted({pn for _, pn in annotations})
        port_str = " / ".join(ports_set)
        pol_str = ", ".join(policy_names)
        label = f"{port_str}\\n({pol_str})"

        dst_ns = workloads[dst]["namespace"] if dst in workloads else ""
        border, _, _ = _ns_palette(dst_ns)

        lines.append(
            f'  {_nid(src)} -> {_nid(dst)} '
            f'[label="{_esc(label)}", color="{border}", fontcolor="{border}", penwidth=1.8]'
        )

    lines.append("}")
    return "\n".join(lines)


# ── Page ──────────────────────────────────────────────────────────────────────

def _api_client():
    try:
        config = get_config()
        return build_api_client_from_config(config)
    except Exception:
        return None


def main() -> None:
    st.title("🗺 Network Policy Map")
    st.caption(
        "Directed graph of allowed pod-to-pod traffic derived from active "
        "NetworkPolicies. Workloads are resolved to their labels."
    )

    client = _api_client()

    with st.spinner("Loading cluster data…"):
        all_namespaces = list_namespaces(client)
        all_pods = list_all_pods(client)
        ns_labels = get_all_namespace_labels(client)
        policies = list_network_policies(client)

    # ── Sidebar ───────────────────────────────────────────────────────────────
    st.sidebar.header("Filters")
    selected_ns = st.sidebar.multiselect(
        "Namespaces",
        options=all_namespaces,
        default=all_namespaces,
        help="Show workloads and policies for these namespaces.",
    )
    show_external = st.sidebar.checkbox("Show external IP blocks", value=True)
    st.sidebar.divider()
    st.sidebar.subheader("Legend")
    for ns in selected_ns:
        border, _, fill = _ns_palette(ns)
        st.sidebar.markdown(
            f'<span style="display:inline-block;width:14px;height:14px;'
            f'background:{fill};border:2px solid {border};border-radius:3px;'
            f'margin-right:6px;vertical-align:middle"></span>**{ns}**',
            unsafe_allow_html=True,
        )

    if not selected_ns:
        st.info("Select at least one namespace in the sidebar.")
        return

    # ── Compute ───────────────────────────────────────────────────────────────
    visible_pods = [p for p in all_pods if p["namespace"] in selected_ns]
    workloads = _build_workloads(visible_pods)
    edges, external_nodes = _collect_edges(
        policies, workloads, ns_labels, set(selected_ns), show_external
    )
    active_policies = [
        p for p in policies if p.get("metadata", {}).get("namespace") in selected_ns
    ]

    # ── Metrics ───────────────────────────────────────────────────────────────
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Namespaces", len(selected_ns))
    c2.metric("Workloads", len(workloads))
    c3.metric("NetworkPolicies", len(active_policies))
    c4.metric("Allowed flows", len(edges))
    st.divider()

    if not workloads:
        st.warning("No pods found in the selected namespaces.")
        return

    dot = _build_dot(workloads, ns_labels, edges, external_nodes, selected_ns)

    tab_graph, tab_flows, tab_policies, tab_dot = st.tabs(
        ["📊 Diagram", "🔗 Allowed Flows", "📋 Policies", "⟨/⟩ DOT source"]
    )

    # ── Diagram tab ───────────────────────────────────────────────────────────
    with tab_graph:
        if not edges and not external_nodes:
            st.info(
                "No allowed flows found in the selected namespaces. "
                "Either no NetworkPolicies are configured, or all traffic is denied."
            )
        st.graphviz_chart(dot, width="stretch")

    # ── Flows table tab ───────────────────────────────────────────────────────
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
            st.dataframe(rows, width="stretch", hide_index=True)

    # ── Policy detail tab ─────────────────────────────────────────────────────
    with tab_policies:
        if not active_policies:
            st.info("No NetworkPolicies found in the selected namespaces.")
        for pol in sorted(
            active_policies,
            key=lambda p: (
                p.get("metadata", {}).get("namespace", ""),
                p.get("metadata", {}).get("name", ""),
            ),
        ):
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
                    st.code(
                        yaml.dump(spec["ingress"], default_flow_style=False).strip(),
                        language="yaml",
                    )
                if spec.get("egress") is not None:
                    st.markdown("**Egress rules**")
                    st.code(
                        yaml.dump(spec["egress"], default_flow_style=False).strip(),
                        language="yaml",
                    )

    # ── Raw DOT tab ───────────────────────────────────────────────────────────
    with tab_dot:
        st.code(dot, language="dot")
        st.download_button(
            "⬇ Download .dot", dot, file_name="netpol-map.dot", mime="text/plain"
        )


main()
