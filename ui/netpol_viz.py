"""
Shared NetworkPolicy visualisation helpers.

Used by:
  pages/Network_Policy_Map.py  – full cluster-wide map
  ui/policy_builder.py         – single-policy preview diagram
"""
from __future__ import annotations


# ── Colour palette ────────────────────────────────────────────────────────────

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


def ns_palette(ns: str) -> tuple[str, str, str]:
    """Return (border, background, node_fill) hex colours for a namespace."""
    return _NS_PALETTE.get(ns, _DEFAULT_PALETTE)


# ── Label-matching engine ─────────────────────────────────────────────────────

def selector_matches(labels: dict[str, str], selector: dict | None) -> bool:
    """Return True if *labels* satisfy a Kubernetes LabelSelector dict."""
    if not selector:
        return True
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

def _primary_app(pod: dict) -> str:
    labels = pod.get("workload_labels") or pod.get("labels") or {}
    return labels.get("app") or labels.get("name") or pod["name"].rsplit("-", 2)[0]


def workload_key(pod: dict) -> str:
    return f"{pod['namespace']}||{_primary_app(pod)}"


def build_workloads(pods: list[dict]) -> dict[str, dict]:
    """Collapse pod replicas into {workload_key: info}."""
    result: dict[str, dict] = {}
    for pod in pods:
        key = workload_key(pod)
        if key not in result:
            labels = pod.get("workload_labels") or pod.get("labels") or {}
            result[key] = {
                "key": key,
                "namespace": pod["namespace"],
                "app": _primary_app(pod),
                "labels": labels,
            }
    return result


def find_peers(
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
            if not selector_matches(ns_lbls, ns_selector):
                continue
        if not selector_matches(w["labels"], pod_selector):
            continue
        matches.append(key)
    return matches


# ── Port formatting ───────────────────────────────────────────────────────────

def format_ports(ports: list[dict] | None) -> str:
    if not ports:
        return "all ports"
    parts = []
    for p in ports:
        proto = p.get("protocol", "TCP")
        port = p.get("port", "")
        parts.append(f"{proto}:{port}" if port else proto)
    return " / ".join(parts)


# ── Edge collection ───────────────────────────────────────────────────────────

def collect_edges(
    policies: list[dict],
    workloads: dict[str, dict],
    ns_labels: dict[str, dict[str, str]],
    visible_ns: set[str],
    show_external: bool = True,
) -> tuple[dict[tuple[str, str], list[tuple[str, str]]], dict[str, str]]:
    """
    Returns:
      edges:          {(src_key, dst_key): [(ports_label, policy_name), ...]}
      external_nodes: {cidr_str: node_id}
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

        targets = find_peers(
            workloads, ns_labels, visible_ns,
            restrict_ns=pol_ns,
            ns_selector=None,
            pod_selector=spec.get("podSelector"),
        )

        for rule in spec.get("ingress", []):
            ports_lbl = format_ports(rule.get("ports"))
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
                    sources = find_peers(
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
            ports_lbl = format_ports(rule.get("ports"))
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
                    dests = find_peers(
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


# ── DOT builder ───────────────────────────────────────────────────────────────

def _esc(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _nid(key: str) -> str:
    return '"' + key.replace('"', '\\"') + '"'


def build_dot(
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
        border, bg, node_fill = ns_palette(ns)
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
            secondary = [
                f"{k}={_esc(str(v))}"
                for k, v in sorted(w["labels"].items())
                if k != "app"
            ][:3]
            sec_html = "<BR/>".join(secondary)
            lbl = (
                f'<<B>{_esc(w["app"])}</B><BR/><FONT POINT-SIZE="8">{sec_html}</FONT>>'
                if sec_html
                else f'<<B>{_esc(w["app"])}</B>>'
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
        label = " / ".join(ports_set) + "\\n(" + ", ".join(policy_names) + ")"
        dst_ns = workloads[dst]["namespace"] if dst in workloads else ""
        border, _, _ = ns_palette(dst_ns)
        lines.append(
            f'  {_nid(src)} -> {_nid(dst)} '
            f'[label="{_esc(label)}", color="{border}", fontcolor="{border}", penwidth=1.8]'
        )

    lines.append("}")
    return "\n".join(lines)


# ── High-level entry points ───────────────────────────────────────────────────

def policy_preview_dot(
    policy_dict: dict,
    all_pods: list[dict],
    ns_labels: dict[str, dict[str, str]],
    show_external: bool = True,
) -> tuple[str, int]:
    """
    Build a DOT diagram for a single crafted policy.

    Returns (dot_string, num_flows).
    Uses all_pods + ns_labels from the cluster to resolve selectors.
    """
    workloads = build_workloads(all_pods)
    visible_ns = set(ns_labels.keys()) | {w["namespace"] for w in workloads.values()}

    edges, external_nodes = collect_edges(
        [policy_dict], workloads, ns_labels, visible_ns, show_external
    )

    # Only keep namespaces that appear in at least one edge
    relevant_ns: set[str] = set()
    for src, dst in edges:
        if src in workloads:
            relevant_ns.add(workloads[src]["namespace"])
        if dst in workloads:
            relevant_ns.add(workloads[dst]["namespace"])
    for cidr in external_nodes:
        pass  # external nodes handled separately

    # Always include the policy's own namespace
    pol_ns = policy_dict.get("metadata", {}).get("namespace", "")
    if pol_ns:
        relevant_ns.add(pol_ns)

    # Filter workloads to only those in relevant namespaces
    filtered_workloads = {
        k: v for k, v in workloads.items() if v["namespace"] in relevant_ns
    }

    dot = build_dot(
        filtered_workloads,
        ns_labels,
        edges,
        external_nodes,
        sorted(relevant_ns),
    )
    return dot, len(edges)


def cluster_map_dot(
    policies: list[dict],
    all_pods: list[dict],
    ns_labels: dict[str, dict[str, str]],
    selected_ns: list[str],
    show_external: bool = True,
) -> tuple[str, dict[tuple[str, str], list[tuple[str, str]]], dict[str, str]]:
    """
    Build a DOT diagram for the full cluster map.

    Returns (dot_string, edges, external_nodes).
    """
    visible_pods = [p for p in all_pods if p["namespace"] in selected_ns]
    workloads = build_workloads(visible_pods)
    edges, external_nodes = collect_edges(
        policies, workloads, ns_labels, set(selected_ns), show_external
    )
    dot = build_dot(workloads, ns_labels, edges, external_nodes, selected_ns)
    return dot, edges, external_nodes
