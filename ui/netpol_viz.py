"""
Shared NetworkPolicy visualisation helpers.

Used by:
  pages/Network_Policy_Map.py  – full cluster-wide map
  ui/policy_builder.py         – single-policy preview diagram
"""
from __future__ import annotations

import hashlib
import socket
from functools import lru_cache


# ── OpenShift Router constants ────────────────────────────────────────────────
INGRESS_CTRL_NS = "openshift-ingress"

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

# ── Per-workload colour palette ───────────────────────────────────────────────

_WORKLOAD_COLORS: list[str] = [
    "#1565C0", "#2E7D32", "#B71C1C", "#6A1B9A",
    "#E65100", "#00695C", "#4E342E", "#37474F",
    "#F57F17", "#880E4F", "#1A237E", "#33691E",
    "#BF360C", "#006064", "#4A148C", "#827717",
]


def _lighten(color: str, factor: float = 0.12) -> str:
    r, g, b = int(color[1:3], 16), int(color[3:5], 16), int(color[5:7], 16)
    return (
        f"#{int(r * factor + 255 * (1 - factor)):02X}"
        f"{int(g * factor + 255 * (1 - factor)):02X}"
        f"{int(b * factor + 255 * (1 - factor)):02X}"
    )


def _wl_color(key: str) -> tuple[str, str]:
    """Return (border, fill) for a workload key — deterministic, stable across restarts."""
    h = int(hashlib.md5(key.encode()).hexdigest(), 16)
    border = _WORKLOAD_COLORS[h % len(_WORKLOAD_COLORS)]
    return border, _lighten(border)


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
    """Compact a K8s port list into a human-readable string.

    Adjacent or overlapping numeric port ranges are merged:
      [{port:80}, {port:81}, {port:82}]  →  TCP:80-82
      [{port:0, endPort:8000}]           →  TCP:0-8000
    Named ports and protocol-only entries are left as-is.
    """
    if not ports:
        return "all ports"

    by_proto: dict[str, list[tuple[int, int]]] = {}
    extras: list[str] = []

    for p in ports:
        proto = p.get("protocol", "TCP")
        port = p.get("port")
        end_port = p.get("endPort")
        if port is None:
            extras.append(proto)
            continue
        try:
            start = int(port)
            end = int(end_port) if end_port is not None else start
            by_proto.setdefault(proto, []).append((min(start, end), max(start, end)))
        except (ValueError, TypeError):
            extras.append(f"{proto}:{port}")

    parts: list[str] = []
    for proto in sorted(by_proto):
        merged: list[tuple[int, int]] = []
        for start, end in sorted(by_proto[proto]):
            if merged and start <= merged[-1][1] + 1:
                merged[-1] = (merged[-1][0], max(merged[-1][1], end))
            else:
                merged.append((start, end))
        for start, end in merged:
            parts.append(f"{proto}:{start}" if start == end else f"{proto}:{start}-{end}")

    parts.extend(extras)
    return " / ".join(parts) if parts else "all ports"


# ── DNS helpers ──────────────────────────────────────────────────────────────

@lru_cache(maxsize=256)
def _resolve_ptr(ip: str) -> str:
    """Reverse-DNS lookup with 1 s timeout; returns the IP itself on failure."""
    old = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(1.0)
        host, _, _ = socket.gethostbyaddr(ip)
        return host
    except Exception:
        return ip
    finally:
        socket.setdefaulttimeout(old)


def cidr_label(cidr: str) -> str:
    """Human-readable label for a CIDR.  'hostname (cidr)' when resolvable, else 'cidr'."""
    ip = cidr.split("/")[0]
    host = _resolve_ptr(ip)
    return f"{host} ({cidr})" if host != ip else cidr


# ── Port-annotation merger ────────────────────────────────────────────────────

def merge_edge_ports(annotations: list[tuple[list[dict] | None, str]]) -> str:
    """Merge raw port lists from multiple rules into one compact label.

    annotations is a list of (raw_ports, policy_name) tuples where raw_ports is
    None (= all ports) or a list of K8s port dicts.
    """
    all_ports: list[dict] = []
    for raw_ports, _ in annotations:
        if raw_ports is None:
            return "all ports"
        all_ports.extend(raw_ports)
    return format_ports(all_ports) if all_ports else "all ports"


# ── Policy issue detection ────────────────────────────────────────────────────

def detect_policy_issues(policy: dict) -> list[str]:
    """Return human-readable issue descriptions for a potentially misconfigured policy.

    Returns [] when the policy looks correct.
    """
    spec = policy.get("spec", {})
    policy_types = set(spec.get("policyTypes") or [])
    issues: list[str] = []

    if "Ingress" in policy_types:
        ingress_rules = spec.get("ingress") or []
        if not ingress_rules:
            issues.append(
                "policyTypes declares Ingress but no ingress rules are defined — "
                "this silently denies all ingress traffic."
            )
        elif not any(r.get("from") for r in ingress_rules):
            issues.append(
                "policyTypes declares Ingress but every ingress rule has an empty 'from' list — "
                "this allows all ingress unrestricted and is likely unintentional."
            )

    if "Egress" in policy_types:
        egress_rules = spec.get("egress") or []
        if not egress_rules:
            issues.append(
                "policyTypes declares Egress but no egress rules are defined — "
                "this silently denies all egress traffic."
            )
        elif not any(r.get("to") for r in egress_rules):
            issues.append(
                "policyTypes declares Egress but every egress rule has an empty 'to' list — "
                "this allows all egress unrestricted and is likely unintentional."
            )

    return issues


# ── Intra-namespace policy detection ─────────────────────────────────────────

def is_intra_namespace_only(policy: dict) -> bool:
    """Return True when every peer in every rule is podSelector-only (same namespace).

    Policies with empty from/to lists (= allow all sources/destinations),
    namespaceSelector, or ipBlock peers are NOT considered intra-namespace.
    """
    spec = policy.get("spec", {})
    ingress_rules = spec.get("ingress") or []
    egress_rules  = spec.get("egress")  or []
    if not ingress_rules and not egress_rules:
        return False
    for rule in ingress_rules:
        peers = rule.get("from") or []
        if not peers:
            return False  # empty from = allow all sources
        for peer in peers:
            if peer.get("namespaceSelector") is not None or peer.get("ipBlock") is not None:
                return False
    for rule in egress_rules:
        peers = rule.get("to") or []
        if not peers:
            return False  # empty to = allow all destinations
        for peer in peers:
            if peer.get("namespaceSelector") is not None or peer.get("ipBlock") is not None:
                return False
    return True


# ── Edge collection ───────────────────────────────────────────────────────────

def collect_edges(
    policies: list[dict],
    workloads: dict[str, dict],
    ns_labels: dict[str, dict[str, str]],
    visible_ns: set[str],
    show_external: bool = True,
) -> tuple[dict[tuple[str, str], list[tuple[list[dict] | None, str]]], dict[str, str]]:
    """
    Returns:
      edges:          {(src_key, dst_key): [(raw_ports, policy_name), ...]}
                      raw_ports is None → all ports; list[dict] → K8s port entries
      external_nodes: {cidr_str: node_id}
    """
    edges: dict[tuple[str, str], list[tuple[list[dict] | None, str]]] = {}
    external_nodes: dict[str, str] = {}

    def add(src: str, dst: str, ports: list[dict] | None, name: str) -> None:
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

        # Respect policyTypes — only visualise directions the policy declares.
        # K8s default when policyTypes is absent: Ingress always; Egress only if
        # egress rules are present in the spec.
        declared = set(spec.get("policyTypes") or [])
        if not declared:
            declared.add("Ingress")
            if spec.get("egress") is not None:
                declared.add("Egress")

        ingress_rules = spec.get("ingress", []) if "Ingress" in declared else []
        egress_rules  = spec.get("egress",  []) if "Egress"  in declared else []

        for rule in ingress_rules:
            raw_ports = rule.get("ports") or None
            peers = rule.get("from") or []
            if not peers:
                # Empty from = allow all sources. Not visualized — surfaces in the
                # Issues tab. Generating all-to-all edges would create noise and is
                # usually a sign of a misconfigured policy.
                continue
            for peer in peers:
                # Check KEY PRESENCE so an empty/null ipBlock never falls through
                # to the pod-type branch and creates spurious pod-to-pod edges.
                is_ip_peer = "ipBlock" in peer or "ip_block" in peer
                if is_ip_peer:
                    ip_block = peer.get("ipBlock") or peer.get("ip_block") or {}
                    if show_external and ip_block.get("cidr"):
                        cidr = ip_block["cidr"]
                        eid = "ext_" + cidr.replace("/", "_").replace(".", "_")
                        external_nodes[cidr] = eid
                        for tgt in targets:
                            add(eid, tgt, raw_ports, pol_name)
                else:
                    ns_sel = (peer.get("namespaceSelector")
                              or peer.get("namespace_selector"))
                    sources = find_peers(
                        workloads, ns_labels, visible_ns,
                        restrict_ns=None if ns_sel is not None else pol_ns,
                        ns_selector=ns_sel,
                        pod_selector=(peer.get("podSelector")
                                      or peer.get("pod_selector")),
                    )
                    for src in sources:
                        for tgt in targets:
                            if src != tgt:
                                add(src, tgt, raw_ports, pol_name)

        for rule in egress_rules:
            raw_ports = rule.get("ports") or None
            peers = rule.get("to") or []
            if not peers:
                # Empty to = allow all destinations. Not visualized — see Issues tab.
                continue
            for peer in peers:
                is_ip_peer = "ipBlock" in peer or "ip_block" in peer
                if is_ip_peer:
                    ip_block = peer.get("ipBlock") or peer.get("ip_block") or {}
                    if show_external and ip_block.get("cidr"):
                        cidr = ip_block["cidr"]
                        eid = "ext_" + cidr.replace("/", "_").replace(".", "_")
                        external_nodes[cidr] = eid
                        for src in targets:
                            add(src, eid, raw_ports, pol_name)
                else:
                    ns_sel = (peer.get("namespaceSelector")
                              or peer.get("namespace_selector"))
                    dests = find_peers(
                        workloads, ns_labels, visible_ns,
                        restrict_ns=None if ns_sel is not None else pol_ns,
                        ns_selector=ns_sel,
                        pod_selector=(peer.get("podSelector")
                                      or peer.get("pod_selector")),
                    )
                    for dst in dests:
                        for src in targets:
                            if src != dst:
                                add(src, dst, raw_ports, pol_name)

    return edges, external_nodes


# ── ANP edge collection ───────────────────────────────────────────────────────

def find_ns_peers(
    ns_labels: dict[str, dict[str, str]],
    visible_ns: set[str],
    ns_selector: dict | None,
) -> list[str]:
    """Return namespace names that match a namespaceSelector (or all visible if selector is empty/None)."""
    result = []
    for ns in visible_ns:
        lbls = ns_labels.get(ns, {"kubernetes.io/metadata.name": ns})
        if selector_matches(lbls, ns_selector):
            result.append(ns)
    return result


def collect_anp_edges(
    anps: list[dict],
    workloads: dict[str, dict],
    ns_labels: dict[str, dict[str, str]],
    visible_ns: set[str],
) -> tuple[dict[tuple[str, str], tuple[str, str]], dict[str, str]]:
    """
    Process AdminNetworkPolicies and return (edges, external_nodes).

    ANPs apply at namespace scope, so edges connect namespace names (not pod keys).
    edges: {(src_ns_or_eid, dst_ns_or_eid): (ports_label, "ANP:{name} {action}")}
    external_nodes: {cidr: eid}
    Only Allow/Deny actions are included (Pass is skipped).
    """
    edges: dict[tuple[str, str], tuple[str, str]] = {}
    external_nodes: dict[str, str] = {}

    def _subject_namespaces(subject: dict) -> list[str]:
        ns_subj = subject.get("namespaces")
        if ns_subj is not None:
            return find_ns_peers(ns_labels, visible_ns, ns_subj)
        pod_subj = subject.get("pods", {})
        wl_keys = find_peers(workloads, ns_labels, visible_ns,
                             restrict_ns=None,
                             ns_selector=pod_subj.get("namespaceSelector"),
                             pod_selector=pod_subj.get("podSelector"))
        return list({workloads[k]["namespace"] for k in wl_keys})

    for anp in sorted(anps, key=lambda a: a.get("priority", 0)):
        name = anp["name"]
        spec = anp.get("spec", {})
        target_ns_list = _subject_namespaces(spec.get("subject", {}))

        for rule in spec.get("ingress", []):
            action = rule.get("action", "Allow")
            if action == "Pass":
                continue
            ports_lbl = _format_anp_ports(rule.get("ports"))
            label = f"ANP:{name} {action}"
            for peer in rule.get("from", []):
                networks = peer.get("networks")
                if networks is not None:
                    for net in networks:
                        cidr = net.get("cidr", "0.0.0.0/0")
                        eid = "ext_" + cidr.replace("/", "_").replace(".", "_")
                        external_nodes[cidr] = eid
                        for tgt_ns in target_ns_list:
                            edges[(eid, tgt_ns)] = (ports_lbl or "all ports", label)
                    continue
                ns_p = peer.get("namespaces")
                pod_p = peer.get("pods", {})
                if ns_p is not None:
                    source_ns = find_ns_peers(ns_labels, visible_ns, ns_p)
                else:
                    wl_keys = find_peers(workloads, ns_labels, visible_ns,
                                        restrict_ns=None,
                                        ns_selector=pod_p.get("namespaceSelector"),
                                        pod_selector=pod_p.get("podSelector"))
                    source_ns = list({workloads[k]["namespace"] for k in wl_keys})
                for src_ns in source_ns:
                    for tgt_ns in target_ns_list:
                        if src_ns != tgt_ns:
                            edges[(src_ns, tgt_ns)] = (ports_lbl or "all ports", label)

        for rule in spec.get("egress", []):
            action = rule.get("action", "Allow")
            if action == "Pass":
                continue
            ports_lbl = _format_anp_ports(rule.get("ports"))
            label = f"ANP:{name} {action}"
            for peer in rule.get("to", []):
                networks = peer.get("networks")
                if networks is not None:
                    for net in networks:
                        cidr = net.get("cidr", "0.0.0.0/0")
                        eid = "ext_" + cidr.replace("/", "_").replace(".", "_")
                        external_nodes[cidr] = eid
                        for src_ns in target_ns_list:
                            edges[(src_ns, eid)] = (ports_lbl or "all ports", label)
                    continue
                ns_p = peer.get("namespaces")
                pod_p = peer.get("pods", {})
                if ns_p is not None:
                    dest_ns = find_ns_peers(ns_labels, visible_ns, ns_p)
                else:
                    wl_keys = find_peers(workloads, ns_labels, visible_ns,
                                        restrict_ns=None,
                                        ns_selector=pod_p.get("namespaceSelector"),
                                        pod_selector=pod_p.get("podSelector"))
                    dest_ns = list({workloads[k]["namespace"] for k in wl_keys})
                for dst_ns in dest_ns:
                    for src_ns in target_ns_list:
                        if src_ns != dst_ns:
                            edges[(src_ns, dst_ns)] = (ports_lbl or "all ports", label)

    return edges, external_nodes


def _format_anp_ports(ports: list | None) -> str:
    if not ports:
        return ""
    parts = []
    for p in ports:
        pn = p.get("portNumber") or p.get("portRange") or {}
        proto = pn.get("protocol", "TCP")
        port = pn.get("port", pn.get("start", ""))
        end = pn.get("end", "")
        if end:
            parts.append(f"{proto}:{port}-{end}")
        elif port:
            parts.append(f"{proto}:{port}")
        else:
            parts.append(proto)
    return " / ".join(parts)


# ── Route reachability ────────────────────────────────────────────────────────

def check_route_reachability(
    routes: list[dict],
    services: list[dict],
    pods: list[dict],
    policies: list[dict],
    ns_labels: dict[str, dict[str, str]],
) -> list[dict]:
    """
    For each route check whether any NetworkPolicy allows ingress from
    the OpenShift router namespace (openshift-ingress).

    Returns list of {route_name, namespace, host, target_svc, reachable, reason}.
    """
    svc_by_key = {(s["namespace"], s["name"]): s for s in services}
    pods_by_ns: dict[str, list[dict]] = {}
    for pod in pods:
        pods_by_ns.setdefault(pod["namespace"], []).append(pod)
    policies_by_ns: dict[str, list[dict]] = {}
    for pol in policies:
        ns = pol.get("metadata", {}).get("namespace", "")
        policies_by_ns.setdefault(ns, []).append(pol)

    ingress_ns_labels = ns_labels.get(
        INGRESS_CTRL_NS, {"kubernetes.io/metadata.name": INGRESS_CTRL_NS}
    )

    results = []
    for route in routes:
        ns = route["namespace"]
        name = route["name"]
        host = route.get("host", "")
        tls = route.get("tls", False)
        target_svc_name = route.get("to", {}).get("name", "")

        if not target_svc_name:
            results.append({"route_name": name, "namespace": ns, "host": host, "tls": tls,
                            "target_svc": "", "reachable": False,
                            "reason": "No target service configured"})
            continue

        svc = svc_by_key.get((ns, target_svc_name))
        if not svc:
            results.append({"route_name": name, "namespace": ns, "host": host, "tls": tls,
                            "target_svc": target_svc_name, "reachable": False,
                            "reason": f"Service '{target_svc_name}' not found"})
            continue

        svc_selector = svc.get("selector", {})
        ns_pods = pods_by_ns.get(ns, [])
        target_pods = (
            [p for p in ns_pods if all(p.get("labels", {}).get(k) == v
             for k, v in svc_selector.items())]
            if svc_selector else ns_pods
        )
        if not target_pods:
            results.append({"route_name": name, "namespace": ns, "host": host, "tls": tls,
                            "target_svc": target_svc_name, "reachable": False,
                            "reason": "No pods match service selector"})
            continue

        ns_policies = policies_by_ns.get(ns, [])
        pod_labels = (target_pods[0].get("workload_labels")
                      or target_pods[0].get("labels", {}))

        # Find policies with Ingress that select these pods
        isolating_policies = [
            pol for pol in ns_policies
            if "Ingress" in pol.get("spec", {}).get("policyTypes", ["Ingress"])
            and selector_matches(pod_labels, pol.get("spec", {}).get("podSelector"))
        ]

        if not isolating_policies:
            results.append({"route_name": name, "namespace": ns, "host": host, "tls": tls,
                            "target_svc": target_svc_name, "reachable": True,
                            "reason": "No ingress isolation (no matching NetworkPolicy)"})
            continue

        allowed = False
        for pol in isolating_policies:
            for rule in pol.get("spec", {}).get("ingress", []):
                peers = rule.get("from", [])
                if not peers:
                    allowed = True
                    break
                for peer in peers:
                    if peer.get("ipBlock"):
                        continue
                    ns_sel = peer.get("namespaceSelector")
                    if ns_sel is not None and selector_matches(ingress_ns_labels, ns_sel):
                        allowed = True
                        break
                if allowed:
                    break
            if allowed:
                break

        results.append({
            "route_name": name, "namespace": ns, "host": host, "tls": tls,
            "target_svc": target_svc_name, "reachable": allowed,
            "reason": (
                f"NetworkPolicy allows ingress from '{INGRESS_CTRL_NS}'" if allowed
                else f"No NetworkPolicy allows ingress from '{INGRESS_CTRL_NS}'"
            ),
        })
    return results


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
    anp_edges: dict[tuple[str, str], tuple[str, str]] | None = None,
    route_results: list[dict] | None = None,
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
        border, bg, _ = ns_palette(ns)
        safe_cluster = ns.replace("-", "_")

        lines += [
            f"  subgraph cluster_{safe_cluster} {{",
            f'    label=<<B>{_esc(ns)}</B>>',
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
            wl_border, wl_fill = _wl_color(key)
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
                f'    {_nid(key)} [label={lbl}, fillcolor="{wl_fill}", color="{wl_border}", penwidth=1.5]'
            )

        lines += ["  }", ""]

    for cidr, eid in external_nodes.items():
        ip = cidr.split("/")[0]
        host = _resolve_ptr(ip)
        if host != ip:
            lbl = (
                f'<<B>External</B><BR/>'
                f'<FONT POINT-SIZE="9">{_esc(host)}</FONT><BR/>'
                f'<FONT POINT-SIZE="8" COLOR="#9E9E9E">{_esc(cidr)}</FONT>>'
            )
        else:
            lbl = f'<<B>External</B><BR/><FONT POINT-SIZE="9">{_esc(cidr)}</FONT>>'
        lines.append(
            f'  {_nid(eid)} [label={lbl}, '
            f'shape=diamond, style="filled,dashed", fillcolor="#F5F5F5", color="#9E9E9E", fontcolor="#616161"]'
        )
    if external_nodes:
        lines.append("")

    # ── Collapsing: if every workload in a source namespace goes to the same dst,
    # replace the individual edges with a single namespace-cluster → dst edge.
    ns_workloads: dict[str, set[str]] = {}
    for k in workloads:
        ns_workloads.setdefault(workloads[k]["namespace"], set()).add(k)

    # Count which src workloads per (src_ns, dst) pair have an edge
    dst_src_by_ns: dict[tuple[str, str], set[str]] = {}
    for (src, dst) in edges:
        if src.startswith("ext_") or src not in workloads:
            continue
        src_ns = workloads[src]["namespace"]
        dst_src_by_ns.setdefault((src_ns, dst), set()).add(src)

    # Collapsible when ≥2 workloads in the namespace and ALL are covered
    collapsible_src: set[tuple[str, str]] = {
        (src_ns, dst)
        for (src_ns, dst), src_set in dst_src_by_ns.items()
        if len(ns_workloads.get(src_ns, set())) >= 2
        and src_set >= ns_workloads.get(src_ns, set())
    }

    # Merge annotations for each collapsed (src_ns, dst) pair
    collapsed_ann: dict[tuple[str, str], list] = {}
    for (src, dst), ann in edges.items():
        if src.startswith("ext_") or src not in workloads:
            continue
        src_ns = workloads[src]["namespace"]
        if (src_ns, dst) in collapsible_src:
            collapsed_ann.setdefault((src_ns, dst), []).extend(ann)

    # Regular NetworkPolicy edges (skip those folded into a namespace-level edge)
    seen: set[tuple[str, str]] = set()
    for (src, dst), annotations in sorted(edges.items()):
        if (src, dst) in seen:
            continue
        seen.add((src, dst))
        if src in workloads and (workloads[src]["namespace"], dst) in collapsible_src:
            continue  # will be drawn as a collapsed edge below
        policy_names = sorted({pn for _, pn in annotations})
        label = merge_edge_ports(annotations) + "\\n" + "\\n".join(policy_names)
        if src.startswith("ext_"):
            color = "#9E9E9E"
        else:
            color, _ = _wl_color(src)
        lines.append(
            f'  {_nid(src)} -> {_nid(dst)} '
            f'[label="{_esc(label)}", color="{color}", fontcolor="{color}", penwidth=1.8]'
        )

    # Collapsed namespace → endpoint edges (drawn with ltail for cluster-level origin)
    for (src_ns, dst), annotations in sorted(collapsed_ann.items()):
        rep_src = min(ns_workloads[src_ns])  # stable representative node inside the cluster
        policy_names = sorted({pn for _, pn in annotations})
        label = merge_edge_ports(annotations) + "\\n" + "\\n".join(policy_names)
        ns_border, _, _ = ns_palette(src_ns)
        safe_src_ns = src_ns.replace("-", "_")
        lines.append(
            f'  {_nid(rep_src)} -> {_nid(dst)} '
            f'[label="{_esc(label)}", color="{ns_border}", fontcolor="{ns_border}", '
            f'penwidth=2.2, style="bold", ltail="cluster_{safe_src_ns}"]'
        )

    # ANP edges — drawn at namespace level using ltail/lhead (compound=true is set on graph)
    if anp_edges:
        # Pick one representative workload node per namespace for the edge endpoints
        ns_rep: dict[str, str] = {}
        for key, w in workloads.items():
            if w["namespace"] not in ns_rep:
                ns_rep[w["namespace"]] = key

        lines.append("")
        for (src, dst), (ports_lbl, action_label) in sorted(anp_edges.items()):
            is_deny = "Deny" in action_label
            color = "#F44336" if is_deny else "#7B1FA2"

            src_is_ext = src.startswith("ext_")
            dst_is_ext = dst.startswith("ext_")

            if src_is_ext:
                src_node = _nid(src)
                ltail_attr = ""
            else:
                if src not in ns_rep:
                    continue
                src_node = _nid(ns_rep[src])
                ltail_attr = f', ltail="cluster_{src.replace("-", "_")}"'

            if dst_is_ext:
                dst_node = _nid(dst)
                lhead_attr = ""
            else:
                if dst not in ns_rep:
                    continue
                dst_node = _nid(ns_rep[dst])
                lhead_attr = f', lhead="cluster_{dst.replace("-", "_")}"'

            lines.append(
                f'  {src_node} -> {dst_node} '
                f'[label="{_esc(action_label + chr(92) + "n" + ports_lbl)}", '
                f'color="{color}", fontcolor="{color}", style="dashed", penwidth=1.5, arrowsize=0.7'
                f'{ltail_attr}{lhead_attr}]'
            )

    # Route reachability nodes and edges
    if route_results:
        has_router = False
        for r in route_results:
            if r["namespace"] not in selected_ns:
                continue
            color = "#4CAF50" if r["reachable"] else "#F44336"
            style = "solid" if r["reachable"] else "dashed"

            if not has_router:
                lines.append('  "_ocp_router" [label=<<B>OpenShift Router</B>>, shape=diamond, style="filled", fillcolor="#E3F2FD", color="#1565C0"]')
                has_router = True

            # Find the target workload key
            target_wk = next(
                (k for k, w in workloads.items()
                 if w["namespace"] == r["namespace"] and w["app"] == r["target_svc"]),
                None
            )
            if target_wk:
                tls_icon = "TLS " if r.get("tls") else ""
                route_label = f'{tls_icon}{r["host"] or r["route_name"]}'
                lines.append(
                    f'  "_ocp_router" -> {_nid(target_wk)} '
                    f'[label="{_esc(route_label)}", color="{color}", '
                    f'style="{style}", fontcolor="{color}", penwidth=1.5, arrowsize=0.7]'
                )

    lines.append("}")
    return "\n".join(lines)


# ── Route-specific diagram ────────────────────────────────────────────────────

def route_diagram_dot(
    route_results: list[dict],
    workloads: dict[str, dict],
    selected_ns: list[str],
) -> str:
    """
    Build a focused DOT diagram showing Route → Service → Workload flow.
    Edges and route nodes are coloured green (reachable) or red (blocked).
    """
    visible = [r for r in route_results if r["namespace"] in selected_ns]
    if not visible:
        return ""

    lines: list[str] = [
        "digraph routes {",
        '  graph [rankdir=LR, fontname="Helvetica Neue", pad=0.5, nodesep=0.5, ranksep=1.1]',
        '  node  [fontname="Helvetica Neue", fontsize=10, margin="0.15,0.10"]',
        '  edge  [fontname="Helvetica Neue", fontsize=9, arrowsize=0.7, arrowhead=vee]',
        "",
        '  "_router" [label=<<B>OpenShift Router</B>>, shape=diamond, style="filled",'
        '   fillcolor="#BBDEFB", color="#1565C0", fontcolor="#0D47A1", width=1.6]',
        "",
    ]

    # Group by namespace so we can draw subgraphs
    ns_routes: dict[str, list[dict]] = {}
    for r in visible:
        ns_routes.setdefault(r["namespace"], []).append(r)

    rendered_workloads: set[str] = set()

    for ns in selected_ns:
        if ns not in ns_routes:
            continue
        border, bg, node_fill = ns_palette(ns)
        safe_ns = ns.replace("-", "_")

        lines += [
            f"  subgraph cluster_{safe_ns}_r {{",
            f'    label=<<B>{_esc(ns)}</B>>',
            f"    style=filled",
            f'    fillcolor="{bg}"',
            f'    color="{border}"',
            f'    fontname="Helvetica Neue"',
            f'    fontsize=12',
            "",
        ]

        for r in ns_routes[ns]:
            ok = r["reachable"]
            ec = "#2E7D32" if ok else "#C62828"
            fc = "#E8F5E9" if ok else "#FFEBEE"
            st_str = "solid" if ok else "dashed"
            tls_pfx = "🔒 " if r.get("tls") else ""
            host = r.get("host") or r["route_name"]

            route_id = f"rt_{safe_ns}_{r['route_name'].replace('-', '_').replace('.', '_')}"
            svc_id   = f"sv_{safe_ns}_{r['target_svc'].replace('-', '_')}" if r["target_svc"] else ""

            # Route node
            lines.append(
                f'    "{route_id}" [label=<<B>{tls_pfx}{_esc(host)}</B>'
                f'<BR/><FONT POINT-SIZE="8">{_esc(r["reason"])}</FONT>>, '
                f'shape=box, style="filled,rounded", fillcolor="{fc}", color="{ec}", fontcolor="{ec}"]'
            )

            if svc_id:
                # Service node
                lines.append(
                    f'    "{svc_id}" [label=<<B>svc/{_esc(r["target_svc"])}</B>>, '
                    f'shape=box, style="filled", fillcolor="#FFF9C4", color="#F9A825", fontcolor="#E65100"]'
                )
                lines.append(
                    f'    "{route_id}" -> "{svc_id}" [color="{ec}", style="{st_str}"]'
                )

                # Workload node (render once per key)
                target_wk = next(
                    (k for k, w in workloads.items()
                     if w["namespace"] == ns and w["app"] == r["target_svc"]),
                    None,
                )
                if target_wk and target_wk not in rendered_workloads:
                    rendered_workloads.add(target_wk)
                    w = workloads[target_wk]
                    lines.append(
                        f'    {_nid(target_wk)} [label=<<B>{_esc(w["app"])}</B>>, '
                        f'shape=box, style="filled,rounded", fillcolor="{node_fill}", color="{border}"]'
                    )
                if target_wk:
                    lines.append(
                        f'    "{svc_id}" -> {_nid(target_wk)} [color="{ec}", style="{st_str}"]'
                    )

        lines += ["  }", ""]

    # Router → route edges (drawn outside subgraphs so graphviz doesn't pull router in)
    for ns in selected_ns:
        if ns not in ns_routes:
            continue
        safe_ns = ns.replace("-", "_")
        for r in ns_routes[ns]:
            ok = r["reachable"]
            ec = "#2E7D32" if ok else "#C62828"
            st_str = "solid" if ok else "dashed"
            route_id = f"rt_{safe_ns}_{r['route_name'].replace('-', '_').replace('.', '_')}"
            lines.append(
                f'  "_router" -> "{route_id}" [color="{ec}", style="{st_str}", penwidth=1.8]'
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

    pol_ns = policy_dict.get("metadata", {}).get("namespace", "")
    spec = policy_dict.get("spec", {})

    edges, external_nodes = collect_edges(
        [policy_dict], workloads, ns_labels, visible_ns, show_external
    )

    # Only include workloads that are actual edge endpoints (matched by a selector),
    # plus the policy's own pod targets so isolated pods remain visible.
    involved: set[str] = {
        key for pair in edges for key in pair if key in workloads
    }
    if pol_ns:
        involved.update(find_peers(
            workloads, ns_labels, visible_ns,
            restrict_ns=pol_ns, ns_selector=None,
            pod_selector=spec.get("podSelector"),
        ))

    filtered_workloads = {k: v for k, v in workloads.items() if k in involved}
    selected_ns = sorted({w["namespace"] for w in filtered_workloads.values()})

    dot = build_dot(filtered_workloads, ns_labels, edges, external_nodes, selected_ns)
    return dot, len(edges)


def compute_cluster_data(
    policies: list[dict],
    all_pods: list[dict],
    ns_labels: dict[str, dict[str, str]],
    selected_ns: list[str],
    show_external: bool = True,
    anps: list[dict] | None = None,
    show_anps: bool = True,
) -> tuple[
    dict[str, dict],
    dict[tuple[str, str], list[tuple[list[dict] | None, str]]],
    dict[str, str],
    dict[tuple[str, str], tuple[str, str]],
    dict[str, str],
]:
    """Compute cluster graph data without rendering DOT.

    Returns (workloads, edges, external_nodes, anp_edges, anp_ext_nodes).
    Separate from rendering so callers can inspect external nodes before filtering.
    """
    visible_pods = [p for p in all_pods if p["namespace"] in selected_ns]
    workloads = build_workloads(visible_pods)
    edges, external_nodes = collect_edges(
        policies, workloads, ns_labels, set(selected_ns), show_external
    )
    anp_edges_dict: dict = {}
    anp_ext_nodes: dict = {}
    if show_anps and anps:
        anp_edges_dict, anp_ext_nodes = collect_anp_edges(
            anps, workloads, ns_labels, set(selected_ns)
        )
    return workloads, edges, external_nodes, anp_edges_dict, anp_ext_nodes


def cluster_map_dot(
    policies: list[dict],
    all_pods: list[dict],
    ns_labels: dict[str, dict[str, str]],
    selected_ns: list[str],
    show_external: bool = True,
    anps: list[dict] | None = None,
    route_results: list[dict] | None = None,
    show_anps: bool = True,
    ext_filter: set[str] | None = None,
) -> tuple[str, dict[tuple[str, str], list[tuple[list[dict] | None, str]]], dict[str, str]]:
    """Build a DOT diagram for the full cluster map.

    Returns (dot_string, edges, external_nodes).
    ext_filter: if set, only CIDRs in this set are included as external nodes.
    """
    workloads, edges, external_nodes, anp_edges_dict, anp_ext_nodes = compute_cluster_data(
        policies, all_pods, ns_labels, selected_ns, show_external, anps, show_anps
    )

    if ext_filter is not None:
        filtered_ext = {c: e for c, e in external_nodes.items() if c in ext_filter}
        kept_eids = set(filtered_ext.values())
        edges = {
            (src, dst): v for (src, dst), v in edges.items()
            if not (src.startswith("ext_") and src not in kept_eids)
            and not (dst.startswith("ext_") and dst not in kept_eids)
        }
        external_nodes = filtered_ext

    all_external = {**external_nodes, **anp_ext_nodes}
    dot = build_dot(
        workloads, ns_labels, edges, all_external, selected_ns,
        anp_edges=anp_edges_dict or None,
        route_results=route_results,
    )
    return dot, edges, external_nodes
