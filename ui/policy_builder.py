"""
Main policy builder UI.

Session state keys owned by this module:
  ingress_rules   – list of rule dicts
  egress_rules    – list of rule dicts
  confirm_apply   – bool, gating the two-step direct-apply confirmation
  submitted_prs   – list[dict], PRs opened in this session (for sidebar history)

Each rule dict schema:
  {
    "peer_type":        "cluster" | "external",
    # cluster peer
    "ns":               str | None,   # selected namespace name (for label discovery)
    "ns_labels_avail":  dict,         # all labels fetched for that namespace
    "ns_labels":        dict,         # user-selected subset → namespaceSelector.matchLabels
    "ns_expressions":   list[dict],   # matchExpressions entries for namespaceSelector
    "pod_labels_avail": dict,         # all workload labels fetched for that pod
    "pod_labels":       dict,         # user-selected subset → podSelector.matchLabels
    "pod_expressions":  list[dict],   # matchExpressions entries for podSelector
    # external peer (egress only)
    "cidr":             str,          # validated CIDR, e.g. "10.200.0.0/16" or "1.2.3.4/32"
    # shared
    "ports":            list[dict],   # [{"protocol": "TCP", "port": 8080}, ...]
  }

  matchExpressions entry schema:
  {
    "key":      str,
    "operator": "In" | "NotIn" | "Exists" | "DoesNotExist",
    "values":   list[str],  # omitted for Exists / DoesNotExist
  }
"""
from __future__ import annotations

import ipaddress
import socket
import traceback
from typing import Any

import streamlit as st
import yaml

from config import AppConfig
from k8s.client import build_api_client_from_config
from k8s import (
    list_namespaces,
    list_pods_in_namespace,
    list_all_pods,
    list_services_in_namespace,
    list_routes_in_namespace,
    get_namespace_labels,
    get_all_namespace_labels,
    apply_network_policy,
)
from gh.pr import GitHubPRClient, build_pr_body
from ui.netpol_viz import policy_preview_dot

# ── Label index helpers ───────────────────────────────────────────────────────

def _build_label_index(labels_collection: list[dict[str, str]]) -> dict[str, list[str]]:
    """Build {key: sorted_unique_values} from a list of label dicts."""
    index: dict[str, set[str]] = {}
    for labels in labels_collection:
        for k, v in labels.items():
            index.setdefault(k, set()).add(v)
    return {k: sorted(vs) for k, vs in sorted(index.items())}


# ── Constants ─────────────────────────────────────────────────────────────────

_PROTOCOLS = ["TCP", "UDP", "SCTP"]
_EXPR_OPERATORS = ["In", "NotIn", "Exists", "DoesNotExist"]

_EMPTY_RULE: dict = {
    "peer_type": "cluster",
    "ns": None,
    "ns_labels_avail": {},
    "ns_labels": {},
    "ns_expressions": [],
    "pod_labels_avail": {},
    "pod_labels": {},
    "pod_expressions": [],
    "cidr": "",
    "ports": [],
}


# ── State helpers ─────────────────────────────────────────────────────────────

def _init_state() -> None:
    st.session_state.setdefault("ingress_rules", [])
    st.session_state.setdefault("egress_rules", [])
    st.session_state.setdefault("confirm_apply", False)
    st.session_state.setdefault("submitted_prs", [])
    st.session_state.setdefault("target_pod_expressions", [])


def _add_rule(key: str) -> None:
    import copy
    st.session_state[key].append(copy.deepcopy(_EMPTY_RULE))


def _remove_rule(key: str, idx: int) -> None:
    st.session_state[key].pop(idx)


# ── YAML generation ───────────────────────────────────────────────────────────

def _build_peer(rule: dict) -> dict:
    """Translate a rule dict into a NetworkPolicy peer (from/to entry)."""
    if rule.get("peer_type") == "external":
        cidr = rule.get("cidr", "").strip()
        return {"ipBlock": {"cidr": cidr or "0.0.0.0/0"}}

    # cluster peer
    peer: dict = {}

    ns_sel: dict = {}
    if rule.get("ns_labels"):
        ns_sel["matchLabels"] = rule["ns_labels"]
    if rule.get("ns_expressions"):
        ns_sel["matchExpressions"] = rule["ns_expressions"]
    if ns_sel:
        peer["namespaceSelector"] = ns_sel

    pod_sel: dict = {}
    if rule.get("pod_labels"):
        pod_sel["matchLabels"] = rule["pod_labels"]
    if rule.get("pod_expressions"):
        pod_sel["matchExpressions"] = rule["pod_expressions"]
    if pod_sel:
        peer["podSelector"] = pod_sel

    # empty peer = "any source/dest"
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
    pod_selector_expressions: list[dict] | None = None,
) -> dict:
    pod_sel: dict = {}
    if pod_selector_labels:
        pod_sel["matchLabels"] = pod_selector_labels
    if pod_selector_expressions:
        pod_sel["matchExpressions"] = pod_selector_expressions

    spec: dict[str, Any] = {
        "podSelector": pod_sel,
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
        covered_nets: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        for rule in egress_rules:
            if rule.get("peer_type") == "external" and rule.get("cidr"):
                try:
                    net = ipaddress.ip_network(rule["cidr"], strict=False)
                    if any(existing.supernet_of(net) or existing == net for existing in covered_nets):
                        continue
                    covered_nets.append(net)
                except ValueError:
                    pass
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


def _selector_summary(selector: dict | None, label: str) -> str:
    """Return a concise human-readable summary for a label selector."""
    if not selector:
        return f"{label}: any"

    parts: list[str] = []

    match_labels = selector.get("matchLabels", {})
    if match_labels:
        labels_txt = ", ".join(f"{k}={v}" for k, v in sorted(match_labels.items()))
        parts.append(f"matchLabels ({labels_txt})")

    match_exprs = selector.get("matchExpressions", [])
    if match_exprs:
        expr_parts: list[str] = []
        for expr in match_exprs:
            key = expr.get("key", "")
            op = expr.get("operator", "")
            values = expr.get("values", [])
            if op in ("Exists", "DoesNotExist"):
                expr_parts.append(f"{key} {op}")
            else:
                values_txt = " OR ".join(str(v) for v in values) if values else "(no values)"
                expr_parts.append(f"{key} {op} [{values_txt}]")
        parts.append("matchExpressions (" + " AND ".join(expr_parts) + ")")

    if not parts:
        return f"{label}: any"
    return f"{label}: " + " AND ".join(parts)


def _ports_summary(ports: list[dict] | None) -> str:
    """Return a concise ports/protocol summary."""
    if not ports:
        return "all ports/protocols"

    items: list[str] = []
    for p in ports:
        proto = p.get("protocol", "TCP")
        port = p.get("port")
        items.append(f"{proto}:{port}" if port else str(proto))
    return ", ".join(items)


def _selector_conditions(selector: dict | None) -> str:
    """Return selector conditions without entity prefix."""
    if not selector:
        return ""

    conditions: list[str] = []

    match_labels = selector.get("matchLabels", {})
    for k, v in sorted(match_labels.items()):
        conditions.append(f"{k}={v}")

    match_exprs = selector.get("matchExpressions", [])
    for expr in match_exprs:
        key = expr.get("key", "")
        op = expr.get("operator", "")
        values = expr.get("values", [])
        if op in ("Exists", "DoesNotExist"):
            conditions.append(f"{key} {op}")
        else:
            values_txt = " OR ".join(str(v) for v in values) if values else "(no values)"
            conditions.append(f"{key} {op} [{values_txt}]")

    return " AND ".join(conditions)


def _describe_namespace_selector(selector: dict | None) -> str:
    conditions = _selector_conditions(selector)
    if not conditions:
        return "all namespaces"
    return f"namespaces where {conditions}"


def _describe_pod_selector(selector: dict | None) -> str:
    conditions = _selector_conditions(selector)
    if not conditions:
        return "all pods"
    return f"pods where {conditions}"


def _describe_cluster_peer(peer: dict) -> str:
    ns_desc = _describe_namespace_selector(peer.get("namespaceSelector"))
    pod_desc = _describe_pod_selector(peer.get("podSelector"))

    if ns_desc == "all namespaces" and pod_desc == "all pods":
        return "all pods in all namespaces"
    if ns_desc == "all namespaces":
        return f"{pod_desc} in all namespaces"
    if pod_desc == "all pods":
        return f"all pods in {ns_desc}"
    return f"{pod_desc} in {ns_desc}"


def explain_policy_preview(policy_dict: dict) -> str:
    """Generate a structured markdown explanation of communication paths."""
    metadata = policy_dict.get("metadata", {})
    spec = policy_dict.get("spec", {})

    name = metadata.get("name", "(unnamed)")
    namespace = metadata.get("namespace", "(unknown namespace)")

    target_desc = _describe_pod_selector(spec.get("podSelector"))
    target_scope = f"{target_desc} in namespace '{namespace}'"

    lines: list[str] = [
        f"**Policy:** '{name}'",
        f"**Namespace:** '{namespace}'",
        "",
        "**Scope**",
        f"- Applies to: {target_scope}",
    ]

    policy_types = spec.get("policyTypes", [])
    if policy_types:
        lines.append(f"- Controls: {', '.join(policy_types)}")

    ingress = spec.get("ingress", [])
    if "Ingress" in policy_types and ingress:
        lines.append("")
        lines.append("**Allowed Ingress (who can talk to selected pods)**")
        for idx, rule in enumerate(ingress, start=1):
            peers = rule.get("from", [])
            ports_txt = _ports_summary(rule.get("ports"))
            if not peers:
                lines.append(
                    f"- Rule {idx}: all sources -> {target_scope} (ports: {ports_txt})"
                )
                continue

            peer = peers[0]
            source_desc = _describe_cluster_peer(peer)
            lines.append(
                f"- Rule {idx}: {source_desc} -> {target_scope} (ports: {ports_txt})"
            )
    elif "Ingress" in policy_types:
        lines.append("")
        lines.append("**Allowed Ingress (who can talk to selected pods)**")
        lines.append("- None (all ingress denied for selected pods)")
    else:
        lines.append("")
        lines.append("**Allowed Ingress (who can talk to selected pods)**")
        lines.append("- Not restricted by this policy")

    egress = spec.get("egress", [])
    if "Egress" in policy_types and egress:
        lines.append("")
        lines.append("**Allowed Egress (where selected pods can talk to)**")
        for idx, rule in enumerate(egress, start=1):
            peers = rule.get("to", [])
            ports_txt = _ports_summary(rule.get("ports"))
            if not peers:
                lines.append(
                    f"- Rule {idx}: {target_scope} -> any destination (ports: {ports_txt})"
                )
                continue

            peer = peers[0]
            ip_block = peer.get("ipBlock")
            if ip_block:
                lines.append(
                    f"- Rule {idx}: {target_scope} -> ipBlock {ip_block.get('cidr', '(unknown CIDR)')} (ports: {ports_txt})"
                )
                continue

            destination_desc = _describe_cluster_peer(peer)
            lines.append(
                f"- Rule {idx}: {target_scope} -> {destination_desc} (ports: {ports_txt})"
            )
    elif "Egress" in policy_types:
        lines.append("")
        lines.append("**Allowed Egress (where selected pods can talk to)**")
        lines.append("- None (all egress denied for selected pods)")
    else:
        lines.append("")
        lines.append("**Allowed Egress (where selected pods can talk to)**")
        lines.append("- Not restricted by this policy")

    lines.append("")
    lines.append("**Selector Logic**")
    lines.append(
        "- In one matchExpressions list: expressions are AND"
    )
    lines.append("- In one In/NotIn expression: listed values are OR")
    lines.append("- Multiple ingress/egress rules: rules are OR")
    return "\n".join(lines)


# ── Label multiselect helper ──────────────────────────────────────────────────

def _label_multiselect(
    label: str,
    available: dict[str, str],
    current: dict[str, str],
    widget_key: str,
) -> dict[str, str]:
    """
    Render a multiselect for label key/value pairs.
    Returns the selected subset as a dict.
    Widget key should include the source name so that changing the namespace/pod
    resets the selection automatically.
    """
    if not available:
        return {}

    options = list(available.keys())
    # Retain only keys that still exist in the current options
    valid_current = [k for k in current if k in available]

    selected_keys: list[str] = st.multiselect(
        label,
        options=options,
        default=valid_current,
        format_func=lambda k: f"{k} = {available[k]}",
        key=widget_key,
    )
    return {k: available[k] for k in selected_keys}


# ── CIDR overlap detection ────────────────────────────────────────────────────

def _check_cidr_overlap(
    cidr: str, all_rules: list[dict], current_idx: int
) -> list[tuple[int, str]]:
    """Return (rule_idx, cidr) pairs whose CIDR already covers *cidr*."""
    try:
        new_net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return []
    result = []
    for idx, rule in enumerate(all_rules):
        if idx == current_idx:
            continue
        if rule.get("peer_type") == "external" and rule.get("cidr"):
            try:
                other_net = ipaddress.ip_network(rule["cidr"], strict=False)
                if other_net.supernet_of(new_net) or other_net == new_net:
                    result.append((idx, rule["cidr"]))
            except ValueError:
                pass
    return result


# ── matchExpressions editor ───────────────────────────────────────────────────

def _render_match_expressions(
    expressions: list[dict],
    widget_key: str,
    available_keys: list[str] | None = None,
    available_values: dict[str, list[str]] | None = None,
) -> list[dict]:
    """Render an inline editor for matchExpressions. Mutates and returns the list.

    available_keys:   selectbox for the key field when provided; else free-text.
    available_values: per-key value lists; renders a multiselect for In/NotIn when
                      the selected key has known values, else falls back to free-text.
    """
    st.markdown("**matchExpressions**")

    # Show existing expressions with delete buttons
    if expressions:
        to_remove: int | None = None
        for i, expr in enumerate(expressions):
            row_col, del_col = st.columns([5, 1])
            op = expr["operator"]
            if op in ("Exists", "DoesNotExist"):
                row_col.markdown(f"`{expr['key']}` **{op}**")
            else:
                vals = ", ".join(expr.get("values", []))
                row_col.markdown(f"`{expr['key']}` **{op}** `[{vals}]`")
            if del_col.button("✕", key=f"{widget_key}_del_expr_{i}"):
                to_remove = i
        if to_remove is not None:
            expressions.pop(to_remove)
            st.rerun()

    # Inline add-form — always visible
    ec1, ec2, ec3, ec4 = st.columns([2, 2, 3, 1])
    if available_keys:
        new_key = ec1.selectbox("Key", [""] + available_keys, key=f"{widget_key}_ekey")
    else:
        new_key = ec1.text_input("Key", key=f"{widget_key}_ekey", placeholder="e.g. tier")
    new_op = ec2.selectbox("Operator", _EXPR_OPERATORS, key=f"{widget_key}_eop")

    values_list: list[str] = []
    if new_op in ("In", "NotIn"):
        # Widget key includes new_key so the widget resets when the key changes
        vals_widget_key = f"{widget_key}_evals_{new_key}"
        key_values = (available_values or {}).get(new_key, []) if new_key else []
        if key_values:
            values_list = ec3.multiselect("Values", key_values, key=vals_widget_key)
        else:
            raw = ec3.text_input(
                "Values (comma-separated)", key=vals_widget_key,
                placeholder="e.g. api, web",
            )
            values_list = [v.strip() for v in raw.split(",") if v.strip()] if raw else []

    if ec4.button("＋", key=f"{widget_key}_eadd", help="Add expression"):
        if new_key:
            expr: dict = {"key": new_key, "operator": new_op}
            if new_op in ("In", "NotIn"):
                expr["values"] = values_list
            expressions.append(expr)
            st.rerun()
        else:
            st.error("Key is required.")
    return expressions


# ── External peer sub-editor ──────────────────────────────────────────────────

def _render_external_peer(
    rule: dict,
    rule_idx: int,
    rules_key: str,
    all_rules: list[dict] | None = None,
) -> None:
    """Render the CIDR / DNS resolution section for an external egress peer."""
    st.markdown("**External destination** *(outside the cluster)*")

    raw_key = f"{rules_key}_{rule_idx}_ext_raw"
    cidr_key = f"{rules_key}_{rule_idx}_cidr_value"
    err_key  = f"{rules_key}_{rule_idx}_ext_err"
    hint_key = f"{rules_key}_{rule_idx}_ext_hint"

    input_col, btn_col = st.columns([5, 1])
    raw_input: str = input_col.text_input(
        "DNS hostname or CIDR subnet",
        placeholder="e.g. api.partner.com  or  10.200.64.0/18",
        key=raw_key,
    )
    resolve_clicked = btn_col.button("Resolve", key=f"{rules_key}_{rule_idx}_resolve_btn")

    if resolve_clicked and raw_input:
        st.session_state.pop(err_key, None)
        st.session_state.pop(hint_key, None)
        raw = raw_input.strip()
        if "/" in raw:
            # Looks like a CIDR – validate it
            try:
                net = ipaddress.ip_network(raw, strict=False)
                st.session_state[cidr_key] = str(net)
            except ValueError as exc:
                st.session_state[err_key] = f"Invalid CIDR: {exc}"
        else:
            # Treat as DNS hostname – resolve to IPs
            try:
                infos = socket.getaddrinfo(raw, None, type=socket.SOCK_STREAM)
                ips = sorted({info[4][0] for info in infos})
                st.session_state[cidr_key] = f"{ips[0]}/32"
                if len(ips) > 1:
                    st.session_state[hint_key] = (
                        f"Resolved {len(ips)} addresses: "
                        + ", ".join(f"`{ip}/32`" for ip in ips)
                        + ". Only the first is pre-filled; add separate rules for others."
                    )
            except socket.gaierror as exc:
                st.session_state[err_key] = f"DNS resolution failed: {exc}"

    if err_key in st.session_state:
        st.error(st.session_state[err_key])

    if hint_key in st.session_state:
        st.info(st.session_state[hint_key])

    # Editable CIDR field – pre-populated by the Resolve button via session state
    cidr_val: str = st.text_input(
        "CIDR to use in ipBlock",
        placeholder="e.g. 10.200.64.0/18",
        key=cidr_key,
    )

    if cidr_val:
        try:
            net = ipaddress.ip_network(cidr_val.strip(), strict=False)
            rule["cidr"] = str(net)
            st.caption(f"→ `ipBlock.cidr: {rule['cidr']}`")
            if all_rules is not None:
                overlaps = _check_cidr_overlap(rule["cidr"], all_rules, rule_idx)
                for oidx, ocidr in overlaps:
                    st.warning(
                        f"Already covered by **egress rule #{oidx + 1}** (`{ocidr}`). "
                        "This rule will be **excluded** from the generated policy."
                    )
        except ValueError:
            st.error(f"Not a valid CIDR: {cidr_val!r}")
            rule["cidr"] = ""
    else:
        rule["cidr"] = ""


# ── Cluster peer sub-editor ───────────────────────────────────────────────────

def _render_cluster_peer(
    api_client: Any,
    rule: dict,
    rule_idx: int,
    rules_key: str,
    all_namespaces: list[str],
    peer_label: str,
    all_ns_label_index: dict[str, list[str]] | None = None,
    all_pod_label_index: dict[str, list[str]] | None = None,
) -> None:
    """Render namespace + pod selector with per-label multiselect and matchExpressions."""

    # ── Row 1: namespace / pod selectors + matchLabels ────────────────────────
    col_ns, col_pod = st.columns(2)

    avail_ns_keys: list[str] = []
    avail_ns_values: dict[str, list[str]] = {}
    pod_map: dict[str, dict] = {}

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
                avail_ns = get_namespace_labels(api_client, selected_ns)
            rule["ns_labels_avail"] = avail_ns
            avail_ns_keys = sorted(avail_ns.keys())
            avail_ns_values = {k: [v] for k, v in avail_ns.items()}

            rule["ns_labels"] = _label_multiselect(
                "Namespace labels to match",
                available=avail_ns,
                current=rule["ns_labels"],
                widget_key=f"{rules_key}_{rule_idx}_ns_lbls_{selected_ns}",
            )
            if not rule["ns_labels"]:
                st.caption("No labels selected → `namespaceSelector` will match **any** namespace.")
        else:
            rule["ns"] = None
            rule["ns_labels_avail"] = {}
            rule["ns_labels"] = {}
            if all_ns_label_index:
                avail_ns_keys = list(all_ns_label_index.keys())
                avail_ns_values = all_ns_label_index

    with col_pod:
        pod_options = ["(any pod)"]
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

        avail_pod_keys: list[str] = []
        avail_pod_values: dict[str, list[str]] = {}

        if selected_pod != "(any pod)" and selected_pod in pod_map:
            avail_pod = pod_map[selected_pod]["workload_labels"]
            rule["pod_labels_avail"] = avail_pod
            if avail_pod:
                rule["pod_labels"] = _label_multiselect(
                    "Pod labels to match",
                    available=avail_pod,
                    current=rule["pod_labels"],
                    widget_key=f"{rules_key}_{rule_idx}_pod_lbls_{selected_pod}",
                )
                avail_pod_keys = sorted(avail_pod.keys())
                avail_pod_values = {k: [v] for k, v in avail_pod.items()}
                if not rule["pod_labels"]:
                    st.caption("No labels selected → `podSelector` will match **all** pods.")
            else:
                rule["pod_labels"] = {}
                st.warning("Pod has no workload labels – selector will match all pods.")
        else:
            rule["pod_labels_avail"] = {}
            rule["pod_labels"] = {}
            if pod_map:
                ns_pod_index = _build_label_index(
                    [p["workload_labels"] for p in pod_map.values()]
                )
                avail_pod_keys = list(ns_pod_index.keys())
                avail_pod_values = ns_pod_index
            elif all_pod_label_index:
                avail_pod_keys = list(all_pod_label_index.keys())
                avail_pod_values = all_pod_label_index

    # ── matchExpressions — rendered sequentially at top level ────────────────
    # st.columns() inside a column context requires Streamlit >=1.37.0.
    # To stay compatible with >=1.32.0 we avoid nesting: each expression block
    # is rendered at the expander's top level (no outer column wrapper).
    st.markdown("**namespaceSelector** matchExpressions")
    rule["ns_expressions"] = _render_match_expressions(
        rule.setdefault("ns_expressions", []),
        widget_key=f"{rules_key}_{rule_idx}_ns_exprs",
        available_keys=avail_ns_keys or None,
        available_values=avail_ns_values or None,
    )

    st.markdown("**podSelector** matchExpressions")
    rule["pod_expressions"] = _render_match_expressions(
        rule.setdefault("pod_expressions", []),
        widget_key=f"{rules_key}_{rule_idx}_pod_exprs",
        available_keys=avail_pod_keys or None,
        available_values=avail_pod_values or None,
    )


# ── Rule editor ───────────────────────────────────────────────────────────────

def _render_rule_editor(
    api_client: Any,
    rule: dict,
    rule_idx: int,
    rules_key: str,
    all_namespaces: list[str],
    direction: str,  # "Ingress" or "Egress"
    all_rules: list[dict] | None = None,
    all_ns_label_index: dict[str, list[str]] | None = None,
    all_pod_label_index: dict[str, list[str]] | None = None,
) -> None:
    peer_label = "Source" if direction == "Ingress" else "Destination"

    # Egress rules support external (off-cluster) peers; ingress always uses cluster peers
    if direction == "Egress":
        peer_type_display = st.radio(
            "Peer type",
            ["Cluster peer", "External endpoint"],
            index=0 if rule.get("peer_type", "cluster") == "cluster" else 1,
            horizontal=True,
            key=f"{rules_key}_{rule_idx}_peer_type_radio",
        )
        rule["peer_type"] = "cluster" if peer_type_display == "Cluster peer" else "external"
    else:
        rule["peer_type"] = "cluster"

    if rule["peer_type"] == "external":
        _render_external_peer(rule, rule_idx, rules_key, all_rules=all_rules)
    else:
        _render_cluster_peer(
            api_client, rule, rule_idx, rules_key, all_namespaces, peer_label,
            all_ns_label_index=all_ns_label_index,
            all_pod_label_index=all_pod_label_index,
        )

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
        from auth.oidc import OIDCAuthenticator
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

        if st.session_state["submitted_prs"]:
            st.divider()
            st.markdown("**PRs submitted this session**")
            for pr in st.session_state["submitted_prs"]:
                st.markdown(
                    f"- [{pr['policy']} → {pr['ns']}]({pr['url']})",
                    unsafe_allow_html=False,
                )

        st.divider()
        st.page_link("pages/How_To_Guide.py", label="📖 How-To Guide", icon=None)
        st.divider()
        st.markdown(
            "<p style='font-size:0.75em;color:grey'>"
            "Cluster data cached 60 s.<br>"
            "YAML generated locally – nothing transmitted until you submit a PR."
            "</p>",
            unsafe_allow_html=True,
        )

    # ── Page header ───────────────────────────────────────────────────────────
    st.title("🔒 NetPol Crafter")
    st.markdown(
        "Build an OpenShift **NetworkPolicy** from cluster resources. "
        "The tool fetches live labels so your selectors are always accurate."
    )

    if config.test_mode:
        st.warning(
            "**TEST MODE** – No real cluster or GitHub connections. "
            "Cluster data is loaded from built-in fixtures. "
            "PR submission is replaced with a local dry-run preview.",
            icon="🧪",
        )

    st.divider()

    # ── Load namespace list + global label indexes ────────────────────────────
    with st.spinner("Loading namespaces…"):
        try:
            all_namespaces = list_namespaces(api_client)
        except Exception as exc:
            st.error(f"Cannot list namespaces: {exc}")
            if config.debug:
                st.code(traceback.format_exc())
            st.stop()

    with st.spinner("Loading label indexes…"):
        try:
            all_ns_labels_map = get_all_namespace_labels(api_client)
            all_ns_label_index = _build_label_index(list(all_ns_labels_map.values()))
            all_pods_global = list_all_pods(api_client)
            all_pod_label_index = _build_label_index(
                [p["workload_labels"] for p in all_pods_global]
            )
        except Exception:
            all_ns_labels_map = {}
            all_ns_label_index = {}
            all_pods_global = []
            all_pod_label_index = {}

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

            selected_target_pod = st.selectbox("Target pod", target_pod_options)

        with target_col2:
            # Build pod label index for this namespace (all pods, then narrow to selection)
            target_ns_pod_index = _build_label_index(
                [p["workload_labels"] for p in target_pods]
            )
            avail_target_keys: list[str] = list(target_ns_pod_index.keys())
            avail_target_values: dict[str, list[str]] = target_ns_pod_index

            if selected_target_pod != "(all pods)" and selected_target_pod in target_pod_map:
                avail_target_labels = target_pod_map[selected_target_pod]["workload_labels"]
                if avail_target_labels:
                    target_pod_labels = _label_multiselect(
                        "Labels to use in podSelector",
                        available=avail_target_labels,
                        current=target_pod_labels,
                        widget_key=f"target_pod_lbls_{selected_target_pod}",
                    )
                    # Narrow to the selected pod's own keys/values
                    avail_target_keys = sorted(avail_target_labels.keys())
                    avail_target_values = {k: [v] for k, v in avail_target_labels.items()}
                    if not target_pod_labels:
                        st.caption("No labels selected → policy applies to **all pods** in namespace.")
                else:
                    st.warning(
                        "This pod has no workload labels. "
                        "The policy will match ALL pods in the namespace."
                    )

        # matchExpressions rendered OUTSIDE the selector columns (no nesting)
        st.session_state["target_pod_expressions"] = _render_match_expressions(
            st.session_state["target_pod_expressions"],
            widget_key="target_pod_exprs",
            available_keys=avail_target_keys or None,
            available_values=avail_target_values or None,
        )

        # Pre-fill from a Service
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
                api_client, rule, idx, "ingress_rules", all_namespaces, "Ingress",
                all_ns_label_index=all_ns_label_index,
                all_pod_label_index=all_pod_label_index,
            )
            if st.button("🗑 Remove this rule", key=f"del_ingress_{idx}", type="secondary"):
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
                api_client, rule, idx, "egress_rules", all_namespaces, "Egress",
                all_rules=st.session_state["egress_rules"],
                all_ns_label_index=all_ns_label_index,
                all_pod_label_index=all_pod_label_index,
            )
            if st.button("🗑 Remove this rule", key=f"del_egress_{idx}", type="secondary"):
                _remove_rule("egress_rules", idx)
                st.rerun()

    if st.button("＋ Add egress rule", key="add_egress"):
        _add_rule("egress_rules")
        st.rerun()

    # ═══════════════════════════════════════════════════════════════════════════
    # SECTION 5 – YAML Preview & Submit
    # ═══════════════════════════════════════════════════════════════════════════
    st.divider()
    st.subheader("5 · YAML preview & submit")

    ready = policy_name and target_namespace
    if not ready:
        st.warning("Fill in a policy name and target namespace to generate YAML.")
        return

    policy_dict = build_network_policy_dict(
        name=policy_name,
        namespace=target_namespace,
        pod_selector_labels=target_pod_labels,
        pod_selector_expressions=st.session_state["target_pod_expressions"],
        ingress_rules=st.session_state["ingress_rules"],
        egress_rules=st.session_state["egress_rules"],
    )
    yaml_str = _to_yaml(policy_dict)

    st.code(yaml_str, language="yaml")
    st.markdown("### Policy explainer")
    st.markdown(explain_policy_preview(policy_dict))

    st.markdown("### Connection diagram")
    _viz_dot, _viz_flows = policy_preview_dot(policy_dict, all_pods_global, all_ns_labels_map)
    if _viz_flows == 0:
        st.info(
            "No matching workloads found for the selectors in this policy. "
            "The diagram will populate once the namespace and pod selectors "
            "match pods in the cluster.",
            icon="ℹ️",
        )
    st.graphviz_chart(_viz_dot, use_container_width=True)

    dl_col, _, _ = st.columns([1, 1, 3])
    dl_col.download_button(
        label="⬇ Download YAML",
        data=yaml_str,
        file_name=f"{policy_name}.yaml",
        mime="text/yaml",
    )

    st.divider()

    tab_pr, tab_apply = st.tabs(["🔀 Open Pull Request  *(GitOps – recommended)*",
                                  "⚡ Apply directly  *(break-glass only)*"])

    with tab_pr:
        _render_pr_tab(config, policy_name, target_namespace, policy_dict, yaml_str, user_info)

    with tab_apply:
        _render_apply_tab(config, api_client, policy_name, target_namespace, policy_dict)


# ── Tab renderers ─────────────────────────────────────────────────────────────

def _render_pr_tab(
    config: AppConfig,
    policy_name: str,
    namespace: str,
    policy_dict: dict,
    yaml_str: str,
    user_info: dict,
) -> None:
    if config.test_mode:
        import datetime
        ts = datetime.datetime.utcnow().strftime("%Y%m%d-%H%M%S")
        simulated_branch = f"netpol/{namespace}/{policy_name}-{ts}"
        simulated_path   = f"{config.github_policies_path}/{namespace}/{policy_name}.yaml"

        st.info(
            "**TEST MODE – dry run.** No PR will be created. "
            "The panels below show exactly what would be sent to GitHub.",
            icon="🧪",
        )

        col_a, col_b = st.columns(2)
        col_a.metric("Repository", config.github_repo)
        col_b.metric("Base branch", config.github_base_branch)

        with st.expander("📁 File that would be committed", expanded=True):
            st.code(simulated_path, language=None)
            st.code(yaml_str, language="yaml")

        pr_title = st.text_input(
            "PR title (preview only)",
            value=f"feat(netpol): {policy_name} in {namespace}",
        )
        default_body = build_pr_body(
            policy_name=policy_name,
            namespace=namespace,
            policy_dict=policy_dict,
            yaml_str=yaml_str,
            user_info=user_info,
        )
        with st.expander("📝 PR description that would be submitted", expanded=False):
            st.text_area("PR body (read-only preview)", value=default_body, height=400,
                         disabled=True, label_visibility="collapsed")

        with st.expander("🌿 Git objects that would be created", expanded=False):
            st.json({
                "action": "dry-run (TEST_MODE=true)",
                "repository": config.github_repo,
                "new_branch": simulated_branch,
                "base_branch": config.github_base_branch,
                "committed_file": simulated_path,
                "pr_title": pr_title,
            })
        return

    if not config.github_configured:
        st.warning(
            "GitHub integration is not configured. "
            "Set `GITHUB_REPO` and either `GITHUB_TOKEN` or the `GITHUB_APP_*` "
            "variables in your `.env` file.",
            icon="⚠️",
        )
        return

    st.markdown(
        f"**Target repository:** `{config.github_repo}` · "
        f"base branch: `{config.github_base_branch}` · "
        f"path: `{config.github_policies_path}/{namespace}/{policy_name}.yaml`"
    )
    st.caption(
        "A new branch `netpol/{namespace}/{policy-name}-{timestamp}` will be created "
        "and a PR opened against the base branch. ArgoCD will deploy on merge."
    )

    default_title = f"feat(netpol): {policy_name} in {namespace}"
    pr_title = st.text_input("PR title", value=default_title)

    default_body = build_pr_body(
        policy_name=policy_name,
        namespace=namespace,
        policy_dict=policy_dict,
        yaml_str=yaml_str,
        user_info=user_info,
    )
    pr_body = st.text_area("PR description", value=default_body, height=340)

    st.divider()

    if st.button("🔀 Create Pull Request", type="primary", use_container_width=False):
        with st.spinner("Creating branch and opening PR…"):
            try:
                client = GitHubPRClient(config)
                pr_url = client.create_policy_pr(
                    policy_yaml=yaml_str,
                    policy_name=policy_name,
                    namespace=namespace,
                    policy_dict=policy_dict,
                    user_info=user_info,
                    pr_title=pr_title,
                    pr_body=pr_body,
                )
                st.session_state["submitted_prs"].append(
                    {"policy": policy_name, "ns": namespace, "url": pr_url}
                )
                st.success(
                    f"✅ Pull Request created: [{pr_title}]({pr_url})",
                    icon="✅",
                )
                st.balloons()
            except Exception as exc:
                st.error(f"Failed to create PR: {exc}")
                if config.debug:
                    st.code(traceback.format_exc())


def _render_apply_tab(
    config: AppConfig,
    api_client: Any,
    policy_name: str,
    namespace: str,
    policy_dict: dict,
) -> None:
    st.error(
        "**Break-glass use only.** Applying directly bypasses GitOps, "
        "skips peer review, and creates drift between the cluster and the "
        "policy repository. Use only during an active incident.",
        icon="🚨",
    )

    if not st.session_state["confirm_apply"]:
        if st.button("🚀 Apply directly to cluster", type="primary"):
            st.session_state["confirm_apply"] = True
            st.rerun()
    else:
        st.warning(
            f"**Confirm:** Apply `{policy_name}` directly to namespace `{namespace}`? "
            "This will not create a PR or git commit."
        )
        confirm_col1, confirm_col2 = st.columns(2)

        if confirm_col1.button("✅ Yes, apply now", type="primary"):
            st.session_state["confirm_apply"] = False
            with st.spinner("Applying NetworkPolicy…"):
                try:
                    result = apply_network_policy(api_client, policy_dict)
                    st.success(
                        f"Policy **{result['name']}** {result['action']} "
                        f"in namespace **{result['namespace']}**. "
                        "Remember to reconcile the policy repository."
                    )
                except Exception as exc:
                    st.error(f"Apply failed: {exc}")
                    if config.debug:
                        st.code(traceback.format_exc())

        if confirm_col2.button("❌ Cancel"):
            st.session_state["confirm_apply"] = False
            st.rerun()
