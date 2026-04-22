"""
How-To Guide — Kubernetes / OpenShift NetworkPolicy reference.
Only reachable via st.navigation() after authentication (enforced in app.py).
Note: st.set_page_config() must NOT be called here; it lives in app.py.
"""
import streamlit as st

if not st.session_state.get("authenticated"):
    st.warning("Please sign in to access this page.")
    st.stop()

st.title("📖 NetworkPolicy – How-To Guide")
st.markdown(
    "A practical reference for the patterns supported by **NetPol Crafter** "
    "and the Kubernetes `networking.k8s.io/v1` NetworkPolicy API."
)
st.divider()

# ── Fundamentals ──────────────────────────────────────────────────────────────

st.header("How NetworkPolicies work")

st.markdown("""
NetworkPolicies are **pod-level firewalls**. They are enforced by the CNI plugin
(Calico, Cilium, OVN-Kubernetes, …) — not by the Linux kernel or `iptables` directly.

| Property | Detail |
|---|---|
| **Scope** | A single namespace; `podSelector` picks which pods it applies to |
| **Default** | All traffic is allowed until at least one policy selects a pod |
| **Additive** | Multiple policies on the same pod are **OR**-ed together |
| **Direction** | Ingress (incoming to pod) and Egress (outgoing from pod) are independent |
| **Statefulness** | Connection-tracking is handled by the CNI — return traffic is allowed automatically |

> A pod with **no** NetworkPolicy selecting it behaves as if it has a wildcard allow rule.
> Once **any** policy selects a pod for a direction, all traffic in that direction not
> explicitly permitted is **denied**.
""")

st.divider()

# ── NodePorts ─────────────────────────────────────────────────────────────────

st.header("NodePort Services and NetworkPolicies")

st.markdown("""
NodePort Services expose a port on **every cluster node's IP**. How NetworkPolicies
interact with them depends on `spec.externalTrafficPolicy`:
""")

col_a, col_b = st.columns(2)

with col_a:
    st.subheader("`externalTrafficPolicy: Cluster` *(default)*")
    st.markdown("""
Traffic flow:

```
Client → NodeIP:NodePort → DNAT + SNAT → PodIP:containerPort
```

The CNI sees the **node's IP** as the source, not the real client.

**Consequence for NetworkPolicy:**
- `podSelector` / `namespaceSelector` rules on the receiving pod cannot
  identify the original client.
- To allow NodePort traffic you must permit the **node CIDR** via an
  `ipBlock` ingress rule.
- The port in the policy must be the **container port** (e.g. `8080`),
  **not** the NodePort (e.g. `32000`).
""")

with col_b:
    st.subheader("`externalTrafficPolicy: Local`")
    st.markdown("""
Traffic flow:

```
Client → NodeIP:NodePort → DNAT only → PodIP:containerPort
```

SNAT is skipped; the pod sees the **real client IP**.

**Consequence for NetworkPolicy:**
- `ipBlock` rules can match the actual client CIDR.
- Only nodes that are running the target pod will accept the traffic;
  other nodes drop it at the node level.
- Same rule: use the **container port**, not the NodePort.
""")

st.info(
    "**Summary:** NetworkPolicies never reference NodePort numbers. "
    "Always write rules against the **container port**. "
    "Use `ipBlock` with node CIDRs when `externalTrafficPolicy: Cluster` is in effect.",
    icon="ℹ️",
)

st.divider()

# ── Policy patterns ───────────────────────────────────────────────────────────

st.header("Policy patterns")
st.markdown("Click any pattern to see what it produces.")

# ── 1. Default deny ───────────────────────────────────────────────────────────

with st.expander("1 · Default deny — block all ingress **and** egress for a set of pods"):
    st.markdown("""
Selecting pods and declaring both `Ingress` and `Egress` in `policyTypes` with
**no** rules causes complete isolation.

**When to use:**
Baseline for sensitive workloads (databases, secret stores).
Pair with allow rules that re-open exactly what is needed.
""")
    st.code("""
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: payments
spec:
  podSelector:
    matchLabels:
      tier: database
  policyTypes:
  - Ingress
  - Egress
""", language="yaml")

# ── 2. Allow ingress from same namespace ──────────────────────────────────────

with st.expander("2 · Allow ingress from pods in the **same namespace**"):
    st.markdown("""
An empty `namespaceSelector` combined with a `podSelector` restricts traffic
to pods within the same namespace that carry specific labels.
""")
    st.code("""
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-from-frontend
  namespace: payments
spec:
  podSelector:
    matchLabels:
      tier: api
  policyTypes:
  - Ingress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          tier: frontend
    ports:
    - protocol: TCP
      port: 8080
""", language="yaml")

# ── 3. Allow ingress from a different namespace ───────────────────────────────

with st.expander("3 · Allow ingress from a **different namespace**"):
    st.markdown("""
Combine `namespaceSelector` + `podSelector` **inside the same `from` entry** to
require both conditions simultaneously (AND logic).

Listing them as separate `from` entries would be OR logic — matching either
condition alone would suffice.
""")
    st.code("""
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-from-monitoring
  namespace: payments
spec:
  podSelector:
    matchLabels:
      tier: api
  policyTypes:
  - Ingress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: monitoring
      podSelector:             # same list item → AND
        matchLabels:
          app: prometheus
    ports:
    - protocol: TCP
      port: 9090
""", language="yaml")
    st.warning(
        "Indentation matters: `namespaceSelector` and `podSelector` at the **same** "
        "list level (under one `-`) = AND. Separate `-` entries = OR.",
        icon="⚠️",
    )

# ── 4. Allow ingress from external IPs ───────────────────────────────────────

with st.expander("4 · Allow ingress from **external IPs** (ipBlock)"):
    st.markdown("""
Use `ipBlock` to allow traffic from specific CIDRs outside the cluster.
The optional `except` field carves out sub-ranges to deny.
""")
    st.code("""
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-external-https
  namespace: payments
spec:
  podSelector:
    matchLabels:
      tier: ingress
  policyTypes:
  - Ingress
  ingress:
  - from:
    - ipBlock:
        cidr: 10.0.0.0/8
        except:
        - 10.96.0.0/12   # exclude cluster service CIDR
    ports:
    - protocol: TCP
      port: 443
""", language="yaml")

# ── 5. Allow egress to a specific namespace ───────────────────────────────────

with st.expander("5 · Allow egress **to a specific namespace**"):
    st.markdown("""
Egress rules follow the same selector logic as ingress, but use `to:` instead of `from:`.
""")
    st.code("""
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-egress-to-db
  namespace: payments
spec:
  podSelector:
    matchLabels:
      tier: api
  policyTypes:
  - Egress
  egress:
  - to:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: data
      podSelector:
        matchLabels:
          app: postgres
    ports:
    - protocol: TCP
      port: 5432
""", language="yaml")

# ── 6. Allow egress to external IPs ──────────────────────────────────────────

with st.expander("6 · Allow egress to **external IPs / SaaS endpoints**"):
    st.markdown("""
Pods that call external APIs (payment gateways, analytics, etc.) need
egress `ipBlock` rules. DNS must be allowed separately (see pattern 7).

If multiple hostnames resolve to the same IP, only one rule is generated
— NetPol Crafter deduplicates overlapping CIDRs automatically.
""")
    st.code("""
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-egress-payment-gateway
  namespace: payments
spec:
  podSelector:
    matchLabels:
      tier: api
  policyTypes:
  - Egress
  egress:
  - to:
    - ipBlock:
        cidr: 185.60.216.35/32   # api.paymentprovider.com
    ports:
    - protocol: TCP
      port: 443
""", language="yaml")

# ── 7. Allow DNS egress ───────────────────────────────────────────────────────

with st.expander("7 · Allow **DNS egress** *(required with any egress restriction)*"):
    st.markdown("""
As soon as you restrict egress, pods can no longer resolve DNS — blocking
everything, including internal service discovery.

Always pair an egress restriction with a DNS allow rule targeting the
cluster DNS service (typically in `kube-system`).
""")
    st.code("""
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-dns-egress
  namespace: payments
spec:
  podSelector: {}   # applies to all pods in namespace
  policyTypes:
  - Egress
  egress:
  - to:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: kube-system
      podSelector:
        matchLabels:
          k8s-app: kube-dns
    ports:
    - protocol: UDP
      port: 53
    - protocol: TCP
      port: 53
""", language="yaml")
    st.info("On OpenShift, the DNS operator runs in `openshift-dns`. Adjust the namespace label accordingly.", icon="ℹ️")

# ── 8. matchLabels vs matchExpressions ────────────────────────────────────────

with st.expander("8 · `matchLabels` vs `matchExpressions`"):
    st.markdown("""
Both fields can appear together on the same selector; they are AND-ed.

| | `matchLabels` | `matchExpressions` |
|---|---|---|
| Type | Equality-based | Set-based |
| Use case | Exact key=value match | In/NotIn a set of values, or key existence check |

**Operators:**

| Operator | Meaning | `values` required |
|---|---|---|
| `In` | key's value is in the list | yes |
| `NotIn` | key's value is NOT in the list | yes |
| `Exists` | key is present (any value) | no |
| `DoesNotExist` | key is absent | no |
""")
    st.code("""
# Allow ingress from any pod that:
#   - has label  env=prod  AND
#   - has label  tier  with value  api  or  worker  AND
#   - does NOT have label  debug
ingress:
- from:
  - podSelector:
      matchLabels:
        env: prod
      matchExpressions:
      - key: tier
        operator: In
        values: [api, worker]
      - key: debug
        operator: DoesNotExist
""", language="yaml")

# ── 9. Allow all ingress / egress ─────────────────────────────────────────────

with st.expander("9 · Allow **all ingress** or **all egress** explicitly"):
    st.markdown("""
An empty `from: []` or `to: []` rule means "allow from/to anywhere".
This is useful when you need to declare `Ingress` or `Egress` in `policyTypes`
(to activate the default-deny) but want to re-open everything for one direction.
""")
    st.code("""
# Restricts egress only; ingress is unrestricted
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: restrict-egress-only
  namespace: payments
spec:
  podSelector:
    matchLabels:
      tier: api
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - {}          # empty rule = allow all ingress
  egress:
  - to:
    - namespaceSelector: {}   # allow egress to any namespace (but not external)
""", language="yaml")

# ── 10. NodePort allow via node CIDR ──────────────────────────────────────────

with st.expander("10 · Allow traffic arriving via a **NodePort** service"):
    st.markdown("""
With `externalTrafficPolicy: Cluster` (the default), traffic from a NodePort
arrives at the pod with the **source IP replaced by a node IP**.

Use an `ipBlock` rule covering your node CIDR so the policy allows it.
""")
    st.code("""
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-nodeport-ingress
  namespace: payments
spec:
  podSelector:
    matchLabels:
      tier: api
  policyTypes:
  - Ingress
  ingress:
  - from:
    - ipBlock:
        cidr: 10.0.0.0/16   # your node subnet
    ports:
    - protocol: TCP
      port: 8080   # container port, NOT the NodePort number
""", language="yaml")
    st.warning(
        "Never put the NodePort number (e.g. `32000`) in the policy. "
        "NetworkPolicies match on the **container port** (`8080` in this example).",
        icon="⚠️",
    )

st.divider()

# ── Limitations ───────────────────────────────────────────────────────────────

st.header("Known limitations")

st.markdown("""
| Limitation | Detail |
|---|---|
| **No node-level blocking** | NetworkPolicies cannot block traffic between nodes or from the host network namespace |
| **No L7 rules** | Standard NetworkPolicy is L3/L4 only. For HTTP path / header matching use Cilium `CiliumNetworkPolicy` or an Istio `AuthorizationPolicy` |
| **NodePort SNAT** | With `externalTrafficPolicy: Cluster`, the real client IP is lost; `ipBlock` rules must target node CIDRs |
| **No egress from host-networked pods** | Pods with `hostNetwork: true` bypass NetworkPolicy enforcement on most CNIs |
| **Cluster-wide policies** | Standard NetworkPolicy is namespace-scoped. Use `GlobalNetworkPolicy` (Calico) or `ClusterNetworkPolicy` (Antrea / Cilium) for cluster-wide rules |
| **DNS after egress restrict** | Blocking all egress also blocks DNS — always add an explicit DNS allow rule |
""")
