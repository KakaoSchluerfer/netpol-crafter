# Pharos – Production Setup Guide

This guide covers deploying Pharos on an OpenShift cluster using
OpenShift OAuth for authentication and a dedicated exporter ServiceAccount for
cluster-wide read access.

---

## Architecture overview

```
  ┌─────────────────────────────────────────────────────────────┐
  │  OpenShift Cluster  (one deployment per cluster)            │
  │                                                             │
  │  ┌────────────────────┐    HTTP :8080     ┌──────────────┐  │
  │  │  pharos-frontend    │ ─────────────────►│  netpol-     │  │
  │  │  (Streamlit :8501) │                   │  exporter    │  │
  │  │                    │                   │  (FastAPI)   │  │
  │  │  • Policy builder  │                   │              │  │
  │  │  • Network map     │                   │  SA token    │  │
  │  └────────────────────┘                   │  reads all   │  │
  │         │ user OAuth token                │  resources   │  │
  │         ▼                                 └──────────────┘  │
  │   OpenShift OAuth                                           │
  │   (OAuthClient CR)                                          │
  └─────────────────────────────────────────────────────────────┘
```

**Key design decisions:**

| Concern | Approach |
|---------|----------|
| Authentication | OpenShift OAuth (`authorization_code` flow) |
| Policy builder data | `pharos-exporter` SA reads cluster-wide; served as JSON REST API |
| Network Policy Map | Logged-in user's OAuth token → shows only RBAC-permitted namespaces |
| GitOps / apply | Out of scope — export the YAML and apply via your existing pipeline |
| Multi-cluster | Deploy one `pharos-frontend` + one `pharos-exporter` per cluster |

---

## 1. Namespace

```bash
oc new-project pharos-frontend 2>/dev/null || oc project pharos-frontend
```

---

## 2. ServiceAccount & RBAC for the exporter

The exporter reads cluster resources with a dedicated ServiceAccount.
The crafter app pod itself needs **no special RBAC** — it uses the logged-in
user's OAuth token for the Network Policy Map.

```yaml
# deploy/rbac.yaml — apply this first
oc apply -f deploy/rbac.yaml
```

The file creates:
- `pharos-exporter` ServiceAccount
- `pharos-exporter` ClusterRole (read-only: namespaces, pods, services,
  routes, networkpolicies, adminnetworkpolicies, baselineadminnetworkpolicies)
- `pharos-exporter` ClusterRoleBinding

> **Note:** AdminNetworkPolicy / BaselineAdminNetworkPolicy are `policy.networking.k8s.io`
> CRDs available on OpenShift 4.14+ with the ANP feature gate enabled.
> The exporter gracefully skips these if the CRD is absent (HTTP 404/403).

---

## 3. Register an OAuthClient on the cluster

OpenShift OAuth requires a pre-registered `OAuthClient` CR.

```bash
cat <<EOF | oc apply -f -
apiVersion: oauth.openshift.io/v1
kind: OAuthClient
metadata:
  name: pharos-frontend
secret: "$(openssl rand -base64 32 | tr -d '=+/' | head -c 40)"
redirectURIs:
  - https://pharos-frontend.apps.your-cluster.example.com
grantMethod: auto
EOF
```

Note the `secret` value — you'll need it as `OCP_CLIENT_SECRET`.

To retrieve the current secret later:
```bash
oc get oauthclient pharos-frontend -o jsonpath='{.secret}'
```

---

## 4. Build the app Secret

```bash
# Generate a strong random app key
APP_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(64))")

oc create secret generic pharos-frontend-env \
  -n pharos-frontend \
  --from-literal=OCP_CLIENT_ID=pharos-frontend \
  --from-literal=OCP_CLIENT_SECRET=<secret-from-step-3> \
  --from-literal=OCP_API_SERVER=https://api.your-cluster.example.com:6443 \
  --from-literal=OCP_REDIRECT_URI=https://pharos-frontend.apps.your-cluster.example.com \
  --from-literal=APP_SECRET_KEY="$APP_KEY" \
  --from-literal=CLUSTER_NAME="Production (OCP 4.14)"
```

If your cluster uses a custom CA:
```bash
# Add the CA bundle as a separate secret
oc create secret generic pharos-frontend-certs \
  -n pharos-frontend \
  --from-file=cluster-ca.crt=/path/to/cluster-ca.crt

# Then set OCP_CA_CERT_PATH=/etc/netpol-certs/cluster-ca.crt in the env Secret
# and mount pharos-frontend-certs at /etc/netpol-certs in the deployment
```

---

## 5. Deploy

```bash
oc apply -f deploy/deployment.yaml
```

This creates:
- `pharos-frontend` Deployment (Streamlit app on port 8501)
- `pharos-exporter` Deployment (FastAPI on port 8080, uses `pharos-exporter` SA)
- `pharos-exporter` Service (ClusterIP, reachable by the crafter)
- `pharos-frontend` Service
- `pharos-frontend` Route (TLS edge termination)

---

## 6. Verify

```bash
# Check pods are running
oc get pods -n pharos-frontend

# Exporter health
oc exec -n pharos-frontend deploy/pharos-exporter -- \
  curl -sf http://localhost:8080/health

# Exporter snapshot (should return real cluster data)
oc exec -n pharos-frontend deploy/pharos-exporter -- \
  curl -s http://localhost:8080/snapshot | python3 -m json.tool | head -40

# App health
oc exec -n pharos-frontend deploy/pharos-frontend -- \
  curl -sf http://localhost:8501/_stcore/health

# Open the app
oc get route pharos-frontend -n pharos-frontend -o jsonpath='{.spec.host}'
```

---

## 7. Route ingress policy pattern

For a route to be reachable through the OpenShift router, the target pods
must have a `NetworkPolicy` that allows ingress from the `openshift-ingress`
namespace. The recommended pattern uses the built-in namespace label:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-router-ingress
  namespace: my-app
spec:
  podSelector:
    matchLabels:
      app: my-app
  policyTypes: [Ingress]
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              policy-group.network.openshift.io/ingress: ""
      ports:
        - protocol: TCP
          port: 8080
```

The label `policy-group.network.openshift.io/ingress: ""` is automatically
present on the `openshift-ingress` namespace in OCP 4.12+.

The Network Policy Map **Route** tab flags any route whose backend pods
lack such a rule, helping you find misconfigured apps before users do.

---

## 8. AdminNetworkPolicy (ANP) setup

ANPs are cluster-scoped and evaluated **before** namespace-scoped
`NetworkPolicy` objects. They are useful for:

- **Platform-wide egress allowlists** (Artifactory, Dynatrace, Splunk, OCP API)
- **Cluster-wide deny baselines** (`BaselineAdminNetworkPolicy`)

Example — allow all production namespaces to reach an internal Artifactory:

```yaml
apiVersion: policy.networking.k8s.io/v1alpha1
kind: AdminNetworkPolicy
metadata:
  name: allow-egress-artifactory
spec:
  priority: 100
  subject:
    namespaces:
      matchLabels:
        environment: production
  egress:
    - action: Allow
      to:
        - networks:
            - cidr: 10.50.10.100/32
      ports:
        - portNumber:
            protocol: TCP
            port: 443
```

The Network Policy Map shows ANP edges in **purple** (Allow) or
**red dashed** (Deny). Use the "Show AdminNetworkPolicies" toggle in the
sidebar to show or hide them.

ANPs require the `AdminNetworkPolicy` feature gate to be enabled on the
cluster (OCP 4.14+ with OVN-Kubernetes). Check availability:

```bash
oc api-resources --api-group=policy.networking.k8s.io
```

---

## 9. Security checklist

| Item | Action |
|------|--------|
| OAuthClient secret | Store in an OCP `Secret`; rotate via `oc patch oauthclient` |
| TLS | Use edge/reencrypt termination on the Route; set `OCP_CA_CERT_PATH` for custom CAs |
| Exporter SA | Minimum read-only RBAC; never add write verbs |
| App secret key | Generate with `secrets.token_urlsafe(64)`; store in OCP Secret |
| Network isolation | Create a `NetworkPolicy` in `pharos-frontend` namespace allowing only router ingress and exporter egress |
| RBAC for users | OCP RBAC controls what namespaces each user sees in the Network Policy Map |
| No write access | The app never applies NetworkPolicies; export the YAML and use your GitOps pipeline |

---

## 10. Local development (TEST_MODE)

```bash
# No credentials or cluster needed
docker compose up --build
open http://localhost:8501
```

The `docker-compose.yml` uses `.env.test` (committed, no real secrets):
- `TEST_MODE=true` — serves realistic banking fixture data
- All OCP OAuth calls are bypassed
- The exporter at `http://localhost:8080` serves fixture data

To test against a real cluster:
```bash
cp .env.example .env
# Fill in OCP_* values
docker compose up --build
```
