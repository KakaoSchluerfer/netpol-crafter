# NetPol Crafter – Production Setup Guide

This guide covers deploying NetPol Crafter in a production OpenShift environment
with access to one or more clusters.

---

## Architecture overview

```
         ┌────────────────────────────────────────────────────────┐
         │  Management cluster (or standalone VM/pod)             │
         │                                                        │
         │  ┌──────────────────┐   CLUSTERS_JSON (SA tokens)     │
         │  │  netpol-crafter  │ ──────────────────────────────► OCP Cluster A
         │  │  (Streamlit pod) │ ──────────────────────────────► OCP Cluster B
         │  └──────────────────┘ ──────────────────────────────► OCP Cluster …
         │         │                                              │
         │         ▼                                              │
         │   Azure AD (OIDC)      GitHub (GitOps PR)             │
         └────────────────────────────────────────────────────────┘
```

The app itself needs **no privileged access** — it reads cluster state with a
read-only ServiceAccount and optionally applies policies using a write-capable SA.

---

## 1. ServiceAccount setup per cluster

Run the following on **each** OpenShift cluster you want to connect.

```bash
# Adjust the namespace name as appropriate
NAMESPACE=netpol-crafter

oc new-project $NAMESPACE 2>/dev/null || oc project $NAMESPACE
```

### 1a. Read-only ClusterRole (required)

```yaml
# rbac-readonly.yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: netpol-crafter-reader
rules:
  - apiGroups: [""]
    resources: ["namespaces", "pods", "services"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["networking.k8s.io"]
    resources: ["networkpolicies"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["route.openshift.io"]
    resources: ["routes"]
    verbs: ["get", "list", "watch"]
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: netpol-crafter
  namespace: netpol-crafter
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: netpol-crafter-reader
subjects:
  - kind: ServiceAccount
    name: netpol-crafter
    namespace: netpol-crafter
roleRef:
  kind: ClusterRole
  name: netpol-crafter-reader
  apiGroup: rbac.authorization.k8s.io
```

```bash
oc apply -f rbac-readonly.yaml
```

### 1b. Write ClusterRole (optional – needed for break-glass direct apply)

```yaml
# rbac-writer.yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: netpol-crafter-writer
rules:
  - apiGroups: ["networking.k8s.io"]
    resources: ["networkpolicies"]
    verbs: ["get", "list", "watch", "create", "update", "patch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: netpol-crafter-writer
subjects:
  - kind: ServiceAccount
    name: netpol-crafter
    namespace: netpol-crafter
roleRef:
  kind: ClusterRole
  name: netpol-crafter-writer
  apiGroup: rbac.authorization.k8s.io
```

```bash
oc apply -f rbac-writer.yaml  # only on clusters where direct apply is needed
```

### 1c. Extract the SA token

On OpenShift 4.11+ tokens are short-lived by default. Create a long-lived one:

```bash
# Create a long-lived token secret
cat <<EOF | oc apply -f -
apiVersion: v1
kind: Secret
metadata:
  name: netpol-crafter-token
  namespace: netpol-crafter
  annotations:
    kubernetes.io/service-account.name: netpol-crafter
type: kubernetes.io/service-account-token
EOF

# Wait a moment for the token to be populated
sleep 3

# Extract the token
oc get secret netpol-crafter-token \
  -n netpol-crafter \
  -o jsonpath='{.data.token}' | base64 -d
```

Save this token — you'll put it in `CLUSTERS_JSON`.

### 1d. Extract the cluster CA certificate

```bash
oc get secret netpol-crafter-token \
  -n netpol-crafter \
  -o jsonpath='{.data.ca\.crt}' | base64 -d > prod-east-ca.crt
```

Or fetch it from the cluster's well-known endpoint:

```bash
oc get cm kube-root-ca.crt -n kube-system -o jsonpath='{.data.ca\.crt}' > prod-east-ca.crt
```

---

## 2. Build the CLUSTERS_JSON secret

Repeat step 1 for every cluster. Then assemble the JSON:

```json
[
  {
    "name":         "prod-east",
    "display_name": "Production East (OCP 4.14)",
    "api_server":   "https://api.ocp-east.example.com:6443",
    "token":        "eyJhbGciOiJSUzI1NiIsI...",
    "ca_cert_path": "/etc/netpol-certs/prod-east-ca.crt"
  },
  {
    "name":         "prod-west",
    "display_name": "Production West (OCP 4.14)",
    "api_server":   "https://api.ocp-west.example.com:6443",
    "token":        "eyJhbGciOiJSUzI1NiIsI...",
    "ca_cert_path": "/etc/netpol-certs/prod-west-ca.crt"
  }
]
```

Store this as a Kubernetes Secret on the **management cluster**:

```bash
# Store the CA certs
oc create secret generic netpol-crafter-certs \
  -n netpol-crafter \
  --from-file=prod-east-ca.crt \
  --from-file=prod-west-ca.crt

# Store the CLUSTERS_JSON and other app secrets
oc create secret generic netpol-crafter-env \
  -n netpol-crafter \
  --from-literal=CLUSTERS_JSON='[{"name":"prod-east",...}]' \
  --from-literal=OIDC_CLIENT_SECRET=... \
  --from-literal=APP_SECRET_KEY=... \
  --from-literal=GITHUB_TOKEN=...
```

---

## 3. Deployment manifest

```yaml
# deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: netpol-crafter
  namespace: netpol-crafter
spec:
  replicas: 1
  selector:
    matchLabels:
      app: netpol-crafter
  template:
    metadata:
      labels:
        app: netpol-crafter
    spec:
      serviceAccountName: netpol-crafter
      containers:
        - name: app
          image: your-registry.example.com/netpol-crafter:latest
          ports:
            - containerPort: 8501
          env:
            # Non-secret config (set directly or via ConfigMap)
            - name: OIDC_CLIENT_ID
              value: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
            - name: AZURE_TENANT_ID
              value: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
            - name: OIDC_REDIRECT_URI
              value: "https://netpol-crafter.internal.example.com"
            - name: GITHUB_REPO
              value: "your-org/network-policies"
            - name: GITHUB_BASE_BRANCH
              value: "main"
            - name: GITHUB_POLICIES_PATH
              value: "policies"
            - name: TEST_MODE
              value: "false"
            # Secret values from the secret
            - name: CLUSTERS_JSON
              valueFrom:
                secretKeyRef:
                  name: netpol-crafter-env
                  key: CLUSTERS_JSON
            - name: OIDC_CLIENT_SECRET
              valueFrom:
                secretKeyRef:
                  name: netpol-crafter-env
                  key: OIDC_CLIENT_SECRET
            - name: APP_SECRET_KEY
              valueFrom:
                secretKeyRef:
                  name: netpol-crafter-env
                  key: APP_SECRET_KEY
            - name: GITHUB_TOKEN
              valueFrom:
                secretKeyRef:
                  name: netpol-crafter-env
                  key: GITHUB_TOKEN
          volumeMounts:
            - name: cluster-certs
              mountPath: /etc/netpol-certs
              readOnly: true
          resources:
            requests:
              cpu: 100m
              memory: 256Mi
            limits:
              cpu: 500m
              memory: 512Mi
          livenessProbe:
            httpGet:
              path: /_stcore/health
              port: 8501
            initialDelaySeconds: 30
            periodSeconds: 30
          readinessProbe:
            httpGet:
              path: /_stcore/health
              port: 8501
            initialDelaySeconds: 10
            periodSeconds: 10
      volumes:
        - name: cluster-certs
          secret:
            secretName: netpol-crafter-certs
---
apiVersion: v1
kind: Service
metadata:
  name: netpol-crafter
  namespace: netpol-crafter
spec:
  selector:
    app: netpol-crafter
  ports:
    - port: 8501
      targetPort: 8501
---
# OpenShift Route (TLS terminated at the router)
apiVersion: route.openshift.io/v1
kind: Route
metadata:
  name: netpol-crafter
  namespace: netpol-crafter
spec:
  host: netpol-crafter.apps.management-cluster.example.com
  to:
    kind: Service
    name: netpol-crafter
  port:
    targetPort: 8501
  tls:
    termination: edge
    insecureEdgeTerminationPolicy: Redirect
```

```bash
oc apply -f deployment.yaml
```

---

## 4. Azure AD app registration

1. Go to **Azure Portal → App registrations → New registration**
2. Name: `netpol-crafter`
3. Supported account types: **Single tenant** (your org only)
4. Redirect URI: `https://netpol-crafter.apps.management-cluster.example.com` (Web)
5. After creation:
   - Note the **Application (client) ID** → `OIDC_CLIENT_ID`
   - Note the **Directory (tenant) ID** → `AZURE_TENANT_ID`
   - **Certificates & secrets → New client secret** → `OIDC_CLIENT_SECRET`
6. **API permissions → Add permission → Microsoft Graph → openid, profile, email**

---

## 5. GitHub App (recommended over PAT)

1. Go to `https://github.com/organizations/YOUR_ORG/settings/apps/new`
2. Set:
   - **Homepage URL**: your app URL
   - **Webhook**: uncheck (not needed)
   - **Permissions**: Repository → Contents (read/write), Pull requests (read/write)
3. Install the app on the target `network-policies` repo
4. Note: **App ID**, **Installation ID**, download the **private key** (.pem)
5. Store the PEM in a secret and set `GITHUB_APP_PRIVATE_KEY_PATH=/run/secrets/github-app.pem`

---

## 6. Token rotation

Long-lived SA tokens don't expire automatically but should be rotated periodically.

```bash
# On each target cluster – delete and recreate the secret
oc delete secret netpol-crafter-token -n netpol-crafter
oc apply -f - <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: netpol-crafter-token
  namespace: netpol-crafter
  annotations:
    kubernetes.io/service-account.name: netpol-crafter
type: kubernetes.io/service-account-token
EOF

sleep 3
NEW_TOKEN=$(oc get secret netpol-crafter-token -n netpol-crafter -o jsonpath='{.data.token}' | base64 -d)

# Update the management cluster secret
oc patch secret netpol-crafter-env \
  -n netpol-crafter \
  --type=json \
  -p="[{\"op\":\"replace\",\"path\":\"/data/CLUSTERS_JSON\",\"value\":\"$(echo -n "$UPDATED_JSON" | base64 -w0)\"}]"

# Restart the app to pick up the new token (cache_resource will re-build clients)
oc rollout restart deployment/netpol-crafter -n netpol-crafter
```

---

## 7. Security checklist

| Item | Action |
|------|--------|
| SA tokens | One SA per cluster; minimum required RBAC (reader vs. writer) |
| TLS | Always use edge/reencrypt termination; `ca_cert_path` must point to the cluster CA |
| Secrets | Store all secrets in OCP Secret objects, never in ConfigMaps or env files |
| OIDC | Restrict the Azure AD app to your tenant; add group-based access control if needed |
| GitHub | Use a GitHub App with scoped repo install, not an org-wide PAT |
| Network | The app pod only needs egress to each cluster API server and to GitHub |
| Write access | Only add the `netpol-crafter-writer` ClusterRole on clusters where break-glass apply is permitted |

---

## 8. Single-cluster (legacy / simple) setup

If you have one cluster and the app runs inside it, skip `CLUSTERS_JSON` entirely and
use the in-cluster ServiceAccount:

```bash
# The SA is already bound above (step 1)
# Just set:
K8S_IN_CLUSTER=true
# No token or ca_cert_path needed — the pod's mounted token handles auth
```

The app falls back to a single cluster named `default` using the pod's own SA token.
