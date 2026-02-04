# Setting Up OIDC Authentication for k3s with simple-idp and Headlamp

This guide walks through configuring OIDC authentication for a k3s Kubernetes cluster using simple-idp as the identity provider and Headlamp as the dashboard UI.

## Architecture

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Browser   │────▶│  Headlamp   │────▶│  k3s API    │
│             │     │  (OIDC RP)  │     │  Server     │
└─────────────┘     └──────┬──────┘     └──────┬──────┘
                           │                   │
                           │ OIDC Auth         │ Validate
                           ▼                   │ Token
                    ┌─────────────┐            │
                    │ simple-idp  │◀───────────┘
                    │  (OIDC IdP) │  Fetch JWKS
                    └─────────────┘
```

| Component | Role | Example URL |
|-----------|------|-------------|
| simple-idp | OIDC Identity Provider | `https://idp.example.com` |
| Headlamp | Kubernetes Dashboard (OIDC Relying Party) | `https://k8s.example.com` |
| k3s API | Kubernetes API Server | `https://k8s-api.example.com:6443` |

## Prerequisites

- k3s cluster (single or multi-node)
- Ingress controller (nginx-gateway, traefik, etc.)
- cert-manager for TLS certificates
- kubectl access to the cluster
- Domain names for IdP and Headlamp

## Part 1: Deploy simple-idp

### 1.1 Build the Container Image

```dockerfile
# Dockerfile
FROM golang:1.24-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /idp ./cmd/idp

FROM alpine:3.19
RUN apk --no-cache add ca-certificates
WORKDIR /app
COPY --from=builder /idp .
RUN mkdir -p /app/data
EXPOSE 8080
CMD ["./idp"]
```

Build and push:
```bash
docker build -t your-registry/simple-idp:latest .
docker push your-registry/simple-idp:latest
```

### 1.2 Create Kubernetes Manifests

```yaml
# simple-idp.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: simple-idp
---
apiVersion: v1
kind: Secret
metadata:
  name: simple-idp-secrets
  namespace: simple-idp
type: Opaque
stringData:
  # OIDC client secret - must match Headlamp's config
  client-secret: "your-secure-client-secret-here"
  # Bootstrap users: email:password:display_name (comma-separated for multiple)
  bootstrap-users: "admin@example.com:secure-password:Admin User,viewer@example.com:viewer-pass:Viewer"
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: simple-idp
  namespace: simple-idp
spec:
  replicas: 1
  selector:
    matchLabels:
      app: simple-idp
  template:
    metadata:
      labels:
        app: simple-idp
    spec:
      containers:
      - name: simple-idp
        image: your-registry/simple-idp:latest
        ports:
        - containerPort: 8080
        env:
        - name: IDP_HOST
          value: "0.0.0.0"
        - name: IDP_PORT
          value: "8080"
        # CRITICAL: Must match the external URL exactly
        - name: IDP_ISSUER_URL
          value: "https://idp.example.com"
        - name: IDP_DATA_DIR
          value: "/app/data"
        - name: IDP_COOKIE_SECURE
          value: "true"
        - name: IDP_LOG_LEVEL
          value: "info"
        - name: IDP_LOG_FORMAT
          value: "json"
        # OIDC client configuration
        - name: IDP_CLIENT_ID
          value: "headlamp"
        - name: IDP_CLIENT_SECRET
          valueFrom:
            secretKeyRef:
              name: simple-idp-secrets
              key: client-secret
        - name: IDP_CLIENT_REDIRECT_URI
          value: "https://k8s.example.com/oidc-callback"
        # Bootstrap users
        - name: IDP_BOOTSTRAP_USERS
          valueFrom:
            secretKeyRef:
              name: simple-idp-secrets
              key: bootstrap-users
        volumeMounts:
        - name: data
          mountPath: /app/data
        livenessProbe:
          httpGet:
            path: /healthz
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /readyz
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 10
      volumes:
      # IMPORTANT: Use PVC to persist signing keys
      - name: data
        persistentVolumeClaim:
          claimName: simple-idp-data
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: simple-idp-data
  namespace: simple-idp
spec:
  accessModes:
  - ReadWriteOnce
  resources:
    requests:
      storage: 1Gi
---
apiVersion: v1
kind: Service
metadata:
  name: simple-idp
  namespace: simple-idp
spec:
  selector:
    app: simple-idp
  ports:
  - port: 80
    targetPort: 8080
```

> **CRITICAL: Use PersistentVolumeClaim, not emptyDir**
>
> simple-idp generates RSA signing keys on startup. If you use `emptyDir`, the keys are lost when the pod restarts, causing all existing tokens to become invalid. Users will see "failed to verify signature" errors and need to re-login. A PVC ensures keys persist across restarts.

### 1.3 Expose simple-idp with TLS

Using Gateway API:

```yaml
# idp-certificate.yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: idp-tls
  namespace: your-gateway-namespace
spec:
  secretName: idp-tls
  issuerRef:
    name: letsencrypt-prod
    kind: ClusterIssuer
  dnsNames:
  - "idp.example.com"
---
# idp-httproute.yaml
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: simple-idp
  namespace: simple-idp
spec:
  parentRefs:
  - name: main-gateway
    namespace: your-gateway-namespace
  hostnames:
  - "idp.example.com"
  rules:
  - matches:
    - path:
        type: PathPrefix
        value: /
    backendRefs:
    - name: simple-idp
      port: 80
```

Add a listener to your Gateway:

```yaml
- name: https-idp
  port: 443
  protocol: HTTPS
  hostname: "idp.example.com"
  tls:
    mode: Terminate
    certificateRefs:
    - name: idp-tls
      kind: Secret
  allowedRoutes:
    namespaces:
      from: All
```

### 1.4 Verify simple-idp

```bash
# Check pod is running
kubectl get pods -n simple-idp

# Check logs
kubectl logs -n simple-idp deploy/simple-idp

# Test OIDC discovery endpoint
curl https://idp.example.com/.well-known/openid-configuration
```

Expected discovery response includes:
```json
{
  "issuer": "https://idp.example.com",
  "authorization_endpoint": "https://idp.example.com/authorize",
  "token_endpoint": "https://idp.example.com/token",
  "jwks_uri": "https://idp.example.com/.well-known/jwks.json",
  "end_session_endpoint": "https://idp.example.com/logout",
  ...
}
```

## Part 2: Configure k3s API Server for OIDC

The Kubernetes API server must be configured to validate OIDC tokens from simple-idp.

### 2.1 For Existing Clusters (Manual Configuration)

SSH to each control plane node and create the configuration:

```bash
sudo tee /etc/rancher/k3s/config.yaml << 'EOF'
kube-apiserver-arg:
  - "oidc-issuer-url=https://idp.example.com"
  - "oidc-client-id=headlamp"
  - "oidc-username-claim=email"
EOF

sudo systemctl restart k3s
```

> **IMPORTANT: Edit config.yaml, NOT k3s.yaml**
>
> - `/etc/rancher/k3s/config.yaml` - Server configuration file (edit this)
> - `/etc/rancher/k3s/k3s.yaml` - Auto-generated kubeconfig (do NOT edit)
>
> If config.yaml doesn't exist, create it. The k3s.yaml file is regenerated on restart.

### 2.2 For New Clusters (Terraform/Cloud-Init)

Add to your cloud-init template:

```yaml
# cloud-init template (e.g., cp1.yaml.tftpl)
runcmd:
  - curl -sfL https://get.k3s.io | sh -s - server
      --disable traefik
      --node-ip ${private_ip}
      --tls-san ${tls_san}
      --token ${k3s_token}
%{ if oidc_issuer_url != "" ~}
      --kube-apiserver-arg=oidc-issuer-url=${oidc_issuer_url}
      --kube-apiserver-arg=oidc-client-id=${oidc_client_id}
      --kube-apiserver-arg=oidc-username-claim=email
%{ endif ~}
```

Terraform variables:
```hcl
variable "oidc_issuer_url" {
  description = "OIDC issuer URL for API server authentication"
  type        = string
  default     = ""
}

variable "oidc_client_id" {
  description = "OIDC client ID (must match Headlamp config)"
  type        = string
  default     = "headlamp"
}
```

### 2.3 Verify k3s OIDC Configuration

```bash
# On control plane node
ps aux | grep kube-apiserver | grep oidc

# Should show:
# --oidc-issuer-url=https://idp.example.com
# --oidc-client-id=headlamp
# --oidc-username-claim=email

# Check k3s logs
sudo journalctl -u k3s | grep -i oidc
```

## Part 3: Configure Headlamp

### 3.1 Deploy Headlamp with OIDC

Using Helm:

```yaml
# headlamp.yaml (HelmRelease for Flux, or use helm install)
apiVersion: helm.toolkit.fluxcd.io/v2
kind: HelmRelease
metadata:
  name: headlamp
  namespace: flux-system
spec:
  interval: 30m
  chart:
    spec:
      chart: headlamp
      version: "0.39.0"
      sourceRef:
        kind: HelmRepository
        name: headlamp
        namespace: flux-system
  targetNamespace: headlamp
  valuesFrom:
  - kind: Secret
    name: headlamp-oidc-secret
    valuesKey: oidc-values
  values:
    replicaCount: 1
    service:
      type: ClusterIP
      port: 80
    ingress:
      enabled: false  # Use Gateway API instead
    serviceAccount:
      create: true
    clusterRoleBinding:
      create: true
    config:
      oidc:
        clientID: "headlamp"
        issuerURL: "https://idp.example.com"
        scopes: "openid profile email"
```

Create the OIDC secret:
```bash
kubectl create secret generic headlamp-oidc-secret \
  --namespace=flux-system \
  --from-literal=oidc-values='config:
  oidc:
    clientSecret: "your-secure-client-secret-here"'
```

> **The client secret must match between simple-idp and Headlamp exactly.**

### 3.2 Expose Headlamp

```yaml
# headlamp-httproute.yaml
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: headlamp
  namespace: headlamp
spec:
  parentRefs:
  - name: main-gateway
    namespace: your-gateway-namespace
  hostnames:
  - "k8s.example.com"
  rules:
  - matches:
    - path:
        type: PathPrefix
        value: /
    backendRefs:
    - name: headlamp
      port: 80
```

## Part 4: Configure RBAC for OIDC Users

OIDC users are identified by their email (the `oidc-username-claim`). Create ClusterRoleBindings to grant permissions:

```yaml
# oidc-rbac.yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: oidc-admin
subjects:
- kind: User
  name: admin@example.com  # Must match email from OIDC token
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: cluster-admin
  apiGroup: rbac.authorization.k8s.io
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: oidc-viewers
subjects:
- kind: User
  name: viewer@example.com
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: view  # Read-only access, no secrets
  apiGroup: rbac.authorization.k8s.io
```

### Adding New Users

1. Add user to simple-idp bootstrap users (update the secret)
2. Add ClusterRoleBinding for the user's email
3. Restart simple-idp: `kubectl rollout restart deployment simple-idp -n simple-idp`

## Part 5: Logout

Headlamp's logout button only clears the Headlamp session, not the IdP session. This means if you click "Logout" in Headlamp, you'll be automatically logged back in because the IdP session is still active.

### Full Logout Options

**Option 1:** Navigate directly to the IdP logout URL:
```
https://idp.example.com/logout?post_logout_redirect_uri=https://k8s.example.com
```

**Option 2:** Clear browser cookies for both domains.

**Option 3:** Open IdP logout in a new tab, then logout from Headlamp.

## Troubleshooting

### "Failed to verify ID Token: expected audience X got Y"

The ID token's `aud` claim doesn't match what k3s expects.

**Cause:** simple-idp wasn't setting the audience correctly.

**Solution:** Ensure simple-idp version includes the fix that sets `aud` to the client_id. Check the token:
```bash
# Decode a JWT token (from browser dev tools)
echo "eyJ..." | cut -d. -f2 | base64 -d | jq .
# Should show: "aud": ["headlamp"]
```

### 401 Unauthorized from Kubernetes API

1. **Check k3s has OIDC configured:**
   ```bash
   ps aux | grep kube-apiserver | grep oidc
   ```

2. **Check ClusterRoleBinding exists:**
   ```bash
   kubectl get clusterrolebinding oidc-admin -o yaml
   ```

3. **Verify email in token matches RBAC subject:**
   ```bash
   # Decode token and check email claim
   echo "eyJ..." | cut -d. -f2 | base64 -d | jq -r .email
   ```

### Token signature verification failed

```
failed to verify id token signature
```

**Cause:** k3s cached old JWKS after simple-idp restarted with new signing keys.

**Solution:**
1. If using emptyDir, switch to PVC (permanent fix)
2. Restart k3s to refresh OIDC key cache:
   ```bash
   sudo systemctl restart k3s
   ```
3. Clear browser cookies and re-login

### Invalid client credentials

**Cause:** Client secret mismatch between Headlamp and simple-idp.

**Solution:** Ensure both secrets have exactly the same value:
```bash
# Check simple-idp secret
kubectl get secret simple-idp-secrets -n simple-idp -o jsonpath='{.data.client-secret}' | base64 -d

# Check Headlamp secret
kubectl get secret headlamp-oidc-secret -n flux-system -o jsonpath='{.data.oidc-values}' | base64 -d
```

### Certificate errors

1. Check certificate is Ready:
   ```bash
   kubectl get certificate -A | grep idp
   ```

2. Check cert-manager logs:
   ```bash
   kubectl logs -n cert-manager deploy/cert-manager
   ```

3. Verify DNS resolves correctly:
   ```bash
   dig idp.example.com
   ```

### OIDC discovery fails

```bash
# Test from inside the cluster
kubectl run curl --rm -it --image=curlimages/curl -- \
  curl -v https://idp.example.com/.well-known/openid-configuration
```

If this fails but external access works, check:
- DNS resolution inside cluster
- Network policies
- Service and HTTPRoute configuration

### k3s config keeps reverting

**Wrong file:** You're editing `/etc/rancher/k3s/k3s.yaml` (kubeconfig) instead of `/etc/rancher/k3s/config.yaml` (server config).

**Solution:** Create or edit `/etc/rancher/k3s/config.yaml`:
```bash
sudo tee /etc/rancher/k3s/config.yaml << 'EOF'
kube-apiserver-arg:
  - "oidc-issuer-url=https://idp.example.com"
  - "oidc-client-id=headlamp"
  - "oidc-username-claim=email"
EOF
sudo systemctl restart k3s
```

## Verification Checklist

- [ ] simple-idp pod is running: `kubectl get pods -n simple-idp`
- [ ] OIDC discovery works: `curl https://idp.example.com/.well-known/openid-configuration`
- [ ] JWKS endpoint works: `curl https://idp.example.com/.well-known/jwks.json`
- [ ] k3s has OIDC args: `ps aux | grep kube-apiserver | grep oidc`
- [ ] Headlamp pod is running: `kubectl get pods -n headlamp`
- [ ] ClusterRoleBindings exist: `kubectl get clusterrolebinding | grep oidc`
- [ ] Can login via Headlamp UI
- [ ] Can view resources after login (no 401 errors)

## Security Considerations

1. **Use HTTPS everywhere** - IdP, Headlamp, and k3s API should all use TLS
2. **Secure client secrets** - Use Sealed Secrets or external secret management
3. **Limit admin users** - Use `view` role for most users, `cluster-admin` only when necessary
4. **Persist signing keys** - Use PVC for simple-idp data directory
5. **Monitor logs** - Watch for authentication failures in k3s and simple-idp logs

## Quick Reference

| Item | Value |
|------|-------|
| IdP Discovery | `https://idp.example.com/.well-known/openid-configuration` |
| JWKS URI | `https://idp.example.com/.well-known/jwks.json` |
| Authorize | `https://idp.example.com/authorize` |
| Token | `https://idp.example.com/token` |
| Logout | `https://idp.example.com/logout?post_logout_redirect_uri=...` |
| k3s Config | `/etc/rancher/k3s/config.yaml` |
| Username Claim | `email` |
| Scopes | `openid profile email` |
