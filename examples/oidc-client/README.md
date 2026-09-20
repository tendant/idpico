# oidc-client

A minimal OpenID Connect relying party built on [`coreos/go-oidc`](https://github.com/coreos/go-oidc) and
[`golang.org/x/oauth2`](https://pkg.go.dev/golang.org/x/oauth2). It contains no IDPico code and takes only
the standard settings every OIDC client needs, so it doubles as the interoperability check for IDPico
(see [CONFORMANCE.md](../../CONFORMANCE.md)): if this client needs a workaround, that is an IDPico bug.

What it does: discovery → Authorization Code + PKCE (S256) with `state` and `nonce` → code exchange →
ID token verification against the provider's JWKS → nonce check → UserInfo.

```bash
cd examples/oidc-client
OIDC_ISSUER=http://localhost:8080 \
OIDC_CLIENT_ID=test-app \
OIDC_CLIENT_SECRET=test-secret \
OIDC_REDIRECT_URI=http://localhost:18081/callback \
LISTEN=:18081 go run .
```

Open <http://localhost:18081/> and click **Sign in**. The callback page prints the verified ID token
claims and the UserInfo response as JSON.

| Variable | Default | |
|---|---|---|
| `OIDC_ISSUER` | — | Provider issuer URL (discovery is fetched from it) |
| `OIDC_CLIENT_ID` | — | Registered client id |
| `OIDC_CLIENT_SECRET` | empty | Client secret; leave empty for a public client |
| `OIDC_REDIRECT_URI` | `http://localhost:8080/callback` | Must be registered on the provider; its path is served by this program |
| `OIDC_SCOPES` | `openid profile email` | Space-separated scopes |
| `LISTEN` | `:8080` | Listen address |

The IDPico client registration for the defaults above is
`IDPICO_BOOTSTRAP_CLIENTS="test-app|test-secret|http://localhost:18081/callback"` (or an admin-created
client with that redirect URI). `make validate-interop` in the repository root starts a throwaway IDPico
and this client and drives a login through both with `scripts/test-interop.sh`.
