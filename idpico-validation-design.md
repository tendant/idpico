# idpico Validation & Conformance Design

**Status:** Draft\
**Target:** idpico v0.1\
**Last updated:** 2026-09-20

## 1. Purpose

idpico is intended to be a small, auditable OpenID Connect (OIDC)
identity provider. Validation should prove not only that its
implementation behaves as expected internally, but that independent OIDC
clients can discover it, authenticate through it, validate its tokens,
and reject malformed or malicious protocol inputs.

The primary validation principle is:

> Unit tests verify the implementation. Black-box conformance and
> independent clients verify the protocol contract.

The validation system MUST treat idpico as an external OIDC provider.
Conformance tests SHOULD communicate only through its public HTTP
endpoints and MUST NOT import idpico internal packages.

## 2. Goals

The validation system should:

-   verify the supported OIDC/OAuth protocol surface;
-   verify security-critical negative cases;
-   independently validate issued ID tokens;
-   detect interoperability regressions;
-   provide one deterministic local/CI command;
-   make failures easy to diagnose;
-   support external OpenID Foundation conformance testing;
-   provide a release gate for idpico.

## 3. Non-goals

The initial validation suite is not intended to:

-   implement the entire OIDC/OAuth specification;
-   replace the OpenID Foundation conformance suite;
-   benchmark throughput or latency;
-   validate unsupported OAuth/OIDC features;
-   test idpico through internal Go APIs;
-   become a general-purpose OAuth testing framework.

Performance, load, HA, disaster recovery, and deployment validation can
be added as separate suites.

## 4. v0.1 Protocol Contract

The v0.1 validation target is deliberately narrow.

### Required

-   OpenID Connect Discovery
-   Authorization Code flow
-   PKCE using `S256`
-   JWKS
-   signed ID tokens
-   UserInfo
-   `state`
-   `nonce`

### Deferred

-   refresh tokens
-   RP-initiated logout
-   dynamic client registration
-   device authorization flow
-   token introspection
-   token revocation
-   federation
-   SAML
-   SCIM

### Explicitly unsupported initially

-   Implicit flow
-   Resource Owner Password Credentials grant

The validation suite MUST distinguish between an unsupported feature and
a broken supported feature.

## 5. Validation Architecture

``` text
                     make validate
                          |
          +---------------+---------------+
          |                               |
     Unit / static                    Black-box
          |                               |
     go test ./...              start isolated idpico
     go vet ./...                        |
          |                     provision test data
          |                               |
          |                 +-------------+-------------+
          |                 |             |             |
          |             discovery      protocol      security
          |                 |             |             |
          |               JWKS       auth/token      negative
          |                               |
          |                       independent JWT
          |                          validation
          |                               |
          +---------------+---------------+
                          |
                 interoperability
                          |
                independent clients
                          |
                OIDF conformance
                          |
                     release gate
```

The black-box validator knows only the issuer URL and test
credentials/client configuration.

## 6. Repository Layout

``` text
idpico/
├── cmd/
├── internal/
├── conformance/
│   ├── discovery_test.go
│   ├── jwks_test.go
│   ├── authorize_test.go
│   ├── token_test.go
│   ├── pkce_test.go
│   ├── jwt_test.go
│   ├── userinfo_test.go
│   ├── security_test.go
│   ├── helpers_test.go
│   └── testdata/
│       └── config.yaml
├── integration/
│   ├── docker-compose.yml
│   └── clients/
├── examples/
│   └── oidc-client/
├── CONFORMANCE.md
└── Makefile
```

`conformance/` MUST NOT import packages under `internal/`.

## 7. Test Environment

A validation run should create an isolated idpico instance with
deterministic test data.

Example configuration:

``` yaml
issuer: http://127.0.0.1:18080

client:
  id: conformance-client
  secret: conformance-secret
  redirect_uri: http://127.0.0.1:18081/callback

user:
  username: alice
  password: test-password
```

Production secrets MUST NOT be required for validation.

The runner should:

1.  allocate or use known local test ports;
2.  create temporary persistent storage;
3.  start idpico;
4.  wait for readiness;
5.  provision the test client and user;
6.  execute validation;
7.  print a summary;
8.  stop idpico;
9.  remove temporary state.

Cleanup SHOULD occur even when tests fail.

## 8. Discovery Validation

Request:

``` text
GET /.well-known/openid-configuration
```

Validate at minimum:

-   HTTP success;
-   valid JSON;
-   exact `issuer`;
-   `authorization_endpoint`;
-   `token_endpoint`;
-   `jwks_uri`;
-   `userinfo_endpoint` when UserInfo is supported;
-   `response_types_supported`;
-   `subject_types_supported`;
-   `id_token_signing_alg_values_supported`;
-   PKCE capability where advertised.

Endpoint URLs SHOULD be internally consistent with the configured
issuer.

Discovery is the first validation stage because downstream clients
depend on it to discover the rest of the protocol surface.

## 9. JWKS Validation

Fetch the advertised `jwks_uri`.

Validate:

-   endpoint is reachable;
-   response is a valid JWK Set;
-   at least one usable signing key exists;
-   signing key contains a stable `kid`;
-   key type and algorithm are compatible with issued tokens;
-   private key material is never exposed.

When an ID token is issued, its `kid` MUST resolve to an appropriate
public key in JWKS.

## 10. Authorization Code Flow

The primary positive-path test is:

``` text
client
  |
  | GET /authorize
  | client_id
  | redirect_uri
  | response_type=code
  | scope=openid
  | state
  | nonce
  | code_challenge
  | code_challenge_method=S256
  v
idpico
  |
  | authenticate user
  v
redirect_uri?code=...&state=...
  |
  | POST /token
  | code
  | code_verifier
  v
tokens
```

Validate:

-   authorization succeeds for a valid registered client;
-   redirect returns an authorization code;
-   returned `state` exactly matches the request;
-   code can be exchanged once;
-   token response has expected fields;
-   ID token validates independently;
-   nonce in the ID token matches the authorization request.

## 11. PKCE Validation

PKCE is a security-critical release gate.

Required cases:

  Authorization              Token exchange     Expected
  -------------------------- ------------------ ----------
  challenge A                verifier A         PASS
  challenge A                verifier B         FAIL
  challenge A                no verifier        FAIL
  malformed challenge        verifier           FAIL
  previously redeemed code   correct verifier   FAIL

For clients for which idpico requires PKCE, attempts to bypass or
downgrade PKCE MUST fail.

`S256` is the required method for the v0.1 contract.

## 12. Redirect URI Validation

Given the registered URI:

``` text
https://app.example.com/callback
```

the suite should exercise cases such as:

  URI                                           Expected
  --------------------------------------------- ----------
  `https://app.example.com/callback`            PASS
  `https://app.example.com/callback/`           FAIL
  `https://app.example.com/callback/foo`        FAIL
  `https://app.example.com.evil.com/callback`   FAIL
  `https://evil.com/callback`                   FAIL
  `http://app.example.com/callback`             FAIL

Query handling should be tested according to the exact URI registered
for the client.

Native loopback redirect handling, if supported later, should have a
dedicated test profile rather than weakening normal redirect matching.

## 13. Independent ID Token Validation

The conformance client MUST validate tokens independently from idpico.

It should:

1.  parse the JWT;
2.  read `kid`;
3.  fetch discovery metadata;
4.  fetch JWKS;
5.  select the matching public key;
6.  verify the cryptographic signature;
7.  verify `iss`;
8.  verify `aud`;
9.  verify `exp`;
10. sanity-check `iat`;
11. verify `nonce`;
12. reject unsupported or unexpected signing algorithms.

The test implementation MUST NOT call idpico's token validation
implementation.

This prevents producer and consumer code from sharing the same protocol
bug.

## 14. JWT Negative Tests

The security suite should reject:

-   modified payload;
-   modified signature;
-   unknown signing key;
-   expired token;
-   incorrect issuer;
-   incorrect audience;
-   nonce mismatch;
-   unsupported signing algorithm;
-   unsigned token;
-   malformed JWT.

Where a test requires generating a synthetic token, the test harness
should use an independent JWT implementation.

## 15. Authorization Security Tests

Required negative cases include:

-   unknown `client_id`;
-   missing `client_id`;
-   unregistered `redirect_uri`;
-   redirect URI prefix/suffix attacks;
-   unsupported `response_type`;
-   missing required `openid` scope where applicable;
-   missing or invalid PKCE;
-   authorization-code replay;
-   code issued to one client redeemed by another;
-   code redeemed using a different redirect URI where binding applies;
-   invalid or expired authorization code;
-   state mismatch detection by the reference client;
-   nonce mismatch detection by the reference client.

Error responses SHOULD also be checked for protocol correctness and
SHOULD NOT leak credentials, secrets, tokens, stack traces, or sensitive
internal details.

## 16. UserInfo Validation

For a valid access token:

-   UserInfo endpoint is reachable;
-   response is valid JSON;
-   `sub` exists;
-   `sub` is consistent with the ID token;
-   expected configured claims are returned.

Negative tests:

-   missing bearer token;
-   malformed token;
-   invalid token;
-   expired token.

## 17. Independent Reference Client

Provide:

``` text
examples/oidc-client/
```

The client should use mainstream OIDC/OAuth libraries rather than idpico
packages.

Its configuration should require only standard values:

``` bash
OIDC_ISSUER=https://idpico.example
OIDC_CLIENT_ID=my-client
OIDC_CLIENT_SECRET=...
OIDC_REDIRECT_URI=http://localhost:8080/callback
```

Expected flow:

``` text
discovery
    |
authorization
    |
callback
    |
code exchange
    |
ID token verification
    |
claims
```

No idpico-specific workaround should be required.

A workaround required by a standard client SHOULD be treated as an
interoperability defect unless it represents a deliberate, documented
protocol restriction.

## 18. Real-Application Interoperability

After black-box conformance passes, test idpico with independent
applications.

Initial targets can include:

-   a standard Go OIDC client;
-   oauth2-proxy;
-   Gatus or another application with generic OIDC support;
-   one idpico user's own service.

For each integration, record:

-   configuration;
-   successful discovery;
-   successful login;
-   callback handling;
-   token verification;
-   logout/session behavior if relevant;
-   any compatibility workaround.

The objective is not to accumulate integrations. Two or three genuinely
independent implementations provide more value than many clients sharing
the same underlying library.

## 19. OpenID Foundation Conformance

The project's own suite is not a replacement for official conformance
testing.

Once local validation is stable, run the relevant OpenID Foundation
provider tests against idpico.

Failures should be classified as:

``` text
BUG
SPEC INTERPRETATION
UNSUPPORTED FEATURE
TEST CONFIGURATION
```

Any failure affecting the declared v0.1 protocol contract blocks
release.

Official certification, if pursued, is a separate product/release
decision from merely running the conformance tests.

## 20. `make validate`

The primary developer interface should be:

``` bash
make validate
```

Suggested targets:

``` makefile
.PHONY: validate validate-unit validate-conformance validate-security validate-all

validate: validate-unit validate-conformance

validate-unit:
    go test ./...

validate-conformance:
    go test -v ./conformance/...

validate-security:
    go test -v ./conformance/... -run Security

validate-all:
    go test ./...
    go test -race ./...
    go vet ./...
    go test -v ./conformance/...
```

The actual implementation may wrap startup/cleanup in a script or Go
test harness.

`make validate` MUST return a non-zero exit status if a required
validation fails.

## 21. Output

The default output should be concise enough for local use while
identifying the failing stage.

Example:

``` text
idpico validation

Discovery
  ✓ discovery document
  ✓ issuer
  ✓ endpoints

JWKS
  ✓ key set
  ✓ signing key
  ✓ kid

Authorization Code
  ✓ authorization
  ✓ callback state
  ✓ code exchange

PKCE
  ✓ S256
  ✓ wrong verifier rejected
  ✓ missing verifier rejected
  ✓ replay rejected

ID Token
  ✓ signature
  ✓ issuer
  ✓ audience
  ✓ expiration
  ✓ nonce

Security
  ✓ invalid redirect rejected
  ✓ unknown client rejected
  ✓ tampered token rejected

PASS: 18/18
```

Verbose mode should expose request/response diagnostics while
automatically redacting:

-   passwords;
-   client secrets;
-   authorization codes where unnecessary;
-   access tokens;
-   ID tokens;
-   cookies;
-   signing private keys.

## 22. CI

CI should run at least:

``` text
go test ./...
go test -race ./...
go vet ./...
make validate
```

A pull request that changes authorization, token, session, client,
redirect, signing, JWKS, or discovery behavior MUST pass the complete
conformance suite.

External OpenID Foundation testing does not need to run on every commit
if its runtime or infrastructure cost is high. It can be a release or
scheduled validation gate.

## 23. Validation Levels

### Level 0 --- Development

-   unit tests
-   static checks

### Level 1 --- Functional

-   discovery
-   JWKS
-   Authorization Code
-   token exchange
-   ID token validation
-   UserInfo

### Level 2 --- Security

-   PKCE S256
-   redirect URI enforcement
-   code replay protection
-   client/code binding
-   state/nonce validation
-   JWT negative tests

### Level 3 --- Interoperability

-   independent Go OIDC client
-   generic OIDC proxy/application
-   at least one real deployed consumer

### Level 4 --- Standards

-   relevant OpenID Foundation conformance profiles pass

A release should state the achieved validation level rather than making
a vague claim of complete OIDC compatibility.

## 24. Release Gate

For the initial v0.1 release:

``` text
Unit tests
     |
     v
Black-box functional validation
     |
     v
Security negative tests
     |
     v
Independent client
     |
     v
Real application integration
     |
     v
OIDF conformance for declared surface
     |
     v
v0.1 release
```

All failures affecting the declared supported surface MUST be resolved
or the affected feature removed from the declared contract.

## 25. Follow-on Operational Validation

Protocol conformance is necessary but not sufficient for an IdP.

After the initial validation suite is stable, add a separate operational
suite covering:

### Signing-key lifecycle

-   signing keys survive restart;
-   `kid` remains stable until intentional rotation;
-   rotation publishes the new public key correctly;
-   previously issued, still-valid tokens remain verifiable during the
    defined overlap period;
-   private key material is never exposed.

### Persistence

-   users survive restart;
-   clients and redirect URIs survive restart;
-   sessions behave according to documented policy;
-   backup and restore preserve required identity state.

### Reverse proxy / TLS

-   correct issuer behind HTTPS;
-   safe handling of forwarded headers;
-   no issuer changes caused by internal proxy topology;
-   secure cookies under production TLS.

### Upgrade

-   upgrade from the previous supported release;
-   schema migration;
-   rollback expectations;
-   existing clients continue authenticating.

These tests should eventually become a separate command such as:

``` bash
make validate-operational
```

## 26. Design Principles

The validation system should preserve the core idpico philosophy:

**Small surface. Strong defaults. Standard clients. Observable
behavior.**

In particular:

1.  Prefer protocol-level tests over implementation-aware tests.
2.  Prefer independent libraries for validation.
3.  Test rejection behavior as carefully as success behavior.
4.  Treat interoperability problems as product problems.
5.  Do not expand the supported protocol surface faster than it can be
    validated.
6.  Keep `make validate` fast enough that developers actually run it.
7.  Use official conformance testing as an external check rather than
    reimplementing the specification.

## 27. Definition of Done

The initial validation project is complete when:

-   `make validate` works from a clean checkout;
-   it starts and cleans up an isolated idpico instance;
-   all declared v0.1 protocol features have positive tests;
-   security-critical behaviors have negative tests;
-   JWT validation is independent from idpico;
-   at least one independent OIDC client works without idpico-specific
    code;
-   CI runs the suite automatically;
-   secrets are redacted from test output;
-   `CONFORMANCE.md` documents the supported profile and known
    limitations;
-   the relevant external OIDC conformance suite has been run and
    results reviewed.

At that point, idpico has a repeatable validation contract that can
serve as the foundation for protocol changes, security hardening,
interoperability work, and release decisions.
