# Architecture

This document explains how Gatehouse is put together: the pieces, how a request moves through them, how the data is laid out, and what each sign-in flow looks like on the wire.

- [Design goals](#design-goals)
- [Components](#components)
- [Request pipeline](#request-pipeline)
- [The module system](#the-module-system)
- [Tokens and sessions](#tokens-and-sessions)
- [Flows](#flows)
- [Data model](#data-model)
- [Scaling and failure](#scaling-and-failure)

## Design goals

1. **Pay only for what you use.** A deployment that needs JWT sign-in should not carry OAuth callbacks or a policy engine. Disabled modules register nothing.
2. **Secure defaults, no insecure switches.** There is no option to turn off hashing, pick a weaker algorithm or skip token rotation.
3. **Resource servers stay independent.** They verify tokens with public keys and never hold a secret that could mint one.
4. **Every defence is a test.** If a property matters (a replayed token ends the session), a test fails when it breaks.
5. **Small enough to read.** About three thousand lines of TypeScript, no framework magic, one database.

## Components

```mermaid
flowchart TB
    client([Client application])
    rs([Resource servers])
    idp([OAuth providers])

    subgraph gatehouse[Gatehouse process]
        direction TB
        subgraph edge["HTTP layer (src/http)"]
            app[app.ts<br/>headers, CORS, rate limits, errors]
            guard[authenticate.ts<br/>token + live session + permission]
            docs[openapi.ts<br/>Swagger UI]
        end
        subgraph corebox["Core (src/core)"]
            users[users.ts<br/>accounts, credentials, lockout]
            sess[sessions.ts<br/>refresh rotation, revocation]
            signin[sign-in.ts<br/>challenge or session]
            keystore[keys.ts<br/>sign, verify, JWKS, rotate]
            reset[password-reset.ts]
            hooks{{context.ts<br/>Hooks}}
        end
        subgraph mods["Modules (src/modules)"]
            rbac[rbac]
            abac[abac]
            oauth[oauth]
            mfa[mfa]
            audit[audit]
        end
        subgraph cryptobox["Primitives (src/crypto)"]
            argon[password.ts<br/>Argon2id]
            box[secretbox.ts<br/>AES-256-GCM]
            totp[totp.ts<br/>RFC 6238]
            tok[tokens.ts<br/>random, SHA-256]
        end
    end

    pg[(PostgreSQL)]

    client --> app
    rs -. JWKS .-> app
    app --> guard --> corebox
    app --> mods
    mods --> hooks
    corebox --> cryptobox
    mods --> cryptobox
    oauth <--> idp
    corebox --> pg
    mods --> pg
```

Dependencies point one way: HTTP depends on core and modules, modules depend on core, core depends on the crypto primitives. The core never imports a module, with one exception that is called out in the code: the permission guard reads roles when `rbac` is enabled.

## Request pipeline

Every request passes the same gates, in this order. A request that fails one never reaches the next.

```mermaid
flowchart LR
    req([Request]) --> size[Body limit<br/>64 KiB]
    size --> hdr[Security headers<br/>no-store, HSTS, CSP]
    hdr --> rl[Rate limit<br/>per IP, stricter on sign-in]
    rl --> val[Strict schema<br/>unknown fields rejected]
    val --> tok{Needs a token?}
    tok -- no --> handler
    tok -- yes --> sig[Verify signature,<br/>issuer, audience, expiry, ES256]
    sig --> live[Session still active?<br/>user not disabled?]
    live --> perm{Needs a permission?}
    perm -- no --> handler[Handler]
    perm -- yes --> check[Superuser, or role grants it<br/>read from the database]
    check --> handler
    handler --> res([Response])
```

Errors leave in one shape, `{ "error": { "code", "message", "details" } }`. Unexpected errors are logged with the request id and answered with a bare `500`, so internals never leak.

## The module system

A module is an object with a name, an optional `setup` and a `routes` function:

```ts
export interface Module {
  name: ModuleName;
  setup?(context: Context): void; // attach to the core's hooks
  routes(app: FastifyInstance, context: Context): void; // add endpoints
}
```

At startup the service reads `MODULES`, looks each name up in the registry and calls `setup` then `routes`. Nothing else knows the module exists.

The core offers three hooks:

| Hook           | Called when                                               | Used by                               |
| -------------- | --------------------------------------------------------- | ------------------------------------- |
| `addClaims`    | An access token is minted                                 | `rbac` adds `roles` and `permissions` |
| `addChallenge` | A user has proved their identity, before a session starts | `mfa` demands a TOTP code             |
| `onEvent`      | Something security-relevant happened                      | `audit` writes it down                |

```mermaid
sequenceDiagram
    participant R as Route (login)
    participant C as Core (sign-in.ts)
    participant H as Hooks
    participant M as mfa module
    participant B as rbac module
    participant A as audit module

    R->>C: completeSignIn(user, "password")
    C->>H: challengesFor(user)
    H->>M: is TOTP enabled?
    M-->>H: no
    H-->>C: no challenges
    C->>H: claimsFor(user)
    H->>B: roles and permissions?
    B-->>H: { roles, permissions }
    C->>C: sign access token, store refresh token hash
    C->>H: emit(login.succeeded)
    H->>A: record
    C-->>R: token pair
```

With no modules enabled, the hooks have no listeners and sign-in is two database writes and a signature.

## Tokens and sessions

There are three kinds of token, each with one job.

| Token         | Form                            | Lifetime            | Stored as    | Job                            |
| ------------- | ------------------------------- | ------------------- | ------------ | ------------------------------ |
| Access token  | ES256 JWT                       | 15 minutes          | not stored   | Prove identity to any service  |
| Refresh token | 32 random bytes                 | 30 days, single-use | SHA-256 hash | Get a new access token         |
| MFA token     | ES256 JWT, audience `<aud>:mfa` | 5 minutes           | not stored   | Finish a sign-in, nothing else |

An access token carries `sub` (user id), `sid` (session id), `email`, and whatever modules add. A **session** is the server-side record behind one sign-in. Ending it, by sign-out, password change, reset or theft detection, invalidates its refresh tokens, and Gatehouse's own endpoints stop accepting its access tokens at once.

### Signing keys

```mermaid
stateDiagram-v2
    [*] --> Active: first token signed, or a rotation
    Active --> Retired: rotate
    Retired --> Removed: verify_until passes
    Removed --> [*]
```

| State   | Signs new tokens | Published in JWKS | Notes                                                                                               |
| ------- | ---------------- | ----------------- | --------------------------------------------------------------------------------------------------- |
| Active  | yes              | yes               | Exactly one at a time, enforced by a unique index                                                   |
| Retired | no               | yes               | Tokens it signed keep verifying until `verify_until`, which is the token lifetime plus five minutes |
| Removed | no               | no                | Nothing it signed can still be unexpired                                                            |

Private keys are encrypted with AES-256-GCM under `KEY_ENCRYPTION_KEY` before they touch the database. Every instance of the service reads the same keys, so any instance can verify a token another signed.

## Flows

### Password sign-in and refresh rotation

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant G as Gatehouse
    participant D as PostgreSQL

    C->>G: POST /v1/auth/login { email, password }
    G->>D: load user
    G->>G: Argon2id verify (also runs for unknown users)
    alt wrong password
        G->>D: failed_logins + 1, maybe lock
        G-->>C: 401 invalid_credentials
    else correct
        G->>D: insert session, insert refresh token hash
        G-->>C: 200 { accessToken, refreshToken }
    end

    Note over C,G: 15 minutes later the access token expires

    C->>G: POST /v1/auth/refresh { refreshToken }
    G->>D: lock the token row, check unused and unexpired
    G->>D: mark used, insert the next token hash
    G-->>C: 200 { new accessToken, new refreshToken }
```

### Refresh token theft

A refresh token is used exactly once. If a used token turns up again, two parties hold the same token and there is no way to tell which is the thief, so the session ends for both.

```mermaid
sequenceDiagram
    autonumber
    participant U as Real client
    participant T as Thief
    participant G as Gatehouse

    Note over T: copies refresh token R1
    U->>G: refresh with R1
    G-->>U: R2 (R1 is now used)
    T->>G: refresh with R1
    G->>G: R1 already used: revoke the session
    G-->>T: 401 refresh_token_reused
    U->>G: any request with the access token
    G-->>U: 401 (session ended)
    Note over U: signs in again. The thief cannot.
```

Two honest requests racing with the same token are serialised by a row lock: one wins and the other is treated as a replay.

### Sign-in with two-factor (module `mfa`)

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant G as Gatehouse

    C->>G: POST /v1/auth/login { email, password }
    G->>G: password correct, TOTP is enabled
    G-->>C: 200 { mfaRequired: true, mfaToken }
    Note over C,G: No session exists yet. The mfaToken is rejected by every other endpoint.
    C->>G: POST /v1/auth/mfa/verify { mfaToken, code }
    G->>G: verify code, refuse a code already used
    G-->>C: 200 { accessToken, refreshToken }
```

### OAuth sign-in (module `oauth`)

```mermaid
sequenceDiagram
    autonumber
    participant B as Browser
    participant A as Your app
    participant G as Gatehouse
    participant P as Provider

    B->>G: GET /v1/oauth/google/start?redirect_uri=...
    G->>G: redirect_uri on the allow-list?<br/>store hash(state) + PKCE verifier
    G-->>B: 302 to provider (state, code_challenge)
    B->>P: user signs in and consents
    P-->>B: 302 to /v1/oauth/google/callback?code&state
    B->>G: callback
    G->>G: claim the state (single use)
    G->>P: POST token (code, code_verifier, client_secret)
    P-->>G: provider access token
    G->>P: GET userinfo
    P-->>G: { sub, email, email_verified }
    G->>G: find or create the user (never link by email)
    G-->>B: 302 to redirect_uri?code=ONE_TIME_CODE
    B->>A: lands on your app
    A->>G: POST /v1/oauth/exchange { code }
    G-->>A: 200 { accessToken, refreshToken } or an MFA challenge
```

The one-time code lives for 60 seconds and works once. Gatehouse's tokens never appear in a URL, so they cannot leak through browser history, referrer headers or proxy logs.

### An authorization decision (modules `rbac` and `abac`)

```mermaid
flowchart TD
    start([POST /v1/authz/evaluate<br/>action, resource, context]) --> subj["Build the subject from the verified token<br/>id, email, attributes, roles"]
    subj --> match[Find policies whose action and resource patterns match<br/>and whose condition is true]
    match --> deny{Any deny?}
    deny -- yes --> no1[Denied<br/>denied_by_policy]
    deny -- no --> allow{Any allow?}
    allow -- yes --> yes[Allowed<br/>allowed_by_policy]
    allow -- no --> no2[Denied<br/>no_matching_policy]
```

A condition that refers to a missing attribute, compares mismatched types or nests too deep evaluates to false. Combined with default deny, a broken policy can only fail closed.

## Data model

```mermaid
erDiagram
    users ||--o{ sessions : has
    sessions ||--o{ refresh_tokens : "rotates through"
    users ||--o{ password_resets : requests
    users ||--o{ user_roles : holds
    roles ||--o{ user_roles : "granted to"
    roles ||--o{ role_permissions : grants
    users ||--o{ oauth_identities : "linked to"
    users ||--o| mfa_totp : "enrolled in"
    users ||--o{ mfa_recovery_codes : owns

    users {
        uuid id PK
        text email UK "stored lower-cased"
        text password_hash "Argon2id, null for OAuth-only"
        boolean is_superuser
        jsonb attributes "for abac"
        int failed_logins
        timestamptz locked_until
        timestamptz disabled_at
    }
    sessions {
        uuid id PK
        uuid user_id FK
        text auth_method "password, oauth:google, password+totp"
        timestamptz revoked_at
        text revoked_reason
    }
    refresh_tokens {
        uuid id PK
        uuid session_id FK
        text token_hash UK "SHA-256"
        timestamptz expires_at
        timestamptz used_at
    }
    signing_keys {
        text kid PK
        jsonb public_jwk
        text private_jwk_encrypted "AES-256-GCM"
        timestamptz retired_at
        timestamptz verify_until
    }
    policies {
        uuid id PK
        text effect "allow or deny"
        text actions "array of patterns"
        text resources "array of patterns"
        jsonb condition
    }
    audit_log {
        bigint id PK
        text type
        uuid actor_id
        text subject_id
        inet ip
        jsonb details
    }
```

`oauth_states` and `oauth_exchange_codes` hold short-lived, hashed, single-use values for the OAuth flow. `signing_keys`, `policies` and `audit_log` stand alone. The audit log has no foreign keys on purpose: its entries outlive the users they describe.

Tables for a disabled module exist but stay empty. Keeping one migration history for every deployment is simpler and safer than a schema that changes shape with configuration.

## Scaling and failure

- **Stateless processes.** All state is in PostgreSQL, so instances can be added behind a load balancer. Signing keys are shared through the database, and key creation takes an advisory lock so two instances starting together cannot both create the first key.
- **Rate limits are per instance.** The limiter keeps its counters in memory. Behind several instances the effective limit is multiplied; put a shared limiter at the edge for strict global limits. Account lockout is in the database and is always global.
- **Database down.** `/readyz` answers `503`, so an orchestrator stops routing to the instance. `/healthz` keeps answering, so it is not restarted for a fault that is not its own.
- **Gatehouse down.** Resource servers keep verifying tokens with cached keys until the tokens expire. New sign-ins and refreshes fail until it is back.
- **Shutdown.** On `SIGTERM` the service stops accepting connections, finishes requests in flight and closes the pool.
