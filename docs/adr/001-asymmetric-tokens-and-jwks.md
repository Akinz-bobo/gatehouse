# 001: Sign access tokens with ES256 and publish the keys

## Context

Access tokens are verified by every service in a system, far more often than they are issued. The common shortcut is HS256, where one shared secret both signs and verifies. Every service that can check a token can then also mint one, so the least secure service sets the security of all of them.

## Decision

Access tokens are JWTs signed with ES256 (ECDSA on P-256). Gatehouse holds the private key. Public keys are published at `/.well-known/jwks.json`. The verifier accepts ES256 only, regardless of the token's header.

## Consequences

- A compromised resource server cannot forge tokens. It never had anything to forge them with.
- Services verify locally with a cached key set, so Gatehouse is not on the request path.
- Keys can be rotated without coordinating a secret change across services: the key id in the token header selects the key.
- Signature verification costs more CPU than HMAC. At these volumes it does not matter.
- The algorithm is fixed in code. There is no configuration that weakens it.

## Alternatives considered

- **HS256 with a shared secret.** Rejected for the reason above.
- **RS256.** Equally sound and more widely supported by old libraries, but keys and signatures are several times larger. ES256 is supported by every current JWT library.
- **EdDSA.** A good choice with less library support today, particularly in managed gateways.
- **Opaque access tokens with introspection.** Gives instant revocation everywhere, at the price of a network call per request and a hard dependency on the auth service. The revocation gap this leaves is covered in [003](003-session-check-on-own-endpoints.md).
