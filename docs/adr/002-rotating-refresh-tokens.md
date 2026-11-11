# 002: Refresh tokens are opaque, single-use and rotate

## Context

A refresh token is the long-lived credential. If it is stolen and nothing notices, the thief has the account for weeks. A JWT refresh token cannot be revoked without a server-side list, at which point it has no advantage over a random string.

## Decision

A refresh token is 32 random bytes. The database stores only its SHA-256 hash. Each use marks the token used and issues a successor in the same transaction, under a row lock. Presenting a token that is already used ends the whole session and raises `token.reuse_detected`.

## Consequences

- Theft becomes visible. Whoever uses the token second, thief or victim, trips the alarm, and the session dies for both.
- A database leak does not yield usable tokens. A fast hash is enough here, unlike for passwords, because the input has 256 bits of entropy.
- Two concurrent refreshes cannot both succeed, so a session cannot fork.
- Clients must refresh from one place and store the new token every time. A client that loses a refresh response has to sign in again.
- There is no grace window for a retried refresh. A window would make flaky networks kinder and theft detection weaker. That trade was made in favour of detection.

## Alternatives considered

- **Long-lived, reusable refresh tokens.** Simple, and silent when stolen.
- **JWT refresh tokens.** No lookup on refresh, and no way to end a session.
- **A reuse grace period of a few seconds.** Common in practice. Worth revisiting if real clients show a high rate of false alarms.
