# 003: Gatehouse checks the session on its own endpoints

## Context

A signed token is valid until it expires. After sign-out, a password change or detected theft, an access token already issued would otherwise keep working for up to 15 minutes. On the auth service itself that window covers the most sensitive operations there are: changing a password, disabling two-factor, editing roles.

## Decision

Gatehouse's own endpoints verify the token and then check, in the database, that the session named by the `sid` claim is still active and the user is not disabled. Administrative permissions are also read from the database on each request and not from token claims.

Resource servers are not required to do this. They verify tokens statelessly and accept the bounded staleness, and can call `/v1/authz/check` when they need a live answer.

## Consequences

- Sign-out, password change, reset and theft detection take effect immediately where it matters most.
- A revoked administrative role stops working at once.
- Each authenticated request to Gatehouse costs one or two indexed lookups. The service is not on other services' request paths, so this does not multiply.
- The system has two freshness levels. The documentation states which applies where.

## Alternatives considered

- **Purely stateless verification everywhere.** Leaves a window in which a stolen token can change the account's password.
- **A revocation list pushed to all services.** Closes the gap everywhere, and adds a distribution system that must itself be reliable and secure. Out of scope for now.
