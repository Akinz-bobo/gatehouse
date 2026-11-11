# 004: Capabilities are opt-in modules attached through hooks

## Context

Different products need different amounts of auth. Shipping everything always-on means every deployment carries attack surface it does not use: OAuth callbacks nobody configured, policy endpoints nobody guards. Shipping separate builds means maintaining several services.

## Decision

A small core (accounts, sessions, tokens, keys) is always on. Everything else is a module selected at startup by the `MODULES` variable. A module registers routes and attaches to three hooks: token claims, sign-in challenges and events. The core never imports a module. A module that is off registers nothing, so its endpoints answer `404`.

The database schema is the same for every configuration. Tables for disabled modules exist and stay empty.

## Consequences

- Attack surface matches what is in use.
- Sign-in with no modules does no extra work.
- Adding a capability is one directory and one registry entry, and it cannot change core behaviour except through a hook.
- Modules compose without knowing about each other: `mfa` challenges an OAuth sign-in because both go through the same final step.
- One build and one migration history to test and operate.
- Event listeners run inline. An audit write that fails fails the request, by design: an action that cannot be recorded does not happen.
- One coupling is accepted: the permission guard consults `rbac` when it is enabled, so administrative permissions can be delegated.

## Alternatives considered

- **Feature flags inside a monolithic service.** Disabled code is still wired in and reachable by mistake.
- **A plugin system loading external packages.** More flexible, and a supply-chain risk in the one service that should have the fewest dependencies.
- **Per-module migrations.** Schema would vary with configuration, and turning a module on later would need migrations to run out of order.
