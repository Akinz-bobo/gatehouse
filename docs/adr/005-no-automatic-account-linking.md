# 005: OAuth identities are never linked to accounts by email

## Context

A user signs in through a provider that reports an email address already used by a local account. Many systems merge the two. That treats "this provider says the email is X" as proof of owning account X.

Two attacks follow. An attacker registers a local account with the victim's email before the victim arrives, and then shares the account once the victim signs in through the provider. Or an attacker finds any configured provider that does not verify emails properly and uses it to enter existing accounts.

## Decision

An identity from a provider is matched only on the pair (provider, subject). If no such identity is linked and the email belongs to an existing account, the sign-in is refused with `account_exists`. Linking happens only when a user who is already signed in asks for it. New accounts are created only when the provider reports the email as verified.

## Consequences

- Neither attack works. Control of an email address at a provider is never enough to enter an existing account.
- A user who registered with a password and later clicks "Sign in with Google" must sign in with the password once and link. The error tells the application to say so.
- The security of an account does not depend on the weakest provider in the configuration.

## Alternatives considered

- **Link when the provider says the email is verified.** Safer than blind linking, and still trusts every provider's verification equally. It also does not stop the pre-registration attack unless local emails are verified too, which this service does not yet do.
- **Link only for an allow-list of trusted providers.** Reasonable once local email verification exists.
