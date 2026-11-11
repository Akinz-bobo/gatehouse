# 006: Argon2id, and a password policy based on length

## Context

Password hashes must stay expensive to attack after a database leak, and password rules should make passwords stronger and not merely more annoying.

## Decision

Passwords are hashed with Argon2id using the parameters OWASP recommends as a minimum (19 MiB of memory, 2 iterations), configurable upwards. The policy follows NIST SP 800-63B: at least 12 characters, at most 128, not on a list of common passwords, not highly repetitive, not built on the email address. There are no composition rules and no forced rotation.

Sign-in runs a full verification against a dummy hash when the account does not exist, is locked or is disabled.

## Consequences

- Guessing leaked hashes is memory-hard, which blunts GPUs and ASICs.
- Long passphrases are accepted as they are. Users are not pushed into `Password1!`.
- Each sign-in costs tens of milliseconds of CPU and 19 MiB of memory. That is a deliberate cost, bounded by rate limits and the 128-character cap.
- Response time does not reveal whether an account exists.
- The common-password list is short. It is a floor, not a breach check.

## Alternatives considered

- **bcrypt.** Still acceptable, but not memory-hard and it truncates input at 72 bytes.
- **scrypt.** Memory-hard, with parameters that are harder to tune well.
- **Composition rules.** Shown to produce predictable patterns. NIST recommends against them.
- **Checking against a breach corpus.** The right next step. Listed in the threat model as a gap.
