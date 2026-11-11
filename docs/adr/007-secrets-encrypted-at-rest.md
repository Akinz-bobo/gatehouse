# 007: Hash what is compared, encrypt what must be read back

## Context

The database holds several kinds of secret. Some only ever need to be compared with a value a caller presents (refresh tokens, reset tokens, recovery codes, OAuth state). Others must be recovered in the clear to be used (signing keys, TOTP secrets). A database is the asset most likely to leak, through a backup, a replica or a query-level bug.

## Decision

- Secrets that are only compared are stored as SHA-256 hashes.
- Secrets that must be read back are encrypted with AES-256-GCM under `KEY_ENCRYPTION_KEY`, a 32-byte key supplied through the environment and never written to the database. Each value gets a random nonce, and the stored form carries a version prefix (`v1.`).
- Passwords are a separate case, covered in [006](006-password-storage-and-policy.md).

## Consequences

- A copy of the database alone cannot mint tokens, generate TOTP codes, refresh a session or complete a reset.
- GCM authenticates as well as encrypts, so a modified ciphertext is rejected and not decrypted into garbage.
- The key-encryption key becomes the single most important secret. Losing it makes signing keys and TOTP secrets unreadable. Leaking it together with the database is a full compromise.
- The version prefix leaves room to rotate that key or change the scheme. The rotation command itself does not exist yet.

## Alternatives considered

- **A cloud KMS or HSM for signing.** Stronger: the private key never enters process memory. It also ties the project to one vendor. The `KeyStore` class is the seam where that would go.
- **Envelope encryption with per-row data keys.** Useful at larger scale. One key is enough for a handful of rows.
- **Storing signing keys in files.** Complicates running several instances, which then need a shared volume.
