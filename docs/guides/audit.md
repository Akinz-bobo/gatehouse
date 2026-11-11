# Audit log (`audit`)

Enable with `MODULES=audit`.

Records security-relevant events in an append-only table. With the module off, the events are still raised inside the service but nothing listens, so nothing is stored.

## What is recorded

| Event                                                            | When                                                                                               |
| ---------------------------------------------------------------- | -------------------------------------------------------------------------------------------------- |
| `user.registered`                                                | An account is created                                                                              |
| `login.succeeded`                                                | A session starts. `details.method` says how (`password`, `oauth:google`, `password+totp`)          |
| `login.failed`                                                   | A sign-in is refused. `details.reason` is `wrong_password`, `unknown_user`, `locked` or `disabled` |
| `session.revoked`                                                | Sign-out, or a user ending one of their sessions                                                   |
| `token.reuse_detected`                                           | A used refresh token was presented: probable theft                                                 |
| `password.changed`, `password.reset_requested`, `password.reset` | Password lifecycle                                                                                 |
| `mfa.enabled`, `mfa.disabled`, `mfa.failed`                      | Two-factor lifecycle and wrong codes                                                               |
| `role.saved`, `role.deleted`, `role.assigned`, `role.removed`    | Changes to who can do what                                                                         |
| `policy.created`, `policy.deleted`                               | Changes to `abac` policies                                                                         |
| `keys.rotated`                                                   | A signing key rotation                                                                             |

Each entry has `id`, `type`, `actorId` (who did it), `subjectId` (who or what it was done to), `ip`, `userAgent`, `details` and `createdAt`.

Passwords, tokens and codes are never written to the log. The reason a sign-in failed is, which is safe here because only administrators can read it, while the caller still got the same vague `401`.

## Reading it

Needs a superuser or the `auth:audit:read` permission.

```bash
curl -s "$BASE/v1/audit?limit=50" -H "authorization: Bearer $ADMIN_TOKEN"
curl -s "$BASE/v1/audit?type=login.failed" -H "authorization: Bearer $ADMIN_TOKEN"
curl -s "$BASE/v1/audit?actorId=$USER_ID" -H "authorization: Bearer $ADMIN_TOKEN"
```

```json
{
  "entries": [
    {
      "id": "1042",
      "type": "token.reuse_detected",
      "actorId": "7b0c...",
      "subjectId": "3f6a...",
      "ip": "203.0.113.9",
      "userAgent": "Mozilla/5.0 ...",
      "details": {},
      "createdAt": "2026-11-11T10:02:11.000Z"
    }
  ],
  "nextCursor": "1041"
}
```

Entries are newest first. To page, pass `nextCursor` as `before`. `nextCursor` is `null` on the last page.

## Append-only

A database trigger rejects every `UPDATE` and `DELETE` on the table:

```
ERROR:  DELETE on audit_log is not allowed: the audit log is append-only
```

That holds for the service's own database role too, so a bug or an injection in the application cannot rewrite history. A database superuser can still drop the trigger. If you need to withstand that, ship entries to a store the database administrator does not control.

For retention, partition the table by time and detach old partitions as a deliberate, reviewed operation.

## What to alert on

- Any `token.reuse_detected`: a refresh token was used twice.
- A burst of `login.failed` for one `subjectId` (someone is guessing a password) or across many from one `ip` (credential stuffing).
- `mfa.failed` repeating for one user: the password is already known to the attacker.
- `role.assigned`, `policy.created` and `keys.rotated` outside a change window.
