CREATE TABLE mfa_totp (
  user_id           uuid PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
  -- The shared secret, encrypted with the service's key-encryption key.
  secret_encrypted  text NOT NULL,
  -- Null until the user proves their authenticator works.
  confirmed_at      timestamptz,
  -- The last 30-second step a code was accepted for, so a code cannot be replayed.
  last_used_step    bigint,
  created_at        timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE mfa_recovery_codes (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id    uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  code_hash  text NOT NULL,
  used_at    timestamptz,
  UNIQUE (user_id, code_hash)
);
