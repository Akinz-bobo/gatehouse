CREATE TABLE sessions (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id         uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  -- How the user proved who they are: password, oauth:<provider>, and +mfa.
  auth_method     text NOT NULL,
  ip              inet,
  user_agent      text,
  created_at      timestamptz NOT NULL DEFAULT now(),
  last_used_at    timestamptz NOT NULL DEFAULT now(),
  revoked_at      timestamptz,
  revoked_reason  text
);

CREATE INDEX sessions_user_id_idx ON sessions (user_id) WHERE revoked_at IS NULL;

-- Refresh tokens are single-use. Each refresh marks the old token used and
-- issues a new one, so a session is a chain of tokens. Presenting a token that
-- was already used means it was stolen or replayed, and ends the session.
CREATE TABLE refresh_tokens (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  session_id  uuid NOT NULL REFERENCES sessions (id) ON DELETE CASCADE,
  -- SHA-256 of the token. The token itself is never stored.
  token_hash  text NOT NULL UNIQUE,
  expires_at  timestamptz NOT NULL,
  used_at     timestamptz,
  created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX refresh_tokens_session_id_idx ON refresh_tokens (session_id);
