CREATE TABLE oauth_identities (
  provider    text NOT NULL,
  -- The provider's own stable identifier for the account.
  subject     text NOT NULL,
  user_id     uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  email       text,
  created_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (provider, subject)
);

CREATE INDEX oauth_identities_user_id_idx ON oauth_identities (user_id);

-- One row per sign-in attempt, alive from redirect to callback.
CREATE TABLE oauth_states (
  state_hash     text PRIMARY KEY,
  provider       text NOT NULL,
  code_verifier  text NOT NULL,
  redirect_uri   text NOT NULL,
  -- Set when a signed-in user is linking a provider to their account.
  link_user_id   uuid REFERENCES users (id) ON DELETE CASCADE,
  expires_at     timestamptz NOT NULL
);

-- A one-time code handed to the client after the callback, exchanged for
-- tokens over a POST. Tokens never travel in a URL.
CREATE TABLE oauth_exchange_codes (
  code_hash    text PRIMARY KEY,
  user_id      uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  provider     text NOT NULL,
  expires_at   timestamptz NOT NULL
);
