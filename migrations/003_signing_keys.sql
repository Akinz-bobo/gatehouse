CREATE TABLE signing_keys (
  kid                    text PRIMARY KEY,
  alg                    text NOT NULL,
  public_jwk             jsonb NOT NULL,
  -- The private key, encrypted with the service's key-encryption key.
  private_jwk_encrypted  text NOT NULL,
  created_at             timestamptz NOT NULL DEFAULT now(),
  -- Set when the key stops signing. It stays published for verification
  -- until `verify_until`, so tokens it already signed remain valid.
  retired_at             timestamptz,
  verify_until           timestamptz,

  CONSTRAINT signing_keys_retirement CHECK ((retired_at IS NULL) = (verify_until IS NULL))
);

-- At most one key signs at a time.
CREATE UNIQUE INDEX signing_keys_one_active_idx ON signing_keys ((true)) WHERE retired_at IS NULL;
