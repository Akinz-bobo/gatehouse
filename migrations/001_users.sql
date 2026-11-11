CREATE TABLE users (
  id                   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  -- Always stored lower-cased, so uniqueness ignores case.
  email                text NOT NULL UNIQUE CHECK (email = lower(email)),
  -- Null for accounts that only sign in through an OAuth provider.
  password_hash        text,
  -- Full administrative access. Works with or without the rbac module.
  is_superuser         boolean NOT NULL DEFAULT false,
  -- Free-form attributes that ABAC policies can read (department, tier, ...).
  attributes           jsonb NOT NULL DEFAULT '{}'::jsonb,
  failed_logins        integer NOT NULL DEFAULT 0,
  locked_until         timestamptz,
  disabled_at          timestamptz,
  password_changed_at  timestamptz,
  created_at           timestamptz NOT NULL DEFAULT now()
);
