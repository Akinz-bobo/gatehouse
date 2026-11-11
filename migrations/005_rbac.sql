CREATE TABLE roles (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name         text NOT NULL UNIQUE CHECK (name ~ '^[a-z][a-z0-9_-]*$'),
  description  text,
  created_at   timestamptz NOT NULL DEFAULT now()
);

-- A permission is a string like `invoices:read`. `invoices:*` and `*` are wildcards.
CREATE TABLE role_permissions (
  role_id     uuid NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
  permission  text NOT NULL CHECK (permission ~ '^(\*|[a-z0-9_-]+(:[a-z0-9_-]+)*(:\*)?)$'),
  PRIMARY KEY (role_id, permission)
);

CREATE TABLE user_roles (
  user_id     uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  role_id     uuid NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
  granted_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, role_id)
);
