CREATE TABLE policies (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name         text NOT NULL UNIQUE,
  description  text,
  effect       text NOT NULL CHECK (effect IN ('allow', 'deny')),
  -- Patterns such as `invoice:read` or `invoice:*`.
  actions      text[] NOT NULL CHECK (cardinality(actions) > 0),
  -- Resource types the policy covers, or `*`.
  resources    text[] NOT NULL CHECK (cardinality(resources) > 0),
  -- A condition tree evaluated against subject, resource and context.
  -- Null means the policy applies whenever action and resource match.
  condition    jsonb,
  created_at   timestamptz NOT NULL DEFAULT now()
);
