CREATE TABLE audit_log (
  id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  type        text NOT NULL,
  -- Who did it, when known. Kept even if the user is later deleted.
  actor_id    uuid,
  -- Who or what it was done to.
  subject_id  text,
  ip          inet,
  user_agent  text,
  details     jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX audit_log_actor_id_idx ON audit_log (actor_id, id DESC);
CREATE INDEX audit_log_type_idx ON audit_log (type, id DESC);

CREATE FUNCTION reject_audit_mutation() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION '% on audit_log is not allowed: the audit log is append-only', TG_OP
    USING ERRCODE = 'restrict_violation';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_log_append_only
  BEFORE UPDATE OR DELETE ON audit_log
  FOR EACH ROW EXECUTE FUNCTION reject_audit_mutation();
