BEGIN;

CREATE SCHEMA aios_skill;

CREATE TABLE aios_skill.skill_release (
  tenant_id text NOT NULL,
  tenant_kind text NOT NULL CHECK (tenant_kind = 'SYNTHETIC'),
  skill_id text NOT NULL
    CHECK (skill_id ~ '^skl_[0-9a-f-]{36}$'),
  release_id text NOT NULL
    CHECK (release_id ~ '^srl_[0-9a-f-]{36}$'),
  sequence bigint NOT NULL
    CHECK (sequence BETWEEN 1 AND 9007199254740991),
  name text NOT NULL
    CHECK (name ~ '^[a-z][a-z0-9]*(-[a-z0-9]+)*$'),
  semantic_version text NOT NULL
    CHECK (
      semantic_version ~
      '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'
    ),
  manifest jsonb NOT NULL CHECK (jsonb_typeof(manifest) = 'object'),
  content_sha256 text NOT NULL
    CHECK (content_sha256 ~ '^sha256:[0-9a-f]{64}$'),
  source_review_ref text NOT NULL
    CHECK (char_length(btrim(source_review_ref)) BETWEEN 1 AND 512),
  source_review_sha256 text NOT NULL
    CHECK (source_review_sha256 ~ '^sha256:[0-9a-f]{64}$'),
  lifecycle_state text NOT NULL
    CHECK (
      lifecycle_state IN (
        'SUBMITTED',
        'STATIC_PASSED',
        'EVALUATED',
        'EVALUATION_FAILED',
        'APPROVED',
        'WITHDRAWN'
      )
    ),
  state_version bigint NOT NULL
    CHECK (state_version BETWEEN 1 AND 9007199254740991),
  static_report jsonb,
  evaluation_suite_id text,
  evaluation_suite_sha256 text,
  evaluation_report jsonb,
  pilot_published boolean NOT NULL DEFAULT false,
  stable_published boolean NOT NULL DEFAULT false,
  withdrawn_at timestamptz,
  withdrawal_reason_ref text,
  identity jsonb NOT NULL CHECK (jsonb_typeof(identity) = 'object'),
  authorization_evidence jsonb NOT NULL
    CHECK (jsonb_typeof(authorization_evidence) = 'object'),
  tenant_lifecycle_version bigint NOT NULL
    CHECK (
      tenant_lifecycle_version BETWEEN 1 AND 9007199254740991
    ),
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, release_id),
  UNIQUE (tenant_id, skill_id, release_id),
  UNIQUE (tenant_id, skill_id, sequence),
  UNIQUE (tenant_id, skill_id, semantic_version),
  FOREIGN KEY (tenant_id, tenant_kind)
    REFERENCES aios_core.tenant_registry(tenant_id, tenant_kind)
    ON DELETE RESTRICT,
  CHECK (updated_at >= created_at),
  CHECK (
    (static_report IS NULL OR jsonb_typeof(static_report) = 'object')
    AND (
      evaluation_report IS NULL
      OR jsonb_typeof(evaluation_report) = 'object'
    )
  ),
  CHECK (
    (evaluation_suite_id IS NULL)
    = (evaluation_suite_sha256 IS NULL)
    AND (evaluation_suite_id IS NULL) = (evaluation_report IS NULL)
  ),
  CHECK (
    evaluation_suite_sha256 IS NULL
    OR evaluation_suite_sha256 ~ '^sha256:[0-9a-f]{64}$'
  ),
  CHECK (
    (withdrawn_at IS NULL) = (withdrawal_reason_ref IS NULL)
  ),
  CONSTRAINT skill_release_state_shape CHECK (
    (
      lifecycle_state = 'SUBMITTED'
      AND static_report IS NULL
      AND evaluation_report IS NULL
      AND withdrawn_at IS NULL
    )
    OR (
      lifecycle_state = 'STATIC_PASSED'
      AND static_report IS NOT NULL
      AND evaluation_report IS NULL
      AND withdrawn_at IS NULL
    )
    OR (
      lifecycle_state IN ('EVALUATED', 'EVALUATION_FAILED')
      AND static_report IS NOT NULL
      AND evaluation_report IS NOT NULL
      AND withdrawn_at IS NULL
    )
    OR (
      lifecycle_state = 'APPROVED'
      AND static_report IS NOT NULL
      AND evaluation_report ->> 'status' = 'PASS'
      AND withdrawn_at IS NULL
    )
    OR (
      lifecycle_state = 'WITHDRAWN'
      AND static_report IS NOT NULL
      AND evaluation_report ->> 'status' = 'PASS'
      AND withdrawn_at IS NOT NULL
    )
  )
);

CREATE TABLE aios_skill.skill_channel (
  tenant_id text NOT NULL,
  tenant_kind text NOT NULL CHECK (tenant_kind = 'SYNTHETIC'),
  skill_id text NOT NULL
    CHECK (skill_id ~ '^skl_[0-9a-f-]{36}$'),
  channel text NOT NULL CHECK (channel IN ('PILOT', 'STABLE')),
  release_id text,
  generation bigint NOT NULL
    CHECK (generation BETWEEN 1 AND 9007199254740991),
  reason_ref text,
  updated_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, skill_id, channel),
  FOREIGN KEY (tenant_id, skill_id, release_id)
    REFERENCES aios_skill.skill_release(tenant_id, skill_id, release_id)
    ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, tenant_kind)
    REFERENCES aios_core.tenant_registry(tenant_id, tenant_kind)
    ON DELETE RESTRICT,
  CHECK (
    reason_ref IS NULL
    OR char_length(btrim(reason_ref)) BETWEEN 1 AND 512
  )
);

CREATE TABLE aios_skill.command_receipt (
  tenant_id text NOT NULL,
  tenant_kind text NOT NULL CHECK (tenant_kind = 'SYNTHETIC'),
  idempotency_key text NOT NULL
    CHECK (char_length(btrim(idempotency_key)) BETWEEN 1 AND 128),
  request_hash text NOT NULL
    CHECK (request_hash ~ '^sha256:[0-9a-f]{64}$'),
  effect_key text NOT NULL
    CHECK (effect_key ~ '^sha256:[0-9a-f]{64}$'),
  command_kind text NOT NULL
    CHECK (command_kind ~ '^[A-Z][A-Z0-9_]{0,63}$'),
  correlation_id text NOT NULL
    CHECK (char_length(btrim(correlation_id)) BETWEEN 1 AND 128),
  result jsonb NOT NULL CHECK (jsonb_typeof(result) = 'object'),
  created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
  PRIMARY KEY (tenant_id, idempotency_key),
  UNIQUE (tenant_id, effect_key),
  FOREIGN KEY (tenant_id, tenant_kind)
    REFERENCES aios_core.tenant_registry(tenant_id, tenant_kind)
    ON DELETE RESTRICT
);

CREATE TABLE aios_skill.skill_event (
  tenant_id text NOT NULL,
  tenant_kind text NOT NULL CHECK (tenant_kind = 'SYNTHETIC'),
  event_id text NOT NULL
    CHECK (event_id ~ '^evt_[0-9a-f-]{36}$'),
  idempotency_key text NOT NULL
    CHECK (char_length(btrim(idempotency_key)) BETWEEN 1 AND 128),
  request_hash text NOT NULL
    CHECK (request_hash ~ '^sha256:[0-9a-f]{64}$'),
  effect_key text NOT NULL
    CHECK (effect_key ~ '^sha256:[0-9a-f]{64}$'),
  command_kind text NOT NULL
    CHECK (command_kind ~ '^[A-Z][A-Z0-9_]{0,63}$'),
  aggregate_id text NOT NULL
    CHECK (char_length(btrim(aggregate_id)) BETWEEN 1 AND 256),
  aggregate_version bigint NOT NULL
    CHECK (aggregate_version BETWEEN 1 AND 9007199254740991),
  event jsonb NOT NULL CHECK (jsonb_typeof(event) = 'object'),
  created_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, event_id),
  UNIQUE (tenant_id, idempotency_key),
  FOREIGN KEY (tenant_id, idempotency_key)
    REFERENCES aios_skill.command_receipt(tenant_id, idempotency_key)
    ON DELETE RESTRICT
    DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY (tenant_id, tenant_kind)
    REFERENCES aios_core.tenant_registry(tenant_id, tenant_kind)
    ON DELETE RESTRICT
);

CREATE FUNCTION aios_skill.reject_append_only_change()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION 'C13 append-only relation cannot change'
    USING ERRCODE = '23000',
          CONSTRAINT = 'skill_append_only_guard';
END;
$$;

CREATE FUNCTION aios_skill.enforce_release_update()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF OLD.tenant_id IS DISTINCT FROM NEW.tenant_id
     OR OLD.tenant_kind IS DISTINCT FROM NEW.tenant_kind
     OR OLD.skill_id IS DISTINCT FROM NEW.skill_id
     OR OLD.release_id IS DISTINCT FROM NEW.release_id
     OR OLD.sequence IS DISTINCT FROM NEW.sequence
     OR OLD.name IS DISTINCT FROM NEW.name
     OR OLD.semantic_version IS DISTINCT FROM NEW.semantic_version
     OR OLD.manifest IS DISTINCT FROM NEW.manifest
     OR OLD.content_sha256 IS DISTINCT FROM NEW.content_sha256
     OR OLD.source_review_ref IS DISTINCT FROM NEW.source_review_ref
     OR OLD.source_review_sha256 IS DISTINCT FROM NEW.source_review_sha256
     OR OLD.identity IS DISTINCT FROM NEW.identity
     OR OLD.authorization_evidence IS DISTINCT FROM NEW.authorization_evidence
     OR OLD.tenant_lifecycle_version IS DISTINCT FROM NEW.tenant_lifecycle_version
     OR OLD.created_at IS DISTINCT FROM NEW.created_at
     OR NEW.state_version <> OLD.state_version + 1
     OR (OLD.pilot_published AND NOT NEW.pilot_published)
     OR (OLD.stable_published AND NOT NEW.stable_published)
  THEN
    RAISE EXCEPTION 'C13 immutable release or state version changed'
      USING ERRCODE = '23000',
            CONSTRAINT = 'skill_release_immutable_guard';
  END IF;

  IF NOT (
    (OLD.lifecycle_state = 'SUBMITTED'
      AND NEW.lifecycle_state = 'STATIC_PASSED')
    OR (OLD.lifecycle_state = 'STATIC_PASSED'
      AND NEW.lifecycle_state IN ('EVALUATED', 'EVALUATION_FAILED'))
    OR (OLD.lifecycle_state = 'EVALUATED'
      AND NEW.lifecycle_state = 'APPROVED')
    OR (OLD.lifecycle_state = 'APPROVED'
      AND NEW.lifecycle_state IN ('APPROVED', 'WITHDRAWN'))
  ) THEN
    RAISE EXCEPTION 'C13 release transition rejected'
      USING ERRCODE = '23000',
            CONSTRAINT = 'skill_release_transition_guard';
  END IF;
  RETURN NEW;
END;
$$;

CREATE FUNCTION aios_skill.enforce_channel_update()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF OLD.tenant_id IS DISTINCT FROM NEW.tenant_id
     OR OLD.tenant_kind IS DISTINCT FROM NEW.tenant_kind
     OR OLD.skill_id IS DISTINCT FROM NEW.skill_id
     OR OLD.channel IS DISTINCT FROM NEW.channel
     OR NEW.generation <> OLD.generation + 1
  THEN
    RAISE EXCEPTION 'C13 channel generation rejected'
      USING ERRCODE = '23000',
            CONSTRAINT = 'skill_channel_generation_guard';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER skill_release_update_guard
BEFORE UPDATE ON aios_skill.skill_release
FOR EACH ROW EXECUTE FUNCTION aios_skill.enforce_release_update();

CREATE TRIGGER skill_release_delete_guard
BEFORE DELETE ON aios_skill.skill_release
FOR EACH ROW EXECUTE FUNCTION aios_skill.reject_append_only_change();

CREATE TRIGGER skill_channel_update_guard
BEFORE UPDATE ON aios_skill.skill_channel
FOR EACH ROW EXECUTE FUNCTION aios_skill.enforce_channel_update();

CREATE TRIGGER skill_channel_delete_guard
BEFORE DELETE ON aios_skill.skill_channel
FOR EACH ROW EXECUTE FUNCTION aios_skill.reject_append_only_change();

CREATE TRIGGER skill_event_append_only_guard
BEFORE UPDATE OR DELETE ON aios_skill.skill_event
FOR EACH ROW EXECUTE FUNCTION aios_skill.reject_append_only_change();

CREATE TRIGGER skill_receipt_append_only_guard
BEFORE UPDATE OR DELETE ON aios_skill.command_receipt
FOR EACH ROW EXECUTE FUNCTION aios_skill.reject_append_only_change();

ALTER TABLE aios_skill.skill_release ENABLE ROW LEVEL SECURITY;
ALTER TABLE aios_skill.skill_release FORCE ROW LEVEL SECURITY;
ALTER TABLE aios_skill.skill_channel ENABLE ROW LEVEL SECURITY;
ALTER TABLE aios_skill.skill_channel FORCE ROW LEVEL SECURITY;
ALTER TABLE aios_skill.skill_event ENABLE ROW LEVEL SECURITY;
ALTER TABLE aios_skill.skill_event FORCE ROW LEVEL SECURITY;
ALTER TABLE aios_skill.command_receipt ENABLE ROW LEVEL SECURITY;
ALTER TABLE aios_skill.command_receipt FORCE ROW LEVEL SECURITY;

COMMIT;
