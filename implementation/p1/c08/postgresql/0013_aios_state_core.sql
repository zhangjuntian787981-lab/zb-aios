BEGIN;

-- C08 is a Synthetic-only state core. It reuses the C07 signed Tenant
-- transaction scope; it does not create another Tenant trust boundary.
CREATE SCHEMA aios_state;

CREATE TABLE aios_state.aios_case (
  tenant_id text NOT NULL,
  tenant_kind text NOT NULL CHECK (tenant_kind = 'SYNTHETIC'),
  case_id text NOT NULL
    CHECK (char_length(btrim(case_id)) BETWEEN 1 AND 128),
  state text NOT NULL CHECK (state IN ('OPEN', 'CLOSED')),
  version bigint NOT NULL
    CHECK (version BETWEEN 1 AND 9007199254740991),
  goal_ref text NOT NULL
    CHECK (char_length(btrim(goal_ref)) BETWEEN 1 AND 512),
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, case_id),
  UNIQUE (tenant_id, case_id, version),
  FOREIGN KEY (tenant_id, tenant_kind)
    REFERENCES aios_core.tenant_registry(tenant_id, tenant_kind)
    ON DELETE RESTRICT,
  CHECK (updated_at >= created_at)
);

CREATE TABLE aios_state.aios_thread (
  tenant_id text NOT NULL,
  tenant_kind text NOT NULL CHECK (tenant_kind = 'SYNTHETIC'),
  thread_id text NOT NULL
    CHECK (char_length(btrim(thread_id)) BETWEEN 1 AND 128),
  case_id text NOT NULL
    CHECK (char_length(btrim(case_id)) BETWEEN 1 AND 128),
  state text NOT NULL CHECK (state IN ('OPEN', 'CLOSED')),
  version bigint NOT NULL
    CHECK (version BETWEEN 1 AND 9007199254740991),
  purpose_ref text NOT NULL
    CHECK (char_length(btrim(purpose_ref)) BETWEEN 1 AND 512),
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, thread_id),
  UNIQUE (tenant_id, thread_id, version),
  FOREIGN KEY (tenant_id, case_id)
    REFERENCES aios_state.aios_case(tenant_id, case_id)
    ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, tenant_kind)
    REFERENCES aios_core.tenant_registry(tenant_id, tenant_kind)
    ON DELETE RESTRICT,
  CHECK (updated_at >= created_at)
);

CREATE TABLE aios_state.aios_artifact (
  tenant_id text NOT NULL,
  tenant_kind text NOT NULL CHECK (tenant_kind = 'SYNTHETIC'),
  artifact_id text NOT NULL
    CHECK (char_length(btrim(artifact_id)) BETWEEN 1 AND 128),
  case_id text NOT NULL
    CHECK (char_length(btrim(case_id)) BETWEEN 1 AND 128),
  thread_id text,
  artifact_version bigint NOT NULL
    CHECK (artifact_version BETWEEN 1 AND 9007199254740991),
  kind text NOT NULL CHECK (kind IN ('INPUT', 'RESULT')),
  content_ref text NOT NULL
    CHECK (char_length(btrim(content_ref)) BETWEEN 1 AND 1024),
  content_sha256 text NOT NULL
    CHECK (content_sha256 ~ '^sha256:[0-9a-f]{64}$'),
  created_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, artifact_id, artifact_version),
  FOREIGN KEY (tenant_id, case_id)
    REFERENCES aios_state.aios_case(tenant_id, case_id)
    ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, thread_id)
    REFERENCES aios_state.aios_thread(tenant_id, thread_id)
    ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, tenant_kind)
    REFERENCES aios_core.tenant_registry(tenant_id, tenant_kind)
    ON DELETE RESTRICT,
  CHECK (
    thread_id IS NULL
    OR char_length(btrim(thread_id)) BETWEEN 1 AND 128
  )
);

CREATE TABLE aios_state.aios_run (
  tenant_id text NOT NULL,
  tenant_kind text NOT NULL CHECK (tenant_kind = 'SYNTHETIC'),
  run_id text NOT NULL
    CHECK (char_length(btrim(run_id)) BETWEEN 1 AND 128),
  case_id text NOT NULL
    CHECK (char_length(btrim(case_id)) BETWEEN 1 AND 128),
  thread_id text NOT NULL
    CHECK (char_length(btrim(thread_id)) BETWEEN 1 AND 128),
  state text NOT NULL
    CHECK (state IN ('RUNNING', 'SUCCEEDED', 'FAILED', 'CANCELLED')),
  version bigint NOT NULL
    CHECK (version BETWEEN 1 AND 9007199254740991),
  base_manifest jsonb NOT NULL
    CHECK (jsonb_typeof(base_manifest) = 'object'),
  identity jsonb NOT NULL CHECK (jsonb_typeof(identity) = 'object'),
  authorization_evidence jsonb NOT NULL
    CHECK (jsonb_typeof(authorization_evidence) = 'object'),
  tenant_lifecycle_version bigint NOT NULL
    CHECK (
      tenant_lifecycle_version BETWEEN 1 AND 9007199254740991
    ),
  result_artifact jsonb,
  reconstruction_hash text,
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, run_id),
  UNIQUE (tenant_id, run_id, version),
  FOREIGN KEY (tenant_id, case_id)
    REFERENCES aios_state.aios_case(tenant_id, case_id)
    ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, thread_id)
    REFERENCES aios_state.aios_thread(tenant_id, thread_id)
    ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, tenant_kind)
    REFERENCES aios_core.tenant_registry(tenant_id, tenant_kind)
    ON DELETE RESTRICT,
  CHECK (
    result_artifact IS NULL
    OR jsonb_typeof(result_artifact) IN ('object', 'string')
  ),
  CHECK (
    reconstruction_hash IS NULL
    OR reconstruction_hash ~ '^sha256:[0-9a-f]{64}$'
  ),
  CONSTRAINT aios_run_state_shape
    CHECK (
      (
        state = 'RUNNING'
        AND result_artifact IS NULL
        AND reconstruction_hash IS NULL
      )
      OR (
        state IN ('SUCCEEDED', 'FAILED', 'CANCELLED')
        AND result_artifact IS NOT NULL
        AND reconstruction_hash IS NOT NULL
      )
    ),
  CHECK (updated_at >= created_at)
);

CREATE TABLE aios_state.aios_tool_call (
  tenant_id text NOT NULL,
  tenant_kind text NOT NULL CHECK (tenant_kind = 'SYNTHETIC'),
  tool_call_id text NOT NULL
    CHECK (char_length(btrim(tool_call_id)) BETWEEN 1 AND 128),
  run_id text NOT NULL
    CHECK (char_length(btrim(run_id)) BETWEEN 1 AND 128),
  state text NOT NULL CHECK (state IN ('PREPARED', 'SUCCEEDED', 'FAILED')),
  version bigint NOT NULL
    CHECK (version BETWEEN 1 AND 9007199254740991),
  operation_ref text NOT NULL
    CHECK (char_length(btrim(operation_ref)) BETWEEN 1 AND 512),
  operation_version text NOT NULL
    CHECK (char_length(btrim(operation_version)) BETWEEN 1 AND 128),
  request_hash text NOT NULL
    CHECK (request_hash ~ '^sha256:[0-9a-f]{64}$'),
  effect_key text NOT NULL
    CHECK (effect_key ~ '^effect_[0-9a-f]{64}$'),
  compensation_ref text,
  authorization_evidence jsonb NOT NULL
    CHECK (jsonb_typeof(authorization_evidence) = 'object'),
  receipt_ref text,
  receipt_hash text,
  outcome text CHECK (outcome IN ('SUCCEEDED', 'FAILED')),
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, tool_call_id),
  UNIQUE (tenant_id, effect_key),
  UNIQUE (tenant_id, tool_call_id, version),
  FOREIGN KEY (tenant_id, run_id)
    REFERENCES aios_state.aios_run(tenant_id, run_id)
    ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, tenant_kind)
    REFERENCES aios_core.tenant_registry(tenant_id, tenant_kind)
    ON DELETE RESTRICT,
  CHECK (
    compensation_ref IS NULL
    OR char_length(btrim(compensation_ref)) BETWEEN 1 AND 1024
  ),
  CHECK (
    receipt_ref IS NULL
    OR char_length(btrim(receipt_ref)) BETWEEN 1 AND 1024
  ),
  CHECK (
    receipt_hash IS NULL
    OR receipt_hash ~ '^sha256:[0-9a-f]{64}$'
  ),
  CHECK (updated_at >= created_at),
  CONSTRAINT aios_tool_call_state_shape
    CHECK (
      (
        state = 'PREPARED'
        AND receipt_ref IS NULL
        AND receipt_hash IS NULL
        AND outcome IS NULL
      )
      OR (
        state IN ('SUCCEEDED', 'FAILED')
        AND receipt_ref IS NOT NULL
        AND receipt_hash IS NOT NULL
        AND outcome IS NOT NULL
      )
    )
);

CREATE TABLE aios_state.command_receipt (
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

CREATE TABLE aios_state.domain_event (
  tenant_id text NOT NULL,
  tenant_kind text NOT NULL CHECK (tenant_kind = 'SYNTHETIC'),
  event_id text NOT NULL
    CHECK (char_length(btrim(event_id)) BETWEEN 1 AND 128),
  idempotency_key text NOT NULL
    CHECK (char_length(btrim(idempotency_key)) BETWEEN 1 AND 128),
  request_hash text NOT NULL
    CHECK (request_hash ~ '^sha256:[0-9a-f]{64}$'),
  effect_key text NOT NULL
    CHECK (effect_key ~ '^sha256:[0-9a-f]{64}$'),
  aggregate_type text NOT NULL
    CHECK (
      aggregate_type IN (
        'CASE', 'THREAD', 'RUN', 'ARTIFACT', 'TOOL_CALL'
      )
    ),
  aggregate_id text NOT NULL
    CHECK (char_length(btrim(aggregate_id)) BETWEEN 1 AND 128),
  aggregate_version bigint NOT NULL
    CHECK (aggregate_version BETWEEN 1 AND 9007199254740991),
  event jsonb NOT NULL CHECK (jsonb_typeof(event) = 'object'),
  created_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, event_id),
  UNIQUE (tenant_id, idempotency_key),
  FOREIGN KEY (tenant_id, idempotency_key)
    REFERENCES aios_state.command_receipt(tenant_id, idempotency_key)
    ON DELETE RESTRICT
    DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY (tenant_id, tenant_kind)
    REFERENCES aios_core.tenant_registry(tenant_id, tenant_kind)
    ON DELETE RESTRICT,
  CHECK ((event ->> 'id') IS NOT DISTINCT FROM event_id),
  CHECK ((event #>> '{data,tenant_id}') IS NOT DISTINCT FROM tenant_id),
  CHECK ((event ->> 'tenantkind') IS NOT DISTINCT FROM tenant_kind),
  CHECK (
    jsonb_typeof(event -> 'synthetic') IS NOT DISTINCT FROM 'boolean'
    AND (event ->> 'synthetic') IS NOT DISTINCT FROM 'true'
  )
);

CREATE TABLE aios_state.outbox (
  tenant_id text NOT NULL,
  tenant_kind text NOT NULL CHECK (tenant_kind = 'SYNTHETIC'),
  event_id text NOT NULL,
  idempotency_key text NOT NULL,
  request_hash text NOT NULL
    CHECK (request_hash ~ '^sha256:[0-9a-f]{64}$'),
  effect_key text NOT NULL
    CHECK (effect_key ~ '^sha256:[0-9a-f]{64}$'),
  event jsonb NOT NULL CHECK (jsonb_typeof(event) = 'object'),
  status text NOT NULL DEFAULT 'PENDING',
  attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
  lease_version bigint NOT NULL DEFAULT 0 CHECK (lease_version >= 0),
  available_at timestamptz NOT NULL DEFAULT statement_timestamp(),
  leased_by text,
  lease_until timestamptz,
  last_error_code text,
  created_at timestamptz NOT NULL,
  published_at timestamptz,
  PRIMARY KEY (tenant_id, event_id),
  FOREIGN KEY (tenant_id, event_id)
    REFERENCES aios_state.domain_event(tenant_id, event_id)
    ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, tenant_kind)
    REFERENCES aios_core.tenant_registry(tenant_id, tenant_kind)
    ON DELETE RESTRICT,
  CHECK (
    leased_by IS NULL
    OR char_length(btrim(leased_by)) BETWEEN 1 AND 128
  ),
  CHECK (
    last_error_code IS NULL
    OR char_length(btrim(last_error_code)) BETWEEN 1 AND 128
  ),
  CHECK (attempt_count::bigint = lease_version),
  CONSTRAINT aios_state_outbox_delivery_shape
    CHECK (
      (
        status = 'PENDING'
        AND attempt_count = 0
        AND lease_version = 0
        AND leased_by IS NULL
        AND lease_until IS NULL
        AND last_error_code IS NULL
        AND published_at IS NULL
      )
      OR (
        status = 'PROCESSING'
        AND attempt_count > 0
        AND leased_by IS NOT NULL
        AND lease_until IS NOT NULL
        AND last_error_code IS NULL
        AND published_at IS NULL
      )
      OR (
        status = 'FAILED'
        AND attempt_count > 0
        AND leased_by IS NULL
        AND lease_until IS NULL
        AND last_error_code IS NOT NULL
        AND published_at IS NULL
      )
      OR (
        status = 'PUBLISHED'
        AND attempt_count > 0
        AND leased_by IS NULL
        AND lease_until IS NULL
        AND last_error_code IS NULL
        AND published_at IS NOT NULL
      )
    ),
  CHECK (status IN ('PENDING', 'PROCESSING', 'PUBLISHED', 'FAILED'))
);

CREATE INDEX aios_case_tenant_state_idx
  ON aios_state.aios_case(tenant_id, state, updated_at, case_id);
CREATE INDEX aios_thread_case_idx
  ON aios_state.aios_thread(tenant_id, case_id, state, thread_id);
CREATE INDEX aios_artifact_case_idx
  ON aios_state.aios_artifact(
    tenant_id, case_id, thread_id, artifact_version, artifact_id
  );
CREATE INDEX aios_run_thread_idx
  ON aios_state.aios_run(tenant_id, thread_id, state, run_id);
CREATE INDEX aios_tool_call_run_idx
  ON aios_state.aios_tool_call(tenant_id, run_id, tool_call_id);
CREATE UNIQUE INDEX aios_tool_call_one_prepared_per_run
  ON aios_state.aios_tool_call(tenant_id, run_id)
  WHERE state = 'PREPARED';
CREATE INDEX domain_event_aggregate_idx
  ON aios_state.domain_event(
    tenant_id, aggregate_type, aggregate_id, aggregate_version, event_id
  );
CREATE INDEX outbox_claim_idx
  ON aios_state.outbox(
    tenant_id, status, available_at, lease_until, created_at, event_id
  );

CREATE FUNCTION aios_state.reject_append_only_change()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION 'C08 append-only record cannot change'
    USING ERRCODE = '23000',
          CONSTRAINT = 'aios_state_append_only_guard';
  RETURN OLD;
END;
$$;

CREATE FUNCTION aios_state.reject_state_delete()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION 'C08 state record cannot be deleted'
    USING ERRCODE = '23000',
          CONSTRAINT = 'aios_state_no_delete_guard';
  RETURN OLD;
END;
$$;

CREATE FUNCTION aios_state.enforce_versioned_update()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
    OR NEW.tenant_kind IS DISTINCT FROM OLD.tenant_kind
    OR NEW.version <> OLD.version + 1
    OR NEW.created_at IS DISTINCT FROM OLD.created_at
    OR NEW.updated_at < OLD.updated_at
  THEN
    RAISE EXCEPTION 'C08 identity or version is immutable'
      USING ERRCODE = '23000',
            CONSTRAINT = 'aios_state_version_guard';
  END IF;

  IF TG_TABLE_NAME = 'aios_case' THEN
    IF NEW.case_id IS DISTINCT FROM OLD.case_id
      OR NEW.goal_ref IS DISTINCT FROM OLD.goal_ref
      OR NOT (OLD.state = 'OPEN' AND NEW.state = 'CLOSED')
    THEN
      RAISE EXCEPTION 'C08 Case transition is invalid'
        USING ERRCODE = '23000',
              CONSTRAINT = 'aios_case_transition_guard';
    END IF;
  ELSIF TG_TABLE_NAME = 'aios_thread' THEN
    IF NEW.thread_id IS DISTINCT FROM OLD.thread_id
      OR NEW.case_id IS DISTINCT FROM OLD.case_id
      OR NEW.purpose_ref IS DISTINCT FROM OLD.purpose_ref
      OR NOT (OLD.state = 'OPEN' AND NEW.state = 'CLOSED')
    THEN
      RAISE EXCEPTION 'C08 Thread transition is invalid'
        USING ERRCODE = '23000',
              CONSTRAINT = 'aios_thread_transition_guard';
    END IF;
  ELSIF TG_TABLE_NAME = 'aios_run' THEN
    IF NEW.run_id IS DISTINCT FROM OLD.run_id
      OR NEW.case_id IS DISTINCT FROM OLD.case_id
      OR NEW.thread_id IS DISTINCT FROM OLD.thread_id
      OR NEW.base_manifest IS DISTINCT FROM OLD.base_manifest
      OR NEW.identity IS DISTINCT FROM OLD.identity
      OR NEW.authorization_evidence
         IS DISTINCT FROM OLD.authorization_evidence
      OR NEW.tenant_lifecycle_version
         IS DISTINCT FROM OLD.tenant_lifecycle_version
      OR NOT (
        OLD.state = 'RUNNING'
        AND NEW.state IN ('RUNNING', 'SUCCEEDED', 'FAILED', 'CANCELLED')
      )
    THEN
      RAISE EXCEPTION 'C08 Run transition is invalid'
        USING ERRCODE = '23000',
              CONSTRAINT = 'aios_run_transition_guard';
    END IF;
  ELSIF TG_TABLE_NAME = 'aios_tool_call' THEN
    IF NEW.tool_call_id IS DISTINCT FROM OLD.tool_call_id
      OR NEW.run_id IS DISTINCT FROM OLD.run_id
      OR NEW.operation_ref IS DISTINCT FROM OLD.operation_ref
      OR NEW.operation_version IS DISTINCT FROM OLD.operation_version
      OR NEW.request_hash IS DISTINCT FROM OLD.request_hash
      OR NEW.effect_key IS DISTINCT FROM OLD.effect_key
      OR NEW.compensation_ref IS DISTINCT FROM OLD.compensation_ref
      OR NEW.authorization_evidence
         IS DISTINCT FROM OLD.authorization_evidence
      OR NOT (
        OLD.state = 'PREPARED'
        AND NEW.state IN ('SUCCEEDED', 'FAILED')
      )
    THEN
      RAISE EXCEPTION 'C08 ToolCall transition is invalid'
        USING ERRCODE = '23000',
              CONSTRAINT = 'aios_tool_call_transition_guard';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

CREATE FUNCTION aios_state.enforce_initial_state()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF NEW.version <> 1 THEN
    RAISE EXCEPTION 'C08 state must start at version 1'
      USING ERRCODE = '23000',
            CONSTRAINT = 'aios_state_initial_version_guard';
  END IF;
  IF TG_TABLE_NAME IN ('aios_case', 'aios_thread')
    AND NEW.state <> 'OPEN'
  THEN
    RAISE EXCEPTION 'C08 Case or Thread must start OPEN'
      USING ERRCODE = '23000',
            CONSTRAINT = 'aios_state_initial_state_guard';
  END IF;
  IF TG_TABLE_NAME = 'aios_run' AND NEW.state <> 'RUNNING' THEN
    RAISE EXCEPTION 'C08 Run must start RUNNING'
      USING ERRCODE = '23000',
            CONSTRAINT = 'aios_state_initial_state_guard';
  END IF;
  IF TG_TABLE_NAME = 'aios_tool_call' AND NEW.state <> 'PREPARED' THEN
    RAISE EXCEPTION 'C08 ToolCall must start PREPARED'
      USING ERRCODE = '23000',
            CONSTRAINT = 'aios_state_initial_state_guard';
  END IF;
  RETURN NEW;
END;
$$;

CREATE FUNCTION aios_state.enforce_artifact_version_chain()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, aios_state
AS $$
DECLARE
  previous aios_state.aios_artifact%ROWTYPE;
BEGIN
  SELECT *
    INTO previous
    FROM aios_state.aios_artifact
   WHERE tenant_id = NEW.tenant_id
     AND artifact_id = NEW.artifact_id
   ORDER BY artifact_version DESC
   LIMIT 1;

  IF NOT FOUND THEN
    IF NEW.artifact_version <> 1 THEN
      RAISE EXCEPTION 'C08 Artifact chain must start at version 1'
        USING ERRCODE = '23000',
              CONSTRAINT = 'aios_artifact_version_chain_guard';
    END IF;
  ELSIF NEW.artifact_version <> previous.artifact_version + 1
    OR NEW.case_id IS DISTINCT FROM previous.case_id
    OR NEW.thread_id IS DISTINCT FROM previous.thread_id
    OR NEW.kind IS DISTINCT FROM previous.kind
  THEN
    RAISE EXCEPTION 'C08 Artifact version chain is invalid'
      USING ERRCODE = '23000',
            CONSTRAINT = 'aios_artifact_version_chain_guard';
  END IF;
  RETURN NEW;
END;
$$;

CREATE FUNCTION aios_state.enforce_domain_event_aggregate()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  matched boolean;
BEGIN
  IF NEW.aggregate_type = 'CASE' THEN
    SELECT true INTO matched
      FROM aios_state.aios_case
     WHERE tenant_id = NEW.tenant_id
       AND case_id = NEW.aggregate_id
       AND version = NEW.aggregate_version;
  ELSIF NEW.aggregate_type = 'THREAD' THEN
    SELECT true INTO matched
      FROM aios_state.aios_thread
     WHERE tenant_id = NEW.tenant_id
       AND thread_id = NEW.aggregate_id
       AND version = NEW.aggregate_version;
  ELSIF NEW.aggregate_type = 'RUN' THEN
    SELECT true INTO matched
      FROM aios_state.aios_run
     WHERE tenant_id = NEW.tenant_id
       AND run_id = NEW.aggregate_id
       AND version = NEW.aggregate_version;
  ELSIF NEW.aggregate_type = 'ARTIFACT' THEN
    SELECT true INTO matched
      FROM aios_state.aios_artifact
     WHERE tenant_id = NEW.tenant_id
       AND artifact_id = NEW.aggregate_id
       AND artifact_version = NEW.aggregate_version;
  ELSE
    SELECT true INTO matched
      FROM aios_state.aios_tool_call
     WHERE tenant_id = NEW.tenant_id
       AND tool_call_id = NEW.aggregate_id
       AND version = NEW.aggregate_version;
  END IF;

  IF NOT coalesce(matched, false) THEN
    RAISE EXCEPTION 'C08 DomainEvent aggregate version is missing'
      USING ERRCODE = '23000',
            CONSTRAINT = 'aios_state_event_aggregate_guard';
  END IF;
  RETURN NEW;
END;
$$;

CREATE FUNCTION aios_state.enforce_event_outbox_pair()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  paired record;
BEGIN
  IF TG_TABLE_NAME = 'domain_event' THEN
    SELECT request_hash, effect_key, idempotency_key, event
      INTO paired
      FROM aios_state.outbox
     WHERE tenant_id = NEW.tenant_id
       AND event_id = NEW.event_id;
  ELSE
    SELECT request_hash, effect_key, idempotency_key, event
      INTO paired
      FROM aios_state.domain_event
     WHERE tenant_id = NEW.tenant_id
       AND event_id = NEW.event_id;
  END IF;

  IF NOT FOUND
    OR paired.request_hash IS DISTINCT FROM NEW.request_hash
    OR paired.effect_key IS DISTINCT FROM NEW.effect_key
    OR paired.idempotency_key IS DISTINCT FROM NEW.idempotency_key
    OR paired.event IS DISTINCT FROM NEW.event
  THEN
    RAISE EXCEPTION 'C08 DomainEvent and Outbox must be exact pairs'
      USING ERRCODE = '23000',
            CONSTRAINT = 'aios_state_event_outbox_pair_guard';
  END IF;
  RETURN NEW;
END;
$$;

CREATE FUNCTION aios_state.enforce_event_receipt_pair()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  paired record;
BEGIN
  IF TG_TABLE_NAME = 'domain_event' THEN
    SELECT request_hash, effect_key
      INTO paired
      FROM aios_state.command_receipt
     WHERE tenant_id = NEW.tenant_id
       AND idempotency_key = NEW.idempotency_key;
    IF NOT FOUND
      OR paired.request_hash IS DISTINCT FROM NEW.request_hash
      OR paired.effect_key IS DISTINCT FROM NEW.effect_key
    THEN
      RAISE EXCEPTION 'C08 DomainEvent requires its CommandReceipt'
        USING ERRCODE = '23000',
              CONSTRAINT = 'aios_state_event_receipt_pair_guard';
    END IF;
    RETURN NEW;
  END IF;

  SELECT request_hash, effect_key
    INTO paired
    FROM aios_state.domain_event
   WHERE tenant_id = NEW.tenant_id
     AND idempotency_key = NEW.idempotency_key
   ORDER BY event_id
   LIMIT 1;
  IF NOT FOUND
    OR paired.request_hash IS DISTINCT FROM NEW.request_hash
    OR paired.effect_key IS DISTINCT FROM NEW.effect_key
  THEN
    RAISE EXCEPTION 'C08 CommandReceipt requires a DomainEvent'
      USING ERRCODE = '23000',
            CONSTRAINT = 'aios_state_event_receipt_pair_guard';
  END IF;
  RETURN NEW;
END;
$$;

CREATE FUNCTION aios_state.enforce_outbox_state()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.status <> 'PENDING'
      OR NEW.attempt_count <> 0
      OR NEW.lease_version <> 0
      OR NEW.leased_by IS NOT NULL
      OR NEW.lease_until IS NOT NULL
      OR NEW.last_error_code IS NOT NULL
      OR NEW.published_at IS NOT NULL
    THEN
      RAISE EXCEPTION 'C08 Outbox must start PENDING'
        USING ERRCODE = '23000',
              CONSTRAINT = 'aios_state_outbox_initial_guard';
    END IF;
    RETURN NEW;
  END IF;

  IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
    OR NEW.tenant_kind IS DISTINCT FROM OLD.tenant_kind
    OR NEW.event_id IS DISTINCT FROM OLD.event_id
    OR NEW.idempotency_key IS DISTINCT FROM OLD.idempotency_key
    OR NEW.request_hash IS DISTINCT FROM OLD.request_hash
    OR NEW.effect_key IS DISTINCT FROM OLD.effect_key
    OR NEW.event IS DISTINCT FROM OLD.event
    OR NEW.created_at IS DISTINCT FROM OLD.created_at
  THEN
    RAISE EXCEPTION 'C08 Outbox payload is immutable'
      USING ERRCODE = '23000',
            CONSTRAINT = 'aios_state_outbox_payload_guard';
  END IF;

  IF OLD.status = 'PUBLISHED' THEN
    RAISE EXCEPTION 'C08 published Outbox record is final'
      USING ERRCODE = '23000',
            CONSTRAINT = 'aios_state_outbox_published_guard';
  END IF;

  IF OLD.status IN ('PENDING', 'FAILED')
    AND NEW.status = 'PROCESSING'
  THEN
    IF OLD.available_at > statement_timestamp()
      OR NEW.attempt_count <> OLD.attempt_count + 1
      OR NEW.lease_version <> OLD.lease_version + 1
      OR NEW.available_at IS DISTINCT FROM OLD.available_at
      OR NEW.leased_by IS NULL
      OR NEW.lease_until <= statement_timestamp()
      OR NEW.last_error_code IS NOT NULL
      OR NEW.published_at IS NOT NULL
    THEN
      RAISE EXCEPTION 'C08 Outbox claim is invalid'
        USING ERRCODE = '23000',
              CONSTRAINT = 'aios_state_outbox_claim_guard';
    END IF;
    RETURN NEW;
  END IF;

  IF OLD.status = 'PROCESSING' AND NEW.status = 'PROCESSING' THEN
    IF OLD.lease_until >= statement_timestamp()
      OR NEW.attempt_count <> OLD.attempt_count + 1
      OR NEW.lease_version <> OLD.lease_version + 1
      OR NEW.available_at IS DISTINCT FROM OLD.available_at
      OR NEW.leased_by IS NULL
      OR NEW.lease_until <= statement_timestamp()
      OR NEW.last_error_code IS NOT NULL
      OR NEW.published_at IS NOT NULL
    THEN
      RAISE EXCEPTION 'C08 Outbox reclaim is invalid'
        USING ERRCODE = '23000',
              CONSTRAINT = 'aios_state_outbox_reclaim_guard';
    END IF;
    RETURN NEW;
  END IF;

  IF OLD.status = 'PROCESSING' AND NEW.status = 'FAILED' THEN
    IF OLD.lease_until < statement_timestamp()
      OR NEW.attempt_count <> OLD.attempt_count
      OR NEW.lease_version <> OLD.lease_version
      OR NEW.available_at <= statement_timestamp()
      OR NEW.leased_by IS NOT NULL
      OR NEW.lease_until IS NOT NULL
      OR NEW.last_error_code IS NULL
      OR NEW.published_at IS NOT NULL
    THEN
      RAISE EXCEPTION 'C08 Outbox failure receipt is invalid'
        USING ERRCODE = '23000',
              CONSTRAINT = 'aios_state_outbox_failure_guard';
    END IF;
    RETURN NEW;
  END IF;

  IF OLD.status = 'PROCESSING' AND NEW.status = 'PUBLISHED' THEN
    IF OLD.lease_until < statement_timestamp()
      OR NEW.attempt_count <> OLD.attempt_count
      OR NEW.lease_version <> OLD.lease_version
      OR NEW.available_at IS DISTINCT FROM OLD.available_at
      OR NEW.leased_by IS NOT NULL
      OR NEW.lease_until IS NOT NULL
      OR NEW.last_error_code IS NOT NULL
      OR NEW.published_at IS NULL
    THEN
      RAISE EXCEPTION 'C08 Outbox completion is invalid'
        USING ERRCODE = '23000',
              CONSTRAINT = 'aios_state_outbox_completion_guard';
    END IF;
    RETURN NEW;
  END IF;

  RAISE EXCEPTION 'C08 Outbox transition is invalid'
    USING ERRCODE = '23000',
          CONSTRAINT = 'aios_state_outbox_transition_guard';
END;
$$;

CREATE TRIGGER aios_case_initial_guard
BEFORE INSERT ON aios_state.aios_case
FOR EACH ROW EXECUTE FUNCTION aios_state.enforce_initial_state();
CREATE TRIGGER aios_thread_initial_guard
BEFORE INSERT ON aios_state.aios_thread
FOR EACH ROW EXECUTE FUNCTION aios_state.enforce_initial_state();
CREATE TRIGGER aios_run_initial_guard
BEFORE INSERT ON aios_state.aios_run
FOR EACH ROW EXECUTE FUNCTION aios_state.enforce_initial_state();
CREATE TRIGGER aios_tool_call_initial_guard
BEFORE INSERT ON aios_state.aios_tool_call
FOR EACH ROW EXECUTE FUNCTION aios_state.enforce_initial_state();
CREATE TRIGGER aios_artifact_version_chain_guard
BEFORE INSERT ON aios_state.aios_artifact
FOR EACH ROW
EXECUTE FUNCTION aios_state.enforce_artifact_version_chain();

CREATE TRIGGER aios_case_update_guard
BEFORE UPDATE ON aios_state.aios_case
FOR EACH ROW EXECUTE FUNCTION aios_state.enforce_versioned_update();
CREATE TRIGGER aios_thread_update_guard
BEFORE UPDATE ON aios_state.aios_thread
FOR EACH ROW EXECUTE FUNCTION aios_state.enforce_versioned_update();
CREATE TRIGGER aios_run_update_guard
BEFORE UPDATE ON aios_state.aios_run
FOR EACH ROW EXECUTE FUNCTION aios_state.enforce_versioned_update();
CREATE TRIGGER aios_tool_call_update_guard
BEFORE UPDATE ON aios_state.aios_tool_call
FOR EACH ROW EXECUTE FUNCTION aios_state.enforce_versioned_update();

CREATE TRIGGER aios_case_no_delete
BEFORE DELETE ON aios_state.aios_case
FOR EACH ROW EXECUTE FUNCTION aios_state.reject_state_delete();
CREATE TRIGGER aios_thread_no_delete
BEFORE DELETE ON aios_state.aios_thread
FOR EACH ROW EXECUTE FUNCTION aios_state.reject_state_delete();
CREATE TRIGGER aios_run_no_delete
BEFORE DELETE ON aios_state.aios_run
FOR EACH ROW EXECUTE FUNCTION aios_state.reject_state_delete();
CREATE TRIGGER aios_tool_call_no_delete
BEFORE DELETE ON aios_state.aios_tool_call
FOR EACH ROW EXECUTE FUNCTION aios_state.reject_state_delete();

CREATE TRIGGER aios_artifact_no_change
BEFORE UPDATE OR DELETE ON aios_state.aios_artifact
FOR EACH ROW EXECUTE FUNCTION aios_state.reject_append_only_change();
CREATE TRIGGER command_receipt_no_change
BEFORE UPDATE OR DELETE ON aios_state.command_receipt
FOR EACH ROW EXECUTE FUNCTION aios_state.reject_append_only_change();
CREATE TRIGGER domain_event_no_change
BEFORE UPDATE OR DELETE ON aios_state.domain_event
FOR EACH ROW EXECUTE FUNCTION aios_state.reject_append_only_change();
CREATE TRIGGER outbox_state_guard
BEFORE INSERT OR UPDATE ON aios_state.outbox
FOR EACH ROW EXECUTE FUNCTION aios_state.enforce_outbox_state();
CREATE TRIGGER outbox_no_delete
BEFORE DELETE ON aios_state.outbox
FOR EACH ROW EXECUTE FUNCTION aios_state.reject_state_delete();

CREATE CONSTRAINT TRIGGER domain_event_aggregate_guard
AFTER INSERT ON aios_state.domain_event
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION aios_state.enforce_domain_event_aggregate();
CREATE CONSTRAINT TRIGGER domain_event_requires_outbox
AFTER INSERT ON aios_state.domain_event
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION aios_state.enforce_event_outbox_pair();
CREATE CONSTRAINT TRIGGER outbox_requires_domain_event
AFTER INSERT ON aios_state.outbox
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION aios_state.enforce_event_outbox_pair();
CREATE CONSTRAINT TRIGGER domain_event_requires_receipt
AFTER INSERT ON aios_state.domain_event
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION aios_state.enforce_event_receipt_pair();
CREATE CONSTRAINT TRIGGER receipt_requires_domain_event
AFTER INSERT ON aios_state.command_receipt
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION aios_state.enforce_event_receipt_pair();

ALTER TABLE aios_state.aios_case ENABLE ROW LEVEL SECURITY;
ALTER TABLE aios_state.aios_case FORCE ROW LEVEL SECURITY;
ALTER TABLE aios_state.aios_thread ENABLE ROW LEVEL SECURITY;
ALTER TABLE aios_state.aios_thread FORCE ROW LEVEL SECURITY;
ALTER TABLE aios_state.aios_artifact ENABLE ROW LEVEL SECURITY;
ALTER TABLE aios_state.aios_artifact FORCE ROW LEVEL SECURITY;
ALTER TABLE aios_state.aios_run ENABLE ROW LEVEL SECURITY;
ALTER TABLE aios_state.aios_run FORCE ROW LEVEL SECURITY;
ALTER TABLE aios_state.aios_tool_call ENABLE ROW LEVEL SECURITY;
ALTER TABLE aios_state.aios_tool_call FORCE ROW LEVEL SECURITY;
ALTER TABLE aios_state.domain_event ENABLE ROW LEVEL SECURITY;
ALTER TABLE aios_state.domain_event FORCE ROW LEVEL SECURITY;
ALTER TABLE aios_state.outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE aios_state.outbox FORCE ROW LEVEL SECURITY;
ALTER TABLE aios_state.command_receipt ENABLE ROW LEVEL SECURITY;
ALTER TABLE aios_state.command_receipt FORCE ROW LEVEL SECURITY;

COMMIT;
