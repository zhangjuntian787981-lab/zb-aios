BEGIN;

-- C09 depends on C03, C05, C07 and C08. It is Synthetic-only before P3.
CREATE SCHEMA aios_personal_memory;

CREATE TABLE aios_personal_memory.personal_scope_signing_secret (
  singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
  secret bytea NOT NULL CHECK (octet_length(secret) = 32),
  created_at timestamptz NOT NULL DEFAULT statement_timestamp()
);

INSERT INTO aios_personal_memory.personal_scope_signing_secret (
  singleton,
  secret
) VALUES (true, public.gen_random_bytes(32));

CREATE FUNCTION aios_personal_memory.issue_principal_scope_signature(
  scope_tenant_id text,
  scope_tenant_kind text,
  scope_principal_id text,
  scope_principal_lifecycle_version bigint,
  scope_principal_security_epoch bigint,
  scope_backend_pid integer,
  scope_transaction_id xid8,
  scope_ttl_seconds integer,
  scope_nonce uuid
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, aios_core, aios_personal_memory
AS $$
DECLARE
  signing_secret bytea;
  expires_epoch_ms bigint;
  payload text;
BEGIN
  IF
    scope_tenant_kind <> 'SYNTHETIC'
    OR scope_tenant_id IS NULL
    OR scope_principal_id IS NULL
    OR scope_principal_id !~
      '^prn_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    OR scope_principal_lifecycle_version < 1
    OR scope_principal_security_epoch < 1
    OR scope_backend_pid < 1
    OR scope_transaction_id IS NULL
    OR scope_ttl_seconds NOT BETWEEN 1 AND 30
    OR scope_nonce IS NULL
    OR NOT EXISTS (
      SELECT 1
        FROM aios_core.principal_registry AS principal
       WHERE principal.tenant_id = scope_tenant_id
         AND principal.tenant_kind = scope_tenant_kind
         AND principal.principal_id = scope_principal_id
         AND principal.principal_kind = 'HUMAN'
         AND principal.state = 'ACTIVE'
         AND principal.lifecycle_version =
             scope_principal_lifecycle_version
         AND principal.security_epoch = scope_principal_security_epoch
    )
  THEN
    RAISE EXCEPTION 'principal scope cannot be signed'
      USING ERRCODE = '42501';
  END IF;

  expires_epoch_ms :=
    floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint
    + (scope_ttl_seconds::bigint * 1000);

  SELECT secret
    INTO STRICT signing_secret
    FROM aios_personal_memory.personal_scope_signing_secret
   WHERE singleton;

  payload := jsonb_build_array(
    scope_tenant_id,
    scope_tenant_kind,
    scope_principal_id,
    scope_principal_lifecycle_version::text,
    scope_principal_security_epoch::text,
    scope_backend_pid::text,
    scope_transaction_id::text,
    expires_epoch_ms::text,
    scope_nonce::text
  )::text;

  RETURN jsonb_build_object(
    'expires_epoch_ms',
    expires_epoch_ms,
    'signature',
    encode(
      public.hmac(
        convert_to(payload, 'UTF8'),
        signing_secret,
        'sha256'
      ),
      'hex'
    )
  );
END
$$;

CREATE FUNCTION aios_personal_memory.runtime_principal_allows(
  row_tenant_id text,
  row_tenant_kind text,
  row_principal_id text
)
RETURNS boolean
LANGUAGE sql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, aios_data, aios_personal_memory
AS $$
  WITH scope AS (
    SELECT
      current_setting('aios.tenant_id', true) AS tenant_id,
      current_setting('aios.tenant_kind', true) AS tenant_kind,
      current_setting('aios.principal_id', true) AS principal_id,
      current_setting('aios.principal_lifecycle_version', true)
        AS principal_lifecycle_version,
      current_setting('aios.principal_security_epoch', true)
        AS principal_security_epoch,
      current_setting('aios.backend_pid', true) AS backend_pid,
      current_setting('aios.transaction_id', true) AS transaction_id,
      current_setting('aios.principal_expires_epoch_ms', true)
        AS expires_epoch_ms,
      current_setting('aios.principal_scope_nonce', true) AS scope_nonce,
      current_setting('aios.principal_scope_signature', true)
        AS scope_signature
  )
  SELECT
    aios_data.runtime_scope_allows(row_tenant_id, row_tenant_kind)
    AND row_tenant_id = scope.tenant_id
    AND row_tenant_kind = scope.tenant_kind
    AND row_principal_id = scope.principal_id
    AND scope.principal_lifecycle_version ~ '^[1-9][0-9]*$'
    AND scope.principal_security_epoch ~ '^[1-9][0-9]*$'
    AND scope.backend_pid ~ '^[1-9][0-9]*$'
    AND scope.transaction_id IS NOT NULL
    AND scope.expires_epoch_ms ~ '^[1-9][0-9]*$'
    AND scope.scope_nonce IS NOT NULL
    AND scope.scope_signature ~ '^[a-f0-9]{64}$'
    AND CASE
          WHEN scope.backend_pid ~ '^[1-9][0-9]*$'
          THEN scope.backend_pid::integer
          ELSE NULL
        END = pg_backend_pid()
    AND scope.transaction_id = pg_current_xact_id()::text
    AND scope.expires_epoch_ms::bigint >
      floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint
    AND scope.scope_signature = encode(
      public.hmac(
        convert_to(
          jsonb_build_array(
            scope.tenant_id,
            scope.tenant_kind,
            scope.principal_id,
            scope.principal_lifecycle_version,
            scope.principal_security_epoch,
            scope.backend_pid,
            scope.transaction_id,
            scope.expires_epoch_ms,
            scope.scope_nonce
          )::text,
          'UTF8'
        ),
        secret.secret,
        'sha256'
      ),
      'hex'
    )
    AND EXISTS (
      SELECT 1
        FROM aios_core.principal_registry AS principal
       WHERE principal.tenant_id = row_tenant_id
         AND principal.tenant_kind = row_tenant_kind
         AND principal.principal_id = row_principal_id
         AND principal.principal_kind = 'HUMAN'
         AND principal.state = 'ACTIVE'
         AND principal.lifecycle_version =
             CASE
               WHEN scope.principal_lifecycle_version ~ '^[1-9][0-9]*$'
               THEN scope.principal_lifecycle_version::bigint
               ELSE NULL
             END
         AND principal.security_epoch =
             CASE
               WHEN scope.principal_security_epoch ~ '^[1-9][0-9]*$'
               THEN scope.principal_security_epoch::bigint
               ELSE NULL
             END
    )
    FROM scope
    CROSS JOIN
      aios_personal_memory.personal_scope_signing_secret AS secret
   WHERE secret.singleton
$$;

CREATE TABLE aios_personal_memory.personal_profile (
  tenant_id text NOT NULL,
  tenant_kind text NOT NULL CHECK (tenant_kind = 'SYNTHETIC'),
  principal_id text NOT NULL,
  principal_kind text NOT NULL CHECK (principal_kind = 'HUMAN'),
  state text NOT NULL CHECK (state IN ('ACTIVE', 'PAUSED')),
  version bigint NOT NULL
    CHECK (version BETWEEN 1 AND 9007199254740991),
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, principal_id),
  FOREIGN KEY (
    principal_id,
    tenant_id,
    tenant_kind,
    principal_kind
  )
  REFERENCES aios_core.principal_registry(
    principal_id,
    tenant_id,
    tenant_kind,
    principal_kind
  )
  ON DELETE RESTRICT,
  CHECK (updated_at >= created_at)
);

CREATE TABLE aios_personal_memory.personal_memory (
  tenant_id text NOT NULL,
  tenant_kind text NOT NULL CHECK (tenant_kind = 'SYNTHETIC'),
  memory_id text NOT NULL
    CHECK (
      memory_id ~ '^mem_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
  principal_id text NOT NULL,
  state text NOT NULL
    CHECK (state IN ('CANDIDATE', 'CONFIRMED', 'EXPIRED', 'DELETED')),
  category text NOT NULL CHECK (category IN ('PREFERENCE', 'WORK_STATE')),
  content text,
  content_sha256 text NOT NULL
    CHECK (content_sha256 ~ '^sha256:[a-f0-9]{64}$'),
  source_ref text NOT NULL
    CHECK (
      char_length(btrim(source_ref)) BETWEEN 1 AND 1024
      AND source_ref
        ~ '^(evidence|fixture|policy|profile|synthetic|test)://'
    ),
  expires_at timestamptz NOT NULL,
  version bigint NOT NULL
    CHECK (version BETWEEN 1 AND 9007199254740991),
  terminal_reason text,
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, memory_id),
  FOREIGN KEY (tenant_id, principal_id)
    REFERENCES aios_personal_memory.personal_profile(
      tenant_id,
      principal_id
    )
    ON DELETE RESTRICT,
  CHECK (expires_at > created_at),
  CHECK (updated_at >= created_at),
  CHECK (
    (
      state IN ('CANDIDATE', 'CONFIRMED')
      AND content IS NOT NULL
      AND char_length(content) BETWEEN 1 AND 2048
      AND terminal_reason IS NULL
    )
    OR (
      state IN ('EXPIRED', 'DELETED')
      AND content IS NULL
      AND terminal_reason IS NOT NULL
      AND char_length(btrim(terminal_reason)) BETWEEN 1 AND 128
    )
  )
);

CREATE INDEX personal_memory_recall_idx
  ON aios_personal_memory.personal_memory(
    tenant_id,
    principal_id,
    state,
    expires_at,
    created_at
  );

CREATE TABLE aios_personal_memory.conversation_checkpoint (
  tenant_id text NOT NULL,
  tenant_kind text NOT NULL CHECK (tenant_kind = 'SYNTHETIC'),
  checkpoint_id text NOT NULL
    CHECK (
      checkpoint_id ~ '^ckp_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
  principal_id text NOT NULL,
  thread_ref text NOT NULL
    CHECK (
      char_length(btrim(thread_ref)) BETWEEN 1 AND 1024
      AND thread_ref
        ~ '^(evidence|fixture|policy|profile|synthetic|test)://'
    ),
  state_ref text NOT NULL
    CHECK (
      char_length(btrim(state_ref)) BETWEEN 1 AND 1024
      AND state_ref
        ~ '^(evidence|fixture|policy|profile|synthetic|test)://'
    ),
  state_sha256 text NOT NULL
    CHECK (state_sha256 ~ '^sha256:[a-f0-9]{64}$'),
  memory_ids text[] NOT NULL DEFAULT '{}'::text[]
    CHECK (cardinality(memory_ids) <= 32),
  version bigint NOT NULL
    CHECK (version BETWEEN 1 AND 9007199254740991),
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, checkpoint_id),
  FOREIGN KEY (tenant_id, principal_id)
    REFERENCES aios_personal_memory.personal_profile(
      tenant_id,
      principal_id
    )
    ON DELETE RESTRICT,
  CHECK (updated_at >= created_at)
);

CREATE TABLE aios_personal_memory.memory_event (
  tenant_id text NOT NULL,
  tenant_kind text NOT NULL CHECK (tenant_kind = 'SYNTHETIC'),
  event_id text NOT NULL
    CHECK (
      event_id ~ '^mev_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
  memory_id text NOT NULL,
  principal_id text NOT NULL,
  event_type text NOT NULL
    CHECK (
      event_type IN (
        'MEMORY_CANDIDATE_PROPOSED',
        'MEMORY_CONFIRMED',
        'MEMORY_EXPIRED',
        'MEMORY_DELETED'
      )
    ),
  from_state text
    CHECK (
      from_state IS NULL
      OR from_state IN ('CANDIDATE', 'CONFIRMED', 'EXPIRED', 'DELETED')
    ),
  to_state text NOT NULL
    CHECK (to_state IN ('CANDIDATE', 'CONFIRMED', 'EXPIRED', 'DELETED')),
  content_sha256 text NOT NULL
    CHECK (content_sha256 ~ '^sha256:[a-f0-9]{64}$'),
  actor_principal_id text NOT NULL,
  authorization_evidence jsonb NOT NULL
    CHECK (jsonb_typeof(authorization_evidence) = 'object'),
  human_consent_evidence jsonb
    CHECK (
      human_consent_evidence IS NULL
      OR CASE
        WHEN jsonb_typeof(human_consent_evidence) = 'object'
        THEN
          human_consent_evidence ?& ARRAY[
            'tenantId',
            'humanPrincipalId',
            'memoryId',
            'expectedVersion',
            'contentSha256',
            'expiresAt',
            'purpose',
            'tokenSha256',
            'consumedAt'
          ]
          AND human_consent_evidence - ARRAY[
            'tenantId',
            'humanPrincipalId',
            'memoryId',
            'expectedVersion',
            'contentSha256',
            'expiresAt',
            'purpose',
            'tokenSha256',
            'consumedAt'
          ] = '{}'::jsonb
          AND jsonb_typeof(
            human_consent_evidence->'tenantId'
          ) = 'string'
          AND human_consent_evidence->>'tenantId'
            ~ '^stn_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
          AND jsonb_typeof(
            human_consent_evidence->'humanPrincipalId'
          ) = 'string'
          AND human_consent_evidence->>'humanPrincipalId'
            ~ '^prn_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
          AND jsonb_typeof(
            human_consent_evidence->'memoryId'
          ) = 'string'
          AND human_consent_evidence->>'memoryId'
            ~ '^mem_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
          AND jsonb_typeof(
            human_consent_evidence->'expectedVersion'
          ) = 'number'
          AND human_consent_evidence->>'expectedVersion'
            ~ '^[1-9][0-9]*$'
          AND (human_consent_evidence->>'expectedVersion')::numeric
            <= 9007199254740991
          AND jsonb_typeof(
            human_consent_evidence->'contentSha256'
          ) = 'string'
          AND human_consent_evidence->>'contentSha256'
            ~ '^sha256:[a-f0-9]{64}$'
          AND jsonb_typeof(
            human_consent_evidence->'expiresAt'
          ) = 'string'
          AND human_consent_evidence->>'expiresAt'
            ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}[.][0-9]{3}Z$'
          AND jsonb_typeof(
            human_consent_evidence->'purpose'
          ) = 'string'
          AND human_consent_evidence->>'purpose' IN (
            'CONFIRM_PERSONAL_MEMORY',
            'CORRECT_PERSONAL_MEMORY'
          )
          AND jsonb_typeof(
            human_consent_evidence->'tokenSha256'
          ) = 'string'
          AND human_consent_evidence->>'tokenSha256'
            ~ '^sha256:[a-f0-9]{64}$'
          AND jsonb_typeof(
            human_consent_evidence->'consumedAt'
          ) = 'string'
          AND human_consent_evidence->>'consumedAt'
            ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}[.][0-9]{3}Z$'
          AND human_consent_evidence->>'expiresAt'
            > human_consent_evidence->>'consumedAt'
        ELSE false
      END
    ),
  correlation_id text NOT NULL
    CHECK (char_length(btrim(correlation_id)) BETWEEN 1 AND 128),
  created_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, event_id),
  FOREIGN KEY (tenant_id, memory_id)
    REFERENCES aios_personal_memory.personal_memory(
      tenant_id,
      memory_id
    )
    ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, principal_id)
    REFERENCES aios_personal_memory.personal_profile(
      tenant_id,
      principal_id
    )
    ON DELETE RESTRICT
);

CREATE TABLE aios_personal_memory.command_receipt (
  tenant_id text NOT NULL,
  tenant_kind text NOT NULL CHECK (tenant_kind = 'SYNTHETIC'),
  principal_id text NOT NULL,
  idempotency_key text NOT NULL
    CHECK (char_length(btrim(idempotency_key)) BETWEEN 1 AND 128),
  request_hash text NOT NULL
    CHECK (request_hash ~ '^sha256:[a-f0-9]{64}$'),
  operation text NOT NULL
    CHECK (operation ~ '^[A-Z][A-Z0-9_]{0,63}$'),
  result jsonb NOT NULL CHECK (jsonb_typeof(result) = 'object'),
  created_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, principal_id, idempotency_key),
  FOREIGN KEY (tenant_id, principal_id)
    REFERENCES aios_personal_memory.personal_profile(
      tenant_id,
      principal_id
    )
    ON DELETE RESTRICT
);

CREATE FUNCTION aios_personal_memory.reject_append_only_change()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION '% is append-only', TG_TABLE_NAME
    USING ERRCODE = '23514';
END
$$;

CREATE FUNCTION aios_personal_memory.reject_row_delete()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION '% rows cannot be deleted', TG_TABLE_NAME
    USING ERRCODE = '23514';
END
$$;

CREATE FUNCTION aios_personal_memory.enforce_profile_update()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF
    NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
    OR NEW.tenant_kind IS DISTINCT FROM OLD.tenant_kind
    OR NEW.principal_id IS DISTINCT FROM OLD.principal_id
    OR NEW.principal_kind IS DISTINCT FROM OLD.principal_kind
    OR NEW.created_at IS DISTINCT FROM OLD.created_at
    OR NEW.version <> OLD.version + 1
    OR NEW.updated_at < OLD.updated_at
    OR NEW.state = OLD.state
  THEN
    RAISE EXCEPTION 'invalid profile update'
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END
$$;

CREATE FUNCTION aios_personal_memory.enforce_memory_update()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF
    NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
    OR NEW.tenant_kind IS DISTINCT FROM OLD.tenant_kind
    OR NEW.memory_id IS DISTINCT FROM OLD.memory_id
    OR NEW.principal_id IS DISTINCT FROM OLD.principal_id
    OR NEW.category IS DISTINCT FROM OLD.category
    OR NEW.content_sha256 IS DISTINCT FROM OLD.content_sha256
    OR NEW.source_ref IS DISTINCT FROM OLD.source_ref
    OR NEW.expires_at IS DISTINCT FROM OLD.expires_at
    OR NEW.created_at IS DISTINCT FROM OLD.created_at
    OR NEW.version <> OLD.version + 1
    OR NEW.updated_at < OLD.updated_at
    OR NOT (
      (OLD.state = 'CANDIDATE' AND NEW.state IN (
        'CONFIRMED', 'EXPIRED', 'DELETED'
      ))
      OR (OLD.state = 'CONFIRMED' AND NEW.state IN ('EXPIRED', 'DELETED'))
      OR (OLD.state = 'EXPIRED' AND NEW.state = 'DELETED')
    )
  THEN
    RAISE EXCEPTION 'invalid personal memory update'
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END
$$;

CREATE FUNCTION aios_personal_memory.enforce_checkpoint_update()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF
    NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
    OR NEW.tenant_kind IS DISTINCT FROM OLD.tenant_kind
    OR NEW.checkpoint_id IS DISTINCT FROM OLD.checkpoint_id
    OR NEW.principal_id IS DISTINCT FROM OLD.principal_id
    OR NEW.created_at IS DISTINCT FROM OLD.created_at
    OR NEW.version <> OLD.version + 1
    OR NEW.updated_at < OLD.updated_at
  THEN
    RAISE EXCEPTION 'invalid checkpoint update'
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END
$$;

CREATE TRIGGER personal_profile_update_guard
BEFORE UPDATE ON aios_personal_memory.personal_profile
FOR EACH ROW
EXECUTE FUNCTION aios_personal_memory.enforce_profile_update();

CREATE TRIGGER personal_profile_no_delete
BEFORE DELETE ON aios_personal_memory.personal_profile
FOR EACH ROW
EXECUTE FUNCTION aios_personal_memory.reject_row_delete();

CREATE TRIGGER personal_memory_update_guard
BEFORE UPDATE ON aios_personal_memory.personal_memory
FOR EACH ROW
EXECUTE FUNCTION aios_personal_memory.enforce_memory_update();

CREATE TRIGGER personal_memory_no_delete
BEFORE DELETE ON aios_personal_memory.personal_memory
FOR EACH ROW
EXECUTE FUNCTION aios_personal_memory.reject_row_delete();

CREATE TRIGGER conversation_checkpoint_update_guard
BEFORE UPDATE ON aios_personal_memory.conversation_checkpoint
FOR EACH ROW
EXECUTE FUNCTION aios_personal_memory.enforce_checkpoint_update();

CREATE TRIGGER conversation_checkpoint_no_delete
BEFORE DELETE ON aios_personal_memory.conversation_checkpoint
FOR EACH ROW
EXECUTE FUNCTION aios_personal_memory.reject_row_delete();

CREATE TRIGGER memory_event_no_change
BEFORE UPDATE OR DELETE ON aios_personal_memory.memory_event
FOR EACH ROW
EXECUTE FUNCTION aios_personal_memory.reject_append_only_change();

CREATE TRIGGER command_receipt_no_change
BEFORE UPDATE OR DELETE ON aios_personal_memory.command_receipt
FOR EACH ROW
EXECUTE FUNCTION aios_personal_memory.reject_append_only_change();

ALTER TABLE aios_personal_memory.personal_profile
  ENABLE ROW LEVEL SECURITY;
ALTER TABLE aios_personal_memory.personal_profile
  FORCE ROW LEVEL SECURITY;
ALTER TABLE aios_personal_memory.personal_memory
  ENABLE ROW LEVEL SECURITY;
ALTER TABLE aios_personal_memory.personal_memory
  FORCE ROW LEVEL SECURITY;
ALTER TABLE aios_personal_memory.conversation_checkpoint
  ENABLE ROW LEVEL SECURITY;
ALTER TABLE aios_personal_memory.conversation_checkpoint
  FORCE ROW LEVEL SECURITY;
ALTER TABLE aios_personal_memory.memory_event
  ENABLE ROW LEVEL SECURITY;
ALTER TABLE aios_personal_memory.memory_event
  FORCE ROW LEVEL SECURITY;
ALTER TABLE aios_personal_memory.command_receipt
  ENABLE ROW LEVEL SECURITY;
ALTER TABLE aios_personal_memory.command_receipt
  FORCE ROW LEVEL SECURITY;

CREATE FUNCTION aios_personal_memory.materialize_due_expiry(
  scope_tenant_id text,
  target_memory_id text,
  target_expected_version bigint,
  command_idempotency_key text,
  command_correlation_id text,
  generated_event_id text,
  command_request_hash text,
  worker_actor_principal_id text,
  worker_actor_lifecycle_version bigint,
  worker_actor_security_epoch bigint,
  authorization_evidence jsonb
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, aios_core, aios_data, aios_personal_memory
AS $$
DECLARE
  effective_now timestamptz := clock_timestamp();
  memory_row aios_personal_memory.personal_memory%ROWTYPE;
  prior_receipt aios_personal_memory.command_receipt%ROWTYPE;
  previous_state text;
  result jsonb;
BEGIN
  IF
    scope_tenant_id IS NULL
    OR scope_tenant_id !~
      '^stn_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    OR target_memory_id IS NULL
    OR target_memory_id !~
      '^mem_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    OR target_expected_version NOT BETWEEN 1 AND 9007199254740991
    OR command_idempotency_key IS NULL
    OR char_length(btrim(command_idempotency_key)) NOT BETWEEN 1 AND 128
    OR command_correlation_id IS NULL
    OR char_length(btrim(command_correlation_id)) NOT BETWEEN 1 AND 128
    OR generated_event_id IS NULL
    OR generated_event_id !~
      '^mev_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    OR command_request_hash IS NULL
    OR command_request_hash !~ '^sha256:[a-f0-9]{64}$'
  THEN
    RAISE EXCEPTION 'invalid C09 retention command'
      USING ERRCODE = '22023';
  END IF;

  IF NOT aios_data.runtime_scope_allows(
    scope_tenant_id,
    'SYNTHETIC'
  ) THEN
    RAISE EXCEPTION 'C09 retention Tenant scope is invalid'
      USING ERRCODE = '42501',
            CONSTRAINT = 'c09_retention_scope_guard';
  END IF;

  IF
    authorization_evidence IS NULL
    OR jsonb_typeof(authorization_evidence) <> 'object'
    OR NOT authorization_evidence ?& ARRAY[
      'tenantId',
      'operation',
      'actorPrincipalId',
      'resourceId',
      'expectedVersion',
      'decisionId',
      'evidenceRef',
      'policyVersion'
    ]
    OR authorization_evidence - ARRAY[
      'tenantId',
      'operation',
      'actorPrincipalId',
      'resourceId',
      'expectedVersion',
      'decisionId',
      'evidenceRef',
      'policyVersion'
    ] <> '{}'::jsonb
    OR authorization_evidence->>'tenantId' <> scope_tenant_id
    OR authorization_evidence->>'operation'
      <> 'C09_RETENTION_MATERIALIZE_EXPIRY'
    OR authorization_evidence->>'actorPrincipalId'
      <> worker_actor_principal_id
    OR authorization_evidence->>'resourceId' <> target_memory_id
    OR jsonb_typeof(authorization_evidence->'expectedVersion')
      <> 'number'
    OR authorization_evidence->>'expectedVersion' !~ '^[1-9][0-9]*$'
    OR (authorization_evidence->>'expectedVersion')::numeric
      <> target_expected_version
    OR char_length(btrim(authorization_evidence->>'decisionId'))
      NOT BETWEEN 1 AND 128
    OR authorization_evidence->>'evidenceRef'
      !~ '^(evidence|fixture|policy|profile|synthetic|test)://'
    OR char_length(btrim(authorization_evidence->>'policyVersion'))
      NOT BETWEEN 1 AND 128
  THEN
    RAISE EXCEPTION 'C09 retention authorization is invalid'
      USING ERRCODE = '42501',
            CONSTRAINT = 'c09_retention_authorization_guard';
  END IF;

  IF NOT EXISTS (
    SELECT 1
      FROM aios_core.principal_registry AS actor
     WHERE actor.tenant_id = scope_tenant_id
       AND actor.tenant_kind = 'SYNTHETIC'
       AND actor.principal_id = worker_actor_principal_id
       AND actor.principal_kind = 'SERVICE'
       AND actor.state = 'ACTIVE'
       AND actor.lifecycle_version = worker_actor_lifecycle_version
       AND actor.security_epoch = worker_actor_security_epoch
  ) THEN
    RAISE EXCEPTION 'C09 retention actor is invalid'
      USING ERRCODE = '42501',
            CONSTRAINT = 'c09_retention_actor_guard';
  END IF;

  PERFORM pg_advisory_xact_lock(
    hashtextextended(
      scope_tenant_id || chr(31) || target_memory_id,
      0
    )
  );

  SELECT *
    INTO memory_row
    FROM aios_personal_memory.personal_memory
   WHERE tenant_id = scope_tenant_id
     AND memory_id = target_memory_id
   FOR UPDATE;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'C09 retention memory was not found'
      USING ERRCODE = '23514',
            CONSTRAINT = 'c09_retention_memory_guard';
  END IF;

  SELECT *
    INTO prior_receipt
    FROM aios_personal_memory.command_receipt
   WHERE tenant_id = scope_tenant_id
     AND principal_id = memory_row.principal_id
     AND idempotency_key = command_idempotency_key;

  IF FOUND THEN
    IF
      prior_receipt.request_hash <> command_request_hash
      OR prior_receipt.operation <> 'MATERIALIZE_EXPIRY'
    THEN
      RAISE EXCEPTION 'C09 retention idempotency conflict'
        USING ERRCODE = '23514',
              CONSTRAINT = 'c09_retention_idempotency_guard';
    END IF;
    RETURN prior_receipt.result;
  END IF;

  IF memory_row.version <> target_expected_version THEN
    RAISE EXCEPTION 'C09 retention version is stale'
      USING ERRCODE = '23514',
            CONSTRAINT = 'c09_retention_version_guard';
  END IF;

  IF
    memory_row.state NOT IN ('CANDIDATE','CONFIRMED')
    OR memory_row.expires_at > effective_now
  THEN
    RAISE EXCEPTION 'C09 memory is not due for expiration'
      USING ERRCODE = '23514',
            CONSTRAINT = 'c09_retention_not_due_guard';
  END IF;

  previous_state := memory_row.state;

  UPDATE aios_personal_memory.personal_memory
     SET state = 'EXPIRED',
         content = NULL,
         version = version + 1,
         terminal_reason = 'RETENTION_EXPIRED',
         updated_at = effective_now
   WHERE tenant_id = scope_tenant_id
     AND memory_id = target_memory_id
     AND version = target_expected_version
  RETURNING *
    INTO memory_row;

  UPDATE aios_personal_memory.conversation_checkpoint
     SET memory_ids = array_remove(memory_ids, target_memory_id),
         version = version + 1,
         updated_at = effective_now
   WHERE tenant_id = scope_tenant_id
     AND principal_id = memory_row.principal_id
     AND target_memory_id = ANY(memory_ids);

  INSERT INTO aios_personal_memory.memory_event (
    tenant_id,
    tenant_kind,
    event_id,
    memory_id,
    principal_id,
    event_type,
    from_state,
    to_state,
    content_sha256,
    actor_principal_id,
    authorization_evidence,
    human_consent_evidence,
    correlation_id,
    created_at
  ) VALUES (
    scope_tenant_id,
    'SYNTHETIC',
    generated_event_id,
    target_memory_id,
    memory_row.principal_id,
    'MEMORY_EXPIRED',
    previous_state,
    'EXPIRED',
    memory_row.content_sha256,
    worker_actor_principal_id,
    authorization_evidence,
    NULL,
    command_correlation_id,
    effective_now
  );

  result := jsonb_build_object(
    'memoryId',
    target_memory_id,
    'state',
    'EXPIRED',
    'version',
    memory_row.version
  );

  INSERT INTO aios_personal_memory.command_receipt (
    tenant_id,
    tenant_kind,
    principal_id,
    idempotency_key,
    request_hash,
    operation,
    result,
    created_at
  ) VALUES (
    scope_tenant_id,
    'SYNTHETIC',
    memory_row.principal_id,
    command_idempotency_key,
    command_request_hash,
    'MATERIALIZE_EXPIRY',
    result,
    effective_now
  );

  RETURN result;
END
$$;

COMMIT;
