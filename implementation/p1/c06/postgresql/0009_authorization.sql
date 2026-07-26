BEGIN;

-- This migration runs after C05 0008_principal_runtime_roles.sql.
-- C06 stores Synthetic Policy Release metadata and authorization evidence.
-- OpenFGA tuples remain in the immutable projected Policy Release.

CREATE TABLE aios_core.authorization_policy_release (
  policy_release_id text PRIMARY KEY
    CHECK (
      policy_release_id ~ '^azr_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
  tenant_id text NOT NULL,
  tenant_kind text NOT NULL CHECK (tenant_kind = 'SYNTHETIC'),
  tenant_lifecycle_version bigint NOT NULL
    CHECK (
      tenant_lifecycle_version > 0
      AND tenant_lifecycle_version <= 9007199254740991
    ),
  fixture_id text NOT NULL
    CHECK (char_length(btrim(fixture_id)) BETWEEN 1 AND 128),
  template_ref text NOT NULL
    CHECK (
      char_length(btrim(template_ref)) BETWEEN 1 AND 512
      AND template_ref
        ~ '^(evidence|fixture|policy|profile|synthetic|test)://'
    ),
  template_sequence bigint NOT NULL
    CHECK (
      template_sequence > 0
      AND template_sequence <= 9007199254740991
    ),
  bundle_sha256 text NOT NULL
    CHECK (bundle_sha256 ~ '^sha256:[0-9a-f]{64}$'),
  model_sha256 text NOT NULL
    CHECK (model_sha256 ~ '^sha256:[0-9a-f]{64}$'),
  operation_catalog_version text NOT NULL
    CHECK (
      char_length(btrim(operation_catalog_version)) BETWEEN 1 AND 128
    ),
  fixture_version text NOT NULL
    CHECK (char_length(btrim(fixture_version)) BETWEEN 1 AND 128),
  state text NOT NULL CHECK (state IN ('STAGED', 'READY', 'FAILED')),
  projection_operation_id text
    CHECK (
      projection_operation_id IS NULL
      OR char_length(btrim(projection_operation_id)) BETWEEN 1 AND 128
    ),
  projection_reason_ref text
    CHECK (
      projection_reason_ref IS NULL
      OR (
        char_length(btrim(projection_reason_ref)) BETWEEN 1 AND 512
        AND projection_reason_ref
          ~ '^(evidence|fixture|policy|profile|synthetic|test)://'
      )
    ),
  openfga_store_id text
    CHECK (
      openfga_store_id IS NULL
      OR openfga_store_id ~ '^[ABCDEFGHJKMNPQRSTVWXYZ0-9]{26}$'
    ),
  authorization_model_id text
    CHECK (
      authorization_model_id IS NULL
      OR authorization_model_id ~ '^[ABCDEFGHJKMNPQRSTVWXYZ0-9]{26}$'
    ),
  tuple_bundle_sha256 text
    CHECK (
      tuple_bundle_sha256 IS NULL
      OR tuple_bundle_sha256 ~ '^sha256:[0-9a-f]{64}$'
    ),
  fixture_report_ref text
    CHECK (
      fixture_report_ref IS NULL
      OR (
        char_length(btrim(fixture_report_ref)) BETWEEN 1 AND 512
        AND fixture_report_ref
          ~ '^(evidence|fixture|policy|profile|synthetic|test)://'
      )
    ),
  fixture_report_sha256 text
    CHECK (
      fixture_report_sha256 IS NULL
      OR fixture_report_sha256 ~ '^sha256:[0-9a-f]{64}$'
    ),
  fixture_pass_count integer CHECK (fixture_pass_count > 0),
  fixture_fail_count integer CHECK (fixture_fail_count >= 0),
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  CONSTRAINT authorization_policy_release_tenant_key
    UNIQUE (policy_release_id, tenant_id),
  CONSTRAINT authorization_policy_release_identity_key
    UNIQUE (
      policy_release_id,
      tenant_id,
      tenant_kind,
      template_sequence
    ),
  CONSTRAINT authorization_policy_release_tenant_fkey
    FOREIGN KEY (tenant_id, tenant_kind)
    REFERENCES aios_core.tenant_registry(tenant_id, tenant_kind)
    ON DELETE RESTRICT,
  CHECK (updated_at >= created_at),
  CONSTRAINT authorization_policy_release_state_shape
    CHECK (
      (
        state = 'STAGED'
        AND projection_operation_id IS NULL
        AND projection_reason_ref IS NULL
        AND openfga_store_id IS NULL
        AND authorization_model_id IS NULL
        AND tuple_bundle_sha256 IS NULL
        AND fixture_report_ref IS NULL
        AND fixture_report_sha256 IS NULL
        AND fixture_pass_count IS NULL
        AND fixture_fail_count IS NULL
      )
      OR (
        state = 'READY'
        AND projection_operation_id IS NOT NULL
        AND projection_reason_ref IS NULL
        AND openfga_store_id IS NOT NULL
        AND authorization_model_id IS NOT NULL
        AND tuple_bundle_sha256 IS NOT NULL
        AND fixture_report_ref IS NOT NULL
        AND fixture_report_sha256 IS NOT NULL
        AND fixture_pass_count IS NOT NULL
        AND fixture_fail_count = 0
      )
      OR (
        state = 'FAILED'
        AND projection_operation_id IS NOT NULL
        AND projection_reason_ref IS NOT NULL
        AND openfga_store_id IS NULL
        AND authorization_model_id IS NULL
        AND tuple_bundle_sha256 IS NULL
        AND fixture_report_ref IS NULL
        AND fixture_report_sha256 IS NULL
        AND fixture_pass_count IS NULL
        AND fixture_fail_count IS NULL
      )
    )
);

CREATE TABLE aios_core.authorization_activation (
  activation_id text PRIMARY KEY
    CHECK (
      activation_id ~ '^aza_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
  tenant_id text NOT NULL,
  tenant_kind text NOT NULL CHECK (tenant_kind = 'SYNTHETIC'),
  policy_release_id text NOT NULL,
  previous_policy_release_id text,
  template_sequence bigint NOT NULL
    CHECK (
      template_sequence > 0
      AND template_sequence <= 9007199254740991
    ),
  activation_version bigint NOT NULL
    CHECK (
      activation_version > 0
      AND activation_version <= 9007199254740991
    ),
  activation_kind text NOT NULL
    CHECK (activation_kind IN ('ACTIVATE', 'ROLLBACK')),
  reason_ref text NOT NULL
    CHECK (
      char_length(btrim(reason_ref)) BETWEEN 1 AND 512
      AND reason_ref
        ~ '^(evidence|fixture|policy|profile|synthetic|test)://'
    ),
  activated_at timestamptz NOT NULL,
  CONSTRAINT authorization_activation_tenant_version_key
    UNIQUE (tenant_id, activation_version),
  CONSTRAINT authorization_activation_identity_key
    UNIQUE (
      activation_id,
      tenant_id,
      policy_release_id,
      activation_version
    ),
  CONSTRAINT authorization_activation_release_version_key
    UNIQUE (tenant_id, policy_release_id, activation_version),
  CONSTRAINT authorization_activation_release_fkey
    FOREIGN KEY (
      policy_release_id,
      tenant_id,
      tenant_kind,
      template_sequence
    )
    REFERENCES aios_core.authorization_policy_release(
      policy_release_id,
      tenant_id,
      tenant_kind,
      template_sequence
    )
    ON DELETE RESTRICT,
  CONSTRAINT authorization_activation_previous_release_fkey
    FOREIGN KEY (previous_policy_release_id, tenant_id)
    REFERENCES aios_core.authorization_policy_release(
      policy_release_id,
      tenant_id
    )
    ON DELETE RESTRICT,
  CHECK (
    (activation_version = 1 AND previous_policy_release_id IS NULL)
    OR (
      activation_version > 1
      AND previous_policy_release_id IS NOT NULL
      AND previous_policy_release_id <> policy_release_id
    )
  )
);

CREATE TABLE aios_core.authorization_active_policy (
  tenant_id text PRIMARY KEY,
  tenant_kind text NOT NULL CHECK (tenant_kind = 'SYNTHETIC'),
  policy_release_id text NOT NULL,
  activation_id text NOT NULL,
  activation_version bigint NOT NULL
    CHECK (
      activation_version > 0
      AND activation_version <= 9007199254740991
    ),
  updated_at timestamptz NOT NULL,
  CONSTRAINT authorization_active_policy_tenant_fkey
    FOREIGN KEY (tenant_id, tenant_kind)
    REFERENCES aios_core.tenant_registry(tenant_id, tenant_kind)
    ON DELETE RESTRICT,
  CONSTRAINT authorization_active_policy_activation_fkey
    FOREIGN KEY (
      activation_id,
      tenant_id,
      policy_release_id,
      activation_version
    )
    REFERENCES aios_core.authorization_activation(
      activation_id,
      tenant_id,
      policy_release_id,
      activation_version
    )
    ON DELETE RESTRICT
);

-- A Decision pins the Policy Bundle directly. Its distinct Tenant-projected
-- Tuple Bundle is recovered through the immutable Policy Release foreign key.
CREATE TABLE aios_core.authorization_decision (
  decision_id text PRIMARY KEY
    CHECK (
      decision_id ~ '^azd_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
  tenant_id text NOT NULL,
  tenant_kind text NOT NULL CHECK (tenant_kind = 'SYNTHETIC'),
  correlation_id text NOT NULL
    CHECK (char_length(btrim(correlation_id)) BETWEEN 1 AND 128),
  surface text NOT NULL
    CHECK (
      surface IN (
        'READ',
        'RETRIEVE',
        'DOWNLOAD',
        'MANAGE',
        'TOOL_CALL',
        'SANDBOX_RUN'
      )
    ),
  resource_type text NOT NULL
    CHECK (resource_type ~ '^[a-z][a-z0-9_]{0,63}$'),
  resource_id text NOT NULL
    CHECK (
      char_length(resource_id) BETWEEN 1 AND 128
      AND resource_id ~ '^[A-Za-z0-9._-]+$'
    ),
  resource_authorization_version bigint NOT NULL
    CHECK (
      resource_authorization_version > 0
      AND resource_authorization_version <= 9007199254740991
    ),
  human_principal_id text NOT NULL
    CHECK (
      human_principal_id ~ '^prn_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
  human_security_epoch bigint NOT NULL
    CHECK (
      human_security_epoch > 0
      AND human_security_epoch <= 9007199254740991
    ),
  workload_actor_principal_id text NOT NULL
    CHECK (
      workload_actor_principal_id ~ '^prn_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
  workload_actor_security_epoch bigint NOT NULL
    CHECK (
      workload_actor_security_epoch > 0
      AND workload_actor_security_epoch <= 9007199254740991
    ),
  leaf_delegation_id text NOT NULL
    CHECK (
      leaf_delegation_id ~ '^dlg_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
  delegation_chain_sha256 text NOT NULL
    CHECK (delegation_chain_sha256 ~ '^sha256:[0-9a-f]{64}$'),
  purpose_ref text NOT NULL
    CHECK (
      char_length(btrim(purpose_ref)) BETWEEN 1 AND 512
      AND purpose_ref
        ~ '^(evidence|fixture|policy|profile|synthetic|test)://'
    ),
  policy_release_id text NOT NULL,
  bundle_sha256 text NOT NULL
    CHECK (bundle_sha256 ~ '^sha256:[0-9a-f]{64}$'),
  openfga_store_id text NOT NULL
    CHECK (openfga_store_id ~ '^[ABCDEFGHJKMNPQRSTVWXYZ0-9]{26}$'),
  authorization_model_id text NOT NULL
    CHECK (
      authorization_model_id ~ '^[ABCDEFGHJKMNPQRSTVWXYZ0-9]{26}$'
    ),
  activation_version bigint NOT NULL
    CHECK (
      activation_version > 0
      AND activation_version <= 9007199254740991
    ),
  consistency text NOT NULL CHECK (consistency = 'HIGHER_CONSISTENCY'),
  effect text NOT NULL CHECK (effect IN ('ALLOW', 'DENY')),
  authorization_status text NOT NULL
    CHECK (authorization_status IN ('ALLOWED', 'DENIED')),
  reason_code text NOT NULL
    CHECK (
      char_length(btrim(reason_code)) BETWEEN 1 AND 128
      AND reason_code ~ '^[A-Z][A-Z0-9_]*$'
    ),
  input_sha256 text NOT NULL
    CHECK (input_sha256 ~ '^sha256:[0-9a-f]{64}$'),
  check_tuples jsonb NOT NULL
    CHECK (jsonb_typeof(check_tuples) = 'object'),
  check_results jsonb NOT NULL
    CHECK (jsonb_typeof(check_results) = 'object'),
  check_result_sha256 text NOT NULL
    CHECK (check_result_sha256 ~ '^sha256:[0-9a-f]{64}$'),
  evaluated_at timestamptz NOT NULL,
  evidence_ref text NOT NULL
    CHECK (
      char_length(btrim(evidence_ref)) BETWEEN 1 AND 512
      AND evidence_ref ~ '^evidence://'
    ),
  CONSTRAINT authorization_decision_release_fkey
    FOREIGN KEY (policy_release_id, tenant_id)
    REFERENCES aios_core.authorization_policy_release(
      policy_release_id,
      tenant_id
    )
    ON DELETE RESTRICT,
  CONSTRAINT authorization_decision_activation_fkey
    FOREIGN KEY (
      tenant_id,
      policy_release_id,
      activation_version
    )
    REFERENCES aios_core.authorization_activation(
      tenant_id,
      policy_release_id,
      activation_version
    )
    ON DELETE RESTRICT,
  CHECK (
    (effect = 'ALLOW' AND authorization_status = 'ALLOWED')
    OR (effect = 'DENY' AND authorization_status = 'DENIED')
  )
);

CREATE TABLE aios_core.authorization_command_receipt (
  tenant_id text NOT NULL,
  tenant_kind text NOT NULL CHECK (tenant_kind = 'SYNTHETIC'),
  idempotency_key text NOT NULL
    CHECK (char_length(btrim(idempotency_key)) BETWEEN 1 AND 128),
  command_hash text NOT NULL
    CHECK (command_hash ~ '^sha256:[0-9a-f]{64}$'),
  result jsonb NOT NULL CHECK (jsonb_typeof(result) = 'object'),
  created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
  PRIMARY KEY (tenant_id, idempotency_key),
  FOREIGN KEY (tenant_id, tenant_kind)
    REFERENCES aios_core.tenant_registry(tenant_id, tenant_kind)
    ON DELETE RESTRICT
);

CREATE TABLE aios_core.authorization_event (
  event_id text PRIMARY KEY
    CHECK (
      event_id ~ '^evt_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
  tenant_id text NOT NULL,
  tenant_kind text NOT NULL CHECK (tenant_kind = 'SYNTHETIC'),
  event jsonb NOT NULL,
  created_at timestamptz NOT NULL,
  FOREIGN KEY (tenant_id, tenant_kind)
    REFERENCES aios_core.tenant_registry(tenant_id, tenant_kind)
    ON DELETE RESTRICT,
  CHECK ((event ->> 'specversion') IS NOT DISTINCT FROM '1.0'),
  CHECK ((event ->> 'id') IS NOT DISTINCT FROM event_id),
  CHECK ((event #>> '{data,tenant_id}') IS NOT DISTINCT FROM tenant_id),
  CHECK ((event ->> 'tenantkind') IS NOT DISTINCT FROM tenant_kind),
  CHECK (
    jsonb_typeof(event -> 'synthetic') IS NOT DISTINCT FROM 'boolean'
    AND (event ->> 'synthetic') IS NOT DISTINCT FROM 'true'
  ),
  CHECK (jsonb_typeof(event -> 'data') IS NOT DISTINCT FROM 'object'),
  CHECK (
    (event ->> 'type') LIKE 'product.authorization.%.v1'
  ),
  CHECK (
    event - ARRAY[
      'specversion', 'id', 'source', 'type', 'subject', 'time',
      'datacontenttype', 'dataschema', 'tenantkind',
      'correlationid', 'synthetic', 'data'
    ] = '{}'::jsonb
  )
);

CREATE TABLE aios_core.authorization_outbox (
  event_id text PRIMARY KEY
    REFERENCES aios_core.authorization_event(event_id)
    ON DELETE RESTRICT,
  tenant_id text NOT NULL,
  tenant_kind text NOT NULL CHECK (tenant_kind = 'SYNTHETIC'),
  event jsonb NOT NULL,
  status text NOT NULL DEFAULT 'PENDING',
  attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
  lease_version bigint NOT NULL DEFAULT 0 CHECK (lease_version >= 0),
  available_at timestamptz NOT NULL DEFAULT statement_timestamp(),
  leased_by text,
  lease_until timestamptz,
  last_error_code text,
  created_at timestamptz NOT NULL,
  published_at timestamptz,
  FOREIGN KEY (tenant_id, tenant_kind)
    REFERENCES aios_core.tenant_registry(tenant_id, tenant_kind)
    ON DELETE RESTRICT,
  CONSTRAINT authorization_outbox_worker_id_shape
    CHECK (
      leased_by IS NULL
      OR char_length(btrim(leased_by)) BETWEEN 1 AND 128
    ),
  CONSTRAINT authorization_outbox_error_code_shape
    CHECK (
      last_error_code IS NULL
      OR char_length(btrim(last_error_code)) BETWEEN 1 AND 128
    ),
  CONSTRAINT authorization_outbox_attempt_lease_match
    CHECK (attempt_count::bigint = lease_version),
  CONSTRAINT authorization_outbox_delivery_shape
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
  CHECK (status IN ('PENDING', 'PROCESSING', 'PUBLISHED', 'FAILED')),
  CHECK ((event ->> 'specversion') IS NOT DISTINCT FROM '1.0'),
  CHECK ((event ->> 'id') IS NOT DISTINCT FROM event_id),
  CHECK ((event #>> '{data,tenant_id}') IS NOT DISTINCT FROM tenant_id),
  CHECK ((event ->> 'tenantkind') IS NOT DISTINCT FROM tenant_kind),
  CHECK (
    jsonb_typeof(event -> 'synthetic') IS NOT DISTINCT FROM 'boolean'
    AND (event ->> 'synthetic') IS NOT DISTINCT FROM 'true'
  ),
  CHECK (jsonb_typeof(event -> 'data') IS NOT DISTINCT FROM 'object'),
  CHECK (
    (event ->> 'type') LIKE 'product.authorization.%.v1'
  ),
  CHECK (
    event - ARRAY[
      'specversion', 'id', 'source', 'type', 'subject', 'time',
      'datacontenttype', 'dataschema', 'tenantkind',
      'correlationid', 'synthetic', 'data'
    ] = '{}'::jsonb
  )
);

CREATE UNIQUE INDEX authorization_policy_release_tenant_template_key
  ON aios_core.authorization_policy_release(tenant_id, template_ref)
  WHERE state <> 'FAILED';

CREATE UNIQUE INDEX authorization_policy_release_tenant_sequence_key
  ON aios_core.authorization_policy_release(tenant_id, template_sequence)
  WHERE state <> 'FAILED';

CREATE INDEX authorization_policy_release_tenant_idx
  ON aios_core.authorization_policy_release(
    tenant_id,
    template_sequence,
    policy_release_id
  );

CREATE INDEX authorization_activation_tenant_idx
  ON aios_core.authorization_activation(
    tenant_id,
    activation_version,
    activation_id
  );

CREATE INDEX authorization_decision_tenant_idx
  ON aios_core.authorization_decision(
    tenant_id,
    evaluated_at,
    decision_id
  );

CREATE INDEX authorization_event_tenant_idx
  ON aios_core.authorization_event(tenant_id, created_at, event_id);

CREATE UNIQUE INDEX authorization_decision_event_subject_key
  ON aios_core.authorization_event((event ->> 'subject'))
  WHERE
    (event ->> 'type') = 'product.authorization.decision-recorded.v1';

CREATE INDEX authorization_outbox_claim_idx
  ON aios_core.authorization_outbox(
    status,
    available_at,
    lease_until,
    created_at,
    event_id
  );

CREATE FUNCTION aios_core.reject_authorization_tombstone_delete()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION 'authorization records are permanent tombstones'
    USING ERRCODE = '23000',
          CONSTRAINT = 'authorization_tombstone_no_delete';
  RETURN OLD;
END;
$$;

CREATE FUNCTION aios_core.reject_authorization_append_only_change()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION 'authorization record is append-only'
    USING ERRCODE = '23000',
          CONSTRAINT = 'authorization_append_only_guard';
  RETURN OLD;
END;
$$;

CREATE FUNCTION aios_core.enforce_authorization_release_insert()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  tenant_state text;
  tenant_version bigint;
  invalid_replacement boolean;
BEGIN
  IF NEW.state <> 'STAGED'
    OR NEW.created_at IS DISTINCT FROM NEW.updated_at
  THEN
    RAISE EXCEPTION 'Policy Release must start staged'
      USING ERRCODE = '23000',
            CONSTRAINT = 'authorization_release_initial_state_guard';
  END IF;

  SELECT state, lifecycle_version
    INTO tenant_state, tenant_version
    FROM aios_core.tenant_registry
   WHERE tenant_id = NEW.tenant_id
     AND tenant_kind = NEW.tenant_kind
   FOR SHARE;

  IF NOT FOUND
    OR tenant_state <> 'ACTIVE'
    OR tenant_version <> NEW.tenant_lifecycle_version
  THEN
    RAISE EXCEPTION 'Policy Release requires the current active Tenant'
      USING ERRCODE = '23000',
            CONSTRAINT = 'authorization_tenant_active_guard';
  END IF;

  SELECT EXISTS (
    SELECT 1
      FROM aios_core.authorization_policy_release AS previous
     WHERE previous.tenant_id = NEW.tenant_id
       AND (
         previous.template_ref = NEW.template_ref
         OR previous.template_sequence = NEW.template_sequence
       )
       AND (
         previous.state <> 'FAILED'
         OR previous.template_ref IS DISTINCT FROM NEW.template_ref
         OR previous.template_sequence IS DISTINCT FROM NEW.template_sequence
         OR previous.tenant_kind IS DISTINCT FROM NEW.tenant_kind
         OR previous.fixture_id IS DISTINCT FROM NEW.fixture_id
         OR previous.bundle_sha256 IS DISTINCT FROM NEW.bundle_sha256
         OR previous.model_sha256 IS DISTINCT FROM NEW.model_sha256
         OR previous.operation_catalog_version IS DISTINCT FROM
           NEW.operation_catalog_version
         OR previous.fixture_version IS DISTINCT FROM NEW.fixture_version
       )
  ) INTO invalid_replacement;

  IF invalid_replacement THEN
    RAISE EXCEPTION 'Policy Release replacement is invalid'
      USING ERRCODE = '23000',
            CONSTRAINT = 'authorization_release_replacement_guard';
  END IF;
  RETURN NEW;
END;
$$;

CREATE FUNCTION aios_core.enforce_authorization_release_update()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  tenant_state text;
  tenant_version bigint;
BEGIN
  IF NEW.policy_release_id IS DISTINCT FROM OLD.policy_release_id
    OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
    OR NEW.tenant_kind IS DISTINCT FROM OLD.tenant_kind
    OR NEW.tenant_lifecycle_version IS DISTINCT FROM
      OLD.tenant_lifecycle_version
    OR NEW.fixture_id IS DISTINCT FROM OLD.fixture_id
    OR NEW.template_ref IS DISTINCT FROM OLD.template_ref
    OR NEW.template_sequence IS DISTINCT FROM OLD.template_sequence
    OR NEW.bundle_sha256 IS DISTINCT FROM OLD.bundle_sha256
    OR NEW.model_sha256 IS DISTINCT FROM OLD.model_sha256
    OR NEW.operation_catalog_version IS DISTINCT FROM
      OLD.operation_catalog_version
    OR NEW.fixture_version IS DISTINCT FROM OLD.fixture_version
    OR NEW.created_at IS DISTINCT FROM OLD.created_at
  THEN
    RAISE EXCEPTION 'Policy Release identity is immutable'
      USING ERRCODE = '23000',
            CONSTRAINT = 'authorization_release_identity_guard';
  END IF;

  SELECT state, lifecycle_version
    INTO tenant_state, tenant_version
    FROM aios_core.tenant_registry
   WHERE tenant_id = NEW.tenant_id
     AND tenant_kind = NEW.tenant_kind
   FOR SHARE;

  IF NOT FOUND
    OR tenant_state <> 'ACTIVE'
    OR tenant_version <> NEW.tenant_lifecycle_version
  THEN
    RAISE EXCEPTION 'Policy projection requires the current active Tenant'
      USING ERRCODE = '23000',
            CONSTRAINT = 'authorization_tenant_active_guard';
  END IF;

  IF OLD.state <> 'STAGED'
    OR NEW.state NOT IN ('READY', 'FAILED')
    OR NEW.updated_at < OLD.updated_at
  THEN
    RAISE EXCEPTION 'Policy Release projection transition is invalid'
      USING ERRCODE = '23000',
            CONSTRAINT = 'authorization_release_transition_guard';
  END IF;
  RETURN NEW;
END;
$$;

CREATE FUNCTION aios_core.enforce_authorization_activation_insert()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  tenant_state text;
  tenant_version bigint;
  release_state text;
  release_sequence bigint;
  release_tenant_version bigint;
  current_release_id text;
  current_activation_version bigint;
  current_sequence bigint;
BEGIN
  SELECT state, lifecycle_version
    INTO tenant_state, tenant_version
    FROM aios_core.tenant_registry
   WHERE tenant_id = NEW.tenant_id
     AND tenant_kind = NEW.tenant_kind
   FOR SHARE;

  IF NOT FOUND OR tenant_state <> 'ACTIVE' THEN
    RAISE EXCEPTION 'Policy activation requires an active Tenant'
      USING ERRCODE = '23000',
            CONSTRAINT = 'authorization_tenant_active_guard';
  END IF;

  SELECT state, template_sequence, tenant_lifecycle_version
    INTO release_state, release_sequence, release_tenant_version
    FROM aios_core.authorization_policy_release
   WHERE policy_release_id = NEW.policy_release_id
     AND tenant_id = NEW.tenant_id
   FOR SHARE;

  IF NOT FOUND
    OR release_state <> 'READY'
    OR release_sequence <> NEW.template_sequence
    OR release_tenant_version <> tenant_version
  THEN
    RAISE EXCEPTION 'Policy activation requires a ready Release'
      USING ERRCODE = '23000',
            CONSTRAINT = 'authorization_activation_release_guard';
  END IF;

  SELECT active.policy_release_id,
         active.activation_version,
         release.template_sequence
    INTO current_release_id, current_activation_version, current_sequence
    FROM aios_core.authorization_active_policy AS active
    JOIN aios_core.authorization_policy_release AS release
      ON release.policy_release_id = active.policy_release_id
     AND release.tenant_id = active.tenant_id
   WHERE active.tenant_id = NEW.tenant_id
   FOR UPDATE OF active;

  IF NOT FOUND THEN
    IF NEW.activation_version <> 1
      OR NEW.previous_policy_release_id IS NOT NULL
      OR NEW.activation_kind <> 'ACTIVATE'
      OR NEW.template_sequence <> 1
    THEN
      RAISE EXCEPTION 'Initial Policy activation is invalid'
        USING ERRCODE = '23000',
              CONSTRAINT = 'authorization_activation_version_guard';
    END IF;
    RETURN NEW;
  END IF;

  IF NEW.activation_version <> current_activation_version + 1
    OR NEW.previous_policy_release_id <> current_release_id
  THEN
    RAISE EXCEPTION 'Policy activation version changed'
      USING ERRCODE = '23000',
            CONSTRAINT = 'authorization_activation_version_guard';
  END IF;

  IF (
      NEW.activation_kind = 'ACTIVATE'
      AND NEW.template_sequence <= current_sequence
    )
    OR (
      NEW.activation_kind = 'ROLLBACK'
      AND NEW.template_sequence >= current_sequence
    )
  THEN
    RAISE EXCEPTION 'Policy activation direction is invalid'
      USING ERRCODE = '23000',
            CONSTRAINT = 'authorization_activation_direction_guard';
  END IF;
  RETURN NEW;
END;
$$;

CREATE FUNCTION aios_core.enforce_authorization_active_policy()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  activation_previous text;
  activation_release text;
  activation_version bigint;
  tenant_state text;
  tenant_version bigint;
  release_tenant_version bigint;
BEGIN
  SELECT state, lifecycle_version
    INTO tenant_state, tenant_version
    FROM aios_core.tenant_registry
   WHERE tenant_id = NEW.tenant_id
     AND tenant_kind = NEW.tenant_kind
   FOR SHARE;

  SELECT previous_policy_release_id,
         activation.policy_release_id,
         activation.activation_version,
         release.tenant_lifecycle_version
    INTO activation_previous,
         activation_release,
         activation_version,
         release_tenant_version
    FROM aios_core.authorization_activation AS activation
    JOIN aios_core.authorization_policy_release AS release
      ON release.policy_release_id = activation.policy_release_id
     AND release.tenant_id = activation.tenant_id
   WHERE activation.activation_id = NEW.activation_id
     AND activation.tenant_id = NEW.tenant_id;

  IF NOT FOUND
    OR activation_release <> NEW.policy_release_id
    OR activation_version <> NEW.activation_version
  THEN
    RAISE EXCEPTION 'Active Policy must reference an exact activation'
      USING ERRCODE = '23000',
            CONSTRAINT = 'authorization_active_activation_guard';
  END IF;

  IF tenant_state <> 'ACTIVE'
    OR tenant_version <> release_tenant_version
  THEN
    RAISE EXCEPTION 'Active Policy requires the current active Tenant'
      USING ERRCODE = '23000',
            CONSTRAINT = 'authorization_tenant_active_guard';
  END IF;

  IF TG_OP = 'INSERT' THEN
    IF NEW.activation_version <> 1
      OR activation_previous IS NOT NULL
    THEN
      RAISE EXCEPTION 'Initial Active Policy is invalid'
        USING ERRCODE = '23000',
              CONSTRAINT = 'authorization_active_version_guard';
    END IF;
    RETURN NEW;
  END IF;

  IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
    OR NEW.tenant_kind IS DISTINCT FROM OLD.tenant_kind
    OR NEW.activation_version <> OLD.activation_version + 1
    OR activation_previous <> OLD.policy_release_id
    OR NEW.updated_at < OLD.updated_at
  THEN
    RAISE EXCEPTION 'Active Policy transition is invalid'
      USING ERRCODE = '23000',
            CONSTRAINT = 'authorization_active_version_guard';
  END IF;
  RETURN NEW;
END;
$$;

CREATE FUNCTION aios_core.enforce_authorization_decision_insert()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  tenant_state text;
  tenant_version bigint;
  active_release_id text;
  active_version bigint;
  release_state text;
  release_bundle text;
  release_store text;
  release_model text;
  release_tenant_version bigint;
BEGIN
  SELECT state, lifecycle_version
    INTO tenant_state, tenant_version
    FROM aios_core.tenant_registry
   WHERE tenant_id = NEW.tenant_id
     AND tenant_kind = NEW.tenant_kind
   FOR SHARE;

  IF NOT FOUND OR tenant_state <> 'ACTIVE' THEN
    RAISE EXCEPTION 'Authorization decision requires an active Tenant'
      USING ERRCODE = '23000',
            CONSTRAINT = 'authorization_tenant_active_guard';
  END IF;

  SELECT policy_release_id, activation_version
    INTO active_release_id, active_version
    FROM aios_core.authorization_active_policy
   WHERE tenant_id = NEW.tenant_id
   FOR SHARE;

  IF NOT FOUND
    OR active_release_id <> NEW.policy_release_id
    OR active_version <> NEW.activation_version
  THEN
    RAISE EXCEPTION 'Active Policy changed during authorization'
      USING ERRCODE = '40001',
            CONSTRAINT = 'authorization_decision_active_policy_guard';
  END IF;

  SELECT
    state,
    bundle_sha256,
    openfga_store_id,
    authorization_model_id,
    tenant_lifecycle_version
    INTO
      release_state,
      release_bundle,
      release_store,
      release_model,
      release_tenant_version
    FROM aios_core.authorization_policy_release
   WHERE policy_release_id = NEW.policy_release_id
     AND tenant_id = NEW.tenant_id
   FOR SHARE;

  IF NOT FOUND
    OR release_state <> 'READY'
    OR release_bundle <> NEW.bundle_sha256
    OR release_store <> NEW.openfga_store_id
    OR release_model <> NEW.authorization_model_id
    OR release_tenant_version <> tenant_version
  THEN
    RAISE EXCEPTION 'Decision Policy Release does not match projection'
      USING ERRCODE = '23000',
            CONSTRAINT = 'authorization_decision_release_guard';
  END IF;
  RETURN NEW;
END;
$$;

CREATE FUNCTION aios_core.enforce_authorization_outbox()
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
      RAISE EXCEPTION 'authorization outbox must start pending'
        USING ERRCODE = '23000',
              CONSTRAINT = 'authorization_outbox_initial_state_guard';
    END IF;
    RETURN NEW;
  END IF;

  IF NEW.event_id IS DISTINCT FROM OLD.event_id
    OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
    OR NEW.tenant_kind IS DISTINCT FROM OLD.tenant_kind
    OR NEW.event IS DISTINCT FROM OLD.event
    OR NEW.created_at IS DISTINCT FROM OLD.created_at
  THEN
    RAISE EXCEPTION 'authorization outbox payload is immutable'
      USING ERRCODE = '23000',
            CONSTRAINT = 'authorization_outbox_payload_guard';
  END IF;

  IF OLD.status = 'PUBLISHED' THEN
    RAISE EXCEPTION 'published authorization outbox event is final'
      USING ERRCODE = '23000',
            CONSTRAINT = 'authorization_outbox_published_guard';
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
      RAISE EXCEPTION 'authorization outbox claim is invalid'
        USING ERRCODE = '23000',
              CONSTRAINT = 'authorization_outbox_claim_guard';
    END IF;
    RETURN NEW;
  END IF;

  IF OLD.status = 'PROCESSING'
    AND NEW.status = 'PROCESSING'
  THEN
    IF OLD.lease_until >= statement_timestamp()
      OR NEW.attempt_count <> OLD.attempt_count + 1
      OR NEW.lease_version <> OLD.lease_version + 1
      OR NEW.available_at IS DISTINCT FROM OLD.available_at
      OR NEW.leased_by IS NULL
      OR NEW.lease_until <= statement_timestamp()
      OR NEW.last_error_code IS NOT NULL
      OR NEW.published_at IS NOT NULL
    THEN
      RAISE EXCEPTION 'authorization outbox reclaim is invalid'
        USING ERRCODE = '23000',
              CONSTRAINT = 'authorization_outbox_reclaim_guard';
    END IF;
    RETURN NEW;
  END IF;

  IF OLD.status = 'PROCESSING'
    AND NEW.status = 'FAILED'
  THEN
    IF OLD.lease_until < statement_timestamp()
      OR NEW.attempt_count <> OLD.attempt_count
      OR NEW.lease_version <> OLD.lease_version
      OR NEW.available_at <= statement_timestamp()
      OR NEW.leased_by IS NOT NULL
      OR NEW.lease_until IS NOT NULL
      OR NEW.last_error_code IS NULL
      OR NEW.published_at IS NOT NULL
    THEN
      RAISE EXCEPTION 'authorization outbox failure receipt is invalid'
        USING ERRCODE = '23000',
              CONSTRAINT = 'authorization_outbox_failure_guard';
    END IF;
    RETURN NEW;
  END IF;

  IF OLD.status = 'PROCESSING'
    AND NEW.status = 'PUBLISHED'
  THEN
    IF OLD.lease_until < statement_timestamp()
      OR NEW.attempt_count <> OLD.attempt_count
      OR NEW.lease_version <> OLD.lease_version
      OR NEW.available_at IS DISTINCT FROM OLD.available_at
      OR NEW.leased_by IS NOT NULL
      OR NEW.lease_until IS NOT NULL
      OR NEW.last_error_code IS NOT NULL
      OR NEW.published_at IS NULL
    THEN
      RAISE EXCEPTION 'authorization outbox completion is invalid'
        USING ERRCODE = '23000',
              CONSTRAINT = 'authorization_outbox_completion_guard';
    END IF;
    RETURN NEW;
  END IF;

  RAISE EXCEPTION 'authorization outbox transition is invalid'
    USING ERRCODE = '23000',
          CONSTRAINT = 'authorization_outbox_transition_guard';
END;
$$;

CREATE FUNCTION aios_core.enforce_authorization_event_outbox_pair()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  paired_event jsonb;
BEGIN
  IF TG_TABLE_NAME = 'authorization_event' THEN
    SELECT event
      INTO paired_event
      FROM aios_core.authorization_outbox
     WHERE event_id = NEW.event_id;
  ELSE
    SELECT event
      INTO paired_event
      FROM aios_core.authorization_event
     WHERE event_id = NEW.event_id;
  END IF;

  IF NOT FOUND OR paired_event IS DISTINCT FROM NEW.event THEN
    RAISE EXCEPTION 'authorization Event and Outbox must be paired'
      USING ERRCODE = '23000',
            CONSTRAINT = 'authorization_event_outbox_pair_guard';
  END IF;
  RETURN NEW;
END;
$$;

CREATE FUNCTION aios_core.enforce_authorization_decision_event_pair()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  paired_value text;
BEGIN
  IF TG_TABLE_NAME = 'authorization_decision' THEN
    SELECT event #>> '{data,input_sha256}'
      INTO paired_value
      FROM aios_core.authorization_event
     WHERE (event ->> 'type') =
       'product.authorization.decision-recorded.v1'
       AND (event ->> 'subject') = NEW.decision_id
       AND (event #>> '{data,decision_id}') = NEW.decision_id
       AND (event #>> '{data,policy_release_id}') =
         NEW.policy_release_id
       AND (event #>> '{data,tuple_bundle_sha256}') = (
         SELECT tuple_bundle_sha256
           FROM aios_core.authorization_policy_release
          WHERE policy_release_id = NEW.policy_release_id
            AND tenant_id = NEW.tenant_id
       )
       AND (event #>> '{data,authorization_model_id}') =
         NEW.authorization_model_id
       AND (event #>> '{data,activation_version}')::bigint =
         NEW.activation_version
       AND (event #>> '{data,effect}') = NEW.effect
       AND (event #>> '{data,reason_code}') = NEW.reason_code;
    IF NOT FOUND OR paired_value <> NEW.input_sha256 THEN
      RAISE EXCEPTION 'authorization Decision requires its exact Event'
        USING ERRCODE = '23000',
              CONSTRAINT = 'authorization_decision_event_pair_guard';
    END IF;
    RETURN NEW;
  END IF;

  IF (NEW.event ->> 'type') <>
    'product.authorization.decision-recorded.v1'
  THEN
    RETURN NEW;
  END IF;

  SELECT decision.decision_id
    INTO paired_value
    FROM aios_core.authorization_decision AS decision
    JOIN aios_core.authorization_policy_release AS release
      ON release.policy_release_id = decision.policy_release_id
     AND release.tenant_id = decision.tenant_id
   WHERE decision.decision_id = (NEW.event ->> 'subject')
     AND decision.tenant_id = NEW.tenant_id
     AND decision.policy_release_id =
       (NEW.event #>> '{data,policy_release_id}')
     AND release.tuple_bundle_sha256 =
       (NEW.event #>> '{data,tuple_bundle_sha256}')
     AND decision.authorization_model_id =
       (NEW.event #>> '{data,authorization_model_id}')
     AND decision.activation_version =
       (NEW.event #>> '{data,activation_version}')::bigint
     AND decision.effect = (NEW.event #>> '{data,effect}')
     AND decision.reason_code = (NEW.event #>> '{data,reason_code}')
     AND decision.input_sha256 = (NEW.event #>> '{data,input_sha256}');

  IF NOT FOUND THEN
    RAISE EXCEPTION 'authorization Decision Event is orphaned'
      USING ERRCODE = '23000',
            CONSTRAINT = 'authorization_decision_event_pair_guard';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER authorization_release_insert_guard
BEFORE INSERT ON aios_core.authorization_policy_release
FOR EACH ROW
EXECUTE FUNCTION aios_core.enforce_authorization_release_insert();

CREATE TRIGGER authorization_release_update_guard
BEFORE UPDATE ON aios_core.authorization_policy_release
FOR EACH ROW
EXECUTE FUNCTION aios_core.enforce_authorization_release_update();

CREATE TRIGGER authorization_release_no_delete
BEFORE DELETE ON aios_core.authorization_policy_release
FOR EACH ROW
EXECUTE FUNCTION aios_core.reject_authorization_tombstone_delete();

CREATE TRIGGER authorization_activation_insert_guard
BEFORE INSERT ON aios_core.authorization_activation
FOR EACH ROW
EXECUTE FUNCTION aios_core.enforce_authorization_activation_insert();

CREATE TRIGGER authorization_activation_no_change
BEFORE UPDATE OR DELETE ON aios_core.authorization_activation
FOR EACH ROW
EXECUTE FUNCTION aios_core.reject_authorization_append_only_change();

CREATE TRIGGER authorization_active_policy_guard
BEFORE INSERT OR UPDATE ON aios_core.authorization_active_policy
FOR EACH ROW
EXECUTE FUNCTION aios_core.enforce_authorization_active_policy();

CREATE TRIGGER authorization_active_policy_no_delete
BEFORE DELETE ON aios_core.authorization_active_policy
FOR EACH ROW
EXECUTE FUNCTION aios_core.reject_authorization_tombstone_delete();

CREATE TRIGGER authorization_decision_insert_guard
BEFORE INSERT ON aios_core.authorization_decision
FOR EACH ROW
EXECUTE FUNCTION aios_core.enforce_authorization_decision_insert();

CREATE TRIGGER authorization_decision_no_change
BEFORE UPDATE OR DELETE ON aios_core.authorization_decision
FOR EACH ROW
EXECUTE FUNCTION aios_core.reject_authorization_append_only_change();

CREATE TRIGGER authorization_command_receipt_no_change
BEFORE UPDATE OR DELETE ON aios_core.authorization_command_receipt
FOR EACH ROW
EXECUTE FUNCTION aios_core.reject_authorization_append_only_change();

CREATE TRIGGER authorization_event_no_change
BEFORE UPDATE OR DELETE ON aios_core.authorization_event
FOR EACH ROW
EXECUTE FUNCTION aios_core.reject_authorization_append_only_change();

CREATE TRIGGER authorization_outbox_state_guard
BEFORE INSERT OR UPDATE ON aios_core.authorization_outbox
FOR EACH ROW
EXECUTE FUNCTION aios_core.enforce_authorization_outbox();

CREATE TRIGGER authorization_outbox_no_delete
BEFORE DELETE ON aios_core.authorization_outbox
FOR EACH ROW
EXECUTE FUNCTION aios_core.reject_authorization_tombstone_delete();

CREATE CONSTRAINT TRIGGER authorization_event_requires_outbox
AFTER INSERT ON aios_core.authorization_event
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION aios_core.enforce_authorization_event_outbox_pair();

CREATE CONSTRAINT TRIGGER authorization_outbox_requires_event
AFTER INSERT ON aios_core.authorization_outbox
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION aios_core.enforce_authorization_event_outbox_pair();

CREATE CONSTRAINT TRIGGER authorization_decision_requires_event
AFTER INSERT ON aios_core.authorization_decision
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION aios_core.enforce_authorization_decision_event_pair();

CREATE CONSTRAINT TRIGGER authorization_decision_event_requires_decision
AFTER INSERT ON aios_core.authorization_event
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION aios_core.enforce_authorization_decision_event_pair();

COMMIT;
