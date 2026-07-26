BEGIN;

CREATE SCHEMA aios_tool;

CREATE FUNCTION aios_tool.valid_audit_intent(value jsonb)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
STRICT
AS $$
  SELECT
    jsonb_typeof(value) = 'object'
    AND value ?& ARRAY[
      'schemaVersion',
      'intentId',
      'tenantId',
      'tenantKind',
      'eventType',
      'subjectId',
      'operationId',
      'identitySha256',
      'authorizationSha256',
      'catalogSha256',
      'normalizedParamSha256',
      'resultReceiptSha256',
      'correlationId',
      'metadataOnly',
      'occurredAt',
      'intentSha256'
    ]
    AND NOT EXISTS (
      SELECT 1
        FROM jsonb_object_keys(value) AS item(key)
       WHERE item.key <> ALL (
         ARRAY[
           'schemaVersion',
           'intentId',
           'tenantId',
           'tenantKind',
           'eventType',
           'subjectId',
           'operationId',
           'identitySha256',
           'authorizationSha256',
           'catalogSha256',
           'normalizedParamSha256',
           'resultReceiptSha256',
           'correlationId',
           'metadataOnly',
           'occurredAt',
           'intentSha256'
         ]
       )
    )
    AND (value ->> 'schemaVersion') =
        'c16-c18-outbox-intent.v1'
    AND (value ->> 'tenantKind') = 'SYNTHETIC'
    AND (value ->> 'eventType') ~ '^[A-Z][A-Z0-9_]{0,63}$'
    AND (value ->> 'identitySha256') ~ '^sha256:[a-f0-9]{64}$'
    AND (value ->> 'authorizationSha256') ~ '^sha256:[a-f0-9]{64}$'
    AND (value ->> 'catalogSha256') ~ '^sha256:[a-f0-9]{64}$'
    AND (value ->> 'normalizedParamSha256') ~
        '^sha256:[a-f0-9]{64}$'
    AND (
      value -> 'resultReceiptSha256' = 'null'::jsonb
      OR (value ->> 'resultReceiptSha256') ~
         '^sha256:[a-f0-9]{64}$'
    )
    AND (value ->> 'metadataOnly')::boolean
    AND (value ->> 'occurredAt') ~
        '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}[.][0-9]{3}Z$';
$$;

CREATE TABLE aios_tool.audit_intent (
  tenant_id text NOT NULL,
  tenant_kind text NOT NULL CHECK (tenant_kind = 'SYNTHETIC'),
  intent_id text NOT NULL
    CHECK (
      intent_id ~
        '^tai_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
  event_type text NOT NULL
    CHECK (event_type ~ '^[A-Z][A-Z0-9_]{0,63}$'),
  subject_id text NOT NULL
    CHECK (char_length(btrim(subject_id)) BETWEEN 1 AND 128),
  intent_sha256 text NOT NULL
    CHECK (intent_sha256 ~ '^sha256:[a-f0-9]{64}$'),
  metadata jsonb NOT NULL
    CONSTRAINT c16_audit_intent_metadata_only
      CHECK (aios_tool.valid_audit_intent(metadata)),
  created_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, intent_id),
  UNIQUE (tenant_id, intent_sha256),
  FOREIGN KEY (tenant_id, tenant_kind)
    REFERENCES aios_data.tenant_data_lifecycle(tenant_id, tenant_kind)
    ON DELETE RESTRICT,
  CHECK ((metadata ->> 'tenantId') IS NOT DISTINCT FROM tenant_id),
  CHECK ((metadata ->> 'intentId') IS NOT DISTINCT FROM intent_id),
  CHECK ((metadata ->> 'eventType') IS NOT DISTINCT FROM event_type),
  CHECK ((metadata ->> 'subjectId') IS NOT DISTINCT FROM subject_id),
  CHECK ((metadata ->> 'intentSha256') IS NOT DISTINCT FROM intent_sha256)
);

CREATE TABLE aios_tool.audit_outbox (
  tenant_id text NOT NULL,
  tenant_kind text NOT NULL CHECK (tenant_kind = 'SYNTHETIC'),
  intent_id text NOT NULL,
  status text NOT NULL
    CHECK (status IN ('PENDING', 'PROCESSING', 'FAILED', 'PUBLISHED')),
  attempt_count bigint NOT NULL DEFAULT 0
    CHECK (attempt_count BETWEEN 0 AND 9007199254740991),
  lease_version bigint NOT NULL DEFAULT 0
    CHECK (lease_version BETWEEN 0 AND 9007199254740991),
  leased_by text,
  lease_until timestamptz,
  available_at timestamptz NOT NULL,
  published_at timestamptz,
  last_error_code text,
  created_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, intent_id),
  FOREIGN KEY (tenant_id, intent_id)
    REFERENCES aios_tool.audit_intent(tenant_id, intent_id)
    ON DELETE RESTRICT
    DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY (tenant_id, tenant_kind)
    REFERENCES aios_data.tenant_data_lifecycle(tenant_id, tenant_kind)
    ON DELETE RESTRICT,
  CHECK (
    leased_by IS NULL
    OR char_length(btrim(leased_by)) BETWEEN 1 AND 128
  ),
  CHECK (
    last_error_code IS NULL
    OR last_error_code ~ '^[A-Z][A-Z0-9_]{0,63}$'
  ),
  CONSTRAINT c16_audit_outbox_state_shape CHECK (
    (
      status IN ('PENDING', 'FAILED')
      AND leased_by IS NULL
      AND lease_until IS NULL
      AND published_at IS NULL
    )
    OR (
      status = 'PROCESSING'
      AND leased_by IS NOT NULL
      AND lease_until IS NOT NULL
      AND published_at IS NULL
    )
    OR (
      status = 'PUBLISHED'
      AND leased_by IS NULL
      AND lease_until IS NULL
      AND published_at IS NOT NULL
      AND last_error_code IS NULL
    )
  )
);

ALTER TABLE aios_tool.audit_intent
  ADD CONSTRAINT c16_audit_intent_outbox_pair
  FOREIGN KEY (tenant_id, intent_id)
  REFERENCES aios_tool.audit_outbox(tenant_id, intent_id)
  ON DELETE RESTRICT
  DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE aios_tool.tool_confirmation (
  tenant_id text NOT NULL,
  tenant_kind text NOT NULL CHECK (tenant_kind = 'SYNTHETIC'),
  tenant_lifecycle_version bigint NOT NULL
    CHECK (tenant_lifecycle_version BETWEEN 1 AND 9007199254740991),
  confirmation_id text NOT NULL
    CHECK (
      confirmation_id ~
        '^tcf_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
  confirmation_sha256 text NOT NULL
    CHECK (confirmation_sha256 ~ '^sha256:[a-f0-9]{64}$'),
  operation_id text NOT NULL
    CHECK (
      operation_id IN (
        'synthetic.approval.status.get',
        'synthetic.erp.order.get',
        'synthetic.bi.metric.get'
      )
    ),
  catalog_version text NOT NULL,
  catalog_sha256 text NOT NULL
    CHECK (catalog_sha256 ~ '^sha256:[a-f0-9]{64}$'),
  adapter_version text NOT NULL,
  normalized_param_sha256 text NOT NULL
    CHECK (normalized_param_sha256 ~ '^sha256:[a-f0-9]{64}$'),
  identity_sha256 text NOT NULL
    CHECK (identity_sha256 ~ '^sha256:[a-f0-9]{64}$'),
  authorization_sha256 text NOT NULL
    CHECK (authorization_sha256 ~ '^sha256:[a-f0-9]{64}$'),
  authorization_authority_sha256 text NOT NULL
    CHECK (
      authorization_authority_sha256 ~ '^sha256:[a-f0-9]{64}$'
    ),
  confirmation jsonb NOT NULL
    CHECK (jsonb_typeof(confirmation) = 'object')
    CHECK (
      (confirmation ->> 'schemaVersion') =
        'c16-tool-confirmation.v1'
    )
    CHECK ((confirmation ->> 'tenantId') IS NOT DISTINCT FROM tenant_id)
    CHECK ((confirmation ->> 'tenantKind') = 'SYNTHETIC')
    CHECK (
      (confirmation ->> 'tenantLifecycleVersion')::bigint
        IS NOT DISTINCT FROM tenant_lifecycle_version
    )
    CHECK (
      (confirmation ->> 'confirmationId')
        IS NOT DISTINCT FROM confirmation_id
    )
    CHECK (
      (confirmation ->> 'confirmationSha256')
        IS NOT DISTINCT FROM confirmation_sha256
    )
    CHECK (
      (confirmation ->> 'operationId')
        IS NOT DISTINCT FROM operation_id
    )
    CHECK (
      (confirmation ->> 'authorizationAuthoritySha256')
        IS NOT DISTINCT FROM authorization_authority_sha256
    ),
  idempotency_key text NOT NULL
    CHECK (char_length(btrim(idempotency_key)) BETWEEN 1 AND 128),
  request_hash text NOT NULL
    CHECK (request_hash ~ '^sha256:[a-f0-9]{64}$'),
  created_audit_intent_id text NOT NULL,
  confirmed_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL CHECK (expires_at > confirmed_at),
  PRIMARY KEY (tenant_id, confirmation_id),
  UNIQUE (tenant_id, confirmation_sha256),
  UNIQUE (tenant_id, idempotency_key),
  FOREIGN KEY (tenant_id, tenant_kind)
    REFERENCES aios_data.tenant_data_lifecycle(tenant_id, tenant_kind)
    ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, created_audit_intent_id)
    REFERENCES aios_tool.audit_intent(tenant_id, intent_id)
    ON DELETE RESTRICT
    DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE aios_tool.tool_call (
  tenant_id text NOT NULL,
  tenant_kind text NOT NULL CHECK (tenant_kind = 'SYNTHETIC'),
  tenant_lifecycle_version bigint NOT NULL
    CHECK (tenant_lifecycle_version BETWEEN 1 AND 9007199254740991),
  call_id text NOT NULL
    CHECK (
      call_id ~
        '^tcl_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
  confirmation_id text NOT NULL,
  confirmation_sha256 text NOT NULL
    CHECK (confirmation_sha256 ~ '^sha256:[a-f0-9]{64}$'),
  operation_id text NOT NULL
    CHECK (
      operation_id IN (
        'synthetic.approval.status.get',
        'synthetic.erp.order.get',
        'synthetic.bi.metric.get'
      )
    ),
  effect_key text NOT NULL
    CHECK (effect_key ~ '^sha256:[a-f0-9]{64}$'),
  call_sha256 text NOT NULL
    CHECK (call_sha256 ~ '^sha256:[a-f0-9]{64}$'),
  identity_sha256 text NOT NULL
    CHECK (identity_sha256 ~ '^sha256:[a-f0-9]{64}$'),
  authorization_sha256 text NOT NULL
    CHECK (authorization_sha256 ~ '^sha256:[a-f0-9]{64}$'),
  authorization_authority_sha256 text NOT NULL
    CHECK (
      authorization_authority_sha256 ~ '^sha256:[a-f0-9]{64}$'
    ),
  status text NOT NULL CHECK (status IN ('STARTED', 'SUCCEEDED')),
  call jsonb NOT NULL
    CHECK (jsonb_typeof(call) = 'object')
    CHECK ((call ->> 'schemaVersion') = 'c16-tool-call.v1')
    CHECK ((call ->> 'tenantId') IS NOT DISTINCT FROM tenant_id)
    CHECK (
      (call ->> 'tenantLifecycleVersion')::bigint
        IS NOT DISTINCT FROM tenant_lifecycle_version
    )
    CHECK ((call ->> 'callId') IS NOT DISTINCT FROM call_id)
    CHECK ((call ->> 'operationId') IS NOT DISTINCT FROM operation_id)
    CHECK ((call ->> 'effectKey') IS NOT DISTINCT FROM effect_key)
    CHECK (
      (call ->> 'authorizationAuthoritySha256')
        IS NOT DISTINCT FROM authorization_authority_sha256
    )
    CHECK ((call ->> 'callSha256') IS NOT DISTINCT FROM call_sha256),
  result jsonb,
  receipt jsonb,
  idempotency_key text NOT NULL
    CHECK (char_length(btrim(idempotency_key)) BETWEEN 1 AND 128),
  request_hash text NOT NULL
    CHECK (request_hash ~ '^sha256:[a-f0-9]{64}$'),
  terminal_audit_intent_id text,
  last_error_code text,
  started_at timestamptz NOT NULL,
  completed_at timestamptz,
  updated_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, call_id),
  UNIQUE (tenant_id, confirmation_id),
  UNIQUE (tenant_id, effect_key),
  UNIQUE (tenant_id, idempotency_key),
  FOREIGN KEY (tenant_id, confirmation_id)
    REFERENCES aios_tool.tool_confirmation(tenant_id, confirmation_id)
    ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, terminal_audit_intent_id)
    REFERENCES aios_tool.audit_intent(tenant_id, intent_id)
    ON DELETE RESTRICT
    DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY (tenant_id, tenant_kind)
    REFERENCES aios_data.tenant_data_lifecycle(tenant_id, tenant_kind)
    ON DELETE RESTRICT,
  CHECK (
    last_error_code IS NULL
    OR last_error_code ~ '^[A-Z][A-Z0-9_]{0,63}$'
  ),
  CONSTRAINT c16_tool_call_state_shape CHECK (
    (
      status = 'STARTED'
      AND result IS NULL
      AND receipt IS NULL
      AND terminal_audit_intent_id IS NULL
      AND completed_at IS NULL
    )
    OR (
      status = 'SUCCEEDED'
      AND jsonb_typeof(result) = 'object'
      AND jsonb_typeof(receipt) = 'object'
      AND terminal_audit_intent_id IS NOT NULL
      AND completed_at IS NOT NULL
      AND last_error_code IS NULL
    )
  )
);

CREATE INDEX c16_audit_delivery_idx
  ON aios_tool.audit_outbox (
    tenant_id,
    status,
    available_at,
    created_at,
    intent_id
  );

CREATE FUNCTION aios_tool.reject_immutable_change()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
  RAISE EXCEPTION 'C16 immutable row cannot be changed'
    USING ERRCODE = '55000';
END
$$;

CREATE FUNCTION aios_tool.enforce_call_transition()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
  IF
    NEW.tenant_id <> OLD.tenant_id
    OR NEW.tenant_kind <> OLD.tenant_kind
    OR NEW.tenant_lifecycle_version <> OLD.tenant_lifecycle_version
    OR NEW.call_id <> OLD.call_id
    OR NEW.confirmation_id <> OLD.confirmation_id
    OR NEW.confirmation_sha256 <> OLD.confirmation_sha256
    OR NEW.operation_id <> OLD.operation_id
    OR NEW.effect_key <> OLD.effect_key
    OR NEW.call_sha256 <> OLD.call_sha256
    OR NEW.identity_sha256 <> OLD.identity_sha256
    OR NEW.authorization_sha256 <> OLD.authorization_sha256
    OR NEW.authorization_authority_sha256 <>
       OLD.authorization_authority_sha256
    OR NEW.call <> OLD.call
    OR NEW.idempotency_key <> OLD.idempotency_key
    OR NEW.request_hash <> OLD.request_hash
    OR NEW.started_at <> OLD.started_at
    OR OLD.status <> 'STARTED'
    OR NEW.status NOT IN ('STARTED', 'SUCCEEDED')
    OR (
      NEW.status = 'STARTED'
      AND (
        NEW.result IS DISTINCT FROM OLD.result
        OR NEW.receipt IS DISTINCT FROM OLD.receipt
        OR NEW.terminal_audit_intent_id IS DISTINCT FROM
           OLD.terminal_audit_intent_id
        OR NEW.completed_at IS DISTINCT FROM OLD.completed_at
      )
    )
  THEN
    RAISE EXCEPTION 'C16 ToolCall transition is invalid'
      USING ERRCODE = '55000';
  END IF;
  RETURN NEW;
END
$$;

CREATE FUNCTION aios_tool.enforce_outbox_transition()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'C16 Outbox cannot be deleted'
      USING ERRCODE = '55000';
  END IF;
  IF
    NEW.tenant_id <> OLD.tenant_id
    OR NEW.tenant_kind <> OLD.tenant_kind
    OR NEW.intent_id <> OLD.intent_id
    OR NEW.created_at <> OLD.created_at
    OR NEW.attempt_count < OLD.attempt_count
    OR NEW.lease_version < OLD.lease_version
    OR OLD.status = 'PUBLISHED'
    OR (
      NEW.status = 'PROCESSING'
      AND (
        NEW.attempt_count <> OLD.attempt_count + 1
        OR NEW.lease_version <> OLD.lease_version + 1
      )
    )
    OR (
      NEW.status IN ('FAILED', 'PUBLISHED')
      AND (
        OLD.status <> 'PROCESSING'
        OR NEW.attempt_count <> OLD.attempt_count
        OR NEW.lease_version <> OLD.lease_version
      )
    )
  THEN
    RAISE EXCEPTION 'C16 Outbox transition is invalid'
      USING ERRCODE = '55000';
  END IF;
  RETURN NEW;
END
$$;

CREATE TRIGGER c16_confirmation_immutable
BEFORE UPDATE OR DELETE ON aios_tool.tool_confirmation
FOR EACH ROW EXECUTE FUNCTION aios_tool.reject_immutable_change();

CREATE TRIGGER c16_audit_intent_immutable
BEFORE UPDATE OR DELETE ON aios_tool.audit_intent
FOR EACH ROW EXECUTE FUNCTION aios_tool.reject_immutable_change();

CREATE TRIGGER c16_tool_call_transition
BEFORE UPDATE ON aios_tool.tool_call
FOR EACH ROW EXECUTE FUNCTION aios_tool.enforce_call_transition();

CREATE TRIGGER c16_tool_call_no_delete
BEFORE DELETE ON aios_tool.tool_call
FOR EACH ROW EXECUTE FUNCTION aios_tool.reject_immutable_change();

CREATE TRIGGER c16_audit_outbox_transition
BEFORE UPDATE OR DELETE ON aios_tool.audit_outbox
FOR EACH ROW EXECUTE FUNCTION aios_tool.enforce_outbox_transition();

COMMIT;
