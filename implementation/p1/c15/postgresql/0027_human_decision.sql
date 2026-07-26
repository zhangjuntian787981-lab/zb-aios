BEGIN;

CREATE SCHEMA aios_decision;

CREATE FUNCTION aios_decision.valid_audit_intent(value jsonb)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
STRICT
SET search_path = pg_catalog
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
      'subjectSha256',
      'artifactId',
      'artifactSha256',
      'decisionId',
      'decisionSha256',
      'effectId',
      'effectKey',
      'humanPrincipalId',
      'workloadActorPrincipalId',
      'leafDelegationId',
      'authorizationDecisionId',
      'authorizationEvidenceRef',
      'authorizationPolicyVersion',
      'correlationId',
      'occurredAt'
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
           'subjectSha256',
           'artifactId',
           'artifactSha256',
           'decisionId',
           'decisionSha256',
           'effectId',
           'effectKey',
           'humanPrincipalId',
           'workloadActorPrincipalId',
           'leafDelegationId',
           'authorizationDecisionId',
           'authorizationEvidenceRef',
           'authorizationPolicyVersion',
           'correlationId',
           'occurredAt'
         ]
       )
    )
    AND (value ->> 'schemaVersion') = 'c15-audit-intent.v1'
    AND (value ->> 'intentId') ~
      '^hai_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    AND (value ->> 'tenantId') ~
      '^stn_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    AND (value ->> 'tenantKind') = 'SYNTHETIC'
    AND (value ->> 'eventType') ~ '^[A-Z][A-Z0-9_]{0,63}$'
    AND jsonb_typeof(value -> 'subjectId') = 'string'
    AND char_length(btrim(value ->> 'subjectId')) BETWEEN 1 AND 128
    AND (value ->> 'subjectSha256') ~ '^sha256:[a-f0-9]{64}$'
    AND (value ->> 'artifactId') ~
      '^dar_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    AND (value ->> 'artifactSha256') ~ '^sha256:[a-f0-9]{64}$'
    AND (
      (
        value -> 'decisionId' = 'null'::jsonb
        AND value -> 'decisionSha256' = 'null'::jsonb
      )
      OR (
        (value ->> 'decisionId') ~
          '^std_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
        AND (value ->> 'decisionSha256') ~
          '^sha256:[a-f0-9]{64}$'
      )
    )
    AND (
      (
        value -> 'effectId' = 'null'::jsonb
        AND value -> 'effectKey' = 'null'::jsonb
      )
      OR (
        (value ->> 'effectId') ~
          '^hef_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
        AND (value ->> 'effectKey') ~ '^sha256:[a-f0-9]{64}$'
      )
    )
    AND (value ->> 'humanPrincipalId') ~
      '^prn_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    AND (value ->> 'workloadActorPrincipalId') ~
      '^prn_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    AND (value ->> 'leafDelegationId') ~
      '^dlg_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    AND jsonb_typeof(value -> 'authorizationDecisionId') = 'string'
    AND (value ->> 'authorizationDecisionId') ~
      '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
    AND (value ->> 'authorizationEvidenceRef') ~
      '^(synthetic|fixture|test|policy|evidence)://[A-Za-z0-9][A-Za-z0-9._~:/-]*$'
    AND jsonb_typeof(value -> 'authorizationPolicyVersion') = 'string'
    AND (value ->> 'authorizationPolicyVersion') ~
      '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
    AND jsonb_typeof(value -> 'correlationId') = 'string'
    AND (value ->> 'correlationId') ~
      '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
    AND (value ->> 'occurredAt') ~
      '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}[.][0-9]{3}Z$';
$$;

CREATE TABLE aios_decision.audit_intent (
  tenant_id text NOT NULL,
  tenant_kind text NOT NULL CHECK (tenant_kind = 'SYNTHETIC'),
  intent_id text NOT NULL
    CHECK (
      intent_id ~
        '^hai_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
  event_type text NOT NULL
    CHECK (event_type ~ '^[A-Z][A-Z0-9_]{0,63}$'),
  subject_id text NOT NULL
    CHECK (char_length(btrim(subject_id)) BETWEEN 1 AND 128),
  subject_sha256 text NOT NULL
    CHECK (subject_sha256 ~ '^sha256:[a-f0-9]{64}$'),
  intent_sha256 text NOT NULL
    CHECK (intent_sha256 ~ '^sha256:[a-f0-9]{64}$'),
  metadata jsonb NOT NULL
    CONSTRAINT c15_audit_intent_metadata_only
      CHECK (aios_decision.valid_audit_intent(metadata)),
  created_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, intent_id),
  UNIQUE (tenant_id, intent_sha256),
  FOREIGN KEY (tenant_id, tenant_kind)
    REFERENCES aios_core.tenant_registry(tenant_id, tenant_kind)
    ON DELETE RESTRICT,
  CHECK ((metadata ->> 'tenantId') IS NOT DISTINCT FROM tenant_id),
  CHECK ((metadata ->> 'intentId') IS NOT DISTINCT FROM intent_id),
  CHECK ((metadata ->> 'eventType') IS NOT DISTINCT FROM event_type),
  CHECK ((metadata ->> 'subjectId') IS NOT DISTINCT FROM subject_id),
  CHECK (
    (metadata ->> 'subjectSha256') IS NOT DISTINCT FROM subject_sha256
  )
);

CREATE TABLE aios_decision.audit_outbox (
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
    REFERENCES aios_decision.audit_intent(tenant_id, intent_id)
    ON DELETE RESTRICT
    DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY (tenant_id, tenant_kind)
    REFERENCES aios_core.tenant_registry(tenant_id, tenant_kind)
    ON DELETE RESTRICT,
  CHECK (
    leased_by IS NULL
    OR char_length(btrim(leased_by)) BETWEEN 1 AND 128
  ),
  CHECK (
    last_error_code IS NULL
    OR last_error_code ~ '^[A-Z][A-Z0-9_]{0,63}$'
  ),
  CONSTRAINT c15_audit_outbox_state_shape CHECK (
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

ALTER TABLE aios_decision.audit_intent
  ADD CONSTRAINT c15_audit_intent_outbox_pair
  FOREIGN KEY (tenant_id, intent_id)
  REFERENCES aios_decision.audit_outbox(tenant_id, intent_id)
  ON DELETE RESTRICT
  DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE aios_decision.draft_artifact (
  tenant_id text NOT NULL,
  tenant_kind text NOT NULL CHECK (tenant_kind = 'SYNTHETIC'),
  artifact_id text NOT NULL
    CHECK (
      artifact_id ~
        '^dar_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
  artifact_sha256 text NOT NULL
    CHECK (artifact_sha256 ~ '^sha256:[a-f0-9]{64}$'),
  workflow_ref text NOT NULL
    CHECK (
      workflow_ref ~
        '^(synthetic|fixture|test|policy|evidence)://[^[:space:]]+$'
    ),
  workflow_version text NOT NULL
    CHECK (char_length(btrim(workflow_version)) BETWEEN 1 AND 128),
  binding_sha256 text NOT NULL
    CHECK (binding_sha256 ~ '^sha256:[a-f0-9]{64}$'),
  artifact jsonb NOT NULL
    CHECK (jsonb_typeof(artifact) = 'object')
    CHECK ((artifact ->> 'schemaVersion') = 'c15-draft-artifact.v1')
    CHECK ((artifact ->> 'artifactKind') = 'SYNTHETIC_DRAFT')
    CHECK ((artifact ->> 'tenantKind') = 'SYNTHETIC')
    CHECK (
      (artifact -> 'candidate' ->> 'operationId') =
        'SYNTHETIC_PREVIEW_EFFECT'
    )
    CHECK ((artifact -> 'display') ?& ARRAY['differences','sources','risks']),
  created_by_idempotency_key text NOT NULL,
  created_audit_intent_id text NOT NULL,
  created_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, artifact_id),
  UNIQUE (tenant_id, artifact_sha256),
  UNIQUE (tenant_id, created_by_idempotency_key),
  FOREIGN KEY (tenant_id, tenant_kind)
    REFERENCES aios_core.tenant_registry(tenant_id, tenant_kind)
    ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, created_audit_intent_id)
    REFERENCES aios_decision.audit_intent(tenant_id, intent_id)
    ON DELETE RESTRICT
    DEFERRABLE INITIALLY DEFERRED,
  CHECK ((artifact ->> 'tenantId') IS NOT DISTINCT FROM tenant_id),
  CHECK ((artifact ->> 'artifactId') IS NOT DISTINCT FROM artifact_id),
  CHECK (
    (artifact ->> 'artifactSha256') IS NOT DISTINCT FROM artifact_sha256
  ),
  CHECK ((artifact ->> 'workflowRef') IS NOT DISTINCT FROM workflow_ref),
  CHECK (
    (artifact ->> 'workflowVersion') IS NOT DISTINCT FROM workflow_version
  ),
  CHECK (
    (artifact ->> 'bindingSha256') IS NOT DISTINCT FROM binding_sha256
  )
);

CREATE TABLE aios_decision.synthetic_test_decision (
  tenant_id text NOT NULL,
  tenant_kind text NOT NULL CHECK (tenant_kind = 'SYNTHETIC'),
  decision_id text NOT NULL
    CHECK (
      decision_id ~
        '^std_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
  decision_sha256 text NOT NULL
    CHECK (decision_sha256 ~ '^sha256:[a-f0-9]{64}$'),
  artifact_id text NOT NULL,
  artifact_sha256 text NOT NULL
    CHECK (artifact_sha256 ~ '^sha256:[a-f0-9]{64}$'),
  outcome text NOT NULL CHECK (outcome = 'APPROVE'),
  decision jsonb NOT NULL
    CHECK (jsonb_typeof(decision) = 'object')
    CHECK (
      (decision ->> 'schemaVersion') =
        'c15-synthetic-test-decision.v1'
    )
    CHECK ((decision ->> 'decisionType') = 'SYNTHETIC_TEST_DECISION')
    CHECK ((decision ->> 'productionReusable')::boolean = false)
    CHECK ((decision ->> 'externalEffectCount')::bigint = 0)
    CHECK ((decision ->> 'status') = 'ACTIVE'),
  created_by_idempotency_key text NOT NULL,
  created_audit_intent_id text NOT NULL,
  decided_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, decision_id),
  UNIQUE (tenant_id, decision_sha256),
  UNIQUE (tenant_id, created_by_idempotency_key),
  FOREIGN KEY (tenant_id, artifact_id)
    REFERENCES aios_decision.draft_artifact(tenant_id, artifact_id)
    ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, created_audit_intent_id)
    REFERENCES aios_decision.audit_intent(tenant_id, intent_id)
    ON DELETE RESTRICT
    DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY (tenant_id, tenant_kind)
    REFERENCES aios_core.tenant_registry(tenant_id, tenant_kind)
    ON DELETE RESTRICT,
  CHECK (expires_at > decided_at),
  CHECK ((decision ->> 'tenantId') IS NOT DISTINCT FROM tenant_id),
  CHECK ((decision ->> 'decisionId') IS NOT DISTINCT FROM decision_id),
  CHECK (
    (decision ->> 'decisionSha256') IS NOT DISTINCT FROM decision_sha256
  ),
  CHECK ((decision ->> 'artifactId') IS NOT DISTINCT FROM artifact_id),
  CHECK (
    (decision ->> 'artifactSha256') IS NOT DISTINCT FROM artifact_sha256
  ),
  CHECK ((decision ->> 'outcome') IS NOT DISTINCT FROM outcome)
);

CREATE TABLE aios_decision.decision_withdrawal (
  tenant_id text NOT NULL,
  tenant_kind text NOT NULL CHECK (tenant_kind = 'SYNTHETIC'),
  decision_id text NOT NULL,
  decision_sha256 text NOT NULL
    CHECK (decision_sha256 ~ '^sha256:[a-f0-9]{64}$'),
  withdrawal_authorization jsonb NOT NULL
    CHECK (jsonb_typeof(withdrawal_authorization) = 'object'),
  created_by_idempotency_key text NOT NULL,
  created_audit_intent_id text NOT NULL,
  withdrawn_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, decision_id),
  UNIQUE (tenant_id, created_by_idempotency_key),
  FOREIGN KEY (tenant_id, decision_id)
    REFERENCES aios_decision.synthetic_test_decision(
      tenant_id,
      decision_id
    )
    ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, created_audit_intent_id)
    REFERENCES aios_decision.audit_intent(tenant_id, intent_id)
    ON DELETE RESTRICT
    DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY (tenant_id, tenant_kind)
    REFERENCES aios_core.tenant_registry(tenant_id, tenant_kind)
    ON DELETE RESTRICT
);

CREATE TABLE aios_decision.workflow_effect (
  tenant_id text NOT NULL,
  tenant_kind text NOT NULL CHECK (tenant_kind = 'SYNTHETIC'),
  effect_id text NOT NULL
    CHECK (
      effect_id ~
        '^hef_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
  effect_key text NOT NULL
    CHECK (effect_key ~ '^sha256:[a-f0-9]{64}$'),
  effect_sha256 text NOT NULL
    CHECK (effect_sha256 ~ '^sha256:[a-f0-9]{64}$'),
  decision_id text NOT NULL,
  decision_sha256 text NOT NULL
    CHECK (decision_sha256 ~ '^sha256:[a-f0-9]{64}$'),
  artifact_id text NOT NULL,
  artifact_sha256 text NOT NULL
    CHECK (artifact_sha256 ~ '^sha256:[a-f0-9]{64}$'),
  expected_readback_sha256 text NOT NULL
    CHECK (expected_readback_sha256 ~ '^sha256:[a-f0-9]{64}$'),
  status text NOT NULL
    CHECK (
      status IN (
        'QUEUED',
        'SUCCEEDED',
        'COMPENSATED',
        'COMPENSATION_FAILED'
      )
    ),
  effect jsonb NOT NULL
    CHECK (jsonb_typeof(effect) = 'object')
    CHECK ((effect ->> 'schemaVersion') = 'c15-synthetic-effect.v1')
    CHECK ((effect ->> 'operationId') = 'SYNTHETIC_PREVIEW_EFFECT')
    CHECK ((effect ->> 'externalEffectCount')::bigint = 0)
    CHECK ((effect ->> 'status') = 'QUEUED'),
  commit_receipt jsonb,
  readback_receipt jsonb,
  compensation_receipt jsonb,
  terminal_audit_intent_id text,
  created_by_idempotency_key text NOT NULL,
  created_audit_intent_id text NOT NULL,
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, effect_id),
  UNIQUE (tenant_id, effect_key),
  UNIQUE (tenant_id, effect_sha256),
  UNIQUE (tenant_id, created_by_idempotency_key),
  FOREIGN KEY (tenant_id, decision_id)
    REFERENCES aios_decision.synthetic_test_decision(
      tenant_id,
      decision_id
    )
    ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, artifact_id)
    REFERENCES aios_decision.draft_artifact(tenant_id, artifact_id)
    ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, created_audit_intent_id)
    REFERENCES aios_decision.audit_intent(tenant_id, intent_id)
    ON DELETE RESTRICT
    DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY (tenant_id, terminal_audit_intent_id)
    REFERENCES aios_decision.audit_intent(tenant_id, intent_id)
    ON DELETE RESTRICT
    DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY (tenant_id, tenant_kind)
    REFERENCES aios_core.tenant_registry(tenant_id, tenant_kind)
    ON DELETE RESTRICT,
  CHECK (updated_at >= created_at),
  CHECK ((effect ->> 'tenantId') IS NOT DISTINCT FROM tenant_id),
  CHECK ((effect ->> 'effectId') IS NOT DISTINCT FROM effect_id),
  CHECK ((effect ->> 'effectKey') IS NOT DISTINCT FROM effect_key),
  CHECK ((effect ->> 'effectSha256') IS NOT DISTINCT FROM effect_sha256),
  CONSTRAINT c15_effect_state_shape CHECK (
    (
      status = 'QUEUED'
      AND commit_receipt IS NULL
      AND readback_receipt IS NULL
      AND compensation_receipt IS NULL
      AND terminal_audit_intent_id IS NULL
    )
    OR (
      status = 'SUCCEEDED'
      AND commit_receipt IS NOT NULL
      AND readback_receipt IS NOT NULL
      AND compensation_receipt IS NULL
      AND terminal_audit_intent_id IS NOT NULL
    )
    OR (
      status IN ('COMPENSATED', 'COMPENSATION_FAILED')
      AND commit_receipt IS NOT NULL
      AND readback_receipt IS NOT NULL
      AND compensation_receipt IS NOT NULL
      AND terminal_audit_intent_id IS NOT NULL
    )
  )
);

CREATE TABLE aios_decision.effect_outbox (
  tenant_id text NOT NULL,
  tenant_kind text NOT NULL CHECK (tenant_kind = 'SYNTHETIC'),
  effect_id text NOT NULL,
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
  PRIMARY KEY (tenant_id, effect_id),
  FOREIGN KEY (tenant_id, effect_id)
    REFERENCES aios_decision.workflow_effect(tenant_id, effect_id)
    ON DELETE RESTRICT
    DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY (tenant_id, tenant_kind)
    REFERENCES aios_core.tenant_registry(tenant_id, tenant_kind)
    ON DELETE RESTRICT,
  CHECK (
    leased_by IS NULL
    OR char_length(btrim(leased_by)) BETWEEN 1 AND 128
  ),
  CHECK (
    last_error_code IS NULL
    OR last_error_code ~ '^[A-Z][A-Z0-9_]{0,63}$'
  ),
  CONSTRAINT c15_effect_outbox_state_shape CHECK (
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

ALTER TABLE aios_decision.workflow_effect
  ADD CONSTRAINT c15_effect_outbox_pair
  FOREIGN KEY (tenant_id, effect_id)
  REFERENCES aios_decision.effect_outbox(tenant_id, effect_id)
  ON DELETE RESTRICT
  DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE aios_decision.command_receipt (
  tenant_id text NOT NULL,
  tenant_kind text NOT NULL CHECK (tenant_kind = 'SYNTHETIC'),
  idempotency_key text NOT NULL
    CHECK (char_length(btrim(idempotency_key)) BETWEEN 1 AND 128),
  operation text NOT NULL
    CHECK (operation IN ('PREPARE', 'DECIDE', 'WITHDRAW', 'EXECUTE')),
  request_hash text NOT NULL
    CHECK (request_hash ~ '^sha256:[a-f0-9]{64}$'),
  subject_id text NOT NULL
    CHECK (char_length(btrim(subject_id)) BETWEEN 1 AND 128),
  audit_intent_id text NOT NULL,
  response jsonb NOT NULL CHECK (jsonb_typeof(response) = 'object'),
  created_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, idempotency_key),
  UNIQUE (tenant_id, operation, subject_id),
  FOREIGN KEY (tenant_id, audit_intent_id)
    REFERENCES aios_decision.audit_intent(tenant_id, intent_id)
    ON DELETE RESTRICT
    DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY (tenant_id, tenant_kind)
    REFERENCES aios_core.tenant_registry(tenant_id, tenant_kind)
    ON DELETE RESTRICT
);

ALTER TABLE aios_decision.draft_artifact
  ADD CONSTRAINT c15_artifact_receipt_pair
  FOREIGN KEY (tenant_id, created_by_idempotency_key)
  REFERENCES aios_decision.command_receipt(tenant_id, idempotency_key)
  ON DELETE RESTRICT
  DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE aios_decision.synthetic_test_decision
  ADD CONSTRAINT c15_decision_receipt_pair
  FOREIGN KEY (tenant_id, created_by_idempotency_key)
  REFERENCES aios_decision.command_receipt(tenant_id, idempotency_key)
  ON DELETE RESTRICT
  DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE aios_decision.decision_withdrawal
  ADD CONSTRAINT c15_withdrawal_receipt_pair
  FOREIGN KEY (tenant_id, created_by_idempotency_key)
  REFERENCES aios_decision.command_receipt(tenant_id, idempotency_key)
  ON DELETE RESTRICT
  DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE aios_decision.workflow_effect
  ADD CONSTRAINT c15_effect_receipt_pair
  FOREIGN KEY (tenant_id, created_by_idempotency_key)
  REFERENCES aios_decision.command_receipt(tenant_id, idempotency_key)
  ON DELETE RESTRICT
  DEFERRABLE INITIALLY DEFERRED;

CREATE FUNCTION aios_decision.reject_append_only_change()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION 'C15 frozen history cannot be changed'
    USING ERRCODE = '42501',
          CONSTRAINT = 'c15_append_only_guard';
END;
$$;

CREATE FUNCTION aios_decision.enforce_command_receipt_pair()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF NEW.operation = 'PREPARE' AND NOT EXISTS (
    SELECT 1
      FROM aios_decision.draft_artifact AS artifact
     WHERE artifact.tenant_id = NEW.tenant_id
       AND artifact.artifact_id = NEW.subject_id
       AND artifact.created_by_idempotency_key = NEW.idempotency_key
       AND artifact.created_audit_intent_id = NEW.audit_intent_id
       AND artifact.artifact = NEW.response
  ) THEN
    RAISE EXCEPTION 'C15 PREPARE receipt is not paired'
      USING ERRCODE = '23514',
            CONSTRAINT = 'c15_command_receipt_pair_guard';
  ELSIF NEW.operation = 'DECIDE' AND NOT EXISTS (
    SELECT 1
      FROM aios_decision.synthetic_test_decision AS decision
     WHERE decision.tenant_id = NEW.tenant_id
       AND decision.decision_id = NEW.subject_id
       AND decision.created_by_idempotency_key = NEW.idempotency_key
       AND decision.created_audit_intent_id = NEW.audit_intent_id
       AND decision.decision = NEW.response
  ) THEN
    RAISE EXCEPTION 'C15 DECIDE receipt is not paired'
      USING ERRCODE = '23514',
            CONSTRAINT = 'c15_command_receipt_pair_guard';
  ELSIF NEW.operation = 'WITHDRAW' AND NOT EXISTS (
    SELECT 1
      FROM aios_decision.decision_withdrawal AS withdrawal
     WHERE withdrawal.tenant_id = NEW.tenant_id
       AND withdrawal.decision_id = NEW.subject_id
       AND withdrawal.created_by_idempotency_key = NEW.idempotency_key
       AND withdrawal.created_audit_intent_id = NEW.audit_intent_id
       AND (NEW.response ->> 'status') = 'WITHDRAWN'
       AND (NEW.response ->> 'decisionSha256') =
         withdrawal.decision_sha256
       AND (NEW.response ->> 'withdrawnAt')::timestamptz =
         withdrawal.withdrawn_at
       AND (NEW.response -> 'withdrawalAuthorization') =
         withdrawal.withdrawal_authorization
  ) THEN
    RAISE EXCEPTION 'C15 WITHDRAW receipt is not paired'
      USING ERRCODE = '23514',
            CONSTRAINT = 'c15_command_receipt_pair_guard';
  ELSIF NEW.operation = 'EXECUTE' AND NOT EXISTS (
    SELECT 1
      FROM aios_decision.workflow_effect AS effect
     WHERE effect.tenant_id = NEW.tenant_id
       AND effect.effect_id = NEW.subject_id
       AND effect.created_by_idempotency_key = NEW.idempotency_key
       AND effect.created_audit_intent_id = NEW.audit_intent_id
       AND effect.effect = NEW.response
  ) THEN
    RAISE EXCEPTION 'C15 EXECUTE receipt is not paired'
      USING ERRCODE = '23514',
            CONSTRAINT = 'c15_command_receipt_pair_guard';
  END IF;
  RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER c15_command_receipt_pair_guard
AFTER INSERT ON aios_decision.command_receipt
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION
  aios_decision.enforce_command_receipt_pair();

CREATE FUNCTION aios_decision.enforce_effect_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'C15 effect history cannot be deleted'
      USING ERRCODE = '42501',
            CONSTRAINT = 'c15_effect_delete_guard';
  END IF;
  IF OLD.status <> 'QUEUED'
     OR NEW.status NOT IN (
       'SUCCEEDED',
       'COMPENSATED',
       'COMPENSATION_FAILED'
     )
     OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
     OR NEW.tenant_kind IS DISTINCT FROM OLD.tenant_kind
     OR NEW.effect_id IS DISTINCT FROM OLD.effect_id
     OR NEW.effect_key IS DISTINCT FROM OLD.effect_key
     OR NEW.effect_sha256 IS DISTINCT FROM OLD.effect_sha256
     OR NEW.decision_id IS DISTINCT FROM OLD.decision_id
     OR NEW.decision_sha256 IS DISTINCT FROM OLD.decision_sha256
     OR NEW.artifact_id IS DISTINCT FROM OLD.artifact_id
     OR NEW.artifact_sha256 IS DISTINCT FROM OLD.artifact_sha256
     OR NEW.expected_readback_sha256 IS DISTINCT FROM
       OLD.expected_readback_sha256
     OR NEW.effect IS DISTINCT FROM OLD.effect
     OR NEW.created_by_idempotency_key IS DISTINCT FROM
       OLD.created_by_idempotency_key
     OR NEW.created_audit_intent_id IS DISTINCT FROM
       OLD.created_audit_intent_id
     OR NEW.created_at IS DISTINCT FROM OLD.created_at
     OR NEW.updated_at < OLD.updated_at THEN
    RAISE EXCEPTION 'C15 effect transition changed a frozen binding'
      USING ERRCODE = '23514',
            CONSTRAINT = 'c15_effect_transition_guard';
  END IF;
  RETURN NEW;
END;
$$;

CREATE FUNCTION aios_decision.enforce_outbox_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'C15 Outbox history cannot be deleted'
      USING ERRCODE = '42501',
            CONSTRAINT = 'c15_outbox_delete_guard';
  END IF;
  IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
     OR NEW.tenant_kind IS DISTINCT FROM OLD.tenant_kind
     OR (to_jsonb(NEW) ->> TG_ARGV[0]) IS DISTINCT FROM
       (to_jsonb(OLD) ->> TG_ARGV[0])
     OR NEW.created_at IS DISTINCT FROM OLD.created_at
     OR NEW.attempt_count < OLD.attempt_count
     OR NEW.lease_version < OLD.lease_version
     OR (
       OLD.status IN ('PENDING', 'FAILED')
       AND NOT (
         NEW.status = 'PROCESSING'
         AND NEW.attempt_count = OLD.attempt_count + 1
         AND NEW.lease_version = OLD.lease_version + 1
         AND NEW.leased_by IS NOT NULL
         AND NEW.lease_until > statement_timestamp()
         AND NEW.available_at IS NOT DISTINCT FROM OLD.available_at
         AND NEW.published_at IS NOT DISTINCT FROM OLD.published_at
         AND NEW.last_error_code IS NULL
       )
     )
     OR (
       OLD.status = 'PROCESSING'
       AND NOT (
         (
           NEW.status = 'PROCESSING'
           AND OLD.lease_until <= statement_timestamp()
           AND NEW.attempt_count = OLD.attempt_count + 1
           AND NEW.lease_version = OLD.lease_version + 1
           AND NEW.leased_by IS NOT NULL
           AND NEW.lease_until > statement_timestamp()
           AND NEW.available_at IS NOT DISTINCT FROM OLD.available_at
           AND NEW.published_at IS NOT DISTINCT FROM OLD.published_at
           AND NEW.last_error_code IS NULL
         )
         OR (
           NEW.status = 'FAILED'
           AND NEW.attempt_count = OLD.attempt_count
           AND NEW.lease_version = OLD.lease_version
           AND NEW.available_at >= statement_timestamp()
           AND NEW.available_at <=
             statement_timestamp() + interval '1 hour'
           AND NEW.last_error_code IS NOT NULL
         )
         OR (
           NEW.status = 'PUBLISHED'
           AND NEW.attempt_count = OLD.attempt_count
           AND NEW.lease_version = OLD.lease_version
           AND NEW.available_at IS NOT DISTINCT FROM OLD.available_at
           AND NEW.published_at >= statement_timestamp()
           AND NEW.last_error_code IS NULL
         )
       )
     )
     OR OLD.status = 'PUBLISHED' THEN
    RAISE EXCEPTION 'C15 Outbox transition is invalid'
      USING ERRCODE = '23514',
            CONSTRAINT = 'c15_outbox_transition_guard';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER c15_artifact_append_only
BEFORE UPDATE OR DELETE ON aios_decision.draft_artifact
FOR EACH ROW EXECUTE FUNCTION aios_decision.reject_append_only_change();
CREATE TRIGGER c15_decision_append_only
BEFORE UPDATE OR DELETE ON aios_decision.synthetic_test_decision
FOR EACH ROW EXECUTE FUNCTION aios_decision.reject_append_only_change();
CREATE TRIGGER c15_withdrawal_append_only
BEFORE UPDATE OR DELETE ON aios_decision.decision_withdrawal
FOR EACH ROW EXECUTE FUNCTION aios_decision.reject_append_only_change();
CREATE TRIGGER c15_audit_intent_append_only
BEFORE UPDATE OR DELETE ON aios_decision.audit_intent
FOR EACH ROW EXECUTE FUNCTION aios_decision.reject_append_only_change();
CREATE TRIGGER c15_receipt_append_only
BEFORE UPDATE OR DELETE ON aios_decision.command_receipt
FOR EACH ROW EXECUTE FUNCTION aios_decision.reject_append_only_change();
CREATE TRIGGER c15_effect_transition_guard
BEFORE UPDATE OR DELETE ON aios_decision.workflow_effect
FOR EACH ROW EXECUTE FUNCTION aios_decision.enforce_effect_transition();
CREATE TRIGGER c15_effect_outbox_transition_guard
BEFORE UPDATE OR DELETE ON aios_decision.effect_outbox
FOR EACH ROW EXECUTE FUNCTION
  aios_decision.enforce_outbox_transition('effect_id');
CREATE TRIGGER c15_audit_outbox_transition_guard
BEFORE UPDATE OR DELETE ON aios_decision.audit_outbox
FOR EACH ROW EXECUTE FUNCTION
  aios_decision.enforce_outbox_transition('intent_id');

CREATE INDEX c15_effect_delivery_idx
  ON aios_decision.effect_outbox (
    tenant_id,
    status,
    available_at,
    created_at,
    effect_id
  );
CREATE INDEX c15_audit_delivery_idx
  ON aios_decision.audit_outbox (
    tenant_id,
    status,
    available_at,
    created_at,
    intent_id
  );

ALTER TABLE aios_decision.draft_artifact ENABLE ROW LEVEL SECURITY;
ALTER TABLE aios_decision.draft_artifact FORCE ROW LEVEL SECURITY;
ALTER TABLE aios_decision.synthetic_test_decision
  ENABLE ROW LEVEL SECURITY;
ALTER TABLE aios_decision.synthetic_test_decision
  FORCE ROW LEVEL SECURITY;
ALTER TABLE aios_decision.decision_withdrawal
  ENABLE ROW LEVEL SECURITY;
ALTER TABLE aios_decision.decision_withdrawal
  FORCE ROW LEVEL SECURITY;
ALTER TABLE aios_decision.workflow_effect ENABLE ROW LEVEL SECURITY;
ALTER TABLE aios_decision.workflow_effect FORCE ROW LEVEL SECURITY;
ALTER TABLE aios_decision.effect_outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE aios_decision.effect_outbox FORCE ROW LEVEL SECURITY;
ALTER TABLE aios_decision.audit_intent ENABLE ROW LEVEL SECURITY;
ALTER TABLE aios_decision.audit_intent FORCE ROW LEVEL SECURITY;
ALTER TABLE aios_decision.audit_outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE aios_decision.audit_outbox FORCE ROW LEVEL SECURITY;
ALTER TABLE aios_decision.command_receipt ENABLE ROW LEVEL SECURITY;
ALTER TABLE aios_decision.command_receipt FORCE ROW LEVEL SECURITY;

COMMIT;
