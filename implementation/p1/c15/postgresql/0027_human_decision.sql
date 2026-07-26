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
  lease_proof_sha256 text,
  available_at timestamptz NOT NULL,
  published_at timestamptz,
  last_error_code text,
  c18_receipt_key text,
  c18_event_id text,
  c18_event_hash text,
  created_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, intent_id),
  FOREIGN KEY (tenant_id, intent_id)
    REFERENCES aios_decision.audit_intent(tenant_id, intent_id)
    ON DELETE RESTRICT
    DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY (tenant_id, tenant_kind)
    REFERENCES aios_core.tenant_registry(tenant_id, tenant_kind)
    ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, c18_receipt_key)
    REFERENCES aios_audit.audit_command_receipt(
      tenant_id,
      idempotency_key
    )
    ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, c18_event_id)
    REFERENCES aios_audit.audit_event(tenant_id, event_id)
    ON DELETE RESTRICT,
  CHECK (
    leased_by IS NULL
    OR char_length(btrim(leased_by)) BETWEEN 1 AND 128
  ),
  CHECK (
    last_error_code IS NULL
    OR last_error_code ~ '^[A-Z][A-Z0-9_]{0,63}$'
  ),
  CHECK (
    lease_proof_sha256 IS NULL
    OR lease_proof_sha256 ~ '^sha256:[a-f0-9]{64}$'
  ),
  CHECK (
    c18_event_hash IS NULL
    OR c18_event_hash ~ '^sha256:[a-f0-9]{64}$'
  ),
  CONSTRAINT c15_audit_outbox_state_shape CHECK (
    (
      status IN ('PENDING', 'FAILED')
      AND leased_by IS NULL
      AND lease_until IS NULL
      AND lease_proof_sha256 IS NULL
      AND published_at IS NULL
      AND c18_receipt_key IS NULL
      AND c18_event_id IS NULL
      AND c18_event_hash IS NULL
    )
    OR (
      status = 'PROCESSING'
      AND leased_by IS NOT NULL
      AND lease_until IS NOT NULL
      AND lease_proof_sha256 IS NOT NULL
      AND published_at IS NULL
      AND c18_receipt_key IS NULL
      AND c18_event_id IS NULL
      AND c18_event_hash IS NULL
    )
    OR (
      status = 'PUBLISHED'
      AND leased_by IS NULL
      AND lease_until IS NULL
      AND lease_proof_sha256 IS NULL
      AND published_at IS NOT NULL
      AND last_error_code IS NULL
      AND c18_receipt_key IS NOT NULL
      AND c18_receipt_key = intent_id
      AND c18_event_id IS NOT NULL
      AND c18_event_hash IS NOT NULL
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
  CONSTRAINT c15_artifact_idempotency_key
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
  CONSTRAINT c15_decision_idempotency_key
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
  CONSTRAINT c15_withdrawal_idempotency_key
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
  CONSTRAINT c15_effect_idempotency_key
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
  lease_proof_sha256 text,
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
  CHECK (
    lease_proof_sha256 IS NULL
    OR lease_proof_sha256 ~ '^sha256:[a-f0-9]{64}$'
  ),
  CONSTRAINT c15_effect_outbox_state_shape CHECK (
    (
      status IN ('PENDING', 'FAILED')
      AND leased_by IS NULL
      AND lease_until IS NULL
      AND lease_proof_sha256 IS NULL
      AND published_at IS NULL
    )
    OR (
      status = 'PROCESSING'
      AND leased_by IS NOT NULL
      AND lease_until IS NOT NULL
      AND lease_proof_sha256 IS NOT NULL
      AND published_at IS NULL
    )
    OR (
      status = 'PUBLISHED'
      AND leased_by IS NULL
      AND lease_until IS NULL
      AND lease_proof_sha256 IS NULL
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
DECLARE
  terminal_readback_sha256 text;
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
  terminal_readback_sha256 := CASE
    WHEN NEW.status = 'SUCCEEDED' THEN NEW.expected_readback_sha256
    ELSE 'sha256:' || encode(
      sha256(
        convert_to(
          '{"artifactSha256":"' || NEW.artifact_sha256
          || '","effectKey":"' || NEW.effect_key
          || '","schemaVersion":"c15-synthetic-readback.v1"'
          || ',"state":"' || CASE
            WHEN NEW.status = 'COMPENSATED'
              THEN 'COMPENSATED'
            ELSE 'MISMATCH'
          END
          || '","tenantId":"' || NEW.tenant_id || '"}',
          'UTF8'
        )
      ),
      'hex'
    )
  END;
  IF jsonb_typeof(NEW.commit_receipt) IS DISTINCT FROM 'object'
     OR (
       NEW.commit_receipt ?& ARRAY[
         'schemaVersion','tenantId','effectKey','operationId',
         'committed','externalEffectCount'
       ]
     ) IS NOT TRUE
     OR (
       SELECT count(*) FROM jsonb_object_keys(NEW.commit_receipt)
     ) <> 6
     OR NEW.commit_receipt ->> 'schemaVersion' IS DISTINCT FROM
       'c15-synthetic-commit-receipt.v1'
     OR NEW.commit_receipt ->> 'tenantId' IS DISTINCT FROM NEW.tenant_id
     OR NEW.commit_receipt ->> 'effectKey' IS DISTINCT FROM NEW.effect_key
     OR NEW.commit_receipt ->> 'operationId' IS DISTINCT FROM
       (NEW.effect ->> 'operationId')
     OR NEW.commit_receipt -> 'committed' IS DISTINCT FROM 'true'::jsonb
     OR NEW.commit_receipt -> 'externalEffectCount'
       IS DISTINCT FROM '0'::jsonb
     OR jsonb_typeof(NEW.readback_receipt) IS DISTINCT FROM 'object'
     OR (
       NEW.readback_receipt ?& ARRAY[
         'schemaVersion','tenantId','effectKey','observedState',
         'readbackSha256','externalEffectCount'
       ]
     ) IS NOT TRUE
     OR (
       SELECT count(*) FROM jsonb_object_keys(NEW.readback_receipt)
     ) <> 6
     OR NEW.readback_receipt ->> 'schemaVersion' IS DISTINCT FROM
       'c15-synthetic-readback-receipt.v1'
     OR NEW.readback_receipt ->> 'tenantId' IS DISTINCT FROM NEW.tenant_id
     OR NEW.readback_receipt ->> 'effectKey' IS DISTINCT FROM NEW.effect_key
     OR NEW.readback_receipt -> 'externalEffectCount'
       IS DISTINCT FROM '0'::jsonb
     OR (NEW.readback_receipt ->> 'observedState') IS DISTINCT FROM (
       CASE
         WHEN NEW.status = 'SUCCEEDED' THEN 'APPLIED'
         WHEN NEW.status = 'COMPENSATED' THEN 'COMPENSATED'
         ELSE 'MISMATCH'
       END
     )
     OR NEW.readback_receipt ->> 'readbackSha256'
       IS DISTINCT FROM terminal_readback_sha256
     OR (
       NEW.status = 'SUCCEEDED'
       AND NEW.compensation_receipt IS NOT NULL
     )
     OR (
       NEW.status = 'COMPENSATED'
       AND (
         jsonb_typeof(NEW.compensation_receipt)
           IS DISTINCT FROM 'object'
         OR (
           NEW.compensation_receipt ?& ARRAY[
             'schemaVersion','tenantId','effectKey','compensated',
             'externalEffectCount'
           ]
         ) IS NOT TRUE
         OR (
           SELECT count(*)
             FROM jsonb_object_keys(NEW.compensation_receipt)
         ) <> 5
         OR NEW.compensation_receipt ->> 'schemaVersion'
           IS DISTINCT FROM 'c15-synthetic-compensation-receipt.v1'
         OR NEW.compensation_receipt ->> 'tenantId'
           IS DISTINCT FROM NEW.tenant_id
         OR NEW.compensation_receipt ->> 'effectKey'
           IS DISTINCT FROM NEW.effect_key
         OR NEW.compensation_receipt -> 'compensated'
           IS DISTINCT FROM 'true'::jsonb
         OR NEW.compensation_receipt -> 'externalEffectCount'
           IS DISTINCT FROM '0'::jsonb
       )
     )
     OR (
       NEW.status = 'COMPENSATION_FAILED'
       AND (
         jsonb_typeof(NEW.compensation_receipt)
           IS DISTINCT FROM 'object'
         OR (
           NEW.compensation_receipt ?& ARRAY[
             'schemaVersion','tenantId','effectKey','errorCode',
             'externalEffectCount'
           ]
         ) IS NOT TRUE
         OR (
           SELECT count(*)
             FROM jsonb_object_keys(NEW.compensation_receipt)
         ) <> 5
         OR NEW.compensation_receipt ->> 'schemaVersion'
           IS DISTINCT FROM 'c15-compensation-failure.v1'
         OR NEW.compensation_receipt ->> 'tenantId'
           IS DISTINCT FROM NEW.tenant_id
         OR NEW.compensation_receipt ->> 'effectKey'
           IS DISTINCT FROM NEW.effect_key
         OR COALESCE(
           NEW.compensation_receipt ->> 'errorCode',
           ''
         ) !~ '^[A-Z][A-Z0-9_]{0,63}$'
         OR NEW.compensation_receipt -> 'externalEffectCount'
           IS DISTINCT FROM '0'::jsonb
       )
     )
     OR NOT EXISTS (
       SELECT 1
         FROM aios_decision.audit_intent AS intent
        WHERE intent.tenant_id = NEW.tenant_id
          AND intent.intent_id = NEW.terminal_audit_intent_id
          AND intent.event_type =
            'SYNTHETIC_EFFECT_' || NEW.status
          AND intent.subject_id = NEW.effect_id
          AND intent.subject_sha256 = NEW.effect_sha256
          AND intent.metadata ->> 'artifactId' = NEW.artifact_id
          AND intent.metadata ->> 'artifactSha256' =
            NEW.artifact_sha256
          AND intent.metadata ->> 'decisionId' = NEW.decision_id
          AND intent.metadata ->> 'decisionSha256' =
            NEW.decision_sha256
          AND intent.metadata ->> 'effectId' = NEW.effect_id
          AND intent.metadata ->> 'effectKey' = NEW.effect_key
          AND intent.metadata ->> 'humanPrincipalId' =
            NEW.effect -> 'executionIdentity' ->> 'humanPrincipalId'
          AND intent.metadata ->> 'workloadActorPrincipalId' =
            NEW.effect -> 'executionIdentity'
              ->> 'workloadActorPrincipalId'
          AND intent.metadata ->> 'leafDelegationId' =
            NEW.effect -> 'executionIdentity' ->> 'leafDelegationId'
          AND intent.metadata ->> 'authorizationDecisionId' =
            NEW.effect -> 'executionAuthorization' ->> 'decisionId'
          AND intent.metadata ->> 'authorizationEvidenceRef' =
            NEW.effect -> 'executionAuthorization' ->> 'evidenceRef'
          AND intent.metadata ->> 'authorizationPolicyVersion' =
            NEW.effect -> 'executionAuthorization' ->> 'policyVersion'
     ) THEN
    RAISE EXCEPTION 'C15 effect completion receipt is invalid'
      USING ERRCODE = '23514',
            CONSTRAINT = 'c15_effect_completion_guard';
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
  IF TG_ARGV[0] = 'effect_id'
     AND OLD.status = 'PROCESSING'
     AND NEW.status = 'PUBLISHED'
     AND NOT EXISTS (
       SELECT 1
        FROM aios_decision.workflow_effect AS effect
       WHERE effect.tenant_id = NEW.tenant_id
          AND effect.effect_id = to_jsonb(NEW) ->> 'effect_id'
          AND effect.status IN (
            'SUCCEEDED',
            'COMPENSATED',
            'COMPENSATION_FAILED'
          )
     ) THEN
    RAISE EXCEPTION 'C15 Effect must be terminal before publication'
      USING ERRCODE = '23514',
            CONSTRAINT = 'c15_effect_terminal_before_publish';
  END IF;
  IF TG_ARGV[0] = 'intent_id'
     AND OLD.status = 'PROCESSING'
     AND NEW.status = 'PUBLISHED'
     AND NOT EXISTS (
       SELECT 1
         FROM aios_audit.audit_command_receipt AS receipt
         JOIN aios_audit.audit_event AS event
           ON event.tenant_id = receipt.tenant_id
          AND event.event_id = receipt.event_id
        WHERE receipt.tenant_id = NEW.tenant_id
          AND receipt.idempotency_key =
            to_jsonb(NEW) ->> 'intent_id'
          AND to_jsonb(NEW) ->> 'c18_receipt_key' =
            receipt.idempotency_key
          AND to_jsonb(NEW) ->> 'c18_event_id' = event.event_id
          AND to_jsonb(NEW) ->> 'c18_event_hash' = event.event_hash
     ) THEN
    RAISE EXCEPTION 'C15 publication requires a persisted C18 receipt'
      USING ERRCODE = '23514',
            CONSTRAINT = 'c15_c18_receipt_guard';
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

CREATE FUNCTION aios_decision.claim_effect_outbox(
  p_tenant_id text,
  p_worker_id text,
  p_limit integer,
  p_lease_seconds integer
)
RETURNS TABLE (
  tenant_id text,
  tenant_kind text,
  effect_id text,
  outbox_status text,
  attempt_count bigint,
  lease_version bigint,
  leased_by text,
  lease_until timestamptz,
  lease_token text,
  available_at timestamptz,
  published_at timestamptz,
  last_error_code text,
  outbox_created_at timestamptz,
  effect jsonb,
  status text,
  commit_receipt jsonb,
  readback_receipt jsonb,
  compensation_receipt jsonb,
  updated_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
  IF aios_data.acquire_runtime_fence() IS NOT TRUE
     OR aios_data.runtime_scope_allows(
       p_tenant_id,
       'SYNTHETIC'
     ) IS NOT TRUE
     OR char_length(btrim(p_worker_id)) NOT BETWEEN 1 AND 128
     OR p_limit NOT BETWEEN 1 AND 100
     OR p_lease_seconds NOT BETWEEN 1 AND 300 THEN
    RAISE EXCEPTION 'C15 Effect claim is invalid'
      USING ERRCODE = '42501',
            CONSTRAINT = 'c15_worker_scope_guard';
  END IF;
  RETURN QUERY
  WITH candidates AS MATERIALIZED (
    SELECT outbox.tenant_id,
           outbox.effect_id,
           gen_random_uuid()::text AS lease_token
      FROM aios_decision.effect_outbox AS outbox
     WHERE outbox.tenant_id = p_tenant_id
       AND (
         (
           outbox.status IN ('PENDING', 'FAILED')
           AND outbox.available_at <= statement_timestamp()
         )
         OR (
           outbox.status = 'PROCESSING'
           AND outbox.lease_until <= statement_timestamp()
         )
       )
     ORDER BY outbox.created_at, outbox.effect_id
     FOR UPDATE SKIP LOCKED
     LIMIT p_limit
  ),
  claimed AS (
    UPDATE aios_decision.effect_outbox AS outbox
       SET status = 'PROCESSING',
           attempt_count = outbox.attempt_count + 1,
           lease_version = outbox.lease_version + 1,
           leased_by = p_worker_id,
           lease_until = statement_timestamp()
             + make_interval(secs => p_lease_seconds),
           lease_proof_sha256 = 'sha256:' || encode(
             sha256(convert_to(candidates.lease_token, 'UTF8')),
             'hex'
           ),
           last_error_code = NULL
      FROM candidates
     WHERE outbox.tenant_id = candidates.tenant_id
       AND outbox.effect_id = candidates.effect_id
    RETURNING outbox.*, candidates.lease_token
  )
  SELECT claimed.tenant_id,
         claimed.tenant_kind,
         claimed.effect_id,
         claimed.status,
         claimed.attempt_count,
         claimed.lease_version,
         claimed.leased_by,
         claimed.lease_until,
         claimed.lease_token,
         claimed.available_at,
         claimed.published_at,
         claimed.last_error_code,
         claimed.created_at,
         workflow.effect,
         workflow.status,
         workflow.commit_receipt,
         workflow.readback_receipt,
         workflow.compensation_receipt,
         workflow.updated_at
    FROM claimed
    JOIN aios_decision.workflow_effect AS workflow
      ON workflow.tenant_id = claimed.tenant_id
     AND workflow.effect_id = claimed.effect_id
   ORDER BY claimed.created_at, claimed.effect_id;
END;
$$;

CREATE FUNCTION aios_decision.complete_effect(
  p_tenant_id text,
  p_effect_id text,
  p_effect_sha256 text,
  p_worker_id text,
  p_lease_version bigint,
  p_lease_token text,
  p_terminal_status text,
  p_commit_receipt jsonb,
  p_readback_receipt jsonb,
  p_compensation_receipt jsonb,
  p_audit_intent_id text
)
RETURNS SETOF aios_decision.workflow_effect
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  changed_rows integer;
BEGIN
  IF aios_data.acquire_runtime_fence() IS NOT TRUE
     OR aios_data.runtime_scope_allows(
       p_tenant_id,
       'SYNTHETIC'
     ) IS NOT TRUE THEN
    RAISE EXCEPTION 'C15 Effect completion escaped scope'
      USING ERRCODE = '42501',
            CONSTRAINT = 'c15_worker_scope_guard';
  END IF;
  PERFORM 1
    FROM aios_decision.effect_outbox AS outbox
   WHERE outbox.tenant_id = p_tenant_id
     AND outbox.effect_id = p_effect_id
     AND outbox.status = 'PROCESSING'
     AND outbox.leased_by = p_worker_id
     AND outbox.lease_version = p_lease_version
     AND outbox.lease_until >= statement_timestamp()
     AND outbox.lease_proof_sha256 = 'sha256:' || encode(
       sha256(convert_to(p_lease_token, 'UTF8')),
       'hex'
     )
   FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'C15 Effect lease is stale'
      USING ERRCODE = '23514',
            CONSTRAINT = 'c15_worker_lease_guard';
  END IF;
  PERFORM 1
    FROM aios_decision.workflow_effect AS workflow
   WHERE workflow.tenant_id = p_tenant_id
     AND workflow.effect_id = p_effect_id
     AND workflow.status = 'QUEUED'
   FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'C15 Effect is already terminal'
      USING ERRCODE = '23514',
            CONSTRAINT = 'c15_effect_terminal_guard';
  END IF;
  IF NOT EXISTS (
    SELECT 1
      FROM aios_decision.workflow_effect AS workflow
     WHERE workflow.tenant_id = p_tenant_id
       AND workflow.effect_id = p_effect_id
       AND workflow.effect_sha256 = p_effect_sha256
  ) THEN
    RAISE EXCEPTION 'C15 claimed Effect binding changed'
      USING ERRCODE = '23514',
            CONSTRAINT = 'c15_claimed_effect_guard';
  END IF;
  IF p_terminal_status NOT IN (
       'SUCCEEDED',
       'COMPENSATED',
       'COMPENSATION_FAILED'
     )
     OR NOT EXISTS (
       SELECT 1
         FROM aios_decision.audit_intent AS intent
         JOIN aios_decision.workflow_effect AS workflow
           ON workflow.tenant_id = intent.tenant_id
          AND workflow.effect_id = p_effect_id
        WHERE intent.tenant_id = p_tenant_id
          AND intent.intent_id = p_audit_intent_id
          AND intent.event_type =
            'SYNTHETIC_EFFECT_' || p_terminal_status
          AND intent.subject_id = workflow.effect_id
          AND intent.subject_sha256 = workflow.effect_sha256
          AND intent.metadata ->> 'artifactId' =
            workflow.artifact_id
          AND intent.metadata ->> 'artifactSha256' =
            workflow.artifact_sha256
          AND intent.metadata ->> 'decisionId' =
            workflow.decision_id
          AND intent.metadata ->> 'decisionSha256' =
            workflow.decision_sha256
          AND intent.metadata ->> 'effectId' =
            workflow.effect_id
          AND intent.metadata ->> 'effectKey' =
            workflow.effect_key
     ) THEN
    RAISE EXCEPTION 'C15 terminal Audit Intent is not bound'
      USING ERRCODE = '23514',
            CONSTRAINT = 'c15_effect_audit_binding_guard';
  END IF;
  UPDATE aios_decision.workflow_effect AS workflow
     SET status = p_terminal_status,
         commit_receipt = p_commit_receipt,
         readback_receipt = p_readback_receipt,
         compensation_receipt = p_compensation_receipt,
         terminal_audit_intent_id = p_audit_intent_id,
         updated_at = statement_timestamp()
   WHERE workflow.tenant_id = p_tenant_id
     AND workflow.effect_id = p_effect_id
     AND workflow.status = 'QUEUED';
  GET DIAGNOSTICS changed_rows = ROW_COUNT;
  IF changed_rows <> 1 THEN
    RAISE EXCEPTION 'C15 Effect is already terminal'
      USING ERRCODE = '23514',
            CONSTRAINT = 'c15_effect_terminal_guard';
  END IF;
  UPDATE aios_decision.effect_outbox AS outbox
     SET status = 'PUBLISHED',
         leased_by = NULL,
         lease_until = NULL,
         lease_proof_sha256 = NULL,
         published_at = statement_timestamp(),
         last_error_code = NULL
   WHERE outbox.tenant_id = p_tenant_id
     AND outbox.effect_id = p_effect_id
     AND outbox.status = 'PROCESSING'
     AND outbox.leased_by = p_worker_id
     AND outbox.lease_version = p_lease_version
     AND EXISTS (
       SELECT 1
         FROM aios_decision.workflow_effect AS workflow
        WHERE workflow.tenant_id = outbox.tenant_id
          AND workflow.effect_id = outbox.effect_id
          AND workflow.status IN (
            'SUCCEEDED',
            'COMPENSATED',
            'COMPENSATION_FAILED'
          )
     );
  GET DIAGNOSTICS changed_rows = ROW_COUNT;
  IF changed_rows <> 1 THEN
    RAISE EXCEPTION 'C15 Effect lease is stale'
      USING ERRCODE = '23514',
            CONSTRAINT = 'c15_worker_lease_guard';
  END IF;
  RETURN QUERY
  SELECT workflow.*
    FROM aios_decision.workflow_effect AS workflow
   WHERE workflow.tenant_id = p_tenant_id
     AND workflow.effect_id = p_effect_id;
END;
$$;

CREATE FUNCTION aios_decision.fail_effect_outbox(
  p_tenant_id text,
  p_effect_id text,
  p_worker_id text,
  p_lease_version bigint,
  p_lease_token text,
  p_retry_seconds integer,
  p_error_code text
)
RETURNS SETOF aios_decision.effect_outbox
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
  IF aios_data.acquire_runtime_fence() IS NOT TRUE
     OR aios_data.runtime_scope_allows(
       p_tenant_id,
       'SYNTHETIC'
     ) IS NOT TRUE
     OR p_retry_seconds NOT BETWEEN 0 AND 3600
     OR p_error_code !~ '^[A-Z][A-Z0-9_]{0,63}$' THEN
    RAISE EXCEPTION 'C15 Effect retry is invalid'
      USING ERRCODE = '42501',
            CONSTRAINT = 'c15_worker_scope_guard';
  END IF;
  RETURN QUERY
  UPDATE aios_decision.effect_outbox AS outbox
     SET status = 'FAILED',
         leased_by = NULL,
         lease_until = NULL,
         lease_proof_sha256 = NULL,
         available_at = statement_timestamp()
           + make_interval(secs => p_retry_seconds),
         published_at = NULL,
         last_error_code = p_error_code
   WHERE outbox.tenant_id = p_tenant_id
     AND outbox.effect_id = p_effect_id
     AND outbox.status = 'PROCESSING'
     AND outbox.leased_by = p_worker_id
     AND outbox.lease_version = p_lease_version
     AND outbox.lease_until >= statement_timestamp()
     AND outbox.lease_proof_sha256 = 'sha256:' || encode(
       sha256(convert_to(p_lease_token, 'UTF8')),
       'hex'
     )
  RETURNING outbox.*;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'C15 Effect lease is stale'
      USING ERRCODE = '23514',
            CONSTRAINT = 'c15_worker_lease_guard';
  END IF;
END;
$$;

CREATE FUNCTION aios_decision.claim_audit_outbox(
  p_tenant_id text,
  p_worker_id text,
  p_limit integer,
  p_lease_seconds integer
)
RETURNS TABLE (
  tenant_id text,
  tenant_kind text,
  intent_id text,
  outbox_status text,
  attempt_count bigint,
  lease_version bigint,
  leased_by text,
  lease_until timestamptz,
  lease_token text,
  available_at timestamptz,
  published_at timestamptz,
  last_error_code text,
  c18_receipt_key text,
  c18_event_id text,
  c18_event_hash text,
  outbox_created_at timestamptz,
  metadata jsonb,
  intent_sha256 text,
  intent_created_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
  IF aios_data.acquire_runtime_fence() IS NOT TRUE
     OR aios_data.runtime_scope_allows(
       p_tenant_id,
       'SYNTHETIC'
     ) IS NOT TRUE
     OR char_length(btrim(p_worker_id)) NOT BETWEEN 1 AND 128
     OR p_limit NOT BETWEEN 1 AND 100
     OR p_lease_seconds NOT BETWEEN 1 AND 300 THEN
    RAISE EXCEPTION 'C15 Audit claim is invalid'
      USING ERRCODE = '42501',
            CONSTRAINT = 'c15_worker_scope_guard';
  END IF;
  RETURN QUERY
  WITH candidates AS MATERIALIZED (
    SELECT outbox.tenant_id,
           outbox.intent_id,
           gen_random_uuid()::text AS lease_token
      FROM aios_decision.audit_outbox AS outbox
     WHERE outbox.tenant_id = p_tenant_id
       AND (
         (
           outbox.status IN ('PENDING', 'FAILED')
           AND outbox.available_at <= statement_timestamp()
         )
         OR (
           outbox.status = 'PROCESSING'
           AND outbox.lease_until <= statement_timestamp()
         )
       )
     ORDER BY outbox.created_at, outbox.intent_id
     FOR UPDATE SKIP LOCKED
     LIMIT p_limit
  ),
  claimed AS (
    UPDATE aios_decision.audit_outbox AS outbox
       SET status = 'PROCESSING',
           attempt_count = outbox.attempt_count + 1,
           lease_version = outbox.lease_version + 1,
           leased_by = p_worker_id,
           lease_until = statement_timestamp()
             + make_interval(secs => p_lease_seconds),
           lease_proof_sha256 = 'sha256:' || encode(
             sha256(convert_to(candidates.lease_token, 'UTF8')),
             'hex'
           ),
           last_error_code = NULL
      FROM candidates
     WHERE outbox.tenant_id = candidates.tenant_id
       AND outbox.intent_id = candidates.intent_id
    RETURNING outbox.*, candidates.lease_token
  )
  SELECT claimed.tenant_id,
         claimed.tenant_kind,
         claimed.intent_id,
         claimed.status,
         claimed.attempt_count,
         claimed.lease_version,
         claimed.leased_by,
         claimed.lease_until,
         claimed.lease_token,
         claimed.available_at,
         claimed.published_at,
         claimed.last_error_code,
         claimed.c18_receipt_key,
         claimed.c18_event_id,
         claimed.c18_event_hash,
         claimed.created_at,
         intent.metadata,
         intent.intent_sha256,
         intent.created_at
    FROM claimed
    JOIN aios_decision.audit_intent AS intent
      ON intent.tenant_id = claimed.tenant_id
     AND intent.intent_id = claimed.intent_id
   ORDER BY claimed.created_at, claimed.intent_id;
END;
$$;

CREATE FUNCTION aios_decision.publish_audit_outbox(
  p_tenant_id text,
  p_intent_id text,
  p_worker_id text,
  p_lease_version bigint,
  p_lease_token text,
  p_c18_event_id text,
  p_c18_event_hash text
)
RETURNS SETOF aios_decision.audit_outbox
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
  IF aios_data.acquire_runtime_fence() IS NOT TRUE
     OR aios_data.runtime_scope_allows(
       p_tenant_id,
       'SYNTHETIC'
     ) IS NOT TRUE
     OR NOT EXISTS (
       SELECT 1
         FROM aios_audit.audit_command_receipt AS receipt
         JOIN aios_audit.audit_event AS event
           ON event.tenant_id = receipt.tenant_id
          AND event.event_id = receipt.event_id
        WHERE receipt.tenant_id = p_tenant_id
          AND receipt.idempotency_key = p_intent_id
          AND event.event_id = p_c18_event_id
          AND event.event_hash = p_c18_event_hash
     ) THEN
    RAISE EXCEPTION 'C15 C18 receipt is not persisted'
      USING ERRCODE = '23514',
            CONSTRAINT = 'c15_c18_receipt_guard';
  END IF;
  RETURN QUERY
  UPDATE aios_decision.audit_outbox AS outbox
     SET status = 'PUBLISHED',
         leased_by = NULL,
         lease_until = NULL,
         lease_proof_sha256 = NULL,
         published_at = statement_timestamp(),
         last_error_code = NULL,
         c18_receipt_key = p_intent_id,
         c18_event_id = p_c18_event_id,
         c18_event_hash = p_c18_event_hash
   WHERE outbox.tenant_id = p_tenant_id
     AND outbox.intent_id = p_intent_id
     AND outbox.status = 'PROCESSING'
     AND outbox.leased_by = p_worker_id
     AND outbox.lease_version = p_lease_version
     AND outbox.lease_until >= statement_timestamp()
     AND outbox.lease_proof_sha256 = 'sha256:' || encode(
       sha256(convert_to(p_lease_token, 'UTF8')),
       'hex'
     )
  RETURNING outbox.*;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'C15 Audit lease is stale'
      USING ERRCODE = '23514',
            CONSTRAINT = 'c15_worker_lease_guard';
  END IF;
END;
$$;

CREATE FUNCTION aios_decision.fail_audit_outbox(
  p_tenant_id text,
  p_intent_id text,
  p_worker_id text,
  p_lease_version bigint,
  p_lease_token text,
  p_retry_seconds integer,
  p_error_code text
)
RETURNS SETOF aios_decision.audit_outbox
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
  IF aios_data.acquire_runtime_fence() IS NOT TRUE
     OR aios_data.runtime_scope_allows(
       p_tenant_id,
       'SYNTHETIC'
     ) IS NOT TRUE
     OR p_retry_seconds NOT BETWEEN 0 AND 3600
     OR p_error_code !~ '^[A-Z][A-Z0-9_]{0,63}$' THEN
    RAISE EXCEPTION 'C15 Audit retry is invalid'
      USING ERRCODE = '42501',
            CONSTRAINT = 'c15_worker_scope_guard';
  END IF;
  RETURN QUERY
  UPDATE aios_decision.audit_outbox AS outbox
     SET status = 'FAILED',
         leased_by = NULL,
         lease_until = NULL,
         lease_proof_sha256 = NULL,
         available_at = statement_timestamp()
           + make_interval(secs => p_retry_seconds),
         published_at = NULL,
         last_error_code = p_error_code
   WHERE outbox.tenant_id = p_tenant_id
     AND outbox.intent_id = p_intent_id
     AND outbox.status = 'PROCESSING'
     AND outbox.leased_by = p_worker_id
     AND outbox.lease_version = p_lease_version
     AND outbox.lease_until >= statement_timestamp()
     AND outbox.lease_proof_sha256 = 'sha256:' || encode(
       sha256(convert_to(p_lease_token, 'UTF8')),
       'hex'
     )
  RETURNING outbox.*;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'C15 Audit lease is stale'
      USING ERRCODE = '23514',
            CONSTRAINT = 'c15_worker_lease_guard';
  END IF;
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
