BEGIN;

CREATE SCHEMA aios_model;

CREATE TABLE aios_model.model_route (
  tenant_id text NOT NULL,
  tenant_kind text NOT NULL CHECK (tenant_kind = 'SYNTHETIC'),
  route_id text NOT NULL
    CHECK (route_id ~ '^mrt_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
  status text NOT NULL CHECK (status IN ('PREPARED', 'SUCCEEDED', 'FAILED')),
  version bigint NOT NULL CHECK (version BETWEEN 1 AND 9007199254740991),
  idempotency_key text NOT NULL
    CHECK (char_length(btrim(idempotency_key)) BETWEEN 1 AND 256),
  request_hash text NOT NULL CHECK (request_hash ~ '^sha256:[0-9a-f]{64}$'),
  correlation_id text NOT NULL
    CHECK (char_length(btrim(correlation_id)) BETWEEN 1 AND 256),
  task_ref text NOT NULL
    CHECK (task_ref ~ '^(synthetic|fixture|test|policy)://[^[:space:]]+$'),
  input_ref text NOT NULL
    CHECK (input_ref ~ '^(synthetic|fixture|test|policy)://[^[:space:]]+$'),
  input_sha256 text NOT NULL CHECK (input_sha256 ~ '^sha256:[0-9a-f]{64}$'),
  data_classification text NOT NULL
    CHECK (data_classification IN ('PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'RESTRICTED')),
  required_plane text NOT NULL CHECK (required_plane IN ('ANY', 'LOCAL_ONLY')),
  tenant_region text NOT NULL CHECK (tenant_region IN ('CN', 'EU', 'US')),
  catalog_version text NOT NULL
    CHECK (char_length(btrim(catalog_version)) BETWEEN 1 AND 128),
  catalog_sha256 text NOT NULL CHECK (catalog_sha256 ~ '^sha256:[0-9a-f]{64}$'),
  tenant_policy_version text NOT NULL
    CHECK (char_length(btrim(tenant_policy_version)) BETWEEN 1 AND 128),
  authorization_evidence jsonb NOT NULL
    CHECK (jsonb_typeof(authorization_evidence) = 'object'),
  identity_binding jsonb NOT NULL
    CHECK (jsonb_typeof(identity_binding) = 'object'),
  evaluated_candidates jsonb NOT NULL
    CHECK (jsonb_typeof(evaluated_candidates) = 'array'),
  candidate_bindings jsonb NOT NULL
    CHECK (
      jsonb_typeof(candidate_bindings) = 'array'
      AND jsonb_array_length(candidate_bindings) > 0
    ),
  selected_model jsonb,
  attempt_receipts jsonb NOT NULL DEFAULT '[]'::jsonb
    CHECK (jsonb_typeof(attempt_receipts) = 'array'),
  response_ref text,
  response_sha256 text,
  usage jsonb,
  rate_version text,
  cost_microusd bigint,
  failure_code text,
  reserved_input_tokens bigint NOT NULL
    CHECK (reserved_input_tokens BETWEEN 1 AND 9007199254740991),
  reserved_output_tokens bigint NOT NULL
    CHECK (reserved_output_tokens BETWEEN 1 AND 9007199254740991),
  reserved_cost_microusd bigint NOT NULL
    CHECK (reserved_cost_microusd BETWEEN 0 AND 9007199254740991),
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, route_id),
  UNIQUE (tenant_id, idempotency_key),
  FOREIGN KEY (tenant_id, tenant_kind)
    REFERENCES aios_core.tenant_registry(tenant_id, tenant_kind)
    ON DELETE RESTRICT,
  CHECK (updated_at >= created_at),
  CHECK (
    selected_model IS NULL OR jsonb_typeof(selected_model) = 'object'
  ),
  CHECK (usage IS NULL OR jsonb_typeof(usage) = 'object'),
  CHECK (
    response_ref IS NULL
    OR response_ref ~ '^(synthetic|fixture|test|policy)://[^[:space:]]+$'
  ),
  CHECK (
    response_sha256 IS NULL
    OR response_sha256 ~ '^sha256:[0-9a-f]{64}$'
  ),
  CHECK (
    cost_microusd IS NULL
    OR cost_microusd BETWEEN 0 AND 9007199254740991
  ),
  CONSTRAINT model_route_state_shape CHECK (
    (
      status = 'PREPARED'
      AND version = 1
      AND selected_model IS NULL
      AND attempt_receipts = '[]'::jsonb
      AND response_ref IS NULL
      AND response_sha256 IS NULL
      AND usage IS NULL
      AND rate_version IS NULL
      AND cost_microusd IS NULL
      AND failure_code IS NULL
    )
    OR
    (
      status = 'SUCCEEDED'
      AND version = 2
      AND selected_model IS NOT NULL
      AND jsonb_array_length(attempt_receipts) > 0
      AND response_ref IS NOT NULL
      AND response_sha256 IS NOT NULL
      AND usage IS NOT NULL
      AND rate_version IS NOT NULL
      AND cost_microusd IS NOT NULL
      AND failure_code IS NULL
    )
    OR
    (
      status = 'FAILED'
      AND version = 2
      AND selected_model IS NULL
      AND jsonb_array_length(attempt_receipts) > 0
      AND response_ref IS NULL
      AND response_sha256 IS NULL
      AND usage IS NULL
      AND rate_version IS NULL
      AND cost_microusd IS NULL
      AND failure_code IS NOT NULL
    )
  )
);

CREATE INDEX model_route_usage_bucket_idx
  ON aios_model.model_route (tenant_id, created_at)
  WHERE status <> 'FAILED';

CREATE FUNCTION aios_model.reject_route_delete()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION 'C14 route history is append-preserving'
    USING ERRCODE = '23514',
          CONSTRAINT = 'model_route_delete_guard';
END;
$$;

CREATE FUNCTION aios_model.enforce_route_update()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF OLD.status <> 'PREPARED'
     OR NEW.status NOT IN ('SUCCEEDED', 'FAILED')
     OR NEW.version <> OLD.version + 1
     OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
     OR NEW.tenant_kind IS DISTINCT FROM OLD.tenant_kind
     OR NEW.route_id IS DISTINCT FROM OLD.route_id
     OR NEW.idempotency_key IS DISTINCT FROM OLD.idempotency_key
     OR NEW.request_hash IS DISTINCT FROM OLD.request_hash
     OR NEW.correlation_id IS DISTINCT FROM OLD.correlation_id
     OR NEW.task_ref IS DISTINCT FROM OLD.task_ref
     OR NEW.input_ref IS DISTINCT FROM OLD.input_ref
     OR NEW.input_sha256 IS DISTINCT FROM OLD.input_sha256
     OR NEW.data_classification IS DISTINCT FROM OLD.data_classification
     OR NEW.required_plane IS DISTINCT FROM OLD.required_plane
     OR NEW.tenant_region IS DISTINCT FROM OLD.tenant_region
     OR NEW.catalog_version IS DISTINCT FROM OLD.catalog_version
     OR NEW.catalog_sha256 IS DISTINCT FROM OLD.catalog_sha256
     OR NEW.tenant_policy_version IS DISTINCT FROM OLD.tenant_policy_version
     OR NEW.authorization_evidence IS DISTINCT FROM OLD.authorization_evidence
     OR NEW.identity_binding IS DISTINCT FROM OLD.identity_binding
     OR NEW.evaluated_candidates IS DISTINCT FROM OLD.evaluated_candidates
     OR NEW.candidate_bindings IS DISTINCT FROM OLD.candidate_bindings
     OR NEW.reserved_input_tokens IS DISTINCT FROM OLD.reserved_input_tokens
     OR NEW.reserved_output_tokens IS DISTINCT FROM OLD.reserved_output_tokens
     OR NEW.reserved_cost_microusd IS DISTINCT FROM OLD.reserved_cost_microusd
     OR NEW.created_at IS DISTINCT FROM OLD.created_at
     OR NEW.updated_at < OLD.updated_at THEN
    RAISE EXCEPTION 'C14 route transition or immutable binding changed'
      USING ERRCODE = '23514',
            CONSTRAINT = 'model_route_transition_guard';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER model_route_delete_guard
BEFORE DELETE ON aios_model.model_route
FOR EACH ROW EXECUTE FUNCTION aios_model.reject_route_delete();

CREATE TRIGGER model_route_transition_guard
BEFORE UPDATE ON aios_model.model_route
FOR EACH ROW EXECUTE FUNCTION aios_model.enforce_route_update();

ALTER TABLE aios_model.model_route ENABLE ROW LEVEL SECURITY;
ALTER TABLE aios_model.model_route FORCE ROW LEVEL SECURITY;

COMMIT;
