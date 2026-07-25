BEGIN;

CREATE SCHEMA IF NOT EXISTS aios_core;

CREATE TABLE aios_core.tenant_registry (
  tenant_id text PRIMARY KEY,
  tenant_kind text NOT NULL,
  state text NOT NULL,
  lifecycle_version bigint NOT NULL CHECK (lifecycle_version > 0),
  generation bigint NOT NULL CHECK (generation > 0),
  creation_key text NOT NULL UNIQUE,
  origin_ref text NOT NULL UNIQUE,
  origin_hash text NOT NULL
    CHECK (origin_hash ~ '^sha256:[0-9a-f]{64}$'),
  config_refs jsonb NOT NULL DEFAULT '[]'::jsonb
    CHECK (jsonb_typeof(config_refs) = 'array'),
  resource_namespace_id text NOT NULL UNIQUE,
  operation_id text NOT NULL
    CHECK (
      operation_id ~ '^op_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  UNIQUE (tenant_id, tenant_kind),
  CHECK (tenant_kind IN ('SYNTHETIC', 'ENTERPRISE')),
  CHECK (
    state IN (
      'PROVISIONING',
      'ACTIVE',
      'SUSPENDED',
      'DELETING',
      'DELETED'
    )
  ),
  CHECK (
    (
      tenant_kind = 'SYNTHETIC'
      AND tenant_id ~ '^stn_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
      AND resource_namespace_id ~ '^sns_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    )
    OR
    (
      tenant_kind = 'ENTERPRISE'
      AND tenant_id ~ '^etn_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
      AND resource_namespace_id ~ '^ens_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    )
  )
);

CREATE TABLE aios_core.tenant_command_receipt (
  idempotency_key text PRIMARY KEY,
  command_hash text NOT NULL
    CHECK (command_hash ~ '^sha256:[0-9a-f]{64}$'),
  result jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE aios_core.tenant_projection (
  tenant_id text NOT NULL
    REFERENCES aios_core.tenant_registry(tenant_id) ON DELETE RESTRICT,
  generation bigint NOT NULL CHECK (generation > 0),
  projection text NOT NULL,
  desired_action text NOT NULL,
  status text NOT NULL,
  attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
  last_error_code text,
  source_event_id text,
  updated_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, generation, projection),
  CHECK (
    projection IN (
      'AUTHORIZATION',
      'IDENTITY',
      'KNOWLEDGE',
      'SECRET_REFS',
      'STORAGE'
    )
  ),
  CHECK (desired_action IN ('PROVISION', 'DELETE')),
  CHECK (status IN ('PENDING', 'READY', 'FAILED', 'DELETED')),
  CHECK (
    (desired_action = 'PROVISION' AND status <> 'DELETED')
    OR desired_action = 'DELETE'
  )
);

CREATE TABLE aios_core.tenant_lifecycle_event (
  event_id text PRIMARY KEY,
  tenant_id text NOT NULL,
  tenant_kind text NOT NULL,
  event jsonb NOT NULL,
  created_at timestamptz NOT NULL,
  FOREIGN KEY (tenant_id, tenant_kind)
    REFERENCES aios_core.tenant_registry(tenant_id, tenant_kind)
    ON DELETE RESTRICT,
  CHECK ((event ->> 'specversion') IS NOT DISTINCT FROM '1.0'),
  CHECK ((event ->> 'subject') IS NOT DISTINCT FROM tenant_id),
  CHECK ((event ->> 'tenantkind') IS NOT DISTINCT FROM tenant_kind),
  CHECK (
    (
      tenant_kind = 'SYNTHETIC'
      AND jsonb_typeof(event -> 'synthetic') IS NOT DISTINCT FROM 'boolean'
      AND (event ->> 'synthetic') IS NOT DISTINCT FROM 'true'
    )
    OR
    (
      tenant_kind = 'ENTERPRISE'
      AND jsonb_typeof(event -> 'synthetic') IS NOT DISTINCT FROM 'boolean'
      AND (event ->> 'synthetic') IS NOT DISTINCT FROM 'false'
    )
  ),
  CHECK (jsonb_typeof(event -> 'data') IS NOT DISTINCT FROM 'object')
);

CREATE TABLE aios_core.tenant_outbox (
  event_id text PRIMARY KEY,
  tenant_id text NOT NULL,
  tenant_kind text NOT NULL,
  event jsonb NOT NULL,
  status text NOT NULL DEFAULT 'PENDING',
  attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
  lease_version bigint NOT NULL DEFAULT 0 CHECK (lease_version >= 0),
  available_at timestamptz NOT NULL DEFAULT now(),
  leased_by text,
  lease_until timestamptz,
  last_error_code text,
  created_at timestamptz NOT NULL,
  published_at timestamptz,
  FOREIGN KEY (tenant_id, tenant_kind)
    REFERENCES aios_core.tenant_registry(tenant_id, tenant_kind)
    ON DELETE RESTRICT,
  CHECK (status IN ('PENDING', 'PROCESSING', 'PUBLISHED', 'FAILED')),
  CHECK ((event ->> 'specversion') IS NOT DISTINCT FROM '1.0'),
  CHECK ((event ->> 'subject') IS NOT DISTINCT FROM tenant_id),
  CHECK ((event ->> 'tenantkind') IS NOT DISTINCT FROM tenant_kind),
  CHECK (
    (
      tenant_kind = 'SYNTHETIC'
      AND jsonb_typeof(event -> 'synthetic') IS NOT DISTINCT FROM 'boolean'
      AND (event ->> 'synthetic') IS NOT DISTINCT FROM 'true'
    )
    OR
    (
      tenant_kind = 'ENTERPRISE'
      AND jsonb_typeof(event -> 'synthetic') IS NOT DISTINCT FROM 'boolean'
      AND (event ->> 'synthetic') IS NOT DISTINCT FROM 'false'
    )
  ),
  CHECK (jsonb_typeof(event -> 'data') IS NOT DISTINCT FROM 'object')
);

CREATE INDEX tenant_outbox_claim_idx
  ON aios_core.tenant_outbox(status, available_at, lease_until, created_at);

CREATE INDEX tenant_lifecycle_event_tenant_idx
  ON aios_core.tenant_lifecycle_event(tenant_id, created_at, event_id);

CREATE FUNCTION aios_core.enforce_tenant_initial_state()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF NEW.state <> 'PROVISIONING'
    OR NEW.lifecycle_version <> 1
    OR NEW.generation <> 1
  THEN
    RAISE EXCEPTION 'new tenant must start at provisioning version one'
      USING ERRCODE = '23000';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER tenant_registry_initial_state_guard
BEFORE INSERT ON aios_core.tenant_registry
FOR EACH ROW EXECUTE FUNCTION aios_core.enforce_tenant_initial_state();

CREATE FUNCTION aios_core.reject_tenant_identity_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
    OR NEW.tenant_kind IS DISTINCT FROM OLD.tenant_kind
    OR NEW.creation_key IS DISTINCT FROM OLD.creation_key
    OR NEW.origin_ref IS DISTINCT FROM OLD.origin_ref
    OR NEW.origin_hash IS DISTINCT FROM OLD.origin_hash
    OR NEW.resource_namespace_id IS DISTINCT FROM OLD.resource_namespace_id
  THEN
    RAISE EXCEPTION 'tenant identity and origin are immutable'
      USING ERRCODE = '23000';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER tenant_registry_identity_immutable
BEFORE UPDATE ON aios_core.tenant_registry
FOR EACH ROW EXECUTE FUNCTION aios_core.reject_tenant_identity_mutation();

CREATE FUNCTION aios_core.enforce_tenant_lifecycle_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF NEW.lifecycle_version <> OLD.lifecycle_version + 1 THEN
    RAISE EXCEPTION 'tenant lifecycle version must increase by one'
      USING ERRCODE = '23000';
  END IF;

  IF NOT (
    (OLD.state = 'PROVISIONING' AND NEW.state IN ('ACTIVE', 'SUSPENDED', 'DELETING'))
    OR (OLD.state = 'ACTIVE' AND NEW.state IN ('SUSPENDED', 'DELETING'))
    OR (OLD.state = 'SUSPENDED' AND NEW.state IN ('PROVISIONING', 'DELETING'))
    OR (OLD.state = 'DELETING' AND NEW.state = 'DELETED')
  ) THEN
    RAISE EXCEPTION 'invalid tenant lifecycle transition'
      USING ERRCODE = '23000';
  END IF;

  IF NEW.state IN ('PROVISIONING', 'DELETING')
    AND NEW.generation <> OLD.generation + 1
  THEN
    RAISE EXCEPTION 'new projection plan requires the next generation'
      USING ERRCODE = '23000';
  END IF;

  IF NEW.state NOT IN ('PROVISIONING', 'DELETING')
    AND NEW.generation <> OLD.generation
  THEN
    RAISE EXCEPTION 'generation changed without a new projection plan'
      USING ERRCODE = '23000';
  END IF;

  IF NEW.generation > OLD.generation
    AND NEW.operation_id IS NOT DISTINCT FROM OLD.operation_id
  THEN
    RAISE EXCEPTION 'new projection plan requires a new operation'
      USING ERRCODE = '23000';
  END IF;

  IF NEW.state = 'ACTIVE' AND (
    SELECT count(*)
      FROM aios_core.tenant_projection
     WHERE tenant_id = NEW.tenant_id
       AND generation = NEW.generation
       AND desired_action = 'PROVISION'
       AND status = 'READY'
  ) <> 5 THEN
    RAISE EXCEPTION 'tenant cannot activate before all projections are ready'
      USING ERRCODE = '23000';
  END IF;

  IF NEW.state = 'DELETED' AND (
    SELECT count(*)
      FROM aios_core.tenant_projection
     WHERE tenant_id = NEW.tenant_id
       AND generation = NEW.generation
       AND desired_action = 'DELETE'
       AND status = 'DELETED'
  ) <> 5 THEN
    RAISE EXCEPTION 'tenant cannot finalize deletion before all projections finish'
      USING ERRCODE = '23000';
  END IF;

  RETURN NEW;
END;
$$;

CREATE TRIGGER tenant_registry_lifecycle_guard
BEFORE UPDATE ON aios_core.tenant_registry
FOR EACH ROW EXECUTE FUNCTION aios_core.enforce_tenant_lifecycle_transition();

CREATE FUNCTION aios_core.reject_tenant_registry_delete()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION 'tenant registry rows are permanent tombstones'
    USING ERRCODE = '23000';
  RETURN OLD;
END;
$$;

CREATE TRIGGER tenant_registry_no_delete
BEFORE DELETE ON aios_core.tenant_registry
FOR EACH ROW EXECUTE FUNCTION aios_core.reject_tenant_registry_delete();

CREATE FUNCTION aios_core.reject_append_only_change()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION 'append-only record cannot be changed'
    USING ERRCODE = '23000';
  RETURN OLD;
END;
$$;

CREATE TRIGGER tenant_command_receipt_no_update
BEFORE UPDATE OR DELETE ON aios_core.tenant_command_receipt
FOR EACH ROW EXECUTE FUNCTION aios_core.reject_append_only_change();

CREATE TRIGGER tenant_lifecycle_event_no_update
BEFORE UPDATE OR DELETE ON aios_core.tenant_lifecycle_event
FOR EACH ROW EXECUTE FUNCTION aios_core.reject_append_only_change();

COMMIT;
