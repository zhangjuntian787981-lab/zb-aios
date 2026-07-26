BEGIN;

CREATE EXTENSION IF NOT EXISTS vector;
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE SCHEMA aios_data;

CREATE TABLE aios_data.tenant_data_lifecycle (
  tenant_id text NOT NULL,
  tenant_kind text NOT NULL,
  lifecycle_version bigint NOT NULL,
  generation bigint NOT NULL,
  operation_id text NOT NULL,
  state text NOT NULL,
  last_event_id text NOT NULL,
  updated_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id),
  UNIQUE (tenant_id, tenant_kind),
  FOREIGN KEY (tenant_id, tenant_kind)
    REFERENCES aios_core.tenant_registry (tenant_id, tenant_kind)
    ON DELETE RESTRICT,
  CHECK (tenant_kind = 'SYNTHETIC'),
  CHECK (lifecycle_version > 0),
  CHECK (generation > 0),
  CHECK (
    state IN (
      'PROVISIONING',
      'ACTIVE',
      'SUSPENDED',
      'DELETING',
      'DELETED'
    )
  )
);

CREATE TABLE aios_data.tenant_data_event_receipt (
  event_id text PRIMARY KEY,
  tenant_id text NOT NULL,
  tenant_kind text NOT NULL,
  lifecycle_version bigint NOT NULL,
  generation bigint NOT NULL,
  operation_id text NOT NULL,
  event_type text NOT NULL,
  event_sha256 text NOT NULL,
  event jsonb NOT NULL,
  applied_at timestamptz NOT NULL,
  FOREIGN KEY (tenant_id, tenant_kind)
    REFERENCES aios_data.tenant_data_lifecycle (tenant_id, tenant_kind)
    ON DELETE RESTRICT,
  UNIQUE (tenant_id, lifecycle_version),
  CHECK (tenant_kind = 'SYNTHETIC'),
  CHECK (lifecycle_version > 0),
  CHECK (generation > 0),
  CHECK (event_sha256 ~ '^sha256:[a-f0-9]{64}$'),
  CHECK ((event ->> 'id') IS NOT DISTINCT FROM event_id),
  CHECK ((event ->> 'subject') IS NOT DISTINCT FROM tenant_id),
  CHECK ((event ->> 'tenantkind') IS NOT DISTINCT FROM tenant_kind),
  CHECK (
    (event -> 'data' ->> 'tenant_id') IS NOT DISTINCT FROM tenant_id
  ),
  CHECK (
    (event -> 'data' ->> 'lifecycle_version')::bigint
      IS NOT DISTINCT FROM lifecycle_version
  )
);

CREATE TABLE aios_data.tenant_sql_record (
  tenant_id text NOT NULL,
  tenant_kind text NOT NULL,
  resource_id text NOT NULL,
  value jsonb NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT statement_timestamp(),
  PRIMARY KEY (tenant_id, resource_id),
  FOREIGN KEY (tenant_id, tenant_kind)
    REFERENCES aios_data.tenant_data_lifecycle (tenant_id, tenant_kind)
    ON DELETE RESTRICT,
  CHECK (tenant_kind = 'SYNTHETIC'),
  CHECK (length(resource_id) BETWEEN 1 AND 128)
);

CREATE TABLE aios_data.tenant_vector_record (
  tenant_id text NOT NULL,
  tenant_kind text NOT NULL,
  resource_id text NOT NULL,
  embedding vector NOT NULL,
  metadata jsonb NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT statement_timestamp(),
  PRIMARY KEY (tenant_id, resource_id),
  FOREIGN KEY (tenant_id, tenant_kind)
    REFERENCES aios_data.tenant_data_lifecycle (tenant_id, tenant_kind)
    ON DELETE RESTRICT,
  CHECK (tenant_kind = 'SYNTHETIC'),
  CHECK (length(resource_id) BETWEEN 1 AND 128),
  CHECK (vector_dims(embedding) BETWEEN 1 AND 2048)
);

CREATE TABLE aios_data.tenant_search_record (
  tenant_id text NOT NULL,
  tenant_kind text NOT NULL,
  resource_id text NOT NULL,
  content text NOT NULL,
  metadata jsonb NOT NULL,
  search_document tsvector
    GENERATED ALWAYS AS (to_tsvector('simple', content)) STORED,
  updated_at timestamptz NOT NULL DEFAULT statement_timestamp(),
  PRIMARY KEY (tenant_id, resource_id),
  FOREIGN KEY (tenant_id, tenant_kind)
    REFERENCES aios_data.tenant_data_lifecycle (tenant_id, tenant_kind)
    ON DELETE RESTRICT,
  CHECK (tenant_kind = 'SYNTHETIC'),
  CHECK (length(resource_id) BETWEEN 1 AND 128),
  CHECK (length(content) BETWEEN 1 AND 1048576)
);

CREATE INDEX tenant_search_document_idx
  ON aios_data.tenant_search_record
  USING gin (search_document);

CREATE TABLE aios_data.tenant_cache_record (
  tenant_id text NOT NULL,
  tenant_kind text NOT NULL,
  cache_key text NOT NULL,
  value jsonb NOT NULL,
  expires_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT statement_timestamp(),
  PRIMARY KEY (tenant_id, cache_key),
  FOREIGN KEY (tenant_id, tenant_kind)
    REFERENCES aios_data.tenant_data_lifecycle (tenant_id, tenant_kind)
    ON DELETE RESTRICT,
  CHECK (tenant_kind = 'SYNTHETIC'),
  CHECK (length(cache_key) BETWEEN 1 AND 256)
);

CREATE TABLE aios_data.runtime_scope_signing_secret (
  singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
  secret bytea NOT NULL CHECK (octet_length(secret) = 32),
  created_at timestamptz NOT NULL DEFAULT statement_timestamp()
);

INSERT INTO aios_data.runtime_scope_signing_secret (singleton, secret)
VALUES (true, public.gen_random_bytes(32));

CREATE FUNCTION aios_data.issue_runtime_scope_signature(
  scope_tenant_id text,
  scope_tenant_kind text,
  scope_lifecycle_version bigint,
  scope_correlation_id text,
  scope_decision_id text,
  scope_evidence_ref text,
  scope_policy_version text,
  scope_backend_pid integer,
  scope_transaction_id xid8,
  scope_ttl_seconds integer,
  scope_nonce uuid
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, aios_data
AS $$
DECLARE
  signing_secret bytea;
  now_epoch_ms bigint;
  expires_epoch_ms bigint;
  payload text;
BEGIN
  now_epoch_ms :=
    floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint;
  IF
    scope_tenant_id IS NULL
    OR scope_tenant_kind IS NULL
    OR scope_lifecycle_version IS NULL
    OR scope_correlation_id IS NULL
    OR scope_decision_id IS NULL
    OR scope_evidence_ref IS NULL
    OR scope_policy_version IS NULL
    OR scope_backend_pid IS NULL
    OR scope_transaction_id IS NULL
    OR scope_ttl_seconds IS NULL
    OR scope_nonce IS NULL
    OR scope_tenant_kind <> 'SYNTHETIC'
    OR scope_lifecycle_version < 1
    OR length(scope_correlation_id) NOT BETWEEN 1 AND 128
    OR length(scope_decision_id) NOT BETWEEN 1 AND 256
    OR length(scope_evidence_ref) NOT BETWEEN 1 AND 512
    OR length(scope_policy_version) NOT BETWEEN 1 AND 256
    OR scope_backend_pid < 1
    OR scope_ttl_seconds NOT BETWEEN 1 AND 30
    OR NOT EXISTS (
      SELECT 1
        FROM aios_data.tenant_data_lifecycle AS lifecycle
       WHERE lifecycle.tenant_id = scope_tenant_id
         AND lifecycle.tenant_kind = scope_tenant_kind
         AND lifecycle.lifecycle_version = scope_lifecycle_version
         AND lifecycle.state = 'ACTIVE'
    )
  THEN
    RAISE EXCEPTION 'runtime scope cannot be signed'
      USING ERRCODE = '42501';
  END IF;

  expires_epoch_ms :=
    now_epoch_ms + (scope_ttl_seconds::bigint * 1000);

  SELECT secret
    INTO STRICT signing_secret
    FROM aios_data.runtime_scope_signing_secret
   WHERE singleton;

  payload := jsonb_build_array(
    scope_tenant_id,
    scope_tenant_kind,
    scope_lifecycle_version::text,
    scope_correlation_id,
    scope_decision_id,
    scope_evidence_ref,
    scope_policy_version,
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

CREATE FUNCTION aios_data.runtime_scope_allows(
  row_tenant_id text,
  row_tenant_kind text
)
RETURNS boolean
LANGUAGE sql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, aios_data
AS $$
  WITH scope AS (
    SELECT
      current_setting('aios.tenant_id', true) AS tenant_id,
      current_setting('aios.tenant_kind', true) AS tenant_kind,
      current_setting('aios.lifecycle_version', true)
        AS lifecycle_version,
      current_setting('aios.correlation_id', true) AS correlation_id,
      current_setting('aios.decision_id', true) AS decision_id,
      current_setting('aios.evidence_ref', true) AS evidence_ref,
      current_setting('aios.policy_version', true) AS policy_version,
      current_setting('aios.backend_pid', true) AS backend_pid,
      current_setting('aios.transaction_id', true) AS transaction_id,
      current_setting('aios.expires_epoch_ms', true)
        AS expires_epoch_ms,
      current_setting('aios.scope_nonce', true) AS scope_nonce,
      current_setting('aios.scope_signature', true) AS scope_signature
  )
  SELECT
    row_tenant_kind = 'SYNTHETIC'
    AND scope.tenant_id IS NOT NULL
    AND scope.tenant_kind IS NOT NULL
    AND scope.lifecycle_version IS NOT NULL
    AND scope.correlation_id IS NOT NULL
    AND scope.decision_id IS NOT NULL
    AND scope.evidence_ref IS NOT NULL
    AND scope.policy_version IS NOT NULL
    AND scope.backend_pid IS NOT NULL
    AND scope.transaction_id IS NOT NULL
    AND scope.expires_epoch_ms IS NOT NULL
    AND scope.scope_nonce IS NOT NULL
    AND row_tenant_id = scope.tenant_id
    AND scope.tenant_kind = 'SYNTHETIC'
    AND scope.lifecycle_version ~ '^[1-9][0-9]*$'
    AND scope.backend_pid ~ '^[1-9][0-9]*$'
    AND scope.expires_epoch_ms ~ '^[1-9][0-9]*$'
    AND CASE
          WHEN scope.backend_pid ~ '^[1-9][0-9]*$'
          THEN scope.backend_pid::integer
          ELSE NULL
        END = pg_backend_pid()
    AND scope.transaction_id = pg_current_xact_id()::text
    AND CASE
          WHEN scope.expires_epoch_ms ~ '^[1-9][0-9]*$'
          THEN scope.expires_epoch_ms::bigint
          ELSE NULL
        END >
        floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint
    AND scope.scope_signature ~ '^[a-f0-9]{64}$'
    AND scope.scope_signature = encode(
      public.hmac(
        convert_to(
          jsonb_build_array(
            scope.tenant_id,
            scope.tenant_kind,
            scope.lifecycle_version,
            scope.correlation_id,
            scope.decision_id,
            scope.evidence_ref,
            scope.policy_version,
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
        FROM aios_data.tenant_data_lifecycle AS lifecycle
       WHERE lifecycle.tenant_id = row_tenant_id
         AND lifecycle.tenant_kind = row_tenant_kind
         AND lifecycle.state = 'ACTIVE'
         AND lifecycle.lifecycle_version =
             CASE
               WHEN scope.lifecycle_version ~ '^[1-9][0-9]*$'
               THEN scope.lifecycle_version::bigint
               ELSE NULL
             END
    )
    FROM scope
    CROSS JOIN aios_data.runtime_scope_signing_secret AS secret
   WHERE secret.singleton
$$;

CREATE FUNCTION aios_data.acquire_runtime_fence()
RETURNS boolean
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, aios_data
AS $$
DECLARE
  matched boolean;
BEGIN
  SELECT true
    INTO matched
    FROM aios_data.tenant_data_lifecycle AS lifecycle
   WHERE lifecycle.tenant_id =
         current_setting('aios.tenant_id', true)
     AND lifecycle.tenant_kind =
         current_setting('aios.tenant_kind', true)
     AND aios_data.runtime_scope_allows(
       lifecycle.tenant_id,
       lifecycle.tenant_kind
     )
   FOR SHARE;
  RETURN coalesce(matched, false);
END
$$;

CREATE FUNCTION aios_data.lifecycle_scope_matches(
  row_tenant_id text,
  row_tenant_kind text
)
RETURNS boolean
LANGUAGE sql
STABLE
SET search_path = pg_catalog
AS $$
  SELECT
    row_tenant_kind = 'SYNTHETIC'
    AND row_tenant_id = current_setting('aios.tenant_id', true)
    AND current_setting('aios.tenant_kind', true) = 'SYNTHETIC'
$$;

ALTER TABLE aios_data.tenant_data_lifecycle
  ENABLE ROW LEVEL SECURITY;
ALTER TABLE aios_data.tenant_data_lifecycle
  FORCE ROW LEVEL SECURITY;
ALTER TABLE aios_data.tenant_data_event_receipt
  ENABLE ROW LEVEL SECURITY;
ALTER TABLE aios_data.tenant_data_event_receipt
  FORCE ROW LEVEL SECURITY;
ALTER TABLE aios_data.tenant_sql_record
  ENABLE ROW LEVEL SECURITY;
ALTER TABLE aios_data.tenant_sql_record
  FORCE ROW LEVEL SECURITY;
ALTER TABLE aios_data.tenant_vector_record
  ENABLE ROW LEVEL SECURITY;
ALTER TABLE aios_data.tenant_vector_record
  FORCE ROW LEVEL SECURITY;
ALTER TABLE aios_data.tenant_search_record
  ENABLE ROW LEVEL SECURITY;
ALTER TABLE aios_data.tenant_search_record
  FORCE ROW LEVEL SECURITY;
ALTER TABLE aios_data.tenant_cache_record
  ENABLE ROW LEVEL SECURITY;
ALTER TABLE aios_data.tenant_cache_record
  FORCE ROW LEVEL SECURITY;

COMMIT;
