BEGIN;

-- This migration runs after C04 0006_identity_runtime_roles.sql.
-- C05 records identity provenance only. It does not grant business access.

CREATE TABLE aios_core.principal_registry (
  principal_id text PRIMARY KEY
    CHECK (
      principal_id ~ '^prn_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
  tenant_id text NOT NULL,
  tenant_kind text NOT NULL CHECK (tenant_kind = 'SYNTHETIC'),
  principal_kind text NOT NULL
    CHECK (principal_kind IN ('HUMAN', 'AGENT', 'SERVICE')),
  creation_key text NOT NULL
    CHECK (char_length(btrim(creation_key)) BETWEEN 1 AND 256),
  state text NOT NULL
    CHECK (state IN ('ACTIVE', 'SUSPENDED', 'DEACTIVATED')),
  lifecycle_version bigint NOT NULL
    CHECK (
      lifecycle_version > 0
      AND lifecycle_version <= 9007199254740991
    ),
  security_epoch bigint NOT NULL
    CHECK (
      security_epoch > 0
      AND security_epoch <= 9007199254740991
    ),
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  CONSTRAINT principal_registry_creation_key
    UNIQUE (tenant_id, creation_key),
  CONSTRAINT principal_registry_tenant_identity_key
    UNIQUE (principal_id, tenant_id, tenant_kind, principal_kind),
  CONSTRAINT principal_registry_tenant_fkey
    FOREIGN KEY (tenant_id, tenant_kind)
    REFERENCES aios_core.tenant_registry(tenant_id, tenant_kind)
    ON DELETE RESTRICT,
  CHECK (updated_at >= created_at)
);

CREATE TABLE aios_core.principal_identity_link (
  identity_link_id text PRIMARY KEY
    CHECK (
      identity_link_id ~ '^lnk_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
  tenant_id text NOT NULL,
  tenant_kind text NOT NULL CHECK (tenant_kind = 'SYNTHETIC'),
  identity_account_id text NOT NULL,
  provider_connection_id text NOT NULL,
  principal_id text NOT NULL,
  principal_kind text NOT NULL CHECK (principal_kind = 'HUMAN'),
  link_evidence_ref text NOT NULL
    CHECK (
      char_length(btrim(link_evidence_ref)) BETWEEN 1 AND 512
      AND link_evidence_ref
        ~ '^(evidence|fixture|policy|profile|synthetic|test)://'
    ),
  state text NOT NULL
    CHECK (state IN ('ACTIVE', 'SUSPENDED', 'RETIRED')),
  lifecycle_version bigint NOT NULL
    CHECK (
      lifecycle_version > 0
      AND lifecycle_version <= 9007199254740991
    ),
  account_lifecycle_version bigint NOT NULL
    CHECK (
      account_lifecycle_version > 0
      AND account_lifecycle_version <= 9007199254740991
    ),
  account_revocation_epoch bigint NOT NULL
    CHECK (
      account_revocation_epoch > 0
      AND account_revocation_epoch <= 9007199254740991
    ),
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  retired_at timestamptz,
  CONSTRAINT principal_identity_link_principal_fkey
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
  CONSTRAINT principal_identity_link_account_fkey
    FOREIGN KEY (
      identity_account_id,
      tenant_id,
      tenant_kind,
      provider_connection_id
    )
    REFERENCES aios_core.identity_account(
      account_id,
      tenant_id,
      tenant_kind,
      provider_connection_id
    )
    ON DELETE RESTRICT,
  CHECK (updated_at >= created_at),
  CHECK (
    (state IN ('ACTIVE', 'SUSPENDED') AND retired_at IS NULL)
    OR (
      state = 'RETIRED'
      AND retired_at IS NOT NULL
      AND retired_at >= created_at
    )
  )
);

CREATE UNIQUE INDEX principal_identity_link_current_account_key
  ON aios_core.principal_identity_link(
    tenant_id,
    identity_account_id
  )
  WHERE state IN ('ACTIVE', 'SUSPENDED');

CREATE INDEX principal_identity_link_principal_idx
  ON aios_core.principal_identity_link(
    tenant_id,
    principal_id,
    state,
    identity_link_id
  );

CREATE TABLE aios_core.principal_delegation (
  delegation_id text PRIMARY KEY
    CHECK (
      delegation_id ~ '^dlg_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
  tenant_id text NOT NULL,
  tenant_kind text NOT NULL CHECK (tenant_kind = 'SYNTHETIC'),
  human_subject_principal_id text NOT NULL,
  human_subject_kind text NOT NULL CHECK (human_subject_kind = 'HUMAN'),
  human_subject_security_epoch bigint NOT NULL
    CHECK (
      human_subject_security_epoch > 0
      AND human_subject_security_epoch <= 9007199254740991
    ),
  delegator_principal_id text NOT NULL,
  delegator_kind text NOT NULL
    CHECK (delegator_kind IN ('HUMAN', 'AGENT', 'SERVICE')),
  delegator_security_epoch bigint NOT NULL
    CHECK (
      delegator_security_epoch > 0
      AND delegator_security_epoch <= 9007199254740991
    ),
  delegate_principal_id text NOT NULL,
  delegate_kind text NOT NULL
    CHECK (delegate_kind IN ('AGENT', 'SERVICE')),
  delegate_security_epoch bigint NOT NULL
    CHECK (
      delegate_security_epoch > 0
      AND delegate_security_epoch <= 9007199254740991
    ),
  parent_delegation_id text,
  depth integer NOT NULL CHECK (depth BETWEEN 1 AND 8),
  provenance_ref text NOT NULL
    CHECK (
      char_length(btrim(provenance_ref)) BETWEEN 1 AND 512
      AND provenance_ref
        ~ '^(evidence|fixture|policy|profile|synthetic|test)://'
    ),
  state text NOT NULL CHECK (state IN ('ACTIVE', 'REVOKED')),
  lifecycle_version bigint NOT NULL
    CHECK (
      lifecycle_version > 0
      AND lifecycle_version <= 9007199254740991
    ),
  created_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL CHECK (expires_at > created_at),
  revoked_at timestamptz,
  revocation_reason_ref text
    CHECK (
      revocation_reason_ref IS NULL
      OR (
        char_length(btrim(revocation_reason_ref)) BETWEEN 1 AND 512
        AND revocation_reason_ref
          ~ '^(evidence|fixture|policy|profile|synthetic|test)://'
      )
    ),
  CONSTRAINT principal_delegation_subject_fkey
    FOREIGN KEY (
      human_subject_principal_id,
      tenant_id,
      tenant_kind,
      human_subject_kind
    )
    REFERENCES aios_core.principal_registry(
      principal_id,
      tenant_id,
      tenant_kind,
      principal_kind
    )
    ON DELETE RESTRICT,
  CONSTRAINT principal_delegation_delegator_fkey
    FOREIGN KEY (
      delegator_principal_id,
      tenant_id,
      tenant_kind,
      delegator_kind
    )
    REFERENCES aios_core.principal_registry(
      principal_id,
      tenant_id,
      tenant_kind,
      principal_kind
    )
    ON DELETE RESTRICT,
  CONSTRAINT principal_delegation_delegate_fkey
    FOREIGN KEY (
      delegate_principal_id,
      tenant_id,
      tenant_kind,
      delegate_kind
    )
    REFERENCES aios_core.principal_registry(
      principal_id,
      tenant_id,
      tenant_kind,
      principal_kind
    )
    ON DELETE RESTRICT,
  CONSTRAINT principal_delegation_parent_target_key
    UNIQUE (
      delegation_id,
      tenant_id,
      tenant_kind,
      human_subject_principal_id,
      human_subject_security_epoch,
      delegate_principal_id,
      delegate_kind,
      delegate_security_epoch
    ),
  CONSTRAINT principal_delegation_parent_fkey
    FOREIGN KEY (
      parent_delegation_id,
      tenant_id,
      tenant_kind,
      human_subject_principal_id,
      human_subject_security_epoch,
      delegator_principal_id,
      delegator_kind,
      delegator_security_epoch
    )
    REFERENCES aios_core.principal_delegation(
      delegation_id,
      tenant_id,
      tenant_kind,
      human_subject_principal_id,
      human_subject_security_epoch,
      delegate_principal_id,
      delegate_kind,
      delegate_security_epoch
    )
    ON DELETE RESTRICT,
  CHECK (delegator_principal_id <> delegate_principal_id),
  CHECK (
    parent_delegation_id IS NULL
    OR parent_delegation_id <> delegation_id
  ),
  CHECK (
    (
      parent_delegation_id IS NULL
      AND delegator_principal_id = human_subject_principal_id
      AND delegator_kind = 'HUMAN'
      AND delegator_security_epoch = human_subject_security_epoch
      AND depth = 1
    )
    OR (
      parent_delegation_id IS NOT NULL
      AND delegator_kind IN ('AGENT', 'SERVICE')
      AND depth BETWEEN 2 AND 8
    )
  ),
  CHECK (
    (
      state = 'ACTIVE'
      AND revoked_at IS NULL
      AND revocation_reason_ref IS NULL
    )
    OR (
      state = 'REVOKED'
      AND revoked_at IS NOT NULL
      AND revoked_at >= created_at
      AND revocation_reason_ref IS NOT NULL
    )
  )
);

COMMENT ON COLUMN aios_core.principal_delegation.provenance_ref
  IS 'Immutable source purposeRef used only for provenance.';

CREATE INDEX principal_delegation_parent_idx
  ON aios_core.principal_delegation(
    parent_delegation_id,
    state,
    delegation_id
  )
  WHERE parent_delegation_id IS NOT NULL;

CREATE TABLE aios_core.principal_command_receipt (
  tenant_id text NOT NULL,
  tenant_kind text NOT NULL CHECK (tenant_kind = 'SYNTHETIC'),
  idempotency_key text NOT NULL
    CHECK (char_length(btrim(idempotency_key)) BETWEEN 1 AND 256),
  command_hash text NOT NULL
    CHECK (command_hash ~ '^sha256:[0-9a-f]{64}$'),
  result jsonb NOT NULL CHECK (jsonb_typeof(result) = 'object'),
  created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
  PRIMARY KEY (tenant_id, idempotency_key),
  FOREIGN KEY (tenant_id, tenant_kind)
    REFERENCES aios_core.tenant_registry(tenant_id, tenant_kind)
    ON DELETE RESTRICT
);

CREATE TABLE aios_core.principal_event (
  event_id text PRIMARY KEY,
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
    event - ARRAY[
      'specversion', 'id', 'source', 'type', 'subject', 'time',
      'datacontenttype', 'dataschema', 'tenantkind',
      'correlationid', 'synthetic', 'data'
    ] = '{}'::jsonb
  )
);

CREATE TABLE aios_core.principal_outbox (
  event_id text PRIMARY KEY
    REFERENCES aios_core.principal_event(event_id)
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
  CONSTRAINT principal_outbox_worker_id_shape
    CHECK (
      leased_by IS NULL
      OR char_length(btrim(leased_by)) BETWEEN 1 AND 128
    ),
  CONSTRAINT principal_outbox_error_code_shape
    CHECK (
      last_error_code IS NULL
      OR char_length(btrim(last_error_code)) BETWEEN 1 AND 128
    ),
  CONSTRAINT principal_outbox_attempt_lease_match
    CHECK (attempt_count::bigint = lease_version),
  CONSTRAINT principal_outbox_delivery_shape
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
    event - ARRAY[
      'specversion', 'id', 'source', 'type', 'subject', 'time',
      'datacontenttype', 'dataschema', 'tenantkind',
      'correlationid', 'synthetic', 'data'
    ] = '{}'::jsonb
  )
);

CREATE INDEX principal_event_tenant_idx
  ON aios_core.principal_event(tenant_id, created_at, event_id);

CREATE INDEX principal_outbox_claim_idx
  ON aios_core.principal_outbox(
    status,
    available_at,
    lease_until,
    created_at,
    event_id
  );

CREATE FUNCTION aios_core.reject_principal_tombstone_delete()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION 'principal records are permanent tombstones'
    USING ERRCODE = '23000',
          CONSTRAINT = 'principal_tombstone_no_delete';
  RETURN OLD;
END;
$$;

CREATE FUNCTION aios_core.reject_principal_append_only_change()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION 'principal receipt or event is append-only'
    USING ERRCODE = '23000',
          CONSTRAINT = 'principal_append_only_guard';
  RETURN OLD;
END;
$$;

CREATE FUNCTION aios_core.enforce_principal_registry_insert()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  tenant_state text;
BEGIN
  IF NEW.state <> 'ACTIVE'
    OR NEW.lifecycle_version <> 1
    OR NEW.security_epoch <> 1
  THEN
    RAISE EXCEPTION 'new principal must begin active at version one'
      USING ERRCODE = '23000',
            CONSTRAINT = 'principal_registry_initial_state_guard';
  END IF;

  SELECT state
    INTO tenant_state
    FROM aios_core.tenant_registry
   WHERE tenant_id = NEW.tenant_id
     AND tenant_kind = NEW.tenant_kind
   FOR SHARE;

  IF NOT FOUND OR tenant_state <> 'ACTIVE' THEN
    RAISE EXCEPTION 'capability creation requires an active tenant'
      USING ERRCODE = '23000',
            CONSTRAINT = 'principal_tenant_active_guard';
  END IF;
  RETURN NEW;
END;
$$;

CREATE FUNCTION aios_core.enforce_principal_registry_update()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  tenant_state text;
BEGIN
  IF NEW.principal_id IS DISTINCT FROM OLD.principal_id
    OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
    OR NEW.tenant_kind IS DISTINCT FROM OLD.tenant_kind
    OR NEW.principal_kind IS DISTINCT FROM OLD.principal_kind
    OR NEW.creation_key IS DISTINCT FROM OLD.creation_key
    OR NEW.created_at IS DISTINCT FROM OLD.created_at
  THEN
    RAISE EXCEPTION 'principal identity is immutable'
      USING ERRCODE = '23000',
            CONSTRAINT = 'principal_registry_identity_guard';
  END IF;

  IF OLD.state = 'DEACTIVATED' THEN
    RAISE EXCEPTION 'deactivated principal cannot be restored'
      USING ERRCODE = '23000',
            CONSTRAINT = 'principal_registry_terminal_guard';
  END IF;

  IF NEW.state = OLD.state THEN
    IF NEW.lifecycle_version <> OLD.lifecycle_version
      OR NEW.security_epoch <> OLD.security_epoch + 1
      OR NEW.updated_at < OLD.updated_at
    THEN
      RAISE EXCEPTION 'principal security epoch must advance by one'
        USING ERRCODE = '23000',
              CONSTRAINT = 'principal_registry_version_guard';
    END IF;
  ELSE
    IF NOT (
      (
        OLD.state = 'ACTIVE'
        AND NEW.state IN ('SUSPENDED', 'DEACTIVATED')
      )
      OR (
        OLD.state = 'SUSPENDED'
        AND NEW.state IN ('ACTIVE', 'DEACTIVATED')
      )
    ) THEN
      RAISE EXCEPTION 'principal lifecycle transition is invalid'
        USING ERRCODE = '23000',
              CONSTRAINT = 'principal_registry_transition_guard';
    END IF;

    IF NEW.lifecycle_version <> OLD.lifecycle_version + 1
      OR NEW.security_epoch <> OLD.security_epoch + 1
      OR NEW.updated_at < OLD.updated_at
    THEN
      RAISE EXCEPTION 'principal lifecycle must advance by one'
        USING ERRCODE = '23000',
              CONSTRAINT = 'principal_registry_version_guard';
    END IF;
  END IF;

  IF NEW.state = 'DEACTIVATED'
    AND (
      EXISTS (
        SELECT 1
          FROM aios_core.principal_identity_link
         WHERE tenant_id = OLD.tenant_id
           AND principal_id = OLD.principal_id
           AND state IN ('ACTIVE', 'SUSPENDED')
      )
      OR EXISTS (
        SELECT 1
          FROM aios_core.principal_delegation
         WHERE tenant_id = OLD.tenant_id
           AND state = 'ACTIVE'
           AND (
             human_subject_principal_id = OLD.principal_id
             OR delegator_principal_id = OLD.principal_id
             OR delegate_principal_id = OLD.principal_id
           )
      )
    )
  THEN
    RAISE EXCEPTION 'principal relations must be retired before deactivation'
      USING ERRCODE = '23000',
            CONSTRAINT = 'principal_registry_active_relation_guard';
  END IF;

  IF OLD.state = 'SUSPENDED' AND NEW.state = 'ACTIVE' THEN
    SELECT state
      INTO tenant_state
      FROM aios_core.tenant_registry
     WHERE tenant_id = NEW.tenant_id
       AND tenant_kind = NEW.tenant_kind
     FOR SHARE;

    IF NOT FOUND OR tenant_state <> 'ACTIVE' THEN
      RAISE EXCEPTION 'capability restoration requires an active tenant'
        USING ERRCODE = '23000',
              CONSTRAINT = 'principal_tenant_active_guard';
    END IF;
  END IF;

  RETURN NEW;
END;
$$;

CREATE FUNCTION aios_core.enforce_principal_identity_link_insert()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  account_state text;
  account_version bigint;
  account_epoch bigint;
  principal_state text;
  tenant_state text;
BEGIN
  IF NEW.lifecycle_version <> 1 THEN
    RAISE EXCEPTION 'new identity link must begin at version one'
      USING ERRCODE = '23000',
            CONSTRAINT = 'principal_identity_link_initial_state_guard';
  END IF;

  SELECT state
    INTO tenant_state
    FROM aios_core.tenant_registry
   WHERE tenant_id = NEW.tenant_id
     AND tenant_kind = NEW.tenant_kind
   FOR SHARE;

  IF NOT FOUND OR tenant_state <> 'ACTIVE' THEN
    RAISE EXCEPTION 'identity link creation requires an active tenant'
      USING ERRCODE = '23000',
            CONSTRAINT = 'principal_tenant_active_guard';
  END IF;

  SELECT state, lifecycle_version, revocation_epoch
    INTO account_state, account_version, account_epoch
    FROM aios_core.identity_account
   WHERE account_id = NEW.identity_account_id
     AND tenant_id = NEW.tenant_id
     AND tenant_kind = NEW.tenant_kind
     AND provider_connection_id = NEW.provider_connection_id;

  IF NOT FOUND
    OR account_state NOT IN ('ACTIVE', 'SUSPENDED')
    OR NEW.state IS DISTINCT FROM account_state
    OR NEW.account_lifecycle_version IS DISTINCT FROM account_version
    OR NEW.account_revocation_epoch IS DISTINCT FROM account_epoch
  THEN
    RAISE EXCEPTION 'identity link does not match the current account'
      USING ERRCODE = '23000',
            CONSTRAINT = 'principal_identity_link_account_state_guard';
  END IF;

  SELECT state
    INTO principal_state
    FROM aios_core.principal_registry
   WHERE principal_id = NEW.principal_id
     AND tenant_id = NEW.tenant_id
     AND tenant_kind = NEW.tenant_kind
     AND principal_kind = NEW.principal_kind;

  IF NOT FOUND OR principal_state <> 'ACTIVE' THEN
    RAISE EXCEPTION 'identity link requires an active human principal'
      USING ERRCODE = '23000',
            CONSTRAINT = 'principal_identity_link_principal_state_guard';
  END IF;

  RETURN NEW;
END;
$$;

CREATE FUNCTION aios_core.enforce_principal_identity_link_update()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  account_state text;
  account_version bigint;
  account_epoch bigint;
  principal_state text;
  tenant_state text;
BEGIN
  IF NEW.identity_link_id IS DISTINCT FROM OLD.identity_link_id
    OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
    OR NEW.tenant_kind IS DISTINCT FROM OLD.tenant_kind
    OR NEW.identity_account_id IS DISTINCT FROM OLD.identity_account_id
    OR NEW.provider_connection_id IS DISTINCT FROM OLD.provider_connection_id
    OR NEW.principal_id IS DISTINCT FROM OLD.principal_id
    OR NEW.principal_kind IS DISTINCT FROM OLD.principal_kind
    OR NEW.link_evidence_ref IS DISTINCT FROM OLD.link_evidence_ref
    OR NEW.created_at IS DISTINCT FROM OLD.created_at
  THEN
    RAISE EXCEPTION 'identity link binding is immutable'
      USING ERRCODE = '23000',
            CONSTRAINT = 'principal_identity_link_binding_guard';
  END IF;

  IF OLD.state = 'RETIRED' THEN
    RAISE EXCEPTION 'retired identity link cannot be restored'
      USING ERRCODE = '23000',
            CONSTRAINT = 'principal_identity_link_terminal_guard';
  END IF;

  IF OLD.state = 'SUSPENDED' AND NEW.state = 'ACTIVE' THEN
    SELECT state
      INTO tenant_state
      FROM aios_core.tenant_registry
     WHERE tenant_id = NEW.tenant_id
       AND tenant_kind = NEW.tenant_kind
     FOR SHARE;

    IF NOT FOUND OR tenant_state <> 'ACTIVE' THEN
      RAISE EXCEPTION 'identity link restoration requires an active tenant'
        USING ERRCODE = '23000',
              CONSTRAINT = 'principal_tenant_active_guard';
    END IF;
  END IF;

  IF NOT (
    (OLD.state = 'ACTIVE' AND NEW.state IN ('ACTIVE', 'SUSPENDED', 'RETIRED'))
    OR (
      OLD.state = 'SUSPENDED'
      AND NEW.state IN ('ACTIVE', 'SUSPENDED', 'RETIRED')
    )
  ) THEN
    RAISE EXCEPTION 'identity link lifecycle transition is invalid'
      USING ERRCODE = '23000',
            CONSTRAINT = 'principal_identity_link_transition_guard';
  END IF;

  IF NEW.lifecycle_version <> OLD.lifecycle_version + 1
    OR NEW.account_lifecycle_version < OLD.account_lifecycle_version
    OR NEW.account_revocation_epoch < OLD.account_revocation_epoch
    OR (
      NEW.state = OLD.state
      AND NEW.account_lifecycle_version = OLD.account_lifecycle_version
      AND NEW.account_revocation_epoch = OLD.account_revocation_epoch
    )
    OR NEW.updated_at < OLD.updated_at
  THEN
    RAISE EXCEPTION 'identity link version cannot move backwards'
      USING ERRCODE = '23000',
            CONSTRAINT = 'principal_identity_link_version_guard';
  END IF;

  IF NEW.state <> 'RETIRED' THEN
    SELECT state, lifecycle_version, revocation_epoch
      INTO account_state, account_version, account_epoch
      FROM aios_core.identity_account
     WHERE account_id = NEW.identity_account_id
       AND tenant_id = NEW.tenant_id
       AND tenant_kind = NEW.tenant_kind
       AND provider_connection_id = NEW.provider_connection_id;

    IF NOT FOUND
      OR NEW.state IS DISTINCT FROM account_state
      OR NEW.account_lifecycle_version IS DISTINCT FROM account_version
      OR NEW.account_revocation_epoch IS DISTINCT FROM account_epoch
    THEN
      RAISE EXCEPTION 'identity link does not match the current account'
        USING ERRCODE = '23000',
              CONSTRAINT = 'principal_identity_link_account_state_guard';
    END IF;

    SELECT state
      INTO principal_state
      FROM aios_core.principal_registry
     WHERE principal_id = NEW.principal_id
       AND tenant_id = NEW.tenant_id
       AND tenant_kind = NEW.tenant_kind
       AND principal_kind = NEW.principal_kind;

    IF NOT FOUND
      OR principal_state NOT IN ('ACTIVE', 'SUSPENDED')
    THEN
      RAISE EXCEPTION 'identity link requires a current human principal'
        USING ERRCODE = '23000',
              CONSTRAINT = 'principal_identity_link_principal_state_guard';
    END IF;
  END IF;

  RETURN NEW;
END;
$$;

CREATE FUNCTION aios_core.enforce_principal_delegation_insert()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  current_state text;
  current_epoch bigint;
  parent_state text;
  parent_depth integer;
  parent_expires_at timestamptz;
  parent_provenance_ref text;
  tenant_state text;
BEGIN
  IF NEW.state <> 'ACTIVE'
    OR NEW.lifecycle_version <> 1
  THEN
    RAISE EXCEPTION 'new delegation must begin active at version one'
      USING ERRCODE = '23000',
            CONSTRAINT = 'principal_delegation_initial_state_guard';
  END IF;

  SELECT state
    INTO tenant_state
    FROM aios_core.tenant_registry
   WHERE tenant_id = NEW.tenant_id
     AND tenant_kind = NEW.tenant_kind
   FOR SHARE;

  IF NOT FOUND OR tenant_state <> 'ACTIVE' THEN
    RAISE EXCEPTION 'delegation creation requires an active tenant'
      USING ERRCODE = '23000',
            CONSTRAINT = 'principal_tenant_active_guard';
  END IF;

  SELECT state, security_epoch
    INTO current_state, current_epoch
    FROM aios_core.principal_registry
   WHERE principal_id = NEW.human_subject_principal_id
     AND tenant_id = NEW.tenant_id
     AND tenant_kind = NEW.tenant_kind
     AND principal_kind = NEW.human_subject_kind;

  IF NOT FOUND
    OR current_state <> 'ACTIVE'
    OR current_epoch <> NEW.human_subject_security_epoch
  THEN
    RAISE EXCEPTION 'delegation human subject is stale or inactive'
      USING ERRCODE = '23000',
            CONSTRAINT = 'principal_delegation_subject_state_guard';
  END IF;

  SELECT state, security_epoch
    INTO current_state, current_epoch
    FROM aios_core.principal_registry
   WHERE principal_id = NEW.delegator_principal_id
     AND tenant_id = NEW.tenant_id
     AND tenant_kind = NEW.tenant_kind
     AND principal_kind = NEW.delegator_kind;

  IF NOT FOUND
    OR current_state <> 'ACTIVE'
    OR current_epoch <> NEW.delegator_security_epoch
  THEN
    RAISE EXCEPTION 'delegation delegator is stale or inactive'
      USING ERRCODE = '23000',
            CONSTRAINT = 'principal_delegation_delegator_state_guard';
  END IF;

  SELECT state, security_epoch
    INTO current_state, current_epoch
    FROM aios_core.principal_registry
   WHERE principal_id = NEW.delegate_principal_id
     AND tenant_id = NEW.tenant_id
     AND tenant_kind = NEW.tenant_kind
     AND principal_kind = NEW.delegate_kind;

  IF NOT FOUND
    OR current_state <> 'ACTIVE'
    OR current_epoch <> NEW.delegate_security_epoch
  THEN
    RAISE EXCEPTION 'delegation delegate is stale or inactive'
      USING ERRCODE = '23000',
            CONSTRAINT = 'principal_delegation_delegate_state_guard';
  END IF;

  IF NEW.parent_delegation_id IS NOT NULL THEN
    SELECT state, depth, expires_at, provenance_ref
      INTO
        parent_state,
        parent_depth,
        parent_expires_at,
        parent_provenance_ref
      FROM aios_core.principal_delegation
     WHERE delegation_id = NEW.parent_delegation_id
       AND tenant_id = NEW.tenant_id
       AND tenant_kind = NEW.tenant_kind
       AND human_subject_principal_id =
           NEW.human_subject_principal_id
       AND human_subject_security_epoch =
           NEW.human_subject_security_epoch
       AND delegate_principal_id = NEW.delegator_principal_id
       AND delegate_kind = NEW.delegator_kind
       AND delegate_security_epoch =
           NEW.delegator_security_epoch;

    IF NOT FOUND OR parent_state <> 'ACTIVE' THEN
      RAISE EXCEPTION 'delegation parent is missing or inactive'
        USING ERRCODE = '23000',
              CONSTRAINT = 'principal_delegation_parent_state_guard';
    END IF;

    IF NEW.depth <> parent_depth + 1
      OR NEW.expires_at > parent_expires_at
      OR NEW.provenance_ref <> parent_provenance_ref
    THEN
      RAISE EXCEPTION 'delegation child exceeds parent bounds'
        USING ERRCODE = '23000',
              CONSTRAINT = 'principal_delegation_parent_bounds_guard';
    END IF;
  END IF;

  RETURN NEW;
END;
$$;

CREATE FUNCTION aios_core.enforce_principal_delegation_update()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF NEW.delegation_id IS DISTINCT FROM OLD.delegation_id
    OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
    OR NEW.tenant_kind IS DISTINCT FROM OLD.tenant_kind
    OR NEW.human_subject_principal_id
      IS DISTINCT FROM OLD.human_subject_principal_id
    OR NEW.human_subject_kind IS DISTINCT FROM OLD.human_subject_kind
    OR NEW.human_subject_security_epoch
      IS DISTINCT FROM OLD.human_subject_security_epoch
    OR NEW.delegator_principal_id
      IS DISTINCT FROM OLD.delegator_principal_id
    OR NEW.delegator_kind IS DISTINCT FROM OLD.delegator_kind
    OR NEW.delegator_security_epoch
      IS DISTINCT FROM OLD.delegator_security_epoch
    OR NEW.delegate_principal_id
      IS DISTINCT FROM OLD.delegate_principal_id
    OR NEW.delegate_kind IS DISTINCT FROM OLD.delegate_kind
    OR NEW.delegate_security_epoch
      IS DISTINCT FROM OLD.delegate_security_epoch
    OR NEW.parent_delegation_id
      IS DISTINCT FROM OLD.parent_delegation_id
    OR NEW.depth IS DISTINCT FROM OLD.depth
    OR NEW.provenance_ref IS DISTINCT FROM OLD.provenance_ref
    OR NEW.created_at IS DISTINCT FROM OLD.created_at
    OR NEW.expires_at IS DISTINCT FROM OLD.expires_at
  THEN
    RAISE EXCEPTION 'delegation chain is immutable'
      USING ERRCODE = '23000',
            CONSTRAINT = 'principal_delegation_binding_guard';
  END IF;

  IF OLD.state <> 'ACTIVE'
    OR NEW.state <> 'REVOKED'
    OR NEW.lifecycle_version <> OLD.lifecycle_version + 1
    OR NEW.revoked_at IS NULL
    OR NEW.revocation_reason_ref IS NULL
  THEN
    RAISE EXCEPTION 'delegation revocation is invalid'
      USING ERRCODE = '23000',
            CONSTRAINT = 'principal_delegation_terminal_guard';
  END IF;

  IF EXISTS (
    SELECT 1
      FROM aios_core.principal_delegation
     WHERE parent_delegation_id = OLD.delegation_id
       AND state = 'ACTIVE'
  ) THEN
    RAISE EXCEPTION 'active child delegation must be revoked first'
      USING ERRCODE = '23000',
            CONSTRAINT = 'principal_delegation_active_child_guard';
  END IF;

  RETURN NEW;
END;
$$;

CREATE FUNCTION aios_core.enforce_principal_outbox()
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
      RAISE EXCEPTION 'principal outbox must start pending'
        USING ERRCODE = '23000',
              CONSTRAINT = 'principal_outbox_initial_state_guard';
    END IF;
    RETURN NEW;
  END IF;

  IF NEW.event_id IS DISTINCT FROM OLD.event_id
    OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
    OR NEW.tenant_kind IS DISTINCT FROM OLD.tenant_kind
    OR NEW.event IS DISTINCT FROM OLD.event
    OR NEW.created_at IS DISTINCT FROM OLD.created_at
  THEN
    RAISE EXCEPTION 'principal outbox payload is immutable'
      USING ERRCODE = '23000',
            CONSTRAINT = 'principal_outbox_payload_guard';
  END IF;

  IF OLD.status = 'PUBLISHED' THEN
    RAISE EXCEPTION 'published principal outbox event is final'
      USING ERRCODE = '23000',
            CONSTRAINT = 'principal_outbox_published_guard';
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
      RAISE EXCEPTION 'principal outbox claim is invalid'
        USING ERRCODE = '23000',
              CONSTRAINT = 'principal_outbox_claim_guard';
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
      RAISE EXCEPTION 'principal outbox reclaim is invalid'
        USING ERRCODE = '23000',
              CONSTRAINT = 'principal_outbox_reclaim_guard';
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
      RAISE EXCEPTION 'principal outbox failure receipt is invalid'
        USING ERRCODE = '23000',
              CONSTRAINT = 'principal_outbox_failure_guard';
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
      RAISE EXCEPTION 'principal outbox completion is invalid'
        USING ERRCODE = '23000',
              CONSTRAINT = 'principal_outbox_completion_guard';
    END IF;
    RETURN NEW;
  END IF;

  RAISE EXCEPTION 'principal outbox transition is invalid'
    USING ERRCODE = '23000',
          CONSTRAINT = 'principal_outbox_transition_guard';
END;
$$;

CREATE FUNCTION aios_core.enforce_principal_event_outbox_pair()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  paired_event jsonb;
BEGIN
  IF TG_TABLE_NAME = 'principal_event' THEN
    SELECT event
      INTO paired_event
      FROM aios_core.principal_outbox
     WHERE event_id = NEW.event_id;
  ELSE
    SELECT event
      INTO paired_event
      FROM aios_core.principal_event
     WHERE event_id = NEW.event_id;
  END IF;

  IF NOT FOUND OR paired_event IS DISTINCT FROM NEW.event THEN
    RAISE EXCEPTION 'principal event and outbox payload must be paired'
      USING ERRCODE = '23000',
            CONSTRAINT = 'principal_event_outbox_pair_guard';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER principal_registry_insert_guard
BEFORE INSERT ON aios_core.principal_registry
FOR EACH ROW EXECUTE FUNCTION aios_core.enforce_principal_registry_insert();

CREATE TRIGGER principal_registry_update_guard
BEFORE UPDATE ON aios_core.principal_registry
FOR EACH ROW EXECUTE FUNCTION aios_core.enforce_principal_registry_update();

CREATE TRIGGER principal_registry_no_delete
BEFORE DELETE ON aios_core.principal_registry
FOR EACH ROW EXECUTE FUNCTION aios_core.reject_principal_tombstone_delete();

CREATE TRIGGER principal_identity_link_insert_guard
BEFORE INSERT ON aios_core.principal_identity_link
FOR EACH ROW
EXECUTE FUNCTION aios_core.enforce_principal_identity_link_insert();

CREATE TRIGGER principal_identity_link_update_guard
BEFORE UPDATE ON aios_core.principal_identity_link
FOR EACH ROW
EXECUTE FUNCTION aios_core.enforce_principal_identity_link_update();

CREATE TRIGGER principal_identity_link_no_delete
BEFORE DELETE ON aios_core.principal_identity_link
FOR EACH ROW EXECUTE FUNCTION aios_core.reject_principal_tombstone_delete();

CREATE TRIGGER principal_delegation_insert_guard
BEFORE INSERT ON aios_core.principal_delegation
FOR EACH ROW
EXECUTE FUNCTION aios_core.enforce_principal_delegation_insert();

CREATE TRIGGER principal_delegation_update_guard
BEFORE UPDATE ON aios_core.principal_delegation
FOR EACH ROW
EXECUTE FUNCTION aios_core.enforce_principal_delegation_update();

CREATE TRIGGER principal_delegation_no_delete
BEFORE DELETE ON aios_core.principal_delegation
FOR EACH ROW EXECUTE FUNCTION aios_core.reject_principal_tombstone_delete();

CREATE TRIGGER principal_command_receipt_no_update
BEFORE UPDATE OR DELETE ON aios_core.principal_command_receipt
FOR EACH ROW EXECUTE FUNCTION aios_core.reject_principal_append_only_change();

CREATE TRIGGER principal_event_no_update
BEFORE UPDATE OR DELETE ON aios_core.principal_event
FOR EACH ROW EXECUTE FUNCTION aios_core.reject_principal_append_only_change();

CREATE TRIGGER principal_outbox_state_guard
BEFORE INSERT OR UPDATE ON aios_core.principal_outbox
FOR EACH ROW EXECUTE FUNCTION aios_core.enforce_principal_outbox();

CREATE TRIGGER principal_outbox_no_delete
BEFORE DELETE ON aios_core.principal_outbox
FOR EACH ROW EXECUTE FUNCTION aios_core.reject_principal_tombstone_delete();

CREATE CONSTRAINT TRIGGER principal_event_requires_outbox
AFTER INSERT ON aios_core.principal_event
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION aios_core.enforce_principal_event_outbox_pair();

CREATE CONSTRAINT TRIGGER principal_outbox_requires_event
AFTER INSERT ON aios_core.principal_outbox
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION aios_core.enforce_principal_event_outbox_pair();

COMMIT;
