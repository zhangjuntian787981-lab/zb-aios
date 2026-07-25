BEGIN;

-- This migration runs after C03 0001_tenant_registry.sql.
-- The database owner and migration role are trusted administrative boundaries.
-- Application roles must not own these tables or disable their triggers.

CREATE TABLE aios_core.identity_provider (
  provider_connection_id text PRIMARY KEY
    CHECK (
      provider_connection_id ~ '^idp_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
  tenant_id text NOT NULL,
  tenant_kind text NOT NULL CHECK (tenant_kind = 'SYNTHETIC'),
  protocol text NOT NULL CHECK (protocol = 'OIDC'),
  issuer text NOT NULL,
  client_id text NOT NULL,
  redirect_routes jsonb NOT NULL
    CHECK (jsonb_typeof(redirect_routes) = 'object'),
  configuration_version bigint NOT NULL CHECK (configuration_version > 0),
  allowed_algorithms jsonb NOT NULL
    CHECK (jsonb_typeof(allowed_algorithms) = 'array'),
  allowed_key_ids jsonb NOT NULL
    CHECK (jsonb_typeof(allowed_key_ids) = 'array'),
  required_authentication_methods jsonb NOT NULL
    CHECK (jsonb_typeof(required_authentication_methods) = 'array'),
  max_authentication_age_seconds integer NOT NULL
    CHECK (max_authentication_age_seconds > 0),
  upstream_protocols jsonb NOT NULL
    CHECK (jsonb_typeof(upstream_protocols) = 'array'),
  policy text NOT NULL CHECK (policy = 'SCIM_REQUIRED'),
  status text NOT NULL CHECK (status IN ('ACTIVE', 'DELETED')),
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  UNIQUE (tenant_id),
  UNIQUE (provider_connection_id, tenant_id, tenant_kind),
  UNIQUE (
    provider_connection_id,
    tenant_id,
    tenant_kind,
    issuer
  ),
  UNIQUE (
    provider_connection_id,
    tenant_id,
    configuration_version
  ),
  FOREIGN KEY (tenant_id, tenant_kind)
    REFERENCES aios_core.tenant_registry(tenant_id, tenant_kind)
    ON DELETE RESTRICT
);

CREATE TABLE aios_core.identity_tenant_projection (
  tenant_id text PRIMARY KEY,
  tenant_kind text NOT NULL CHECK (tenant_kind = 'SYNTHETIC'),
  fixture_id text NOT NULL,
  fixture_hash text NOT NULL
    CHECK (fixture_hash ~ '^sha256:[0-9a-f]{64}$'),
  provider_connection_id text NOT NULL,
  state text NOT NULL CHECK (state IN ('READY', 'SUSPENDED', 'DELETED')),
  generation bigint NOT NULL CHECK (generation > 0),
  operation_id text NOT NULL
    CHECK (
      operation_id ~ '^op_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
  revocation_epoch bigint NOT NULL CHECK (revocation_epoch > 0),
  updated_at timestamptz NOT NULL,
  FOREIGN KEY (tenant_id, tenant_kind)
    REFERENCES aios_core.tenant_registry(tenant_id, tenant_kind)
    ON DELETE RESTRICT,
  FOREIGN KEY (
    provider_connection_id,
    tenant_id,
    tenant_kind
  )
    REFERENCES aios_core.identity_provider(
      provider_connection_id,
      tenant_id,
      tenant_kind
    )
    ON DELETE RESTRICT
);

CREATE TABLE aios_core.identity_account (
  account_id text PRIMARY KEY
    CHECK (
      account_id ~ '^sia_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
  tenant_id text NOT NULL,
  tenant_kind text NOT NULL CHECK (tenant_kind = 'SYNTHETIC'),
  provider_connection_id text NOT NULL,
  issuer text NOT NULL,
  subject text NOT NULL,
  directory_object_id text NOT NULL,
  fixture_user_id text NOT NULL,
  state text NOT NULL CHECK (state IN ('ACTIVE', 'SUSPENDED', 'TERMINATED')),
  lifecycle_version bigint NOT NULL CHECK (lifecycle_version > 0),
  source_revision bigint NOT NULL CHECK (source_revision > 0),
  source_payload_hash text NOT NULL
    CHECK (source_payload_hash ~ '^sha256:[0-9a-f]{64}$'),
  revocation_epoch bigint NOT NULL CHECK (revocation_epoch > 0),
  incarnation bigint NOT NULL CHECK (incarnation > 0),
  profile_ref text NOT NULL
    CHECK (profile_ref ~ '^(fixture|policy|profile|synthetic|test)://'),
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  CONSTRAINT identity_account_directory_key
    UNIQUE (tenant_id, provider_connection_id, directory_object_id),
  CONSTRAINT identity_account_subject_key
    UNIQUE (tenant_id, provider_connection_id, issuer, subject),
  UNIQUE (account_id, tenant_id, tenant_kind, provider_connection_id),
  FOREIGN KEY (
    provider_connection_id,
    tenant_id,
    tenant_kind,
    issuer
  )
    REFERENCES aios_core.identity_provider(
      provider_connection_id,
      tenant_id,
      tenant_kind,
      issuer
    )
    ON DELETE RESTRICT
);

CREATE TABLE aios_core.identity_source_receipt (
  tenant_id text NOT NULL
    REFERENCES aios_core.tenant_registry(tenant_id)
    ON DELETE RESTRICT,
  source_event_id text NOT NULL,
  payload_hash text NOT NULL
    CHECK (payload_hash ~ '^sha256:[0-9a-f]{64}$'),
  result jsonb NOT NULL CHECK (jsonb_typeof(result) = 'object'),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, source_event_id)
);

CREATE TABLE aios_core.identity_login_transaction (
  transaction_id text PRIMARY KEY
    CHECK (
      transaction_id ~ '^lgn_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
  tenant_id text NOT NULL
    REFERENCES aios_core.identity_tenant_projection(tenant_id)
    ON DELETE RESTRICT,
  provider_connection_id text NOT NULL,
  provider_configuration_version bigint NOT NULL
    CHECK (provider_configuration_version > 0),
  state_hash text NOT NULL
    CHECK (state_hash ~ '^sha256:[0-9a-f]{64}$'),
  nonce_hash text NOT NULL
    CHECK (nonce_hash ~ '^sha256:[0-9a-f]{64}$'),
  pkce_verifier_hash text NOT NULL
    CHECK (pkce_verifier_hash ~ '^sha256:[0-9a-f]{64}$'),
  redirect_uri text NOT NULL,
  return_route text NOT NULL,
  issued_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL CHECK (expires_at > issued_at),
  claimed_at timestamptz,
  claim_hash text
    CHECK (claim_hash IS NULL OR claim_hash ~ '^sha256:[0-9a-f]{64}$'),
  consumed_at timestamptz,
  CHECK ((claimed_at IS NULL) = (claim_hash IS NULL)),
  CHECK (consumed_at IS NULL OR claimed_at IS NOT NULL),
  CHECK (claimed_at IS NULL OR claimed_at >= issued_at),
  CHECK (consumed_at IS NULL OR consumed_at >= claimed_at),
  FOREIGN KEY (
    provider_connection_id,
    tenant_id,
    provider_configuration_version
  )
    REFERENCES aios_core.identity_provider(
      provider_connection_id,
      tenant_id,
      configuration_version
    )
    ON DELETE RESTRICT
);

CREATE TABLE aios_core.identity_session (
  session_id text PRIMARY KEY
    CHECK (
      session_id ~ '^ses_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
  tenant_id text NOT NULL,
  tenant_kind text NOT NULL CHECK (tenant_kind = 'SYNTHETIC'),
  account_id text NOT NULL,
  provider_connection_id text NOT NULL,
  token_hash text NOT NULL
    CONSTRAINT identity_session_token_hash_key UNIQUE
    CHECK (token_hash ~ '^sha256:[0-9a-f]{64}$'),
  account_revocation_epoch bigint NOT NULL CHECK (account_revocation_epoch > 0),
  tenant_revocation_epoch bigint NOT NULL CHECK (tenant_revocation_epoch > 0),
  status text NOT NULL CHECK (status IN ('ACTIVE', 'REVOKED')),
  authentication_time timestamptz NOT NULL,
  authentication_methods jsonb NOT NULL
    CHECK (jsonb_typeof(authentication_methods) = 'array'),
  issued_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL CHECK (expires_at > issued_at),
  revoked_at timestamptz,
  CHECK (
    (status = 'ACTIVE' AND revoked_at IS NULL)
    OR (status = 'REVOKED' AND revoked_at IS NOT NULL)
  ),
  FOREIGN KEY (
    account_id,
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
    ON DELETE RESTRICT
);

CREATE TABLE aios_core.identity_command_receipt (
  idempotency_key text PRIMARY KEY,
  command_hash text NOT NULL
    CHECK (command_hash ~ '^sha256:[0-9a-f]{64}$'),
  result jsonb NOT NULL CHECK (jsonb_typeof(result) = 'object'),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE aios_core.identity_event (
  event_id text PRIMARY KEY,
  tenant_id text NOT NULL,
  tenant_kind text NOT NULL CHECK (tenant_kind = 'SYNTHETIC'),
  event jsonb NOT NULL,
  created_at timestamptz NOT NULL,
  FOREIGN KEY (tenant_id, tenant_kind)
    REFERENCES aios_core.tenant_registry(tenant_id, tenant_kind)
    ON DELETE RESTRICT,
  CHECK ((event ->> 'specversion') IS NOT DISTINCT FROM '1.0'),
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

CREATE TABLE aios_core.identity_outbox (
  event_id text PRIMARY KEY
    REFERENCES aios_core.identity_event(event_id)
    ON DELETE RESTRICT,
  tenant_id text NOT NULL,
  tenant_kind text NOT NULL CHECK (tenant_kind = 'SYNTHETIC'),
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

CREATE INDEX identity_account_tenant_idx
  ON aios_core.identity_account(tenant_id, account_id);

CREATE INDEX identity_login_pending_idx
  ON aios_core.identity_login_transaction(expires_at)
  WHERE consumed_at IS NULL;

CREATE INDEX identity_session_tenant_idx
  ON aios_core.identity_session(tenant_id, session_id);

CREATE INDEX identity_session_active_account_idx
  ON aios_core.identity_session(account_id)
  WHERE status = 'ACTIVE';

CREATE INDEX identity_session_active_tenant_idx
  ON aios_core.identity_session(tenant_id)
  WHERE status = 'ACTIVE';

CREATE INDEX identity_event_tenant_idx
  ON aios_core.identity_event(tenant_id, created_at, event_id);

CREATE INDEX identity_outbox_claim_idx
  ON aios_core.identity_outbox(
    status,
    available_at,
    lease_until,
    created_at,
    event_id
  );

CREATE FUNCTION aios_core.reject_identity_tombstone_delete()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION 'identity records are permanent tombstones'
    USING ERRCODE = '23000',
          CONSTRAINT = 'identity_tombstone_no_delete';
  RETURN OLD;
END;
$$;

CREATE FUNCTION aios_core.reject_identity_append_only_change()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION 'identity receipt or event is append-only'
    USING ERRCODE = '23000',
          CONSTRAINT = 'identity_append_only_guard';
  RETURN OLD;
END;
$$;

CREATE FUNCTION aios_core.enforce_identity_projection_update()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
    OR NEW.tenant_kind IS DISTINCT FROM OLD.tenant_kind
    OR NEW.fixture_id IS DISTINCT FROM OLD.fixture_id
    OR NEW.fixture_hash IS DISTINCT FROM OLD.fixture_hash
    OR NEW.provider_connection_id IS DISTINCT FROM OLD.provider_connection_id
  THEN
    RAISE EXCEPTION 'identity projection binding is immutable'
      USING ERRCODE = '23000',
            CONSTRAINT = 'identity_projection_binding_guard';
  END IF;

  IF OLD.state = 'DELETED' AND NEW.state <> 'DELETED' THEN
    RAISE EXCEPTION 'deleted identity projection cannot be restored'
      USING ERRCODE = '23000',
            CONSTRAINT = 'identity_projection_terminal_guard';
  END IF;

  IF NEW.generation < OLD.generation
    OR NEW.revocation_epoch < OLD.revocation_epoch
    OR (
      NEW.generation = OLD.generation
      AND NEW.operation_id IS DISTINCT FROM OLD.operation_id
    )
    OR (
      NEW.generation > OLD.generation
      AND NEW.operation_id IS NOT DISTINCT FROM OLD.operation_id
    )
  THEN
    RAISE EXCEPTION 'identity projection version cannot move backwards'
      USING ERRCODE = '23000',
            CONSTRAINT = 'identity_projection_version_guard';
  END IF;

  IF (
    NEW.state IS DISTINCT FROM OLD.state
    OR NEW.generation IS DISTINCT FROM OLD.generation
    OR NEW.operation_id IS DISTINCT FROM OLD.operation_id
  )
    AND NEW.revocation_epoch <= OLD.revocation_epoch
  THEN
    RAISE EXCEPTION 'identity projection changes must advance revocation'
      USING ERRCODE = '23000',
            CONSTRAINT = 'identity_projection_epoch_guard';
  END IF;
  RETURN NEW;
END;
$$;

CREATE FUNCTION aios_core.enforce_identity_provider_update()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF NEW.provider_connection_id IS DISTINCT FROM OLD.provider_connection_id
    OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
    OR NEW.tenant_kind IS DISTINCT FROM OLD.tenant_kind
    OR NEW.protocol IS DISTINCT FROM OLD.protocol
    OR NEW.issuer IS DISTINCT FROM OLD.issuer
    OR NEW.client_id IS DISTINCT FROM OLD.client_id
    OR NEW.redirect_routes IS DISTINCT FROM OLD.redirect_routes
    OR NEW.configuration_version IS DISTINCT FROM OLD.configuration_version
    OR NEW.allowed_algorithms IS DISTINCT FROM OLD.allowed_algorithms
    OR NEW.allowed_key_ids IS DISTINCT FROM OLD.allowed_key_ids
    OR NEW.required_authentication_methods
      IS DISTINCT FROM OLD.required_authentication_methods
    OR NEW.max_authentication_age_seconds
      IS DISTINCT FROM OLD.max_authentication_age_seconds
    OR NEW.upstream_protocols IS DISTINCT FROM OLD.upstream_protocols
    OR NEW.policy IS DISTINCT FROM OLD.policy
    OR NEW.created_at IS DISTINCT FROM OLD.created_at
  THEN
    RAISE EXCEPTION 'identity provider binding is immutable'
      USING ERRCODE = '23000',
            CONSTRAINT = 'identity_provider_binding_guard';
  END IF;

  IF OLD.status = 'DELETED' AND NEW.status <> 'DELETED' THEN
    RAISE EXCEPTION 'deleted identity provider cannot be restored'
      USING ERRCODE = '23000',
            CONSTRAINT = 'identity_provider_terminal_guard';
  END IF;
  RETURN NEW;
END;
$$;

CREATE FUNCTION aios_core.enforce_identity_account_update()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF NEW.account_id IS DISTINCT FROM OLD.account_id
    OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
    OR NEW.tenant_kind IS DISTINCT FROM OLD.tenant_kind
    OR NEW.provider_connection_id IS DISTINCT FROM OLD.provider_connection_id
    OR NEW.issuer IS DISTINCT FROM OLD.issuer
    OR NEW.subject IS DISTINCT FROM OLD.subject
    OR NEW.directory_object_id IS DISTINCT FROM OLD.directory_object_id
    OR NEW.fixture_user_id IS DISTINCT FROM OLD.fixture_user_id
    OR NEW.incarnation IS DISTINCT FROM OLD.incarnation
    OR NEW.profile_ref IS DISTINCT FROM OLD.profile_ref
    OR NEW.created_at IS DISTINCT FROM OLD.created_at
  THEN
    RAISE EXCEPTION 'identity account binding is immutable'
      USING ERRCODE = '23000',
            CONSTRAINT = 'identity_account_binding_guard';
  END IF;

  IF OLD.state = 'TERMINATED' AND NEW.state <> 'TERMINATED' THEN
    RAISE EXCEPTION 'terminated identity account cannot be restored'
      USING ERRCODE = '23000',
            CONSTRAINT = 'identity_account_terminal_guard';
  END IF;

  IF NEW.lifecycle_version < OLD.lifecycle_version
    OR NEW.source_revision < OLD.source_revision
    OR NEW.revocation_epoch < OLD.revocation_epoch
  THEN
    RAISE EXCEPTION 'identity account version cannot move backwards'
      USING ERRCODE = '23000',
            CONSTRAINT = 'identity_account_version_guard';
  END IF;

  IF (
    NEW.state IS DISTINCT FROM OLD.state
    OR NEW.source_revision IS DISTINCT FROM OLD.source_revision
    OR NEW.source_payload_hash IS DISTINCT FROM OLD.source_payload_hash
  )
    AND (
      NEW.lifecycle_version <> OLD.lifecycle_version + 1
      OR NEW.revocation_epoch <> OLD.revocation_epoch + 1
    )
  THEN
    RAISE EXCEPTION 'identity account changes must advance lifecycle and revocation'
      USING ERRCODE = '23000',
            CONSTRAINT = 'identity_account_epoch_guard';
  END IF;

  IF NEW.state <> 'TERMINATED'
    AND NEW.source_revision IS DISTINCT FROM OLD.source_revision
    AND NEW.source_revision <= OLD.source_revision
  THEN
    RAISE EXCEPTION 'identity account source revision must increase'
      USING ERRCODE = '23000',
            CONSTRAINT = 'identity_account_source_revision_guard';
  END IF;
  RETURN NEW;
END;
$$;

CREATE FUNCTION aios_core.enforce_identity_login_transaction_update()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF NEW.transaction_id IS DISTINCT FROM OLD.transaction_id
    OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
    OR NEW.provider_connection_id IS DISTINCT FROM OLD.provider_connection_id
    OR NEW.provider_configuration_version
      IS DISTINCT FROM OLD.provider_configuration_version
    OR NEW.state_hash IS DISTINCT FROM OLD.state_hash
    OR NEW.nonce_hash IS DISTINCT FROM OLD.nonce_hash
    OR NEW.pkce_verifier_hash IS DISTINCT FROM OLD.pkce_verifier_hash
    OR NEW.redirect_uri IS DISTINCT FROM OLD.redirect_uri
    OR NEW.return_route IS DISTINCT FROM OLD.return_route
    OR NEW.issued_at IS DISTINCT FROM OLD.issued_at
    OR NEW.expires_at IS DISTINCT FROM OLD.expires_at
    OR (
      OLD.claimed_at IS NOT NULL
      AND (
        NEW.claimed_at IS DISTINCT FROM OLD.claimed_at
        OR NEW.claim_hash IS DISTINCT FROM OLD.claim_hash
      )
    )
    OR (
      OLD.consumed_at IS NOT NULL
      AND NEW.consumed_at IS DISTINCT FROM OLD.consumed_at
    )
  THEN
    RAISE EXCEPTION 'login transaction binding is immutable'
      USING ERRCODE = '23000',
            CONSTRAINT = 'identity_login_transaction_guard';
  END IF;
  RETURN NEW;
END;
$$;

CREATE FUNCTION aios_core.enforce_identity_session_update()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF NEW.session_id IS DISTINCT FROM OLD.session_id
    OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
    OR NEW.tenant_kind IS DISTINCT FROM OLD.tenant_kind
    OR NEW.account_id IS DISTINCT FROM OLD.account_id
    OR NEW.provider_connection_id IS DISTINCT FROM OLD.provider_connection_id
    OR NEW.token_hash IS DISTINCT FROM OLD.token_hash
    OR NEW.account_revocation_epoch IS DISTINCT FROM OLD.account_revocation_epoch
    OR NEW.tenant_revocation_epoch IS DISTINCT FROM OLD.tenant_revocation_epoch
    OR NEW.authentication_time IS DISTINCT FROM OLD.authentication_time
    OR NEW.authentication_methods IS DISTINCT FROM OLD.authentication_methods
    OR NEW.issued_at IS DISTINCT FROM OLD.issued_at
    OR NEW.expires_at IS DISTINCT FROM OLD.expires_at
  THEN
    RAISE EXCEPTION 'identity session binding is immutable'
      USING ERRCODE = '23000',
            CONSTRAINT = 'identity_session_binding_guard';
  END IF;

  IF OLD.status = 'REVOKED' AND NEW.status <> 'REVOKED' THEN
    RAISE EXCEPTION 'revoked identity session cannot be restored'
      USING ERRCODE = '23000',
            CONSTRAINT = 'identity_session_terminal_guard';
  END IF;

  IF OLD.revoked_at IS NOT NULL
    AND NEW.revoked_at IS DISTINCT FROM OLD.revoked_at
  THEN
    RAISE EXCEPTION 'revoked identity session timestamp is immutable'
      USING ERRCODE = '23000',
            CONSTRAINT = 'identity_session_revocation_guard';
  END IF;
  RETURN NEW;
END;
$$;

CREATE FUNCTION aios_core.enforce_identity_outbox_identity()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF NEW.event_id IS DISTINCT FROM OLD.event_id
    OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
    OR NEW.tenant_kind IS DISTINCT FROM OLD.tenant_kind
    OR NEW.event IS DISTINCT FROM OLD.event
    OR NEW.created_at IS DISTINCT FROM OLD.created_at
  THEN
    RAISE EXCEPTION 'identity outbox payload is immutable'
      USING ERRCODE = '23000',
            CONSTRAINT = 'identity_outbox_payload_guard';
  END IF;
  RETURN NEW;
END;
$$;

CREATE FUNCTION aios_core.enforce_identity_event_outbox_pair()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  paired_event jsonb;
BEGIN
  IF TG_TABLE_NAME = 'identity_event' THEN
    SELECT event
      INTO paired_event
      FROM aios_core.identity_outbox
     WHERE event_id = NEW.event_id;
  ELSE
    SELECT event
      INTO paired_event
      FROM aios_core.identity_event
     WHERE event_id = NEW.event_id;
  END IF;

  IF NOT FOUND OR paired_event IS DISTINCT FROM NEW.event THEN
    RAISE EXCEPTION 'identity event and outbox payload must be paired'
      USING ERRCODE = '23000',
            CONSTRAINT = 'identity_event_outbox_pair_guard';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER identity_projection_update_guard
BEFORE UPDATE ON aios_core.identity_tenant_projection
FOR EACH ROW EXECUTE FUNCTION aios_core.enforce_identity_projection_update();

CREATE TRIGGER identity_provider_update_guard
BEFORE UPDATE ON aios_core.identity_provider
FOR EACH ROW EXECUTE FUNCTION aios_core.enforce_identity_provider_update();

CREATE TRIGGER identity_account_update_guard
BEFORE UPDATE ON aios_core.identity_account
FOR EACH ROW EXECUTE FUNCTION aios_core.enforce_identity_account_update();

CREATE TRIGGER identity_login_transaction_update_guard
BEFORE UPDATE ON aios_core.identity_login_transaction
FOR EACH ROW
EXECUTE FUNCTION aios_core.enforce_identity_login_transaction_update();

CREATE TRIGGER identity_session_update_guard
BEFORE UPDATE ON aios_core.identity_session
FOR EACH ROW EXECUTE FUNCTION aios_core.enforce_identity_session_update();

CREATE TRIGGER identity_outbox_update_guard
BEFORE UPDATE ON aios_core.identity_outbox
FOR EACH ROW EXECUTE FUNCTION aios_core.enforce_identity_outbox_identity();

CREATE TRIGGER identity_projection_no_delete
BEFORE DELETE ON aios_core.identity_tenant_projection
FOR EACH ROW EXECUTE FUNCTION aios_core.reject_identity_tombstone_delete();

CREATE TRIGGER identity_provider_no_delete
BEFORE DELETE ON aios_core.identity_provider
FOR EACH ROW EXECUTE FUNCTION aios_core.reject_identity_tombstone_delete();

CREATE TRIGGER identity_account_no_delete
BEFORE DELETE ON aios_core.identity_account
FOR EACH ROW EXECUTE FUNCTION aios_core.reject_identity_tombstone_delete();

CREATE TRIGGER identity_login_transaction_no_delete
BEFORE DELETE ON aios_core.identity_login_transaction
FOR EACH ROW EXECUTE FUNCTION aios_core.reject_identity_tombstone_delete();

CREATE TRIGGER identity_session_no_delete
BEFORE DELETE ON aios_core.identity_session
FOR EACH ROW EXECUTE FUNCTION aios_core.reject_identity_tombstone_delete();

CREATE TRIGGER identity_outbox_no_delete
BEFORE DELETE ON aios_core.identity_outbox
FOR EACH ROW EXECUTE FUNCTION aios_core.reject_identity_tombstone_delete();

CREATE TRIGGER identity_source_receipt_no_update
BEFORE UPDATE OR DELETE ON aios_core.identity_source_receipt
FOR EACH ROW EXECUTE FUNCTION aios_core.reject_identity_append_only_change();

CREATE TRIGGER identity_command_receipt_no_update
BEFORE UPDATE OR DELETE ON aios_core.identity_command_receipt
FOR EACH ROW EXECUTE FUNCTION aios_core.reject_identity_append_only_change();

CREATE TRIGGER identity_event_no_update
BEFORE UPDATE OR DELETE ON aios_core.identity_event
FOR EACH ROW EXECUTE FUNCTION aios_core.reject_identity_append_only_change();

CREATE CONSTRAINT TRIGGER identity_event_requires_outbox
AFTER INSERT ON aios_core.identity_event
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION aios_core.enforce_identity_event_outbox_pair();

CREATE CONSTRAINT TRIGGER identity_outbox_requires_event
AFTER INSERT ON aios_core.identity_outbox
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION aios_core.enforce_identity_event_outbox_pair();

COMMIT;
