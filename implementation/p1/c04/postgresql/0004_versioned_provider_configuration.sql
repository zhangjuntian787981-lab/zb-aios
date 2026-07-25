BEGIN;

-- Provider connection identity stays stable. Security configuration is
-- versioned so an in-flight login can remain pinned to the exact version it
-- started with while new logins move to the next version.

ALTER TABLE aios_core.identity_provider
  ADD CONSTRAINT identity_provider_connection_tenant_key
  UNIQUE (provider_connection_id, tenant_id);

CREATE TABLE aios_core.identity_provider_configuration (
  provider_connection_id text NOT NULL,
  tenant_id text NOT NULL,
  configuration_version bigint NOT NULL
    CHECK (
      configuration_version > 0
      AND configuration_version <= 9007199254740991
    ),
  redirect_routes jsonb NOT NULL
    CHECK (jsonb_typeof(redirect_routes) = 'object'),
  allowed_algorithms jsonb NOT NULL
    CHECK (
      jsonb_typeof(allowed_algorithms) = 'array'
      AND jsonb_array_length(allowed_algorithms) > 0
    ),
  allowed_key_ids jsonb NOT NULL
    CHECK (
      jsonb_typeof(allowed_key_ids) = 'array'
      AND jsonb_array_length(allowed_key_ids) > 0
    ),
  required_authentication_methods jsonb NOT NULL
    CHECK (
      jsonb_typeof(required_authentication_methods) = 'array'
      AND jsonb_array_length(required_authentication_methods) > 0
    ),
  max_authentication_age_seconds integer NOT NULL
    CHECK (max_authentication_age_seconds > 0),
  upstream_protocols jsonb NOT NULL
    CHECK (
      jsonb_typeof(upstream_protocols) = 'array'
      AND jsonb_array_length(upstream_protocols) > 0
    ),
  state text NOT NULL CHECK (state IN ('CURRENT', 'GRACE', 'RETIRED')),
  activated_at timestamptz NOT NULL,
  grace_until timestamptz,
  retired_at timestamptz,
  retirement_mode text
    CHECK (retirement_mode IN ('NORMAL', 'EMERGENCY')),
  PRIMARY KEY (provider_connection_id, configuration_version),
  UNIQUE (provider_connection_id, tenant_id, configuration_version),
  FOREIGN KEY (provider_connection_id, tenant_id)
    REFERENCES aios_core.identity_provider(provider_connection_id, tenant_id)
    ON DELETE RESTRICT,
  CHECK (
    (
      state = 'CURRENT'
      AND grace_until IS NULL
      AND retired_at IS NULL
      AND retirement_mode IS NULL
    )
    OR (
      state = 'GRACE'
      AND grace_until IS NOT NULL
      AND grace_until > activated_at
      AND retired_at IS NULL
      AND retirement_mode IS NULL
    )
    OR (
      state = 'RETIRED'
      AND retired_at IS NOT NULL
      AND retired_at >= activated_at
      AND retirement_mode IS NOT NULL
      AND (
        retirement_mode = 'EMERGENCY'
        OR (
          retirement_mode = 'NORMAL'
          AND grace_until IS NOT NULL
          AND retired_at >= grace_until
        )
      )
    )
  )
);

CREATE UNIQUE INDEX identity_provider_one_current_configuration
  ON aios_core.identity_provider_configuration(provider_connection_id)
  WHERE state = 'CURRENT';

INSERT INTO aios_core.identity_provider_configuration (
  provider_connection_id,
  tenant_id,
  configuration_version,
  redirect_routes,
  allowed_algorithms,
  allowed_key_ids,
  required_authentication_methods,
  max_authentication_age_seconds,
  upstream_protocols,
  state,
  activated_at,
  grace_until,
  retired_at,
  retirement_mode
)
SELECT
  provider_connection_id,
  tenant_id,
  configuration_version,
  redirect_routes,
  allowed_algorithms,
  allowed_key_ids,
  required_authentication_methods,
  max_authentication_age_seconds,
  upstream_protocols,
  'CURRENT',
  created_at,
  NULL,
  NULL,
  NULL
FROM aios_core.identity_provider;

ALTER TABLE aios_core.identity_tenant_projection
  ADD CONSTRAINT identity_projection_safe_integer_guard
  CHECK (
    generation <= 9007199254740991
    AND revocation_epoch <= 9007199254740991
  );

ALTER TABLE aios_core.identity_account
  ADD CONSTRAINT identity_account_safe_integer_guard
  CHECK (
    lifecycle_version <= 9007199254740991
    AND source_revision <= 9007199254740991
    AND revocation_epoch <= 9007199254740991
    AND incarnation <= 9007199254740991
  );

ALTER TABLE aios_core.identity_provider
  ADD CONSTRAINT identity_provider_version_safe_integer_guard
  CHECK (configuration_version <= 9007199254740991);

ALTER TABLE aios_core.identity_login_transaction
  ADD CONSTRAINT identity_login_safe_integer_guard
  CHECK (provider_configuration_version <= 9007199254740991);

ALTER TABLE aios_core.identity_session
  ADD CONSTRAINT identity_session_epoch_safe_integer_guard
  CHECK (
    account_revocation_epoch <= 9007199254740991
    AND tenant_revocation_epoch <= 9007199254740991
  );

DO $$
DECLARE
  old_constraint text;
BEGIN
  SELECT constraint_name
    INTO old_constraint
    FROM information_schema.table_constraints
   WHERE table_schema = 'aios_core'
     AND table_name = 'identity_login_transaction'
     AND constraint_type = 'FOREIGN KEY'
     AND constraint_name IN (
       SELECT c.conname
         FROM pg_constraint c
        WHERE c.conrelid =
              'aios_core.identity_login_transaction'::regclass
          AND pg_get_constraintdef(c.oid) LIKE
              'FOREIGN KEY (provider_connection_id, tenant_id, provider_configuration_version)%'
     )
   LIMIT 1;

  IF old_constraint IS NULL THEN
    RAISE EXCEPTION 'provider configuration foreign key was not found';
  END IF;

  EXECUTE format(
    'ALTER TABLE aios_core.identity_login_transaction DROP CONSTRAINT %I',
    old_constraint
  );
END;
$$;

ALTER TABLE aios_core.identity_login_transaction
  ADD CONSTRAINT identity_login_provider_configuration_fkey
  FOREIGN KEY (
    provider_connection_id,
    tenant_id,
    provider_configuration_version
  )
  REFERENCES aios_core.identity_provider_configuration(
    provider_connection_id,
    tenant_id,
    configuration_version
  )
  ON DELETE RESTRICT;

ALTER TABLE aios_core.identity_session
  ADD COLUMN provider_configuration_version bigint;

UPDATE aios_core.identity_session AS session
   SET provider_configuration_version = provider.configuration_version
  FROM aios_core.identity_provider AS provider
 WHERE provider.provider_connection_id = session.provider_connection_id;

ALTER TABLE aios_core.identity_session
  ALTER COLUMN provider_configuration_version SET NOT NULL,
  ADD CONSTRAINT identity_session_provider_configuration_version_check
    CHECK (
      provider_configuration_version > 0
      AND provider_configuration_version <= 9007199254740991
    ),
  ADD CONSTRAINT identity_session_provider_configuration_fkey
    FOREIGN KEY (
      provider_connection_id,
      tenant_id,
      provider_configuration_version
    )
    REFERENCES aios_core.identity_provider_configuration(
      provider_connection_id,
      tenant_id,
      configuration_version
    )
    ON DELETE RESTRICT;

CREATE FUNCTION aios_core.enforce_identity_provider_configuration_insert()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  latest_version bigint;
BEGIN
  SELECT max(configuration_version)
    INTO latest_version
    FROM aios_core.identity_provider_configuration
   WHERE provider_connection_id = NEW.provider_connection_id;

  IF NEW.state <> 'CURRENT'
    OR (
      latest_version IS NULL
      AND NEW.configuration_version <> 1
    )
    OR (
      latest_version IS NOT NULL
      AND NEW.configuration_version <> latest_version + 1
    )
  THEN
    RAISE EXCEPTION 'provider configuration version must advance by one'
      USING ERRCODE = '23000',
            CONSTRAINT = 'identity_provider_configuration_version_guard';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER identity_provider_configuration_insert_guard
BEFORE INSERT ON aios_core.identity_provider_configuration
FOR EACH ROW
EXECUTE FUNCTION aios_core.enforce_identity_provider_configuration_insert();

CREATE FUNCTION aios_core.enforce_identity_provider_configuration_update()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF NEW.provider_connection_id IS DISTINCT FROM OLD.provider_connection_id
    OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
    OR NEW.configuration_version IS DISTINCT FROM OLD.configuration_version
    OR NEW.redirect_routes IS DISTINCT FROM OLD.redirect_routes
    OR NEW.allowed_algorithms IS DISTINCT FROM OLD.allowed_algorithms
    OR NEW.allowed_key_ids IS DISTINCT FROM OLD.allowed_key_ids
    OR NEW.required_authentication_methods
      IS DISTINCT FROM OLD.required_authentication_methods
    OR NEW.max_authentication_age_seconds
      IS DISTINCT FROM OLD.max_authentication_age_seconds
    OR NEW.upstream_protocols IS DISTINCT FROM OLD.upstream_protocols
    OR NEW.activated_at IS DISTINCT FROM OLD.activated_at
  THEN
    RAISE EXCEPTION 'provider configuration payload is immutable'
      USING ERRCODE = '23000',
            CONSTRAINT = 'identity_provider_configuration_payload_guard';
  END IF;

  IF NEW.state IS NOT DISTINCT FROM OLD.state THEN
    IF NEW.grace_until IS DISTINCT FROM OLD.grace_until
      OR NEW.retired_at IS DISTINCT FROM OLD.retired_at
      OR NEW.retirement_mode IS DISTINCT FROM OLD.retirement_mode
    THEN
      RAISE EXCEPTION 'provider configuration timestamps are immutable'
        USING ERRCODE = '23000',
              CONSTRAINT = 'identity_provider_configuration_state_guard';
    END IF;
    RETURN NEW;
  END IF;

  IF OLD.state = 'CURRENT' AND NEW.state = 'GRACE' THEN
    IF NEW.grace_until IS NULL
      OR NEW.grace_until <= NEW.activated_at
      OR NEW.retired_at IS NOT NULL
      OR NEW.retirement_mode IS NOT NULL
    THEN
      RAISE EXCEPTION 'invalid provider grace transition'
        USING ERRCODE = '23000',
              CONSTRAINT = 'identity_provider_configuration_state_guard';
    END IF;
    RETURN NEW;
  END IF;

  IF (
      OLD.state = 'CURRENT'
      AND NEW.state = 'RETIRED'
      AND NEW.grace_until IS NULL
      AND NEW.retirement_mode = 'EMERGENCY'
    )
    OR (
      OLD.state = 'GRACE'
      AND NEW.state = 'RETIRED'
      AND NEW.grace_until IS NOT DISTINCT FROM OLD.grace_until
      AND (
        NEW.retirement_mode = 'EMERGENCY'
        OR (
          NEW.retirement_mode = 'NORMAL'
          AND NEW.retired_at >= OLD.grace_until
        )
      )
    )
  THEN
    IF NEW.retired_at IS NULL
      OR NEW.retired_at < NEW.activated_at
      OR NEW.retirement_mode IS NULL
    THEN
      RAISE EXCEPTION 'invalid provider retirement transition'
        USING ERRCODE = '23000',
              CONSTRAINT = 'identity_provider_configuration_state_guard';
    END IF;
    RETURN NEW;
  END IF;

  RAISE EXCEPTION 'provider configuration state cannot move backwards'
    USING ERRCODE = '23000',
          CONSTRAINT = 'identity_provider_configuration_state_guard';
END;
$$;

CREATE TRIGGER identity_provider_configuration_update_guard
BEFORE UPDATE ON aios_core.identity_provider_configuration
FOR EACH ROW
EXECUTE FUNCTION aios_core.enforce_identity_provider_configuration_update();

CREATE TRIGGER identity_provider_configuration_no_delete
BEFORE DELETE ON aios_core.identity_provider_configuration
FOR EACH ROW EXECUTE FUNCTION aios_core.reject_identity_tombstone_delete();

CREATE OR REPLACE FUNCTION aios_core.enforce_identity_provider_update()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  configuration_changed boolean;
BEGIN
  IF NEW.provider_connection_id IS DISTINCT FROM OLD.provider_connection_id
    OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
    OR NEW.tenant_kind IS DISTINCT FROM OLD.tenant_kind
    OR NEW.protocol IS DISTINCT FROM OLD.protocol
    OR NEW.issuer IS DISTINCT FROM OLD.issuer
    OR NEW.client_id IS DISTINCT FROM OLD.client_id
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

  configuration_changed :=
    NEW.redirect_routes IS DISTINCT FROM OLD.redirect_routes
    OR NEW.configuration_version IS DISTINCT FROM OLD.configuration_version
    OR NEW.allowed_algorithms IS DISTINCT FROM OLD.allowed_algorithms
    OR NEW.allowed_key_ids IS DISTINCT FROM OLD.allowed_key_ids
    OR NEW.required_authentication_methods
      IS DISTINCT FROM OLD.required_authentication_methods
    OR NEW.max_authentication_age_seconds
      IS DISTINCT FROM OLD.max_authentication_age_seconds
    OR NEW.upstream_protocols IS DISTINCT FROM OLD.upstream_protocols;

  IF configuration_changed
    AND (
      NEW.configuration_version <> OLD.configuration_version + 1
      OR NOT EXISTS (
        SELECT 1
          FROM aios_core.identity_provider_configuration AS configuration
         WHERE configuration.provider_connection_id =
               NEW.provider_connection_id
           AND configuration.tenant_id = NEW.tenant_id
           AND configuration.configuration_version =
               NEW.configuration_version
           AND configuration.redirect_routes = NEW.redirect_routes
           AND configuration.allowed_algorithms = NEW.allowed_algorithms
           AND configuration.allowed_key_ids = NEW.allowed_key_ids
           AND configuration.required_authentication_methods =
               NEW.required_authentication_methods
           AND configuration.max_authentication_age_seconds =
               NEW.max_authentication_age_seconds
           AND configuration.upstream_protocols = NEW.upstream_protocols
           AND configuration.state = 'CURRENT'
      )
    )
  THEN
    RAISE EXCEPTION 'identity provider configuration mirror is invalid'
      USING ERRCODE = '23000',
            CONSTRAINT = 'identity_provider_configuration_mirror_guard';
  END IF;
  RETURN NEW;
END;
$$;

CREATE FUNCTION aios_core.sync_identity_provider_configuration_mirror()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  UPDATE aios_core.identity_provider
     SET redirect_routes = NEW.redirect_routes,
         configuration_version = NEW.configuration_version,
         allowed_algorithms = NEW.allowed_algorithms,
         allowed_key_ids = NEW.allowed_key_ids,
         required_authentication_methods =
           NEW.required_authentication_methods,
         max_authentication_age_seconds =
           NEW.max_authentication_age_seconds,
         upstream_protocols = NEW.upstream_protocols,
         updated_at = NEW.activated_at
   WHERE provider_connection_id = NEW.provider_connection_id
     AND tenant_id = NEW.tenant_id;
  RETURN NEW;
END;
$$;

CREATE TRIGGER identity_provider_configuration_mirror_sync
AFTER INSERT ON aios_core.identity_provider_configuration
FOR EACH ROW
EXECUTE FUNCTION aios_core.sync_identity_provider_configuration_mirror();

CREATE OR REPLACE FUNCTION aios_core.enforce_identity_session_update()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF NEW.session_id IS DISTINCT FROM OLD.session_id
    OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
    OR NEW.tenant_kind IS DISTINCT FROM OLD.tenant_kind
    OR NEW.account_id IS DISTINCT FROM OLD.account_id
    OR NEW.provider_connection_id IS DISTINCT FROM OLD.provider_connection_id
    OR NEW.provider_configuration_version
      IS DISTINCT FROM OLD.provider_configuration_version
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

COMMIT;
