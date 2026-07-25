BEGIN;

CREATE TABLE aios_core.scim_provisioning_checkpoint (
  tenant_id text NOT NULL
    CHECK (
      tenant_id ~ '^stn_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
  provider_connection_id text NOT NULL
    CHECK (
      provider_connection_id ~ '^idp_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
  external_id text NOT NULL
    CHECK (
      length(external_id) BETWEEN 1 AND 256
      AND external_id ~ '^[A-Za-z0-9._:@/+~-]+$'
    ),
  user_name text NOT NULL
    CHECK (
      length(user_name) BETWEEN 1 AND 128
      AND user_name ~ '^[A-Za-z0-9._@+-]+$'
    ),
  source_revision bigint NOT NULL
    CHECK (
      source_revision > 0
      AND source_revision <= 9007199254740991
    ),
  desired_state text NOT NULL
    CHECK (desired_state IN ('ACTIVE', 'SUSPENDED', 'TERMINATED')),
  profile jsonb NOT NULL
    CHECK (
      jsonb_typeof(profile) = 'object'
      AND profile ?& ARRAY['givenName', 'familyName', 'email']
      AND profile - ARRAY['givenName', 'familyName', 'email'] = '{}'::jsonb
      AND jsonb_typeof(profile -> 'givenName') = 'string'
      AND length(profile ->> 'givenName') BETWEEN 1 AND 128
      AND jsonb_typeof(profile -> 'familyName') = 'string'
      AND length(profile ->> 'familyName') BETWEEN 1 AND 128
      AND jsonb_typeof(profile -> 'email') = 'string'
      AND length(profile ->> 'email') BETWEEN 3 AND 254
      AND profile ->> 'email' ~ '^[^[:space:]@]+@[^[:space:]@]+$'
    ),
  status text NOT NULL CHECK (status IN ('PENDING', 'CONFIRMED')),
  resource_id text
    CHECK (
      resource_id IS NULL
      OR (
        length(resource_id) BETWEEN 1 AND 128
        AND resource_id ~ '^[A-Za-z0-9._~-]+$'
      )
    ),
  created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT statement_timestamp(),
  PRIMARY KEY (tenant_id, provider_connection_id, external_id),
  CONSTRAINT scim_checkpoint_user_name_key
    UNIQUE (tenant_id, provider_connection_id, user_name),
  CONSTRAINT scim_checkpoint_provider_fkey
    FOREIGN KEY (provider_connection_id, tenant_id)
    REFERENCES aios_core.identity_provider(
      provider_connection_id,
      tenant_id
    )
    ON DELETE RESTRICT
);

CREATE FUNCTION aios_core.enforce_scim_checkpoint_insert()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF NEW.status <> 'PENDING' OR NEW.resource_id IS NOT NULL THEN
    RAISE EXCEPTION 'new SCIM checkpoint must begin pending without a resource'
      USING ERRCODE = '23000',
            CONSTRAINT = 'scim_checkpoint_initial_state_guard';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER scim_checkpoint_insert_guard
BEFORE INSERT ON aios_core.scim_provisioning_checkpoint
FOR EACH ROW
EXECUTE FUNCTION aios_core.enforce_scim_checkpoint_insert();

CREATE FUNCTION aios_core.enforce_scim_checkpoint_update()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
    OR NEW.provider_connection_id IS DISTINCT FROM OLD.provider_connection_id
    OR NEW.external_id IS DISTINCT FROM OLD.external_id
    OR NEW.user_name IS DISTINCT FROM OLD.user_name
  THEN
    RAISE EXCEPTION 'SCIM checkpoint binding is immutable'
      USING ERRCODE = '23000',
            CONSTRAINT = 'scim_checkpoint_binding_guard';
  END IF;

  IF NEW.created_at IS DISTINCT FROM OLD.created_at
    OR NEW.updated_at < OLD.updated_at
  THEN
    RAISE EXCEPTION 'SCIM checkpoint timestamps cannot move backwards'
      USING ERRCODE = '23000',
            CONSTRAINT = 'scim_checkpoint_timestamp_guard';
  END IF;

  IF NEW.source_revision < OLD.source_revision THEN
    RAISE EXCEPTION 'SCIM checkpoint revision cannot move backwards'
      USING ERRCODE = '23000',
            CONSTRAINT = 'scim_checkpoint_revision_guard';
  END IF;

  IF NEW.source_revision = OLD.source_revision THEN
    IF NEW.desired_state IS DISTINCT FROM OLD.desired_state
      OR NEW.profile IS DISTINCT FROM OLD.profile
    THEN
      RAISE EXCEPTION 'SCIM checkpoint revision is bound to its content'
        USING ERRCODE = '23000',
              CONSTRAINT = 'scim_checkpoint_content_guard';
    END IF;

    IF OLD.status = 'CONFIRMED' AND NEW.status <> 'CONFIRMED' THEN
      RAISE EXCEPTION 'confirmed SCIM checkpoint cannot become pending'
        USING ERRCODE = '23000',
              CONSTRAINT = 'scim_checkpoint_status_guard';
    END IF;

    IF NEW.status = OLD.status
      AND NEW.resource_id IS DISTINCT FROM OLD.resource_id
    THEN
      RAISE EXCEPTION 'SCIM resource binding can change only on confirmation'
        USING ERRCODE = '23000',
              CONSTRAINT = 'scim_checkpoint_resource_guard';
    END IF;

    IF OLD.status = 'PENDING' AND NEW.status = 'CONFIRMED'
      AND NEW.resource_id IS NULL
    THEN
      RAISE EXCEPTION 'confirmed SCIM checkpoint requires a resource'
        USING ERRCODE = '23000',
              CONSTRAINT = 'scim_checkpoint_resource_guard';
    END IF;

    RETURN NEW;
  END IF;

  IF OLD.desired_state = 'TERMINATED'
    AND NEW.desired_state <> 'TERMINATED'
  THEN
    RAISE EXCEPTION 'terminated SCIM identity cannot be restored'
      USING ERRCODE = '23000',
            CONSTRAINT = 'scim_checkpoint_terminal_guard';
  END IF;

  IF NEW.status <> 'PENDING'
    OR NEW.resource_id IS DISTINCT FROM OLD.resource_id
  THEN
    RAISE EXCEPTION 'new SCIM revision must begin as pending'
      USING ERRCODE = '23000',
            CONSTRAINT = 'scim_checkpoint_revision_state_guard';
  END IF;

  RETURN NEW;
END;
$$;

CREATE TRIGGER scim_checkpoint_update_guard
BEFORE UPDATE ON aios_core.scim_provisioning_checkpoint
FOR EACH ROW
EXECUTE FUNCTION aios_core.enforce_scim_checkpoint_update();

CREATE FUNCTION aios_core.reject_scim_checkpoint_delete()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION 'SCIM checkpoint tombstones cannot be deleted'
    USING ERRCODE = '23000',
          CONSTRAINT = 'scim_checkpoint_no_delete';
END;
$$;

CREATE TRIGGER scim_checkpoint_no_delete
BEFORE DELETE ON aios_core.scim_provisioning_checkpoint
FOR EACH ROW
EXECUTE FUNCTION aios_core.reject_scim_checkpoint_delete();

COMMIT;
