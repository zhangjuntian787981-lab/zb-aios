BEGIN;

-- This migration runs after C04 0005_scim_checkpoint.sql.
-- The migration owner remains separate from the three NOLOGIN runtime roles.

CREATE ROLE aios_c04_core_runtime
  NOLOGIN
  NOSUPERUSER
  NOCREATEDB
  NOCREATEROLE
  NOINHERIT
  NOREPLICATION
  NOBYPASSRLS;

CREATE ROLE aios_c04_outbox_worker
  NOLOGIN
  NOSUPERUSER
  NOCREATEDB
  NOCREATEROLE
  NOINHERIT
  NOREPLICATION
  NOBYPASSRLS;

CREATE ROLE aios_c04_scim_checkpoint_runtime
  NOLOGIN
  NOSUPERUSER
  NOCREATEDB
  NOCREATEROLE
  NOINHERIT
  NOREPLICATION
  NOBYPASSRLS;

REVOKE ALL PRIVILEGES ON SCHEMA aios_core FROM PUBLIC;
REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA aios_core FROM PUBLIC;
REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA aios_core FROM PUBLIC;
REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA aios_core FROM PUBLIC;

ALTER DEFAULT PRIVILEGES IN SCHEMA aios_core
  REVOKE ALL PRIVILEGES ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA aios_core
  REVOKE ALL PRIVILEGES ON SEQUENCES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA aios_core
  REVOKE ALL PRIVILEGES ON FUNCTIONS FROM PUBLIC;

GRANT USAGE ON SCHEMA aios_core TO
  aios_c04_core_runtime,
  aios_c04_outbox_worker,
  aios_c04_scim_checkpoint_runtime;

GRANT SELECT, INSERT, UPDATE ON TABLE
  aios_core.identity_tenant_projection,
  aios_core.identity_provider,
  aios_core.identity_provider_configuration,
  aios_core.identity_account,
  aios_core.identity_login_transaction,
  aios_core.identity_session
TO aios_c04_core_runtime;

GRANT SELECT, INSERT ON TABLE
  aios_core.identity_source_receipt,
  aios_core.identity_command_receipt,
  aios_core.identity_event,
  aios_core.identity_outbox
TO aios_c04_core_runtime;

GRANT SELECT, UPDATE ON TABLE
  aios_core.identity_outbox
TO aios_c04_outbox_worker;

GRANT SELECT, INSERT, UPDATE ON TABLE
  aios_core.scim_provisioning_checkpoint
TO aios_c04_scim_checkpoint_runtime;

COMMIT;
