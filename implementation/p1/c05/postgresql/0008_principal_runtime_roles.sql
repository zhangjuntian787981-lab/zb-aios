BEGIN;

-- This migration runs after C05 0007_stable_principal.sql.
-- The migration owner remains separate from both NOLOGIN runtime roles.

CREATE ROLE aios_c05_core_runtime
  NOLOGIN
  NOSUPERUSER
  NOCREATEDB
  NOCREATEROLE
  NOINHERIT
  NOREPLICATION
  NOBYPASSRLS;

CREATE ROLE aios_c05_outbox_worker
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

-- These trigger functions must compare an IdentityLink with the current C04
-- account and lock the current C03 Tenant state without granting C05 direct
-- read access to either upstream table. Their bodies use only qualified
-- relations and no dynamic SQL.
ALTER FUNCTION aios_core.enforce_principal_registry_insert()
  SECURITY DEFINER;
ALTER FUNCTION aios_core.enforce_principal_registry_insert()
  SET search_path = pg_catalog, aios_core;
ALTER FUNCTION aios_core.enforce_principal_registry_update()
  SECURITY DEFINER;
ALTER FUNCTION aios_core.enforce_principal_registry_update()
  SET search_path = pg_catalog, aios_core;
ALTER FUNCTION aios_core.enforce_principal_identity_link_insert()
  SECURITY DEFINER;
ALTER FUNCTION aios_core.enforce_principal_identity_link_insert()
  SET search_path = pg_catalog, aios_core;
ALTER FUNCTION aios_core.enforce_principal_identity_link_update()
  SECURITY DEFINER;
ALTER FUNCTION aios_core.enforce_principal_identity_link_update()
  SET search_path = pg_catalog, aios_core;
ALTER FUNCTION aios_core.enforce_principal_delegation_insert()
  SECURITY DEFINER;
ALTER FUNCTION aios_core.enforce_principal_delegation_insert()
  SET search_path = pg_catalog, aios_core;

REVOKE ALL PRIVILEGES
  ON FUNCTION aios_core.enforce_principal_registry_insert()
  FROM PUBLIC, aios_c05_core_runtime, aios_c05_outbox_worker;
REVOKE ALL PRIVILEGES
  ON FUNCTION aios_core.enforce_principal_registry_update()
  FROM PUBLIC, aios_c05_core_runtime, aios_c05_outbox_worker;
REVOKE ALL PRIVILEGES
  ON FUNCTION aios_core.enforce_principal_identity_link_insert()
  FROM PUBLIC, aios_c05_core_runtime, aios_c05_outbox_worker;
REVOKE ALL PRIVILEGES
  ON FUNCTION aios_core.enforce_principal_identity_link_update()
  FROM PUBLIC, aios_c05_core_runtime, aios_c05_outbox_worker;
REVOKE ALL PRIVILEGES
  ON FUNCTION aios_core.enforce_principal_delegation_insert()
  FROM PUBLIC, aios_c05_core_runtime, aios_c05_outbox_worker;

GRANT USAGE ON SCHEMA aios_core TO
  aios_c05_core_runtime,
  aios_c05_outbox_worker;

GRANT SELECT, INSERT, UPDATE ON TABLE
  aios_core.principal_registry,
  aios_core.principal_identity_link,
  aios_core.principal_delegation
TO aios_c05_core_runtime;

GRANT SELECT, INSERT ON TABLE
  aios_core.principal_command_receipt,
  aios_core.principal_event,
  aios_core.principal_outbox
TO aios_c05_core_runtime;

GRANT SELECT, UPDATE ON TABLE
  aios_core.principal_outbox
TO aios_c05_outbox_worker;

COMMIT;
