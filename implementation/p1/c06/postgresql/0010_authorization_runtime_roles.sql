BEGIN;

-- This migration runs after C06 0009_authorization.sql.
-- The migration owner remains separate from all NOLOGIN runtime roles.

CREATE ROLE aios_c06_control_runtime
  NOLOGIN
  NOSUPERUSER
  NOCREATEDB
  NOCREATEROLE
  NOINHERIT
  NOREPLICATION
  NOBYPASSRLS;

CREATE ROLE aios_c06_decision_runtime
  NOLOGIN
  NOSUPERUSER
  NOCREATEDB
  NOCREATEROLE
  NOINHERIT
  NOREPLICATION
  NOBYPASSRLS;

CREATE ROLE aios_c06_outbox_worker
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

-- These guards recheck the authoritative C03 Tenant without granting either
-- C06 runtime role direct access to the C03 or C05 tables.
ALTER FUNCTION aios_core.enforce_authorization_release_insert()
  SECURITY DEFINER;
ALTER FUNCTION aios_core.enforce_authorization_release_insert()
  SET search_path = pg_catalog, aios_core;
ALTER FUNCTION aios_core.enforce_authorization_release_update()
  SECURITY DEFINER;
ALTER FUNCTION aios_core.enforce_authorization_release_update()
  SET search_path = pg_catalog, aios_core;
ALTER FUNCTION aios_core.enforce_authorization_activation_insert()
  SECURITY DEFINER;
ALTER FUNCTION aios_core.enforce_authorization_activation_insert()
  SET search_path = pg_catalog, aios_core;
ALTER FUNCTION aios_core.enforce_authorization_active_policy()
  SECURITY DEFINER;
ALTER FUNCTION aios_core.enforce_authorization_active_policy()
  SET search_path = pg_catalog, aios_core;
ALTER FUNCTION aios_core.enforce_authorization_decision_insert()
  SECURITY DEFINER;
ALTER FUNCTION aios_core.enforce_authorization_decision_insert()
  SET search_path = pg_catalog, aios_core;

REVOKE ALL PRIVILEGES
  ON FUNCTION aios_core.enforce_authorization_release_insert()
  FROM PUBLIC,
       aios_c06_control_runtime,
       aios_c06_decision_runtime,
       aios_c06_outbox_worker;
REVOKE ALL PRIVILEGES
  ON FUNCTION aios_core.enforce_authorization_release_update()
  FROM PUBLIC,
       aios_c06_control_runtime,
       aios_c06_decision_runtime,
       aios_c06_outbox_worker;
REVOKE ALL PRIVILEGES
  ON FUNCTION aios_core.enforce_authorization_activation_insert()
  FROM PUBLIC,
       aios_c06_control_runtime,
       aios_c06_decision_runtime,
       aios_c06_outbox_worker;
REVOKE ALL PRIVILEGES
  ON FUNCTION aios_core.enforce_authorization_active_policy()
  FROM PUBLIC,
       aios_c06_control_runtime,
       aios_c06_decision_runtime,
       aios_c06_outbox_worker;
REVOKE ALL PRIVILEGES
  ON FUNCTION aios_core.enforce_authorization_decision_insert()
  FROM PUBLIC,
       aios_c06_control_runtime,
       aios_c06_decision_runtime,
       aios_c06_outbox_worker;

GRANT USAGE ON SCHEMA aios_core TO
  aios_c06_control_runtime,
  aios_c06_decision_runtime,
  aios_c06_outbox_worker;

GRANT SELECT, INSERT, UPDATE ON TABLE
  aios_core.authorization_policy_release,
  aios_core.authorization_active_policy
TO aios_c06_control_runtime;

GRANT SELECT, INSERT ON TABLE
  aios_core.authorization_activation,
  aios_core.authorization_command_receipt,
  aios_core.authorization_event,
  aios_core.authorization_outbox
TO aios_c06_control_runtime;

GRANT SELECT ON TABLE
  aios_core.authorization_decision
TO aios_c06_control_runtime;

GRANT SELECT ON TABLE
  aios_core.authorization_policy_release,
  aios_core.authorization_activation,
  aios_core.authorization_active_policy
TO aios_c06_decision_runtime;

GRANT SELECT, INSERT ON TABLE
  aios_core.authorization_decision,
  aios_core.authorization_event,
  aios_core.authorization_outbox
TO aios_c06_decision_runtime;

GRANT SELECT, UPDATE ON TABLE
  aios_core.authorization_outbox
TO aios_c06_outbox_worker;

COMMIT;
