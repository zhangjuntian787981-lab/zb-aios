BEGIN;

CREATE ROLE aios_c12_owner
  NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION
  NOBYPASSRLS;

CREATE ROLE aios_c12_runtime
  NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION
  NOBYPASSRLS;

REVOKE ALL ON SCHEMA aios_orchestration FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA aios_orchestration FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA aios_orchestration FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA aios_orchestration FROM PUBLIC;

ALTER DEFAULT PRIVILEGES IN SCHEMA aios_orchestration
  REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA aios_orchestration
  REVOKE ALL ON SEQUENCES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA aios_orchestration
  REVOKE ALL ON FUNCTIONS FROM PUBLIC;

ALTER SCHEMA aios_orchestration OWNER TO aios_c12_owner;
ALTER TABLE aios_orchestration.task_state OWNER TO aios_c12_owner;
ALTER TABLE aios_orchestration.command_receipt OWNER TO aios_c12_owner;
ALTER FUNCTION aios_orchestration.enforce_task_state_write()
  OWNER TO aios_c12_owner;
ALTER FUNCTION aios_orchestration.reject_command_receipt_mutation()
  OWNER TO aios_c12_owner;

CREATE POLICY task_state_owner_policy
  ON aios_orchestration.task_state TO aios_c12_owner
  USING (true) WITH CHECK (true);
CREATE POLICY task_state_runtime_policy
  ON aios_orchestration.task_state TO aios_c12_runtime
  USING (aios_data.runtime_scope_allows(tenant_id, tenant_kind))
  WITH CHECK (aios_data.runtime_scope_allows(tenant_id, tenant_kind));

CREATE POLICY command_receipt_owner_policy
  ON aios_orchestration.command_receipt TO aios_c12_owner
  USING (true) WITH CHECK (true);
CREATE POLICY command_receipt_runtime_policy
  ON aios_orchestration.command_receipt TO aios_c12_runtime
  USING (aios_data.runtime_scope_allows(tenant_id, tenant_kind))
  WITH CHECK (aios_data.runtime_scope_allows(tenant_id, tenant_kind));

GRANT USAGE ON SCHEMA aios_orchestration TO aios_c12_runtime;
GRANT USAGE ON SCHEMA aios_data TO aios_c12_runtime;
GRANT EXECUTE ON FUNCTION aios_data.runtime_scope_allows(text, text)
  TO aios_c12_runtime;
GRANT EXECUTE ON FUNCTION aios_data.acquire_runtime_fence()
  TO aios_c12_runtime;

GRANT SELECT, INSERT, UPDATE ON TABLE
  aios_orchestration.task_state
TO aios_c12_runtime;

GRANT SELECT, INSERT ON TABLE
  aios_orchestration.command_receipt
TO aios_c12_runtime;

COMMIT;
