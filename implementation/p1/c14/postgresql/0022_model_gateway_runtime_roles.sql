BEGIN;

CREATE ROLE aios_c14_owner
  NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION
  NOBYPASSRLS;

CREATE ROLE aios_c14_runtime
  NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION
  NOBYPASSRLS;

REVOKE ALL ON SCHEMA aios_model FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA aios_model FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA aios_model FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA aios_model FROM PUBLIC;

ALTER DEFAULT PRIVILEGES IN SCHEMA aios_model
  REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA aios_model
  REVOKE ALL ON SEQUENCES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA aios_model
  REVOKE ALL ON FUNCTIONS FROM PUBLIC;

ALTER SCHEMA aios_model OWNER TO aios_c14_owner;
ALTER TABLE aios_model.model_route OWNER TO aios_c14_owner;
ALTER FUNCTION aios_model.reject_route_delete()
  OWNER TO aios_c14_owner;
ALTER FUNCTION aios_model.enforce_route_update()
  OWNER TO aios_c14_owner;

CREATE POLICY model_route_owner_policy
  ON aios_model.model_route TO aios_c14_owner
  USING (true) WITH CHECK (true);

CREATE POLICY model_route_runtime_policy
  ON aios_model.model_route TO aios_c14_runtime
  USING (aios_data.runtime_scope_allows(tenant_id, tenant_kind))
  WITH CHECK (aios_data.runtime_scope_allows(tenant_id, tenant_kind));

GRANT USAGE ON SCHEMA aios_model TO aios_c14_runtime;
GRANT USAGE ON SCHEMA aios_data TO aios_c14_runtime;
GRANT EXECUTE ON FUNCTION aios_data.runtime_scope_allows(text, text)
  TO aios_c14_runtime;
GRANT EXECUTE ON FUNCTION aios_data.acquire_runtime_fence()
  TO aios_c14_runtime;
GRANT SELECT, INSERT, UPDATE ON TABLE aios_model.model_route
  TO aios_c14_runtime;

COMMIT;
