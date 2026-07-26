BEGIN;

CREATE ROLE aios_c07_owner
  NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION
  NOBYPASSRLS;

CREATE ROLE aios_c07_lifecycle_runtime
  NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION
  NOBYPASSRLS;

CREATE ROLE aios_c07_data_runtime
  NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION
  NOBYPASSRLS;

CREATE ROLE aios_c07_scope_runtime
  NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION
  NOBYPASSRLS;

CREATE ROLE aios_c07_restore_runtime
  NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION
  NOBYPASSRLS;

REVOKE ALL ON SCHEMA aios_data FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA aios_data FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA aios_data FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA aios_data FROM PUBLIC;

ALTER SCHEMA aios_data OWNER TO aios_c07_owner;
ALTER TABLE aios_data.tenant_data_lifecycle OWNER TO aios_c07_owner;
ALTER TABLE aios_data.tenant_data_event_receipt OWNER TO aios_c07_owner;
ALTER TABLE aios_data.tenant_sql_record OWNER TO aios_c07_owner;
ALTER TABLE aios_data.tenant_vector_record OWNER TO aios_c07_owner;
ALTER TABLE aios_data.tenant_search_record OWNER TO aios_c07_owner;
ALTER TABLE aios_data.tenant_cache_record OWNER TO aios_c07_owner;
ALTER TABLE aios_data.runtime_scope_signing_secret
  OWNER TO aios_c07_owner;
ALTER FUNCTION aios_data.issue_runtime_scope_signature(
  text, text, bigint, text, text, text, text, integer, xid8, integer, uuid
) OWNER TO aios_c07_owner;
ALTER FUNCTION aios_data.runtime_scope_allows(text, text)
  OWNER TO aios_c07_owner;
ALTER FUNCTION aios_data.acquire_runtime_fence()
  OWNER TO aios_c07_owner;
ALTER FUNCTION aios_data.lifecycle_scope_matches(text, text)
  OWNER TO aios_c07_owner;

CREATE POLICY tenant_lifecycle_owner_policy
  ON aios_data.tenant_data_lifecycle
  TO aios_c07_owner
  USING (true)
  WITH CHECK (true);
CREATE POLICY tenant_lifecycle_worker_policy
  ON aios_data.tenant_data_lifecycle
  TO aios_c07_lifecycle_runtime
  USING (aios_data.lifecycle_scope_matches(tenant_id, tenant_kind))
  WITH CHECK (aios_data.lifecycle_scope_matches(tenant_id, tenant_kind));
CREATE POLICY tenant_event_receipt_worker_policy
  ON aios_data.tenant_data_event_receipt
  TO aios_c07_lifecycle_runtime
  USING (aios_data.lifecycle_scope_matches(tenant_id, tenant_kind))
  WITH CHECK (aios_data.lifecycle_scope_matches(tenant_id, tenant_kind));

CREATE POLICY tenant_sql_runtime_policy
  ON aios_data.tenant_sql_record
  TO aios_c07_data_runtime, aios_c07_restore_runtime
  USING (aios_data.runtime_scope_allows(tenant_id, tenant_kind))
  WITH CHECK (aios_data.runtime_scope_allows(tenant_id, tenant_kind));
CREATE POLICY tenant_vector_runtime_policy
  ON aios_data.tenant_vector_record
  TO aios_c07_data_runtime, aios_c07_restore_runtime
  USING (aios_data.runtime_scope_allows(tenant_id, tenant_kind))
  WITH CHECK (aios_data.runtime_scope_allows(tenant_id, tenant_kind));
CREATE POLICY tenant_search_runtime_policy
  ON aios_data.tenant_search_record
  TO aios_c07_data_runtime, aios_c07_restore_runtime
  USING (aios_data.runtime_scope_allows(tenant_id, tenant_kind))
  WITH CHECK (aios_data.runtime_scope_allows(tenant_id, tenant_kind));
CREATE POLICY tenant_cache_runtime_policy
  ON aios_data.tenant_cache_record
  TO aios_c07_data_runtime, aios_c07_restore_runtime
  USING (aios_data.runtime_scope_allows(tenant_id, tenant_kind))
  WITH CHECK (aios_data.runtime_scope_allows(tenant_id, tenant_kind));

CREATE POLICY tenant_sql_lifecycle_policy
  ON aios_data.tenant_sql_record
  TO aios_c07_lifecycle_runtime
  USING (aios_data.lifecycle_scope_matches(tenant_id, tenant_kind));
CREATE POLICY tenant_vector_lifecycle_policy
  ON aios_data.tenant_vector_record
  TO aios_c07_lifecycle_runtime
  USING (aios_data.lifecycle_scope_matches(tenant_id, tenant_kind));
CREATE POLICY tenant_search_lifecycle_policy
  ON aios_data.tenant_search_record
  TO aios_c07_lifecycle_runtime
  USING (aios_data.lifecycle_scope_matches(tenant_id, tenant_kind));
CREATE POLICY tenant_cache_lifecycle_policy
  ON aios_data.tenant_cache_record
  TO aios_c07_lifecycle_runtime
  USING (aios_data.lifecycle_scope_matches(tenant_id, tenant_kind));

GRANT USAGE ON SCHEMA aios_data
  TO
    aios_c07_data_runtime,
    aios_c07_lifecycle_runtime,
    aios_c07_restore_runtime,
    aios_c07_scope_runtime;

GRANT EXECUTE ON FUNCTION aios_data.issue_runtime_scope_signature(
  text, text, bigint, text, text, text, text, integer, xid8, integer, uuid
) TO aios_c07_scope_runtime;
GRANT EXECUTE ON FUNCTION aios_data.runtime_scope_allows(text, text)
  TO aios_c07_data_runtime, aios_c07_restore_runtime;
GRANT EXECUTE ON FUNCTION aios_data.acquire_runtime_fence()
  TO aios_c07_data_runtime;
GRANT EXECUTE ON FUNCTION aios_data.lifecycle_scope_matches(text, text)
  TO aios_c07_lifecycle_runtime;

GRANT SELECT, INSERT, UPDATE ON
  aios_data.tenant_sql_record,
  aios_data.tenant_vector_record,
  aios_data.tenant_search_record,
  aios_data.tenant_cache_record
  TO aios_c07_data_runtime;

GRANT SELECT ON
  aios_data.tenant_sql_record,
  aios_data.tenant_vector_record,
  aios_data.tenant_search_record,
  aios_data.tenant_cache_record
  TO aios_c07_restore_runtime;

GRANT DELETE ON
  aios_data.tenant_sql_record,
  aios_data.tenant_vector_record,
  aios_data.tenant_search_record,
  aios_data.tenant_cache_record
  TO aios_c07_lifecycle_runtime;

GRANT SELECT (tenant_id, tenant_kind) ON
  aios_data.tenant_sql_record,
  aios_data.tenant_vector_record,
  aios_data.tenant_search_record,
  aios_data.tenant_cache_record
  TO aios_c07_lifecycle_runtime;

GRANT SELECT, INSERT, UPDATE ON
  aios_data.tenant_data_lifecycle
  TO aios_c07_lifecycle_runtime;

GRANT SELECT, INSERT ON
  aios_data.tenant_data_event_receipt
  TO aios_c07_lifecycle_runtime;

COMMIT;
