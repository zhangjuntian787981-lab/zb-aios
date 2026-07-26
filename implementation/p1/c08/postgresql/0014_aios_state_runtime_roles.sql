BEGIN;

CREATE ROLE aios_c08_owner
  NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION
  NOBYPASSRLS;

CREATE ROLE aios_c08_runtime
  NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION
  NOBYPASSRLS;

CREATE ROLE aios_c08_outbox_worker
  NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION
  NOBYPASSRLS;

REVOKE ALL ON SCHEMA aios_state FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA aios_state FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA aios_state FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA aios_state FROM PUBLIC;

ALTER DEFAULT PRIVILEGES IN SCHEMA aios_state
  REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA aios_state
  REVOKE ALL ON SEQUENCES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA aios_state
  REVOKE ALL ON FUNCTIONS FROM PUBLIC;

ALTER SCHEMA aios_state OWNER TO aios_c08_owner;
ALTER TABLE aios_state.aios_case OWNER TO aios_c08_owner;
ALTER TABLE aios_state.aios_thread OWNER TO aios_c08_owner;
ALTER TABLE aios_state.aios_artifact OWNER TO aios_c08_owner;
ALTER TABLE aios_state.aios_run OWNER TO aios_c08_owner;
ALTER TABLE aios_state.aios_tool_call OWNER TO aios_c08_owner;
ALTER TABLE aios_state.domain_event OWNER TO aios_c08_owner;
ALTER TABLE aios_state.outbox OWNER TO aios_c08_owner;
ALTER TABLE aios_state.command_receipt OWNER TO aios_c08_owner;
ALTER FUNCTION aios_state.reject_append_only_change()
  OWNER TO aios_c08_owner;
ALTER FUNCTION aios_state.reject_state_delete()
  OWNER TO aios_c08_owner;
ALTER FUNCTION aios_state.enforce_versioned_update()
  OWNER TO aios_c08_owner;
ALTER FUNCTION aios_state.enforce_initial_state()
  OWNER TO aios_c08_owner;
ALTER FUNCTION aios_state.enforce_artifact_version_chain()
  OWNER TO aios_c08_owner;
ALTER FUNCTION aios_state.enforce_domain_event_aggregate()
  OWNER TO aios_c08_owner;
ALTER FUNCTION aios_state.enforce_event_outbox_pair()
  OWNER TO aios_c08_owner;
ALTER FUNCTION aios_state.enforce_event_receipt_pair()
  OWNER TO aios_c08_owner;
ALTER FUNCTION aios_state.enforce_outbox_state()
  OWNER TO aios_c08_owner;

CREATE POLICY aios_case_owner_policy
  ON aios_state.aios_case TO aios_c08_owner
  USING (true) WITH CHECK (true);
CREATE POLICY aios_case_runtime_policy
  ON aios_state.aios_case TO aios_c08_runtime
  USING (aios_data.runtime_scope_allows(tenant_id, tenant_kind))
  WITH CHECK (aios_data.runtime_scope_allows(tenant_id, tenant_kind));

CREATE POLICY aios_thread_owner_policy
  ON aios_state.aios_thread TO aios_c08_owner
  USING (true) WITH CHECK (true);
CREATE POLICY aios_thread_runtime_policy
  ON aios_state.aios_thread TO aios_c08_runtime
  USING (aios_data.runtime_scope_allows(tenant_id, tenant_kind))
  WITH CHECK (aios_data.runtime_scope_allows(tenant_id, tenant_kind));

CREATE POLICY aios_artifact_owner_policy
  ON aios_state.aios_artifact TO aios_c08_owner
  USING (true) WITH CHECK (true);
CREATE POLICY aios_artifact_runtime_policy
  ON aios_state.aios_artifact TO aios_c08_runtime
  USING (aios_data.runtime_scope_allows(tenant_id, tenant_kind))
  WITH CHECK (aios_data.runtime_scope_allows(tenant_id, tenant_kind));

CREATE POLICY aios_run_owner_policy
  ON aios_state.aios_run TO aios_c08_owner
  USING (true) WITH CHECK (true);
CREATE POLICY aios_run_runtime_policy
  ON aios_state.aios_run TO aios_c08_runtime
  USING (aios_data.runtime_scope_allows(tenant_id, tenant_kind))
  WITH CHECK (aios_data.runtime_scope_allows(tenant_id, tenant_kind));

CREATE POLICY aios_tool_call_owner_policy
  ON aios_state.aios_tool_call TO aios_c08_owner
  USING (true) WITH CHECK (true);
CREATE POLICY aios_tool_call_runtime_policy
  ON aios_state.aios_tool_call TO aios_c08_runtime
  USING (aios_data.runtime_scope_allows(tenant_id, tenant_kind))
  WITH CHECK (aios_data.runtime_scope_allows(tenant_id, tenant_kind));

CREATE POLICY domain_event_owner_policy
  ON aios_state.domain_event TO aios_c08_owner
  USING (true) WITH CHECK (true);
CREATE POLICY domain_event_runtime_policy
  ON aios_state.domain_event TO aios_c08_runtime
  USING (aios_data.runtime_scope_allows(tenant_id, tenant_kind))
  WITH CHECK (aios_data.runtime_scope_allows(tenant_id, tenant_kind));

CREATE POLICY outbox_owner_policy
  ON aios_state.outbox TO aios_c08_owner
  USING (true) WITH CHECK (true);
CREATE POLICY outbox_runtime_select_policy
  ON aios_state.outbox FOR SELECT TO aios_c08_runtime
  USING (aios_data.runtime_scope_allows(tenant_id, tenant_kind));
CREATE POLICY outbox_runtime_insert_policy
  ON aios_state.outbox FOR INSERT TO aios_c08_runtime
  WITH CHECK (aios_data.runtime_scope_allows(tenant_id, tenant_kind));
CREATE POLICY outbox_worker_select_policy
  ON aios_state.outbox FOR SELECT TO aios_c08_outbox_worker
  USING (aios_data.runtime_scope_allows(tenant_id, tenant_kind));
CREATE POLICY outbox_worker_update_policy
  ON aios_state.outbox FOR UPDATE TO aios_c08_outbox_worker
  USING (aios_data.runtime_scope_allows(tenant_id, tenant_kind))
  WITH CHECK (aios_data.runtime_scope_allows(tenant_id, tenant_kind));

CREATE POLICY command_receipt_owner_policy
  ON aios_state.command_receipt TO aios_c08_owner
  USING (true) WITH CHECK (true);
CREATE POLICY command_receipt_runtime_policy
  ON aios_state.command_receipt TO aios_c08_runtime
  USING (aios_data.runtime_scope_allows(tenant_id, tenant_kind))
  WITH CHECK (aios_data.runtime_scope_allows(tenant_id, tenant_kind));

GRANT USAGE ON SCHEMA aios_state
  TO aios_c08_runtime, aios_c08_outbox_worker;
GRANT USAGE ON SCHEMA aios_data
  TO aios_c08_runtime, aios_c08_outbox_worker;
GRANT EXECUTE ON FUNCTION aios_data.runtime_scope_allows(text, text)
  TO aios_c08_runtime, aios_c08_outbox_worker;
GRANT EXECUTE ON FUNCTION aios_data.acquire_runtime_fence()
  TO aios_c08_runtime, aios_c08_outbox_worker;

GRANT SELECT, INSERT ON TABLE
  aios_state.aios_case,
  aios_state.aios_thread
TO aios_c08_runtime;

GRANT SELECT, INSERT, UPDATE ON TABLE
  aios_state.aios_run,
  aios_state.aios_tool_call
TO aios_c08_runtime;

GRANT SELECT, INSERT ON TABLE
  aios_state.aios_artifact,
  aios_state.domain_event,
  aios_state.command_receipt
TO aios_c08_runtime;

GRANT SELECT, INSERT ON TABLE aios_state.outbox
TO aios_c08_runtime;

GRANT SELECT, UPDATE ON TABLE aios_state.outbox
TO aios_c08_outbox_worker;

COMMIT;
