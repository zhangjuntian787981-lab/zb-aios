BEGIN;

CREATE ROLE aios_c16_owner
  NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION
  NOBYPASSRLS;
CREATE ROLE aios_c16_runtime
  NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION
  NOBYPASSRLS;
CREATE ROLE aios_c16_worker
  NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION
  NOBYPASSRLS;
CREATE ROLE aios_c16_audit_worker
  NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION
  NOBYPASSRLS;
CREATE ROLE aios_c16_recovery_reader
  NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION
  NOBYPASSRLS;

ALTER SCHEMA aios_tool OWNER TO aios_c16_owner;
ALTER FUNCTION aios_tool.valid_audit_intent(jsonb)
  OWNER TO aios_c16_owner;
ALTER FUNCTION aios_tool.reject_immutable_change()
  OWNER TO aios_c16_owner;
ALTER FUNCTION aios_tool.enforce_call_transition()
  OWNER TO aios_c16_owner;
ALTER FUNCTION aios_tool.enforce_outbox_transition()
  OWNER TO aios_c16_owner;
ALTER TABLE aios_tool.audit_intent OWNER TO aios_c16_owner;
ALTER TABLE aios_tool.audit_outbox OWNER TO aios_c16_owner;
ALTER TABLE aios_tool.tool_confirmation OWNER TO aios_c16_owner;
ALTER TABLE aios_tool.tool_call OWNER TO aios_c16_owner;

REVOKE ALL ON SCHEMA aios_tool FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA aios_tool FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA aios_tool FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA aios_tool FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA aios_tool
  REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA aios_tool
  REVOKE ALL ON SEQUENCES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA aios_tool
  REVOKE ALL ON FUNCTIONS FROM PUBLIC;

ALTER TABLE aios_tool.audit_intent ENABLE ROW LEVEL SECURITY;
ALTER TABLE aios_tool.audit_intent FORCE ROW LEVEL SECURITY;
ALTER TABLE aios_tool.audit_outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE aios_tool.audit_outbox FORCE ROW LEVEL SECURITY;
ALTER TABLE aios_tool.tool_confirmation ENABLE ROW LEVEL SECURITY;
ALTER TABLE aios_tool.tool_confirmation FORCE ROW LEVEL SECURITY;
ALTER TABLE aios_tool.tool_call ENABLE ROW LEVEL SECURITY;
ALTER TABLE aios_tool.tool_call FORCE ROW LEVEL SECURITY;

CREATE POLICY c16_audit_intent_owner ON aios_tool.audit_intent
  TO aios_c16_owner USING (true) WITH CHECK (true);
CREATE POLICY c16_audit_intent_runtime ON aios_tool.audit_intent
  FOR INSERT TO aios_c16_runtime
  WITH CHECK (aios_data.runtime_scope_allows(tenant_id, tenant_kind));
CREATE POLICY c16_audit_intent_worker ON aios_tool.audit_intent
  FOR INSERT TO aios_c16_worker
  WITH CHECK (aios_data.runtime_scope_allows(tenant_id, tenant_kind));
CREATE POLICY c16_audit_intent_audit_worker ON aios_tool.audit_intent
  FOR SELECT TO aios_c16_audit_worker
  USING (aios_data.runtime_scope_allows(tenant_id, tenant_kind));
CREATE POLICY c16_audit_intent_recovery ON aios_tool.audit_intent
  FOR SELECT TO aios_c16_recovery_reader
  USING (aios_data.runtime_scope_allows(tenant_id, tenant_kind));

CREATE POLICY c16_audit_outbox_owner ON aios_tool.audit_outbox
  TO aios_c16_owner USING (true) WITH CHECK (true);
CREATE POLICY c16_audit_outbox_runtime ON aios_tool.audit_outbox
  FOR INSERT TO aios_c16_runtime
  WITH CHECK (aios_data.runtime_scope_allows(tenant_id, tenant_kind));
CREATE POLICY c16_audit_outbox_worker_insert ON aios_tool.audit_outbox
  FOR INSERT TO aios_c16_worker
  WITH CHECK (aios_data.runtime_scope_allows(tenant_id, tenant_kind));
CREATE POLICY c16_audit_outbox_audit_worker ON aios_tool.audit_outbox
  TO aios_c16_audit_worker
  USING (aios_data.runtime_scope_allows(tenant_id, tenant_kind))
  WITH CHECK (aios_data.runtime_scope_allows(tenant_id, tenant_kind));
CREATE POLICY c16_audit_outbox_recovery ON aios_tool.audit_outbox
  FOR SELECT TO aios_c16_recovery_reader
  USING (aios_data.runtime_scope_allows(tenant_id, tenant_kind));

CREATE POLICY c16_confirmation_owner ON aios_tool.tool_confirmation
  TO aios_c16_owner USING (true) WITH CHECK (true);
CREATE POLICY c16_confirmation_runtime ON aios_tool.tool_confirmation
  TO aios_c16_runtime
  USING (aios_data.runtime_scope_allows(tenant_id, tenant_kind))
  WITH CHECK (aios_data.runtime_scope_allows(tenant_id, tenant_kind));
CREATE POLICY c16_confirmation_recovery ON aios_tool.tool_confirmation
  FOR SELECT TO aios_c16_recovery_reader
  USING (aios_data.runtime_scope_allows(tenant_id, tenant_kind));

CREATE POLICY c16_call_owner ON aios_tool.tool_call
  TO aios_c16_owner USING (true) WITH CHECK (true);
CREATE POLICY c16_call_runtime ON aios_tool.tool_call
  TO aios_c16_runtime
  USING (aios_data.runtime_scope_allows(tenant_id, tenant_kind))
  WITH CHECK (aios_data.runtime_scope_allows(tenant_id, tenant_kind));
CREATE POLICY c16_call_worker ON aios_tool.tool_call
  TO aios_c16_worker
  USING (aios_data.runtime_scope_allows(tenant_id, tenant_kind))
  WITH CHECK (aios_data.runtime_scope_allows(tenant_id, tenant_kind));
CREATE POLICY c16_call_recovery ON aios_tool.tool_call
  FOR SELECT TO aios_c16_recovery_reader
  USING (aios_data.runtime_scope_allows(tenant_id, tenant_kind));

GRANT USAGE ON SCHEMA aios_tool TO
  aios_c16_runtime,
  aios_c16_worker,
  aios_c16_audit_worker,
  aios_c16_recovery_reader;
GRANT USAGE ON SCHEMA aios_data TO
  aios_c16_runtime,
  aios_c16_worker,
  aios_c16_audit_worker,
  aios_c16_recovery_reader;
GRANT EXECUTE ON FUNCTION aios_data.runtime_scope_allows(text, text) TO
  aios_c16_runtime,
  aios_c16_worker,
  aios_c16_audit_worker,
  aios_c16_recovery_reader;
GRANT EXECUTE ON FUNCTION aios_data.acquire_runtime_fence() TO
  aios_c16_runtime,
  aios_c16_worker,
  aios_c16_audit_worker,
  aios_c16_recovery_reader;
GRANT EXECUTE ON FUNCTION aios_tool.valid_audit_intent(jsonb) TO
  aios_c16_runtime,
  aios_c16_worker;
GRANT SELECT, INSERT ON TABLE
  aios_tool.tool_confirmation,
  aios_tool.tool_call
TO aios_c16_runtime;
GRANT INSERT ON TABLE
  aios_tool.audit_intent,
  aios_tool.audit_outbox
TO aios_c16_runtime;

GRANT SELECT, UPDATE ON TABLE aios_tool.tool_call
  TO aios_c16_worker;
GRANT INSERT ON TABLE
  aios_tool.audit_intent,
  aios_tool.audit_outbox
TO aios_c16_worker;

GRANT SELECT ON TABLE aios_tool.audit_intent
  TO aios_c16_audit_worker;
GRANT SELECT, UPDATE ON TABLE aios_tool.audit_outbox
  TO aios_c16_audit_worker;

GRANT SELECT ON ALL TABLES IN SCHEMA aios_tool
  TO aios_c16_recovery_reader;

COMMIT;
