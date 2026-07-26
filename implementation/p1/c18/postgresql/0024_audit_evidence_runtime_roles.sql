BEGIN;

CREATE ROLE aios_c18_owner
  NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION
  NOBYPASSRLS;

CREATE ROLE aios_c18_writer
  NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION
  NOBYPASSRLS;

CREATE ROLE aios_c18_reader
  NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION
  NOBYPASSRLS;

CREATE ROLE aios_c18_outbox_worker
  NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION
  NOBYPASSRLS;

REVOKE ALL ON SCHEMA aios_audit FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA aios_audit FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA aios_audit FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA aios_audit FROM PUBLIC;

ALTER DEFAULT PRIVILEGES IN SCHEMA aios_audit
  REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA aios_audit
  REVOKE ALL ON SEQUENCES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA aios_audit
  REVOKE ALL ON FUNCTIONS FROM PUBLIC;

ALTER SCHEMA aios_audit OWNER TO aios_c18_owner;
ALTER TABLE aios_audit.audit_head OWNER TO aios_c18_owner;
ALTER TABLE aios_audit.audit_event OWNER TO aios_c18_owner;
ALTER TABLE aios_audit.audit_outbox OWNER TO aios_c18_owner;
ALTER TABLE aios_audit.audit_command_receipt OWNER TO aios_c18_owner;
ALTER FUNCTION aios_audit.metadata_only(jsonb)
  OWNER TO aios_c18_owner;
ALTER FUNCTION aios_audit.reject_append_only_change()
  OWNER TO aios_c18_owner;
ALTER FUNCTION aios_audit.enforce_head_transition()
  OWNER TO aios_c18_owner;
ALTER FUNCTION aios_audit.enforce_outbox_transition()
  OWNER TO aios_c18_owner;

CREATE POLICY audit_head_owner_policy
  ON aios_audit.audit_head TO aios_c18_owner
  USING (true) WITH CHECK (true);
CREATE POLICY audit_head_writer_policy
  ON aios_audit.audit_head TO aios_c18_writer
  USING (aios_data.runtime_scope_allows(tenant_id, tenant_kind))
  WITH CHECK (aios_data.runtime_scope_allows(tenant_id, tenant_kind));
CREATE POLICY audit_head_reader_policy
  ON aios_audit.audit_head FOR SELECT TO aios_c18_reader
  USING (aios_data.runtime_scope_allows(tenant_id, tenant_kind));

CREATE POLICY audit_event_owner_policy
  ON aios_audit.audit_event TO aios_c18_owner
  USING (true) WITH CHECK (true);
CREATE POLICY audit_event_writer_policy
  ON aios_audit.audit_event TO aios_c18_writer
  USING (aios_data.runtime_scope_allows(tenant_id, tenant_kind))
  WITH CHECK (aios_data.runtime_scope_allows(tenant_id, tenant_kind));
CREATE POLICY audit_event_reader_policy
  ON aios_audit.audit_event FOR SELECT TO aios_c18_reader
  USING (aios_data.runtime_scope_allows(tenant_id, tenant_kind));

CREATE POLICY audit_outbox_owner_policy
  ON aios_audit.audit_outbox TO aios_c18_owner
  USING (true) WITH CHECK (true);
CREATE POLICY audit_outbox_writer_select_policy
  ON aios_audit.audit_outbox FOR SELECT TO aios_c18_writer
  USING (aios_data.runtime_scope_allows(tenant_id, tenant_kind));
CREATE POLICY audit_outbox_writer_insert_policy
  ON aios_audit.audit_outbox FOR INSERT TO aios_c18_writer
  WITH CHECK (aios_data.runtime_scope_allows(tenant_id, tenant_kind));
CREATE POLICY audit_outbox_worker_select_policy
  ON aios_audit.audit_outbox FOR SELECT TO aios_c18_outbox_worker
  USING (aios_data.runtime_scope_allows(tenant_id, tenant_kind));
CREATE POLICY audit_outbox_worker_update_policy
  ON aios_audit.audit_outbox FOR UPDATE TO aios_c18_outbox_worker
  USING (aios_data.runtime_scope_allows(tenant_id, tenant_kind))
  WITH CHECK (aios_data.runtime_scope_allows(tenant_id, tenant_kind));

CREATE POLICY audit_receipt_owner_policy
  ON aios_audit.audit_command_receipt TO aios_c18_owner
  USING (true) WITH CHECK (true);
CREATE POLICY audit_receipt_writer_policy
  ON aios_audit.audit_command_receipt TO aios_c18_writer
  USING (aios_data.runtime_scope_allows(tenant_id, tenant_kind))
  WITH CHECK (aios_data.runtime_scope_allows(tenant_id, tenant_kind));

GRANT USAGE ON SCHEMA aios_audit
  TO aios_c18_writer, aios_c18_reader, aios_c18_outbox_worker;
GRANT USAGE ON SCHEMA aios_data
  TO aios_c18_writer, aios_c18_reader, aios_c18_outbox_worker;
GRANT EXECUTE ON FUNCTION aios_data.runtime_scope_allows(text, text)
  TO aios_c18_writer, aios_c18_reader, aios_c18_outbox_worker;
GRANT EXECUTE ON FUNCTION aios_data.acquire_runtime_fence()
  TO aios_c18_writer, aios_c18_reader, aios_c18_outbox_worker;
GRANT EXECUTE ON FUNCTION aios_audit.metadata_only(jsonb)
  TO aios_c18_writer, aios_c18_outbox_worker;

GRANT SELECT, INSERT, UPDATE ON TABLE aios_audit.audit_head
  TO aios_c18_writer;
GRANT SELECT, INSERT ON TABLE
  aios_audit.audit_event,
  aios_audit.audit_outbox,
  aios_audit.audit_command_receipt
TO aios_c18_writer;

GRANT SELECT ON TABLE
  aios_audit.audit_head,
  aios_audit.audit_event
TO aios_c18_reader;

GRANT SELECT, UPDATE ON TABLE aios_audit.audit_outbox
  TO aios_c18_outbox_worker;

COMMIT;
