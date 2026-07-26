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

CREATE ROLE aios_c18_recovery_reader
  NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION
  NOBYPASSRLS;

CREATE ROLE aios_c18_recovery_writer
  NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION
  NOBYPASSRLS;

CREATE ROLE aios_c18_retention_worker
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
ALTER TABLE aios_audit.audit_delivery_intent OWNER TO aios_c18_owner;
ALTER TABLE aios_audit.audit_outbox OWNER TO aios_c18_owner;
ALTER TABLE aios_audit.audit_command_receipt OWNER TO aios_c18_owner;
ALTER FUNCTION aios_audit.jsonb_has_exact_keys(jsonb, text[])
  OWNER TO aios_c18_owner;
ALTER FUNCTION aios_audit.metadata_string_matches(jsonb, text, integer)
  OWNER TO aios_c18_owner;
ALTER FUNCTION aios_audit.metadata_positive_integer(jsonb)
  OWNER TO aios_c18_owner;
ALTER FUNCTION aios_audit.metadata_shape(jsonb, text)
  OWNER TO aios_c18_owner;
ALTER FUNCTION aios_audit.metadata_only(jsonb)
  OWNER TO aios_c18_owner;
ALTER FUNCTION aios_audit.restore_target_is_empty(text)
  OWNER TO aios_c18_owner;
ALTER FUNCTION aios_audit.reject_append_only_change()
  OWNER TO aios_c18_owner;
ALTER FUNCTION aios_audit.enforce_head_transition()
  OWNER TO aios_c18_owner;
ALTER FUNCTION aios_audit.enforce_outbox_transition()
  OWNER TO aios_c18_owner;
ALTER FUNCTION aios_audit.require_initial_outbox()
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
CREATE POLICY audit_head_recovery_reader_policy
  ON aios_audit.audit_head FOR SELECT TO aios_c18_recovery_reader
  USING (aios_data.runtime_scope_allows(tenant_id, tenant_kind));
CREATE POLICY audit_head_recovery_writer_policy
  ON aios_audit.audit_head FOR INSERT TO aios_c18_recovery_writer
  WITH CHECK (aios_data.runtime_scope_allows(tenant_id, tenant_kind));

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
CREATE POLICY audit_event_recovery_policy
  ON aios_audit.audit_event FOR SELECT TO aios_c18_recovery_reader
  USING (aios_data.runtime_scope_allows(tenant_id, tenant_kind));
CREATE POLICY audit_event_restore_policy
  ON aios_audit.audit_event FOR INSERT TO aios_c18_recovery_writer
  WITH CHECK (aios_data.runtime_scope_allows(tenant_id, tenant_kind));

CREATE POLICY audit_delivery_intent_owner_policy
  ON aios_audit.audit_delivery_intent TO aios_c18_owner
  USING (true) WITH CHECK (true);
CREATE POLICY audit_delivery_intent_writer_policy
  ON aios_audit.audit_delivery_intent FOR INSERT TO aios_c18_writer
  WITH CHECK (aios_data.runtime_scope_allows(tenant_id, tenant_kind));
CREATE POLICY audit_delivery_intent_outbox_policy
  ON aios_audit.audit_delivery_intent
  FOR SELECT TO aios_c18_outbox_worker
  USING (aios_data.runtime_scope_allows(tenant_id, tenant_kind));
CREATE POLICY audit_delivery_intent_recovery_policy
  ON aios_audit.audit_delivery_intent
  FOR SELECT TO aios_c18_recovery_reader
  USING (aios_data.runtime_scope_allows(tenant_id, tenant_kind));
CREATE POLICY audit_delivery_intent_restore_policy
  ON aios_audit.audit_delivery_intent
  FOR INSERT TO aios_c18_recovery_writer
  WITH CHECK (aios_data.runtime_scope_allows(tenant_id, tenant_kind));
CREATE POLICY audit_delivery_intent_retention_policy
  ON aios_audit.audit_delivery_intent
  FOR SELECT TO aios_c18_retention_worker
  USING (aios_data.runtime_scope_allows(tenant_id, tenant_kind));

CREATE POLICY audit_outbox_owner_policy
  ON aios_audit.audit_outbox TO aios_c18_owner
  USING (true) WITH CHECK (true);
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
CREATE POLICY audit_outbox_recovery_policy
  ON aios_audit.audit_outbox FOR SELECT TO aios_c18_recovery_reader
  USING (aios_data.runtime_scope_allows(tenant_id, tenant_kind));
CREATE POLICY audit_outbox_restore_policy
  ON aios_audit.audit_outbox FOR INSERT TO aios_c18_recovery_writer
  WITH CHECK (aios_data.runtime_scope_allows(tenant_id, tenant_kind));
CREATE POLICY audit_outbox_retention_select_policy
  ON aios_audit.audit_outbox FOR SELECT TO aios_c18_retention_worker
  USING (aios_data.runtime_scope_allows(tenant_id, tenant_kind));
CREATE POLICY audit_outbox_retention_delete_policy
  ON aios_audit.audit_outbox FOR DELETE TO aios_c18_retention_worker
  USING (
    aios_data.runtime_scope_allows(tenant_id, tenant_kind)
    AND status = 'PUBLISHED'
    AND published_at <= statement_timestamp() - interval '30 days'
    AND EXISTS (
      SELECT 1
        FROM aios_audit.audit_delivery_intent AS intent
       WHERE intent.tenant_id = audit_outbox.tenant_id
         AND intent.event_id = audit_outbox.event_id
         AND intent.legal_hold = false
    )
  );

CREATE POLICY audit_receipt_owner_policy
  ON aios_audit.audit_command_receipt TO aios_c18_owner
  USING (true) WITH CHECK (true);
CREATE POLICY audit_receipt_writer_policy
  ON aios_audit.audit_command_receipt TO aios_c18_writer
  USING (aios_data.runtime_scope_allows(tenant_id, tenant_kind))
  WITH CHECK (aios_data.runtime_scope_allows(tenant_id, tenant_kind));
CREATE POLICY audit_receipt_recovery_policy
  ON aios_audit.audit_command_receipt
  FOR SELECT TO aios_c18_recovery_reader
  USING (aios_data.runtime_scope_allows(tenant_id, tenant_kind));
CREATE POLICY audit_receipt_restore_policy
  ON aios_audit.audit_command_receipt
  FOR INSERT TO aios_c18_recovery_writer
  WITH CHECK (aios_data.runtime_scope_allows(tenant_id, tenant_kind));

GRANT USAGE ON SCHEMA aios_audit TO
  aios_c18_writer,
  aios_c18_reader,
  aios_c18_outbox_worker,
  aios_c18_recovery_reader,
  aios_c18_recovery_writer,
  aios_c18_retention_worker;
GRANT USAGE ON SCHEMA aios_data TO
  aios_c18_owner,
  aios_c18_writer,
  aios_c18_reader,
  aios_c18_outbox_worker,
  aios_c18_recovery_reader,
  aios_c18_recovery_writer,
  aios_c18_retention_worker;
GRANT EXECUTE ON FUNCTION aios_data.runtime_scope_allows(text, text) TO
  aios_c18_owner,
  aios_c18_writer,
  aios_c18_reader,
  aios_c18_outbox_worker,
  aios_c18_recovery_reader,
  aios_c18_recovery_writer,
  aios_c18_retention_worker;
GRANT EXECUTE ON FUNCTION aios_data.acquire_runtime_fence() TO
  aios_c18_writer,
  aios_c18_reader,
  aios_c18_outbox_worker,
  aios_c18_recovery_reader,
  aios_c18_recovery_writer,
  aios_c18_retention_worker;
GRANT EXECUTE ON FUNCTION
  aios_audit.jsonb_has_exact_keys(jsonb, text[]),
  aios_audit.metadata_string_matches(jsonb, text, integer),
  aios_audit.metadata_positive_integer(jsonb),
  aios_audit.metadata_shape(jsonb, text)
TO aios_c18_writer,aios_c18_recovery_writer;
GRANT EXECUTE ON FUNCTION aios_audit.metadata_only(jsonb)
  TO aios_c18_writer,aios_c18_recovery_writer;
GRANT EXECUTE ON FUNCTION aios_audit.restore_target_is_empty(text)
  TO aios_c18_recovery_writer;

GRANT SELECT, INSERT, UPDATE ON TABLE aios_audit.audit_head
  TO aios_c18_writer;
GRANT SELECT, INSERT ON TABLE
  aios_audit.audit_event,
  aios_audit.audit_command_receipt
TO aios_c18_writer;
GRANT INSERT ON TABLE aios_audit.audit_outbox
  TO aios_c18_writer;
GRANT INSERT ON TABLE aios_audit.audit_delivery_intent
  TO aios_c18_writer;

GRANT SELECT ON TABLE
  aios_audit.audit_head,
  aios_audit.audit_event
TO aios_c18_reader;

GRANT SELECT, UPDATE ON TABLE aios_audit.audit_outbox
  TO aios_c18_outbox_worker;
GRANT SELECT ON TABLE aios_audit.audit_delivery_intent
  TO aios_c18_outbox_worker;

GRANT SELECT ON TABLE
  aios_audit.audit_event,
  aios_audit.audit_head,
  aios_audit.audit_delivery_intent,
  aios_audit.audit_outbox,
  aios_audit.audit_command_receipt
TO aios_c18_recovery_reader;

GRANT INSERT ON TABLE
  aios_audit.audit_head,
  aios_audit.audit_event,
  aios_audit.audit_delivery_intent,
  aios_audit.audit_outbox,
  aios_audit.audit_command_receipt
TO aios_c18_recovery_writer;

GRANT SELECT ON TABLE
  aios_audit.audit_delivery_intent,
  aios_audit.audit_outbox
TO aios_c18_retention_worker;
GRANT DELETE ON TABLE aios_audit.audit_outbox
  TO aios_c18_retention_worker;

COMMIT;
