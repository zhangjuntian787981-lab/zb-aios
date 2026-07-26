BEGIN;

CREATE ROLE aios_c10_owner
  NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION
  NOBYPASSRLS;

CREATE ROLE aios_c10_runtime
  NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION
  NOBYPASSRLS;

CREATE ROLE aios_c10_reader
  NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION
  NOBYPASSRLS;

REVOKE ALL ON SCHEMA aios_knowledge FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA aios_knowledge FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA aios_knowledge FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA aios_knowledge FROM PUBLIC;

ALTER DEFAULT PRIVILEGES IN SCHEMA aios_knowledge
  REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA aios_knowledge
  REVOKE ALL ON SEQUENCES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA aios_knowledge
  REVOKE ALL ON FUNCTIONS FROM PUBLIC;

ALTER SCHEMA aios_knowledge OWNER TO aios_c10_owner;
ALTER TABLE aios_knowledge.knowledge_document OWNER TO aios_c10_owner;
ALTER TABLE aios_knowledge.source_node OWNER TO aios_c10_owner;
ALTER TABLE aios_knowledge.knowledge_revision OWNER TO aios_c10_owner;
ALTER TABLE aios_knowledge.command_receipt OWNER TO aios_c10_owner;
ALTER FUNCTION aios_knowledge.reject_physical_change()
  OWNER TO aios_c10_owner;
ALTER FUNCTION aios_knowledge.enforce_document_transition()
  OWNER TO aios_c10_owner;
ALTER FUNCTION aios_knowledge.enforce_source_node_insert()
  OWNER TO aios_c10_owner;
ALTER FUNCTION aios_knowledge.enforce_source_node_update()
  OWNER TO aios_c10_owner;
ALTER FUNCTION aios_knowledge.enforce_document_evidence_pair()
  OWNER TO aios_c10_owner;
ALTER FUNCTION aios_knowledge.enforce_source_document_pair()
  OWNER TO aios_c10_owner;
ALTER FUNCTION aios_knowledge.enforce_revision_document_pair()
  OWNER TO aios_c10_owner;

CREATE POLICY knowledge_document_owner_policy
  ON aios_knowledge.knowledge_document TO aios_c10_owner
  USING (true) WITH CHECK (true);
CREATE POLICY knowledge_document_runtime_policy
  ON aios_knowledge.knowledge_document TO aios_c10_runtime
  USING (aios_data.runtime_scope_allows(tenant_id, tenant_kind))
  WITH CHECK (aios_data.runtime_scope_allows(tenant_id, tenant_kind));
CREATE POLICY knowledge_document_reader_policy
  ON aios_knowledge.knowledge_document FOR SELECT TO aios_c10_reader
  USING (aios_data.runtime_scope_allows(tenant_id, tenant_kind));

CREATE POLICY source_node_owner_policy
  ON aios_knowledge.source_node TO aios_c10_owner
  USING (true) WITH CHECK (true);
CREATE POLICY source_node_runtime_policy
  ON aios_knowledge.source_node TO aios_c10_runtime
  USING (aios_data.runtime_scope_allows(tenant_id, tenant_kind))
  WITH CHECK (aios_data.runtime_scope_allows(tenant_id, tenant_kind));
CREATE POLICY source_node_reader_policy
  ON aios_knowledge.source_node FOR SELECT TO aios_c10_reader
  USING (aios_data.runtime_scope_allows(tenant_id, tenant_kind));

CREATE POLICY knowledge_revision_owner_policy
  ON aios_knowledge.knowledge_revision TO aios_c10_owner
  USING (true) WITH CHECK (true);
CREATE POLICY knowledge_revision_runtime_policy
  ON aios_knowledge.knowledge_revision TO aios_c10_runtime
  USING (aios_data.runtime_scope_allows(tenant_id, tenant_kind))
  WITH CHECK (aios_data.runtime_scope_allows(tenant_id, tenant_kind));
CREATE POLICY knowledge_revision_reader_policy
  ON aios_knowledge.knowledge_revision FOR SELECT TO aios_c10_reader
  USING (aios_data.runtime_scope_allows(tenant_id, tenant_kind));

CREATE POLICY command_receipt_owner_policy
  ON aios_knowledge.command_receipt TO aios_c10_owner
  USING (true) WITH CHECK (true);
CREATE POLICY command_receipt_runtime_policy
  ON aios_knowledge.command_receipt TO aios_c10_runtime
  USING (aios_data.runtime_scope_allows(tenant_id, tenant_kind))
  WITH CHECK (aios_data.runtime_scope_allows(tenant_id, tenant_kind));

GRANT USAGE ON SCHEMA aios_knowledge
  TO aios_c10_runtime, aios_c10_reader;
GRANT USAGE ON SCHEMA aios_data
  TO aios_c10_runtime, aios_c10_reader;
GRANT EXECUTE ON FUNCTION aios_data.runtime_scope_allows(text, text)
  TO aios_c10_runtime, aios_c10_reader;
GRANT EXECUTE ON FUNCTION aios_data.acquire_runtime_fence()
  TO aios_c10_runtime;

GRANT SELECT, INSERT, UPDATE ON
  aios_knowledge.knowledge_document,
  aios_knowledge.source_node
TO aios_c10_runtime;

GRANT SELECT, INSERT ON
  aios_knowledge.knowledge_revision,
  aios_knowledge.command_receipt
TO aios_c10_runtime;

GRANT SELECT ON
  aios_knowledge.knowledge_document,
  aios_knowledge.source_node,
  aios_knowledge.knowledge_revision
TO aios_c10_reader;

COMMIT;
