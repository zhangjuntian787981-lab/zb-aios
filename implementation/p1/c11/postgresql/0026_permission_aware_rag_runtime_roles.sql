BEGIN;

CREATE ROLE aios_c11_owner
  NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION
  NOBYPASSRLS;

CREATE ROLE aios_c11_projector
  NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION
  NOBYPASSRLS;

CREATE ROLE aios_c11_query
  NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION
  NOBYPASSRLS;

REVOKE ALL ON SCHEMA aios_core FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA aios_core FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA aios_core FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA aios_core FROM PUBLIC;

REVOKE ALL ON SCHEMA aios_rag FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA aios_rag FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA aios_rag FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA aios_rag FROM PUBLIC;

ALTER DEFAULT PRIVILEGES IN SCHEMA aios_rag
  REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA aios_rag
  REVOKE ALL ON SEQUENCES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA aios_rag
  REVOKE ALL ON FUNCTIONS FROM PUBLIC;

ALTER SCHEMA aios_rag OWNER TO aios_c11_owner;
ALTER TABLE aios_rag.tenant_index_epoch OWNER TO aios_c11_owner;
ALTER TABLE aios_rag.document_projection OWNER TO aios_c11_owner;
ALTER TABLE aios_rag.chunk_index OWNER TO aios_c11_owner;
ALTER TABLE aios_rag.retrieval_cache OWNER TO aios_c11_owner;
ALTER TABLE aios_rag.projection_receipt OWNER TO aios_c11_owner;
ALTER TABLE aios_rag.query_audit OWNER TO aios_c11_owner;
ALTER SEQUENCE aios_rag.query_audit_audit_id_seq OWNER TO aios_c11_owner;
ALTER FUNCTION aios_rag.reject_physical_change()
  OWNER TO aios_c11_owner;
ALTER FUNCTION aios_rag.enforce_epoch_update()
  OWNER TO aios_c11_owner;
ALTER FUNCTION aios_rag.enforce_projection_update()
  OWNER TO aios_c11_owner;
ALTER FUNCTION aios_rag.enforce_chunk_shape()
  OWNER TO aios_c11_owner;
ALTER FUNCTION aios_rag.enforce_projection_catalog_pair()
  OWNER TO aios_c11_owner;

CREATE POLICY rag_epoch_owner_policy
  ON aios_rag.tenant_index_epoch TO aios_c11_owner
  USING (true) WITH CHECK (true);
CREATE POLICY rag_epoch_projector_policy
  ON aios_rag.tenant_index_epoch TO aios_c11_projector
  USING (aios_data.runtime_scope_allows(tenant_id, tenant_kind))
  WITH CHECK (aios_data.runtime_scope_allows(tenant_id, tenant_kind));
CREATE POLICY rag_epoch_query_policy
  ON aios_rag.tenant_index_epoch FOR SELECT TO aios_c11_query
  USING (aios_data.runtime_scope_allows(tenant_id, tenant_kind));

CREATE POLICY rag_projection_owner_policy
  ON aios_rag.document_projection TO aios_c11_owner
  USING (true) WITH CHECK (true);
CREATE POLICY rag_projection_projector_policy
  ON aios_rag.document_projection TO aios_c11_projector
  USING (aios_data.runtime_scope_allows(tenant_id, tenant_kind))
  WITH CHECK (aios_data.runtime_scope_allows(tenant_id, tenant_kind));
CREATE POLICY rag_projection_query_policy
  ON aios_rag.document_projection FOR SELECT TO aios_c11_query
  USING (aios_data.runtime_scope_allows(tenant_id, tenant_kind));

CREATE POLICY rag_chunk_owner_policy
  ON aios_rag.chunk_index TO aios_c11_owner
  USING (true) WITH CHECK (true);
CREATE POLICY rag_chunk_projector_policy
  ON aios_rag.chunk_index TO aios_c11_projector
  USING (aios_data.runtime_scope_allows(tenant_id, tenant_kind))
  WITH CHECK (aios_data.runtime_scope_allows(tenant_id, tenant_kind));
CREATE POLICY rag_chunk_query_policy
  ON aios_rag.chunk_index FOR SELECT TO aios_c11_query
  USING (aios_data.runtime_scope_allows(tenant_id, tenant_kind));

CREATE POLICY rag_cache_owner_policy
  ON aios_rag.retrieval_cache TO aios_c11_owner
  USING (true) WITH CHECK (true);
CREATE POLICY rag_cache_projector_policy
  ON aios_rag.retrieval_cache TO aios_c11_projector
  USING (aios_data.runtime_scope_allows(tenant_id, tenant_kind))
  WITH CHECK (aios_data.runtime_scope_allows(tenant_id, tenant_kind));
CREATE POLICY rag_cache_query_policy
  ON aios_rag.retrieval_cache TO aios_c11_query
  USING (aios_data.runtime_scope_allows(tenant_id, tenant_kind))
  WITH CHECK (aios_data.runtime_scope_allows(tenant_id, tenant_kind));

CREATE POLICY rag_receipt_owner_policy
  ON aios_rag.projection_receipt TO aios_c11_owner
  USING (true) WITH CHECK (true);
CREATE POLICY rag_receipt_projector_policy
  ON aios_rag.projection_receipt TO aios_c11_projector
  USING (aios_data.runtime_scope_allows(tenant_id, tenant_kind))
  WITH CHECK (aios_data.runtime_scope_allows(tenant_id, tenant_kind));

CREATE POLICY rag_audit_owner_policy
  ON aios_rag.query_audit TO aios_c11_owner
  USING (true) WITH CHECK (true);
CREATE POLICY rag_audit_query_policy
  ON aios_rag.query_audit FOR INSERT TO aios_c11_query
  WITH CHECK (aios_data.runtime_scope_allows(tenant_id, tenant_kind));

CREATE POLICY knowledge_document_c11_projector_policy
  ON aios_knowledge.knowledge_document FOR SELECT TO aios_c11_projector
  USING (aios_data.runtime_scope_allows(tenant_id, tenant_kind));
CREATE POLICY knowledge_document_c11_query_policy
  ON aios_knowledge.knowledge_document FOR SELECT TO aios_c11_query
  USING (aios_data.runtime_scope_allows(tenant_id, tenant_kind));
CREATE POLICY source_node_c11_projector_policy
  ON aios_knowledge.source_node FOR SELECT TO aios_c11_projector
  USING (aios_data.runtime_scope_allows(tenant_id, tenant_kind));
CREATE POLICY source_node_c11_query_policy
  ON aios_knowledge.source_node FOR SELECT TO aios_c11_query
  USING (aios_data.runtime_scope_allows(tenant_id, tenant_kind));

GRANT USAGE ON SCHEMA aios_rag
  TO aios_c11_projector, aios_c11_query;
GRANT USAGE ON SCHEMA aios_data
  TO aios_c11_projector, aios_c11_query;
GRANT USAGE ON SCHEMA aios_knowledge
  TO aios_c11_projector, aios_c11_query;
GRANT EXECUTE ON FUNCTION aios_data.runtime_scope_allows(text, text)
  TO aios_c11_projector, aios_c11_query;
GRANT EXECUTE ON FUNCTION aios_data.acquire_runtime_fence()
  TO aios_c11_projector, aios_c11_query;

GRANT SELECT, INSERT, UPDATE ON
  aios_rag.tenant_index_epoch,
  aios_rag.document_projection,
  aios_rag.chunk_index
TO aios_c11_projector;
GRANT SELECT, DELETE ON aios_rag.retrieval_cache
  TO aios_c11_projector;
GRANT SELECT, INSERT ON aios_rag.projection_receipt
  TO aios_c11_projector;
GRANT SELECT ON
  aios_knowledge.knowledge_document,
  aios_knowledge.source_node
TO aios_c11_projector;

GRANT SELECT ON
  aios_rag.tenant_index_epoch,
  aios_rag.document_projection,
  aios_rag.chunk_index
TO aios_c11_query;
GRANT SELECT, INSERT, UPDATE, DELETE ON aios_rag.retrieval_cache
  TO aios_c11_query;
GRANT INSERT ON aios_rag.query_audit
  TO aios_c11_query;
GRANT USAGE, SELECT ON SEQUENCE aios_rag.query_audit_audit_id_seq
  TO aios_c11_query;
GRANT SELECT ON
  aios_knowledge.knowledge_document,
  aios_knowledge.source_node
TO aios_c11_query;

COMMIT;
