BEGIN;

CREATE SCHEMA aios_rag;

CREATE TABLE aios_rag.tenant_index_epoch (
  tenant_id text PRIMARY KEY,
  tenant_kind text NOT NULL CHECK (tenant_kind = 'SYNTHETIC'),
  index_epoch bigint NOT NULL DEFAULT 0
    CHECK (index_epoch BETWEEN 0 AND 9007199254740991),
  updated_at timestamptz NOT NULL,
  UNIQUE (tenant_id, tenant_kind),
  FOREIGN KEY (tenant_id, tenant_kind)
    REFERENCES aios_core.tenant_registry(tenant_id, tenant_kind)
    ON DELETE RESTRICT
);

CREATE TABLE aios_rag.document_projection (
  tenant_id text NOT NULL,
  tenant_kind text NOT NULL CHECK (tenant_kind = 'SYNTHETIC'),
  document_id text NOT NULL
    CHECK (document_id ~ '^[a-z][a-z0-9_-]{0,127}$'),
  document_version bigint NOT NULL
    CHECK (document_version BETWEEN 1 AND 9007199254740991),
  projection_version bigint NOT NULL
    CHECK (projection_version BETWEEN 1 AND 9007199254740991),
  catalog_revision bigint NOT NULL
    CHECK (catalog_revision BETWEEN 1 AND 9007199254740991),
  state text NOT NULL CHECK (
    state IN (
      'QUARANTINED',
      'INSPECTED',
      'REJECTED',
      'PARSED_CANDIDATE',
      'PUBLISHED',
      'WITHDRAWN',
      'EXPIRED',
      'DELETED'
    )
  ),
  content_sha256 text NOT NULL
    CHECK (content_sha256 ~ '^sha256:[0-9a-f]{64}$'),
  parse_sha256 text
    CHECK (
      parse_sha256 IS NULL
      OR parse_sha256 ~ '^sha256:[0-9a-f]{64}$'
    ),
  valid_from timestamptz,
  valid_until timestamptz,
  classification text CHECK (
    classification IS NULL
    OR classification IN ('PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'RESTRICTED')
  ),
  acl jsonb,
  index_epoch bigint NOT NULL
    CHECK (index_epoch BETWEEN 1 AND 9007199254740991),
  authorization_evidence jsonb NOT NULL
    CHECK (jsonb_typeof(authorization_evidence) = 'object'),
  updated_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, document_id, document_version),
  UNIQUE (
    tenant_id,
    document_id,
    document_version,
    projection_version
  ),
  FOREIGN KEY (tenant_id, tenant_kind)
    REFERENCES aios_core.tenant_registry(tenant_id, tenant_kind)
    ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, document_id, document_version)
    REFERENCES aios_knowledge.knowledge_document(
      tenant_id,
      document_id,
      document_version
    )
    ON DELETE RESTRICT,
  CHECK (
    (
      state = 'PUBLISHED'
      AND valid_from IS NOT NULL
      AND valid_until IS NOT NULL
      AND valid_until > valid_from
      AND classification IS NOT NULL
      AND jsonb_typeof(acl) = 'object'
      AND jsonb_typeof(acl -> 'readPrincipalRefs') = 'array'
      AND jsonb_array_length(acl -> 'readPrincipalRefs') > 0
      AND jsonb_typeof(acl -> 'managePrincipalRefs') = 'array'
    )
    OR (
      state <> 'PUBLISHED'
      AND valid_from IS NULL
      AND valid_until IS NULL
      AND classification IS NULL
      AND acl IS NULL
    )
  )
);

CREATE TABLE aios_rag.chunk_index (
  tenant_id text NOT NULL,
  tenant_kind text NOT NULL CHECK (tenant_kind = 'SYNTHETIC'),
  document_id text NOT NULL,
  document_version bigint NOT NULL,
  catalog_revision bigint NOT NULL
    CHECK (catalog_revision BETWEEN 1 AND 9007199254740991),
  chunk_id text NOT NULL CHECK (chunk_id ~ '^knn_[0-9a-f]{32}$'),
  ordinal bigint NOT NULL
    CHECK (ordinal BETWEEN 1 AND 9007199254740991),
  original_node_id text NOT NULL
    CHECK (original_node_id ~ '^knn_[0-9a-f]{32}$'),
  page_node_id text NOT NULL
    CHECK (page_node_id ~ '^knn_[0-9a-f]{32}$'),
  section_node_id text
    CHECK (
      section_node_id IS NULL
      OR section_node_id ~ '^knn_[0-9a-f]{32}$'
    ),
  table_node_id text
    CHECK (
      table_node_id IS NULL
      OR table_node_id ~ '^knn_[0-9a-f]{32}$'
    ),
  location jsonb NOT NULL CHECK (jsonb_typeof(location) = 'object'),
  chunk_text text NOT NULL
    CHECK (char_length(chunk_text) BETWEEN 1 AND 100000),
  text_sha256 text NOT NULL
    CHECK (text_sha256 ~ '^sha256:[0-9a-f]{64}$'),
  source_sha256 text NOT NULL
    CHECK (source_sha256 ~ '^sha256:[0-9a-f]{64}$'),
  embedding_model text NOT NULL
    CHECK (embedding_model = 'c11-deterministic-hash-embedding-v1'),
  embedding vector(8) NOT NULL,
  search_vector tsvector
    GENERATED ALWAYS AS (to_tsvector('simple', chunk_text)) STORED,
  state text NOT NULL CHECK (
    state IN ('PUBLISHED', 'WITHDRAWN', 'EXPIRED', 'DELETED')
  ),
  active boolean NOT NULL,
  index_epoch bigint NOT NULL
    CHECK (index_epoch BETWEEN 1 AND 9007199254740991),
  PRIMARY KEY (
    tenant_id,
    document_id,
    document_version,
    chunk_id
  ),
  UNIQUE (
    tenant_id,
    document_id,
    document_version,
    ordinal
  ),
  FOREIGN KEY (tenant_id, tenant_kind)
    REFERENCES aios_core.tenant_registry(tenant_id, tenant_kind)
    ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, document_id, document_version)
    REFERENCES aios_rag.document_projection(
      tenant_id,
      document_id,
      document_version
    )
    ON DELETE RESTRICT
    DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY (
    tenant_id,
    document_id,
    document_version,
    chunk_id
  )
    REFERENCES aios_knowledge.source_node(
      tenant_id,
      document_id,
      document_version,
      node_id
    )
    ON DELETE RESTRICT,
  CHECK (
    (state = 'PUBLISHED' AND active)
    OR (state <> 'PUBLISHED' AND NOT active)
  )
);

CREATE TABLE aios_rag.retrieval_cache (
  tenant_id text NOT NULL,
  tenant_kind text NOT NULL CHECK (tenant_kind = 'SYNTHETIC'),
  cache_key text NOT NULL
    CHECK (cache_key ~ '^sha256:[0-9a-f]{64}$'),
  principal_scope_hash text NOT NULL
    CHECK (principal_scope_hash ~ '^sha256:[0-9a-f]{64}$'),
  as_of timestamptz NOT NULL,
  index_epoch bigint NOT NULL
    CHECK (index_epoch BETWEEN 0 AND 9007199254740991),
  document_refs jsonb NOT NULL
    CHECK (jsonb_typeof(document_refs) = 'array'),
  candidates jsonb NOT NULL CHECK (jsonb_typeof(candidates) = 'array'),
  created_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, cache_key),
  FOREIGN KEY (tenant_id, tenant_kind)
    REFERENCES aios_core.tenant_registry(tenant_id, tenant_kind)
    ON DELETE RESTRICT
);

CREATE TABLE aios_rag.projection_receipt (
  tenant_id text NOT NULL,
  tenant_kind text NOT NULL CHECK (tenant_kind = 'SYNTHETIC'),
  idempotency_key text NOT NULL
    CHECK (char_length(btrim(idempotency_key)) BETWEEN 1 AND 128),
  request_hash text NOT NULL
    CHECK (request_hash ~ '^sha256:[0-9a-f]{64}$'),
  document_id text NOT NULL,
  document_version bigint NOT NULL
    CHECK (document_version BETWEEN 1 AND 9007199254740991),
  result jsonb NOT NULL CHECK (jsonb_typeof(result) = 'object'),
  created_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, idempotency_key),
  FOREIGN KEY (tenant_id, tenant_kind)
    REFERENCES aios_core.tenant_registry(tenant_id, tenant_kind)
    ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, document_id, document_version)
    REFERENCES aios_rag.document_projection(
      tenant_id,
      document_id,
      document_version
    )
    ON DELETE RESTRICT
);

CREATE TABLE aios_rag.query_audit (
  audit_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant_id text NOT NULL,
  tenant_kind text NOT NULL CHECK (tenant_kind = 'SYNTHETIC'),
  audit_version text NOT NULL CHECK (audit_version = 'c11-query-audit-v1'),
  request_id_hash text NOT NULL
    CHECK (request_id_hash ~ '^sha256:[0-9a-f]{64}$'),
  query_hash text NOT NULL
    CHECK (query_hash ~ '^sha256:[0-9a-f]{64}$'),
  filter_hash text NOT NULL
    CHECK (filter_hash ~ '^sha256:[0-9a-f]{64}$'),
  principal_scope_hash text NOT NULL
    CHECK (principal_scope_hash ~ '^sha256:[0-9a-f]{64}$'),
  authorization_decision_id text NOT NULL
    CHECK (char_length(btrim(authorization_decision_id)) BETWEEN 1 AND 512),
  candidate_count bigint NOT NULL
    CHECK (candidate_count BETWEEN 0 AND 20),
  evidence_count bigint NOT NULL
    CHECK (evidence_count BETWEEN 0 AND 20),
  result_status text NOT NULL CHECK (
    result_status IN ('ANSWERABLE', 'REFUSED')
  ),
  reason_code text NOT NULL CHECK (
    reason_code IN (
      'SUFFICIENT_AUTHORIZED_EVIDENCE',
      'INSUFFICIENT_AUTHORIZED_EVIDENCE'
    )
  ),
  evidence_id_hashes jsonb NOT NULL
    CHECK (jsonb_typeof(evidence_id_hashes) = 'array'),
  cache_hit boolean NOT NULL,
  recorded_at timestamptz NOT NULL,
  FOREIGN KEY (tenant_id, tenant_kind)
    REFERENCES aios_core.tenant_registry(tenant_id, tenant_kind)
    ON DELETE RESTRICT
);

CREATE INDEX rag_projection_filter_idx
  ON aios_rag.document_projection(
    tenant_id,
    state,
    valid_from,
    valid_until,
    document_id,
    document_version
  );

CREATE INDEX rag_projection_acl_idx
  ON aios_rag.document_projection USING gin (acl jsonb_path_ops);

CREATE INDEX rag_chunk_filter_idx
  ON aios_rag.chunk_index(
    tenant_id,
    active,
    state,
    document_id,
    document_version
  );

CREATE INDEX rag_chunk_fts_idx
  ON aios_rag.chunk_index USING gin (search_vector);

CREATE INDEX rag_chunk_vector_idx
  ON aios_rag.chunk_index
  USING hnsw (embedding vector_cosine_ops);

CREATE INDEX rag_query_audit_tenant_time_idx
  ON aios_rag.query_audit(tenant_id, recorded_at DESC);

CREATE FUNCTION aios_rag.reject_physical_change()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION 'C11 append-only evidence cannot be changed physically'
    USING ERRCODE = '23000',
          CONSTRAINT = 'rag_append_only_guard';
END;
$$;

CREATE FUNCTION aios_rag.enforce_epoch_update()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
     OR NEW.tenant_kind IS DISTINCT FROM OLD.tenant_kind
     OR NEW.index_epoch <> OLD.index_epoch + 1
     OR NEW.updated_at < OLD.updated_at THEN
    RAISE EXCEPTION 'C11 Tenant index epoch changed incorrectly'
      USING ERRCODE = '23000',
            CONSTRAINT = 'rag_index_epoch_guard';
  END IF;
  RETURN NEW;
END;
$$;

CREATE FUNCTION aios_rag.enforce_projection_update()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
     OR NEW.tenant_kind IS DISTINCT FROM OLD.tenant_kind
     OR NEW.document_id IS DISTINCT FROM OLD.document_id
     OR NEW.document_version IS DISTINCT FROM OLD.document_version
     OR NEW.content_sha256 IS DISTINCT FROM OLD.content_sha256
     OR NEW.parse_sha256 IS DISTINCT FROM OLD.parse_sha256
     OR NEW.projection_version <> OLD.projection_version + 1
     OR NEW.catalog_revision <= OLD.catalog_revision
     OR NEW.index_epoch <= OLD.index_epoch
     OR NEW.updated_at < OLD.updated_at THEN
    RAISE EXCEPTION 'C11 projection version or immutable field changed'
      USING ERRCODE = '23000',
            CONSTRAINT = 'rag_projection_version_guard';
  END IF;
  RETURN NEW;
END;
$$;

CREATE FUNCTION aios_rag.enforce_chunk_shape()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  source_node aios_knowledge.source_node%ROWTYPE;
  catalog_state text;
  catalog_revision bigint;
  has_original boolean;
  has_page boolean;
  has_section boolean;
  has_table boolean;
BEGIN
  IF TG_OP = 'UPDATE' AND (
    NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
    OR NEW.tenant_kind IS DISTINCT FROM OLD.tenant_kind
    OR NEW.document_id IS DISTINCT FROM OLD.document_id
    OR NEW.document_version IS DISTINCT FROM OLD.document_version
    OR NEW.chunk_id IS DISTINCT FROM OLD.chunk_id
    OR NEW.ordinal IS DISTINCT FROM OLD.ordinal
    OR NEW.original_node_id IS DISTINCT FROM OLD.original_node_id
    OR NEW.page_node_id IS DISTINCT FROM OLD.page_node_id
    OR NEW.section_node_id IS DISTINCT FROM OLD.section_node_id
    OR NEW.table_node_id IS DISTINCT FROM OLD.table_node_id
    OR NEW.location IS DISTINCT FROM OLD.location
    OR NEW.chunk_text IS DISTINCT FROM OLD.chunk_text
    OR NEW.text_sha256 IS DISTINCT FROM OLD.text_sha256
    OR NEW.source_sha256 IS DISTINCT FROM OLD.source_sha256
    OR NEW.embedding_model IS DISTINCT FROM OLD.embedding_model
    OR NEW.embedding IS DISTINCT FROM OLD.embedding
  ) THEN
    RAISE EXCEPTION 'C11 indexed provenance and content are immutable'
      USING ERRCODE = '23000',
            CONSTRAINT = 'rag_chunk_immutable_guard';
  END IF;

  SELECT node.*
    INTO source_node
    FROM aios_knowledge.source_node AS node
   WHERE node.tenant_id = NEW.tenant_id
     AND node.document_id = NEW.document_id
     AND node.document_version = NEW.document_version
     AND node.node_id = NEW.chunk_id;
  SELECT state, revision
    INTO catalog_state, catalog_revision
    FROM aios_knowledge.knowledge_document
   WHERE tenant_id = NEW.tenant_id
     AND document_id = NEW.document_id
     AND document_version = NEW.document_version;

  IF source_node.node_id IS NULL
     OR source_node.node_type <> 'CHUNK'
     OR source_node.ordinal <> NEW.ordinal
     OR source_node.location <> NEW.location
     OR source_node.text_sha256 <> NEW.text_sha256
     OR source_node.source_sha256 <> NEW.source_sha256
     OR source_node.availability_state <> NEW.state
     OR catalog_state <> NEW.state
     OR catalog_revision <> NEW.catalog_revision
     OR NEW.text_sha256 <>
       'sha256:' || encode(digest(convert_to(NEW.chunk_text, 'UTF8'), 'sha256'), 'hex')
     OR vector_dims(NEW.embedding) <> 8 THEN
    RAISE EXCEPTION 'C11 Chunk does not match C10 source evidence'
      USING ERRCODE = '23000',
            CONSTRAINT = 'rag_chunk_source_guard';
  END IF;

  WITH RECURSIVE ancestry AS (
    SELECT node_id, node_type, parent_node_id
      FROM aios_knowledge.source_node
     WHERE tenant_id = NEW.tenant_id
       AND document_id = NEW.document_id
       AND document_version = NEW.document_version
       AND node_id = NEW.chunk_id
    UNION ALL
    SELECT parent.node_id, parent.node_type, parent.parent_node_id
      FROM aios_knowledge.source_node AS parent
      JOIN ancestry AS child ON child.parent_node_id = parent.node_id
     WHERE parent.tenant_id = NEW.tenant_id
       AND parent.document_id = NEW.document_id
       AND parent.document_version = NEW.document_version
  )
  SELECT
    bool_or(node_type = 'ORIGINAL' AND node_id = NEW.original_node_id),
    bool_or(node_type = 'PAGE' AND node_id = NEW.page_node_id),
    bool_or(
      node_type = 'SECTION'
      AND node_id = NEW.section_node_id
    ),
    bool_or(
      node_type = 'TABLE'
      AND node_id = NEW.table_node_id
    )
    INTO has_original, has_page, has_section, has_table
    FROM ancestry;

  IF NOT coalesce(has_original, false)
     OR NOT coalesce(has_page, false)
     OR (
       NEW.section_node_id IS NOT NULL
       AND NOT coalesce(has_section, false)
     )
     OR (
       NEW.section_node_id IS NULL
       AND coalesce(has_section, false)
     )
     OR (
       NEW.table_node_id IS NOT NULL
       AND NOT coalesce(has_table, false)
     )
     OR (
       NEW.table_node_id IS NULL
       AND coalesce(has_table, false)
     ) THEN
    RAISE EXCEPTION 'C11 Original/Page/Section/Table/Chunk chain is invalid'
      USING ERRCODE = '23000',
            CONSTRAINT = 'rag_chunk_chain_guard';
  END IF;
  RETURN NEW;
END;
$$;

CREATE FUNCTION aios_rag.enforce_projection_catalog_pair()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  catalog aios_knowledge.knowledge_document%ROWTYPE;
  active_count bigint;
  persisted_count bigint;
  source_count bigint;
BEGIN
  SELECT document.*
    INTO catalog
    FROM aios_knowledge.knowledge_document AS document
   WHERE document.tenant_id = NEW.tenant_id
     AND document.document_id = NEW.document_id
     AND document.document_version = NEW.document_version;
  IF catalog.document_id IS NULL
     OR catalog.revision <> NEW.catalog_revision
     OR catalog.state <> NEW.state
     OR catalog.content_sha256 <> NEW.content_sha256
     OR catalog.parse_sha256 IS DISTINCT FROM NEW.parse_sha256 THEN
    RAISE EXCEPTION 'C11 projection does not match current C10 state'
      USING ERRCODE = '23000',
            CONSTRAINT = 'rag_projection_catalog_guard';
  END IF;

  IF NEW.state = 'PUBLISHED' AND (
    NEW.valid_from IS DISTINCT FROM
      (catalog.metadata ->> 'validFrom')::timestamptz
    OR NEW.valid_until IS DISTINCT FROM
      (catalog.metadata ->> 'validUntil')::timestamptz
    OR NEW.classification IS DISTINCT FROM
      catalog.metadata ->> 'classification'
    OR NEW.acl IS DISTINCT FROM catalog.metadata -> 'acl'
  ) THEN
    RAISE EXCEPTION 'C11 publication metadata differs from C10'
      USING ERRCODE = '23000',
            CONSTRAINT = 'rag_projection_metadata_guard';
  END IF;

  SELECT count(*), count(*) FILTER (WHERE active)
    INTO persisted_count, active_count
    FROM aios_rag.chunk_index
   WHERE tenant_id = NEW.tenant_id
     AND document_id = NEW.document_id
     AND document_version = NEW.document_version;
  SELECT count(*)
    INTO source_count
    FROM aios_knowledge.source_node
   WHERE tenant_id = NEW.tenant_id
     AND document_id = NEW.document_id
     AND document_version = NEW.document_version
     AND node_type = 'CHUNK';

  IF (
    NEW.state = 'PUBLISHED'
    AND (
      active_count <> source_count
      OR persisted_count <> source_count
      OR EXISTS (
        SELECT 1
          FROM aios_rag.chunk_index
         WHERE tenant_id = NEW.tenant_id
           AND document_id = NEW.document_id
           AND document_version = NEW.document_version
           AND (
             state <> NEW.state
             OR catalog_revision <> NEW.catalog_revision
             OR index_epoch <> NEW.index_epoch
           )
      )
    )
  ) OR (
    NEW.state <> 'PUBLISHED'
    AND (
      active_count <> 0
      OR EXISTS (
        SELECT 1
          FROM aios_rag.chunk_index
         WHERE tenant_id = NEW.tenant_id
           AND document_id = NEW.document_id
           AND document_version = NEW.document_version
           AND (
             state <> NEW.state
             OR catalog_revision <> NEW.catalog_revision
             OR index_epoch <> NEW.index_epoch
           )
      )
    )
  ) THEN
    RAISE EXCEPTION 'C11 index invalidation or publication is incomplete'
      USING ERRCODE = '23000',
            CONSTRAINT = 'rag_projection_chunk_guard';
  END IF;

  IF EXISTS (
    SELECT 1
      FROM aios_rag.retrieval_cache
     WHERE tenant_id = NEW.tenant_id
  ) THEN
    RAISE EXCEPTION 'C11 projection changed without cache invalidation'
      USING ERRCODE = '23000',
            CONSTRAINT = 'rag_projection_cache_guard';
  END IF;
  RETURN NULL;
END;
$$;

CREATE TRIGGER rag_epoch_update_guard
BEFORE UPDATE ON aios_rag.tenant_index_epoch
FOR EACH ROW EXECUTE FUNCTION aios_rag.enforce_epoch_update();

CREATE TRIGGER rag_projection_update_guard
BEFORE UPDATE ON aios_rag.document_projection
FOR EACH ROW EXECUTE FUNCTION aios_rag.enforce_projection_update();

CREATE TRIGGER rag_projection_delete_guard
BEFORE DELETE ON aios_rag.document_projection
FOR EACH ROW EXECUTE FUNCTION aios_rag.reject_physical_change();

CREATE TRIGGER rag_chunk_shape_guard
BEFORE INSERT OR UPDATE ON aios_rag.chunk_index
FOR EACH ROW EXECUTE FUNCTION aios_rag.enforce_chunk_shape();

CREATE TRIGGER rag_chunk_delete_guard
BEFORE DELETE ON aios_rag.chunk_index
FOR EACH ROW EXECUTE FUNCTION aios_rag.reject_physical_change();

CREATE TRIGGER rag_receipt_change_guard
BEFORE UPDATE OR DELETE ON aios_rag.projection_receipt
FOR EACH ROW EXECUTE FUNCTION aios_rag.reject_physical_change();

CREATE TRIGGER rag_query_audit_change_guard
BEFORE UPDATE OR DELETE ON aios_rag.query_audit
FOR EACH ROW EXECUTE FUNCTION aios_rag.reject_physical_change();

CREATE CONSTRAINT TRIGGER rag_projection_catalog_pair_guard
AFTER INSERT OR UPDATE ON aios_rag.document_projection
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION
  aios_rag.enforce_projection_catalog_pair();

ALTER TABLE aios_rag.tenant_index_epoch ENABLE ROW LEVEL SECURITY;
ALTER TABLE aios_rag.tenant_index_epoch FORCE ROW LEVEL SECURITY;
ALTER TABLE aios_rag.document_projection ENABLE ROW LEVEL SECURITY;
ALTER TABLE aios_rag.document_projection FORCE ROW LEVEL SECURITY;
ALTER TABLE aios_rag.chunk_index ENABLE ROW LEVEL SECURITY;
ALTER TABLE aios_rag.chunk_index FORCE ROW LEVEL SECURITY;
ALTER TABLE aios_rag.retrieval_cache ENABLE ROW LEVEL SECURITY;
ALTER TABLE aios_rag.retrieval_cache FORCE ROW LEVEL SECURITY;
ALTER TABLE aios_rag.projection_receipt ENABLE ROW LEVEL SECURITY;
ALTER TABLE aios_rag.projection_receipt FORCE ROW LEVEL SECURITY;
ALTER TABLE aios_rag.query_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE aios_rag.query_audit FORCE ROW LEVEL SECURITY;

COMMIT;
