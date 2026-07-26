BEGIN;

CREATE SCHEMA aios_knowledge;

CREATE TABLE aios_knowledge.knowledge_document (
  tenant_id text NOT NULL,
  tenant_kind text NOT NULL CHECK (tenant_kind = 'SYNTHETIC'),
  document_id text NOT NULL
    CHECK (document_id ~ '^[a-z][a-z0-9_-]{0,127}$'),
  document_version bigint NOT NULL
    CHECK (document_version BETWEEN 1 AND 9007199254740991),
  revision bigint NOT NULL
    CHECK (revision BETWEEN 1 AND 9007199254740991),
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
  fixture_ref text NOT NULL
    CHECK (fixture_ref ~ '^fixture://c10/\S+$'),
  source_ref text NOT NULL
    CHECK (
      source_ref ~ '^(evidence|fixture|policy|profile|synthetic|test)://\S+$'
    ),
  filename text NOT NULL
    CHECK (char_length(btrim(filename)) BETWEEN 1 AND 255),
  declared_media_type text NOT NULL
    CHECK (char_length(btrim(declared_media_type)) BETWEEN 1 AND 128),
  detected_media_type text,
  content_sha256 text NOT NULL
    CHECK (content_sha256 ~ '^sha256:[0-9a-f]{64}$'),
  content_size bigint NOT NULL
    CHECK (content_size BETWEEN 1 AND 9007199254740991),
  quarantine_ref text NOT NULL,
  inspection jsonb,
  parser_version text,
  parse_sha256 text,
  metadata jsonb,
  authorization_evidence jsonb NOT NULL
    CHECK (jsonb_typeof(authorization_evidence) = 'object'),
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  published_at timestamptz,
  withdrawn_at timestamptz,
  expired_at timestamptz,
  deleted_at timestamptz,
  PRIMARY KEY (tenant_id, document_id, document_version),
  UNIQUE (tenant_id, document_id, document_version, revision),
  UNIQUE (tenant_id, quarantine_ref),
  FOREIGN KEY (tenant_id, tenant_kind)
    REFERENCES aios_core.tenant_registry(tenant_id, tenant_kind)
    ON DELETE RESTRICT,
  CHECK (
    detected_media_type IS NULL
    OR char_length(btrim(detected_media_type)) BETWEEN 1 AND 128
  ),
  CHECK (
    inspection IS NULL
    OR jsonb_typeof(inspection) = 'object'
  ),
  CHECK (
    parser_version IS NULL
    OR char_length(btrim(parser_version)) BETWEEN 1 AND 128
  ),
  CHECK (
    parse_sha256 IS NULL
    OR parse_sha256 ~ '^sha256:[0-9a-f]{64}$'
  ),
  CHECK (
    metadata IS NULL
    OR jsonb_typeof(metadata) = 'object'
  ),
  CHECK (updated_at >= created_at),
  CONSTRAINT knowledge_document_quarantine_reference_shape CHECK (
    quarantine_ref =
      'quarantine://c10/' || tenant_id || '/' || document_id || '/' ||
      document_version::text || '/' || substring(content_sha256 FROM 8)
  ),
  CONSTRAINT knowledge_document_state_shape CHECK (
    (
      state = 'QUARANTINED'
      AND inspection IS NULL
      AND parser_version IS NULL
      AND parse_sha256 IS NULL
      AND metadata IS NULL
    )
    OR (
      state = 'INSPECTED'
      AND inspection ->> 'outcome' = 'PASS'
      AND parser_version IS NULL
      AND parse_sha256 IS NULL
      AND metadata IS NULL
    )
    OR (
      state = 'REJECTED'
      AND inspection ->> 'outcome' = 'REJECT'
      AND parser_version IS NULL
      AND parse_sha256 IS NULL
      AND metadata IS NULL
    )
    OR (
      state = 'PARSED_CANDIDATE'
      AND inspection ->> 'outcome' = 'PASS'
      AND parser_version IS NOT NULL
      AND parse_sha256 IS NOT NULL
      AND metadata IS NULL
    )
    OR (
      state IN ('PUBLISHED', 'WITHDRAWN', 'EXPIRED')
      AND inspection ->> 'outcome' = 'PASS'
      AND parser_version IS NOT NULL
      AND parse_sha256 IS NOT NULL
      AND metadata ?& ARRAY[
        'ownerPrincipalId',
        'sourceRef',
        'version',
        'validFrom',
        'validUntil',
        'classification',
        'acl'
      ]
      AND jsonb_typeof(metadata -> 'acl') = 'object'
    )
    OR state = 'DELETED'
  ),
  CONSTRAINT knowledge_document_timeline_shape CHECK (
    (state <> 'PUBLISHED' OR published_at IS NOT NULL)
    AND (state <> 'WITHDRAWN' OR withdrawn_at IS NOT NULL)
    AND (state <> 'EXPIRED' OR expired_at IS NOT NULL)
    AND (state <> 'DELETED' OR deleted_at IS NOT NULL)
  )
);

CREATE TABLE aios_knowledge.source_node (
  tenant_id text NOT NULL,
  tenant_kind text NOT NULL CHECK (tenant_kind = 'SYNTHETIC'),
  document_id text NOT NULL,
  document_version bigint NOT NULL,
  node_id text NOT NULL
    CHECK (node_id ~ '^knn_[0-9a-f]{32}$'),
  node_type text NOT NULL
    CHECK (node_type IN ('ORIGINAL', 'PAGE', 'SECTION', 'TABLE', 'CHUNK')),
  parent_node_id text,
  ordinal bigint NOT NULL
    CHECK (ordinal BETWEEN 0 AND 9007199254740991),
  location jsonb NOT NULL CHECK (jsonb_typeof(location) = 'object'),
  text_sha256 text NOT NULL
    CHECK (text_sha256 ~ '^sha256:[0-9a-f]{64}$'),
  source_sha256 text NOT NULL
    CHECK (source_sha256 ~ '^sha256:[0-9a-f]{64}$'),
  authority_status text NOT NULL CHECK (authority_status = 'CANDIDATE'),
  availability_state text NOT NULL CHECK (
    availability_state IN (
      'CANDIDATE', 'PUBLISHED', 'WITHDRAWN', 'EXPIRED', 'DELETED'
    )
  ),
  deleted_at timestamptz,
  PRIMARY KEY (
    tenant_id,
    document_id,
    document_version,
    node_id
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
    REFERENCES aios_knowledge.knowledge_document(
      tenant_id,
      document_id,
      document_version
    )
    ON DELETE RESTRICT,
  FOREIGN KEY (
    tenant_id,
    document_id,
    document_version,
    parent_node_id
  )
    REFERENCES aios_knowledge.source_node(
      tenant_id,
      document_id,
      document_version,
      node_id
    )
    ON DELETE RESTRICT
    DEFERRABLE INITIALLY DEFERRED,
  CHECK (
    (node_type = 'ORIGINAL' AND parent_node_id IS NULL AND ordinal = 0)
    OR (node_type <> 'ORIGINAL' AND parent_node_id IS NOT NULL)
  ),
  CHECK (
    (availability_state = 'DELETED' AND deleted_at IS NOT NULL)
    OR (availability_state <> 'DELETED' AND deleted_at IS NULL)
  )
);

CREATE TABLE aios_knowledge.knowledge_revision (
  tenant_id text NOT NULL,
  tenant_kind text NOT NULL CHECK (tenant_kind = 'SYNTHETIC'),
  document_id text NOT NULL,
  document_version bigint NOT NULL,
  revision bigint NOT NULL
    CHECK (revision BETWEEN 1 AND 9007199254740991),
  state text NOT NULL,
  snapshot jsonb NOT NULL CHECK (jsonb_typeof(snapshot) = 'object'),
  effective_at timestamptz NOT NULL,
  PRIMARY KEY (
    tenant_id,
    document_id,
    document_version,
    revision
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
    ON DELETE RESTRICT
);

CREATE TABLE aios_knowledge.command_receipt (
  tenant_id text NOT NULL,
  tenant_kind text NOT NULL CHECK (tenant_kind = 'SYNTHETIC'),
  idempotency_key text NOT NULL
    CHECK (char_length(btrim(idempotency_key)) BETWEEN 1 AND 128),
  request_hash text NOT NULL
    CHECK (request_hash ~ '^sha256:[0-9a-f]{64}$'),
  command_kind text NOT NULL
    CHECK (
      command_kind IN (
        'UPLOAD', 'INSPECT', 'PARSE', 'PUBLISH',
        'WITHDRAW', 'EXPIRE', 'DELETE'
      )
    ),
  document_id text NOT NULL,
  document_version bigint NOT NULL,
  result jsonb NOT NULL CHECK (jsonb_typeof(result) = 'object'),
  created_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, idempotency_key),
  FOREIGN KEY (tenant_id, tenant_kind)
    REFERENCES aios_core.tenant_registry(tenant_id, tenant_kind)
    ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, document_id, document_version)
    REFERENCES aios_knowledge.knowledge_document(
      tenant_id,
      document_id,
      document_version
    )
    ON DELETE RESTRICT
);

CREATE INDEX knowledge_document_as_of_idx
  ON aios_knowledge.knowledge_document(
    tenant_id,
    document_id,
    document_version DESC,
    state
  );

CREATE INDEX knowledge_revision_as_of_idx
  ON aios_knowledge.knowledge_revision(
    tenant_id,
    document_id,
    effective_at DESC,
    document_version DESC,
    revision DESC
  );

CREATE INDEX source_node_availability_idx
  ON aios_knowledge.source_node(
    tenant_id,
    availability_state,
    document_id,
    document_version
  );

CREATE FUNCTION aios_knowledge.reject_physical_change()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION 'C10 append-only evidence cannot be changed physically'
    USING ERRCODE = '23000',
          CONSTRAINT = 'knowledge_append_only_guard';
END;
$$;

CREATE FUNCTION aios_knowledge.enforce_document_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
     OR NEW.tenant_kind IS DISTINCT FROM OLD.tenant_kind
     OR NEW.document_id IS DISTINCT FROM OLD.document_id
     OR NEW.document_version IS DISTINCT FROM OLD.document_version
     OR NEW.fixture_ref IS DISTINCT FROM OLD.fixture_ref
     OR NEW.source_ref IS DISTINCT FROM OLD.source_ref
     OR NEW.filename IS DISTINCT FROM OLD.filename
     OR NEW.declared_media_type IS DISTINCT FROM OLD.declared_media_type
     OR NEW.content_sha256 IS DISTINCT FROM OLD.content_sha256
     OR NEW.content_size IS DISTINCT FROM OLD.content_size
     OR NEW.quarantine_ref IS DISTINCT FROM OLD.quarantine_ref
     OR NEW.created_at IS DISTINCT FROM OLD.created_at
     OR NEW.revision <> OLD.revision + 1
     OR NEW.updated_at < OLD.updated_at THEN
    RAISE EXCEPTION 'C10 immutable field or revision changed'
      USING ERRCODE = '23000',
            CONSTRAINT = 'knowledge_document_revision_guard';
  END IF;

  IF NOT (
    (OLD.state = 'QUARANTINED' AND NEW.state IN ('INSPECTED', 'REJECTED', 'DELETED'))
    OR (OLD.state = 'INSPECTED' AND NEW.state IN ('PARSED_CANDIDATE', 'DELETED'))
    OR (OLD.state = 'REJECTED' AND NEW.state = 'DELETED')
    OR (OLD.state = 'PARSED_CANDIDATE' AND NEW.state IN ('PUBLISHED', 'DELETED'))
    OR (OLD.state = 'PUBLISHED' AND NEW.state IN ('WITHDRAWN', 'EXPIRED', 'DELETED'))
    OR (OLD.state IN ('WITHDRAWN', 'EXPIRED') AND NEW.state = 'DELETED')
  ) THEN
    RAISE EXCEPTION 'C10 state transition is invalid'
      USING ERRCODE = '23000',
            CONSTRAINT = 'knowledge_document_transition_guard';
  END IF;
  RETURN NEW;
END;
$$;

CREATE FUNCTION aios_knowledge.enforce_source_node_insert()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  parent_type text;
  document_hash text;
BEGIN
  SELECT content_sha256
    INTO document_hash
    FROM aios_knowledge.knowledge_document
   WHERE tenant_id = NEW.tenant_id
     AND document_id = NEW.document_id
     AND document_version = NEW.document_version;
  IF document_hash IS NULL OR NEW.source_sha256 <> document_hash THEN
    RAISE EXCEPTION 'C10 source hash does not match the original'
      USING ERRCODE = '23000',
            CONSTRAINT = 'knowledge_source_hash_guard';
  END IF;
  IF NEW.node_type = 'ORIGINAL' THEN
    IF NEW.text_sha256 <> document_hash THEN
      RAISE EXCEPTION 'C10 original hash is invalid'
        USING ERRCODE = '23000',
              CONSTRAINT = 'knowledge_original_hash_guard';
    END IF;
    RETURN NEW;
  END IF;

  SELECT node_type
    INTO parent_type
    FROM aios_knowledge.source_node
   WHERE tenant_id = NEW.tenant_id
     AND document_id = NEW.document_id
     AND document_version = NEW.document_version
     AND node_id = NEW.parent_node_id;
  IF parent_type IS NULL
     OR (NEW.node_type = 'PAGE' AND parent_type <> 'ORIGINAL')
     OR (NEW.node_type = 'SECTION' AND parent_type <> 'PAGE')
     OR (
       NEW.node_type = 'TABLE'
       AND parent_type NOT IN ('PAGE', 'SECTION')
     )
     OR (
       NEW.node_type = 'CHUNK'
       AND parent_type NOT IN ('PAGE', 'SECTION', 'TABLE')
     ) THEN
    RAISE EXCEPTION 'C10 source parent type is invalid'
      USING ERRCODE = '23000',
            CONSTRAINT = 'knowledge_source_parent_guard';
  END IF;
  RETURN NEW;
END;
$$;

CREATE FUNCTION aios_knowledge.enforce_source_node_update()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
     OR NEW.tenant_kind IS DISTINCT FROM OLD.tenant_kind
     OR NEW.document_id IS DISTINCT FROM OLD.document_id
     OR NEW.document_version IS DISTINCT FROM OLD.document_version
     OR NEW.node_id IS DISTINCT FROM OLD.node_id
     OR NEW.node_type IS DISTINCT FROM OLD.node_type
     OR NEW.parent_node_id IS DISTINCT FROM OLD.parent_node_id
     OR NEW.ordinal IS DISTINCT FROM OLD.ordinal
     OR NEW.location IS DISTINCT FROM OLD.location
     OR NEW.text_sha256 IS DISTINCT FROM OLD.text_sha256
     OR NEW.source_sha256 IS DISTINCT FROM OLD.source_sha256
     OR NEW.authority_status IS DISTINCT FROM OLD.authority_status THEN
    RAISE EXCEPTION 'C10 source provenance is immutable'
      USING ERRCODE = '23000',
            CONSTRAINT = 'knowledge_source_immutable_guard';
  END IF;
  RETURN NEW;
END;
$$;

CREATE FUNCTION aios_knowledge.enforce_document_evidence_pair()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  expected_availability text;
  revision_snapshot jsonb;
  persisted_node_count bigint;
BEGIN
  SELECT snapshot
    INTO revision_snapshot
    FROM aios_knowledge.knowledge_revision
     WHERE tenant_id = NEW.tenant_id
       AND document_id = NEW.document_id
       AND document_version = NEW.document_version
       AND revision = NEW.revision
       AND state = NEW.state
       AND snapshot ->> 'contentSha256' = NEW.content_sha256;
  IF revision_snapshot IS NULL THEN
    RAISE EXCEPTION 'C10 document revision evidence is missing'
      USING ERRCODE = '23000',
            CONSTRAINT = 'knowledge_document_revision_pair_guard';
  END IF;

  IF NEW.state IN (
    'PARSED_CANDIDATE', 'PUBLISHED', 'WITHDRAWN', 'EXPIRED', 'DELETED'
  ) AND NEW.parse_sha256 IS NOT NULL THEN
    SELECT count(*)
      INTO persisted_node_count
      FROM aios_knowledge.source_node
     WHERE tenant_id = NEW.tenant_id
       AND document_id = NEW.document_id
       AND document_version = NEW.document_version;
    expected_availability := CASE NEW.state
      WHEN 'PARSED_CANDIDATE' THEN 'CANDIDATE'
      ELSE NEW.state
    END;
    IF jsonb_typeof(revision_snapshot -> 'nodes') <> 'array'
       OR jsonb_array_length(revision_snapshot -> 'nodes')
          <> persisted_node_count
       OR NOT EXISTS (
      SELECT 1
        FROM aios_knowledge.source_node
       WHERE tenant_id = NEW.tenant_id
         AND document_id = NEW.document_id
         AND document_version = NEW.document_version
         AND node_type = 'ORIGINAL'
    ) OR NOT EXISTS (
      SELECT 1
        FROM aios_knowledge.source_node
       WHERE tenant_id = NEW.tenant_id
         AND document_id = NEW.document_id
         AND document_version = NEW.document_version
         AND node_type = 'PAGE'
    ) OR NOT EXISTS (
      SELECT 1
        FROM aios_knowledge.source_node
       WHERE tenant_id = NEW.tenant_id
         AND document_id = NEW.document_id
         AND document_version = NEW.document_version
         AND node_type = 'CHUNK'
    ) OR EXISTS (
      SELECT 1
        FROM aios_knowledge.source_node
       WHERE tenant_id = NEW.tenant_id
         AND document_id = NEW.document_id
         AND document_version = NEW.document_version
         AND availability_state <> expected_availability
    ) THEN
      RAISE EXCEPTION 'C10 source-node propagation is incomplete'
        USING ERRCODE = '23000',
              CONSTRAINT = 'knowledge_source_propagation_guard';
    END IF;
  END IF;
  RETURN NULL;
END;
$$;

CREATE FUNCTION aios_knowledge.enforce_source_document_pair()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  document_state text;
  document_deleted_at timestamptz;
  document_revision bigint;
  expected_availability text;
BEGIN
  SELECT state, deleted_at, revision
    INTO document_state, document_deleted_at, document_revision
    FROM aios_knowledge.knowledge_document
   WHERE tenant_id = NEW.tenant_id
     AND document_id = NEW.document_id
     AND document_version = NEW.document_version;
  expected_availability := CASE document_state
    WHEN 'PARSED_CANDIDATE' THEN 'CANDIDATE'
    ELSE document_state
  END;
  IF expected_availability IS NULL
     OR NEW.availability_state <> expected_availability
     OR (
       expected_availability = 'DELETED'
       AND NEW.deleted_at IS DISTINCT FROM document_deleted_at
     )
     OR NOT EXISTS (
       SELECT 1
         FROM aios_knowledge.knowledge_revision AS revision
         CROSS JOIN LATERAL jsonb_array_elements(
           revision.snapshot -> 'nodes'
         ) AS expected(node)
        WHERE revision.tenant_id = NEW.tenant_id
          AND revision.document_id = NEW.document_id
          AND revision.document_version = NEW.document_version
          AND revision.revision = document_revision
          AND expected.node ->> 'nodeId' = NEW.node_id
          AND expected.node ->> 'nodeType' = NEW.node_type
          AND (expected.node ->> 'parentNodeId')
              IS NOT DISTINCT FROM NEW.parent_node_id
          AND (expected.node ->> 'ordinal')::bigint = NEW.ordinal
          AND expected.node -> 'location' = NEW.location
          AND expected.node ->> 'textSha256' = NEW.text_sha256
          AND expected.node ->> 'sourceSha256' = NEW.source_sha256
          AND expected.node ->> 'authorityStatus' =
              NEW.authority_status
          AND expected.node ->> 'availabilityState' =
              NEW.availability_state
     ) THEN
    RAISE EXCEPTION 'C10 source node and document state diverged'
      USING ERRCODE = '23000',
            CONSTRAINT = 'knowledge_source_document_pair_guard';
  END IF;
  RETURN NULL;
END;
$$;

CREATE FUNCTION aios_knowledge.enforce_revision_document_pair()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
      FROM aios_knowledge.knowledge_document AS document
     WHERE document.tenant_id = NEW.tenant_id
       AND document.document_id = NEW.document_id
       AND document.document_version = NEW.document_version
       AND document.revision = NEW.revision
       AND document.state = NEW.state
       AND NEW.snapshot ->> 'tenantId' = NEW.tenant_id
       AND NEW.snapshot ->> 'tenantKind' = NEW.tenant_kind
       AND NEW.snapshot ->> 'documentId' = NEW.document_id
       AND (NEW.snapshot ->> 'documentVersion')::bigint =
           NEW.document_version
       AND (NEW.snapshot ->> 'revision')::bigint = NEW.revision
       AND NEW.snapshot ->> 'state' = NEW.state
       AND NEW.snapshot ->> 'contentSha256' = document.content_sha256
       AND NEW.snapshot ->> 'updatedAt' =
           to_char(
             document.updated_at AT TIME ZONE 'UTC',
             'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'
           )
  ) THEN
    RAISE EXCEPTION 'C10 revision and document state diverged'
      USING ERRCODE = '23000',
            CONSTRAINT = 'knowledge_revision_document_pair_guard';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER knowledge_document_transition_guard
BEFORE UPDATE ON aios_knowledge.knowledge_document
FOR EACH ROW EXECUTE FUNCTION
  aios_knowledge.enforce_document_transition();

CREATE TRIGGER knowledge_document_delete_guard
BEFORE DELETE ON aios_knowledge.knowledge_document
FOR EACH ROW EXECUTE FUNCTION
  aios_knowledge.reject_physical_change();

CREATE TRIGGER knowledge_source_insert_guard
BEFORE INSERT ON aios_knowledge.source_node
FOR EACH ROW EXECUTE FUNCTION
  aios_knowledge.enforce_source_node_insert();

CREATE TRIGGER knowledge_source_update_guard
BEFORE UPDATE ON aios_knowledge.source_node
FOR EACH ROW EXECUTE FUNCTION
  aios_knowledge.enforce_source_node_update();

CREATE TRIGGER knowledge_source_delete_guard
BEFORE DELETE ON aios_knowledge.source_node
FOR EACH ROW EXECUTE FUNCTION
  aios_knowledge.reject_physical_change();

CREATE TRIGGER knowledge_revision_update_guard
BEFORE UPDATE OR DELETE ON aios_knowledge.knowledge_revision
FOR EACH ROW EXECUTE FUNCTION
  aios_knowledge.reject_physical_change();

CREATE TRIGGER knowledge_revision_insert_guard
BEFORE INSERT ON aios_knowledge.knowledge_revision
FOR EACH ROW EXECUTE FUNCTION
  aios_knowledge.enforce_revision_document_pair();

CREATE TRIGGER knowledge_receipt_update_guard
BEFORE UPDATE OR DELETE ON aios_knowledge.command_receipt
FOR EACH ROW EXECUTE FUNCTION
  aios_knowledge.reject_physical_change();

CREATE CONSTRAINT TRIGGER knowledge_document_evidence_pair_guard
AFTER INSERT OR UPDATE ON aios_knowledge.knowledge_document
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION
  aios_knowledge.enforce_document_evidence_pair();

CREATE CONSTRAINT TRIGGER knowledge_source_document_pair_guard
AFTER INSERT OR UPDATE ON aios_knowledge.source_node
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION
  aios_knowledge.enforce_source_document_pair();

ALTER TABLE aios_knowledge.knowledge_document ENABLE ROW LEVEL SECURITY;
ALTER TABLE aios_knowledge.knowledge_document FORCE ROW LEVEL SECURITY;
ALTER TABLE aios_knowledge.source_node ENABLE ROW LEVEL SECURITY;
ALTER TABLE aios_knowledge.source_node FORCE ROW LEVEL SECURITY;
ALTER TABLE aios_knowledge.knowledge_revision ENABLE ROW LEVEL SECURITY;
ALTER TABLE aios_knowledge.knowledge_revision FORCE ROW LEVEL SECURITY;
ALTER TABLE aios_knowledge.command_receipt ENABLE ROW LEVEL SECURITY;
ALTER TABLE aios_knowledge.command_receipt FORCE ROW LEVEL SECURITY;

COMMIT;
