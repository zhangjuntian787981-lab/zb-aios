BEGIN;

-- C18 reuses the C07 signed per-transaction Tenant scope. C08 events and
-- Outbox rows may be referenced by C18, but they never replace these tables.
CREATE SCHEMA aios_audit;

CREATE FUNCTION aios_audit.metadata_only(value jsonb)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
STRICT
AS $$
DECLARE
  pair record;
  item jsonb;
  normalized_key text;
  scalar_value text;
BEGIN
  IF jsonb_typeof(value) = 'object' THEN
    FOR pair IN
      SELECT object_entry.key AS item_key,
             object_entry.item_value
        FROM jsonb_each(value)
          AS object_entry(key, item_value)
    LOOP
      normalized_key :=
        replace(replace(lower(pair.item_key), '_', ''), '-', '');
      IF normalized_key = ANY (
        ARRAY[
          'accesskey',
          'apikey',
          'authorizationheader',
          'body',
          'bytes',
          'clientsecret',
          'content',
          'cookie',
          'credential',
          'filebytes',
          'input',
          'message',
          'modelinput',
          'modeloutput',
          'output',
          'password',
          'privatekey',
          'prompt',
          'prompttext',
          'raw',
          'secret',
          'text',
          'token',
          'toolarguments'
        ]
      ) THEN
        RETURN false;
      END IF;
      IF normalized_key = 'authorization'
         AND jsonb_typeof(pair.item_value) <> 'object' THEN
        RETURN false;
      END IF;
      IF NOT aios_audit.metadata_only(pair.item_value) THEN
        RETURN false;
      END IF;
    END LOOP;
    RETURN true;
  END IF;

  IF jsonb_typeof(value) = 'array' THEN
    FOR item IN
      SELECT array_entry.item_value
        FROM jsonb_array_elements(value)
          AS array_entry(item_value)
    LOOP
      IF NOT aios_audit.metadata_only(item) THEN
        RETURN false;
      END IF;
    END LOOP;
    RETURN true;
  END IF;

  IF jsonb_typeof(value) = 'string' THEN
    scalar_value := value #>> '{}';
    RETURN
      char_length(scalar_value) <= 2048
      AND scalar_value !~* (
        'basic[[:space:]]+[a-z0-9+/=]+'
        '|bearer[[:space:]]+[a-z0-9._~-]+'
        '|sk-[a-z0-9_-]{8,}'
        '|aiza[a-z0-9_-]{8,}'
        '|akia[a-z0-9]{16}'
        '|gh[pousr]_[a-z0-9]{8,}'
        '|-----BEGIN [A-Z ]+PRIVATE KEY-----'
        '|(api[_-]?key|access[_-]?key|client[_-]?secret'
        '|password|secret|token)[[:space:]]*[:=]'
      );
  END IF;

  RETURN jsonb_typeof(value) IN ('null', 'boolean', 'number');
END;
$$;

CREATE TABLE aios_audit.audit_head (
  tenant_id text NOT NULL,
  tenant_kind text NOT NULL CHECK (tenant_kind = 'SYNTHETIC'),
  last_sequence bigint NOT NULL DEFAULT 0
    CHECK (last_sequence BETWEEN 0 AND 9007199254740991),
  last_event_id text,
  last_event_hash text NOT NULL DEFAULT
    'sha256:0000000000000000000000000000000000000000000000000000000000000000'
    CHECK (last_event_hash ~ '^sha256:[a-f0-9]{64}$'),
  updated_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id),
  UNIQUE (tenant_id, tenant_kind),
  FOREIGN KEY (tenant_id, tenant_kind)
    REFERENCES aios_core.tenant_registry(tenant_id, tenant_kind)
    ON DELETE RESTRICT,
  CHECK (
    (
      last_sequence = 0
      AND last_event_id IS NULL
      AND last_event_hash =
        'sha256:0000000000000000000000000000000000000000000000000000000000000000'
    )
    OR (
      last_sequence > 0
      AND last_event_id IS NOT NULL
      AND last_event_id ~
        '^aev_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    )
  )
);

CREATE TABLE aios_audit.audit_event (
  tenant_id text NOT NULL,
  tenant_kind text NOT NULL CHECK (tenant_kind = 'SYNTHETIC'),
  event_id text NOT NULL
    CHECK (
      event_id ~
        '^aev_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
  sequence bigint NOT NULL
    CHECK (sequence BETWEEN 1 AND 9007199254740991),
  previous_event_hash text NOT NULL
    CHECK (previous_event_hash ~ '^sha256:[a-f0-9]{64}$'),
  event_hash text NOT NULL
    CHECK (event_hash ~ '^sha256:[a-f0-9]{64}$'),
  payload_sha256 text NOT NULL
    CHECK (payload_sha256 ~ '^sha256:[a-f0-9]{64}$'),
  payload jsonb NOT NULL
    CHECK (jsonb_typeof(payload) = 'object')
    CONSTRAINT audit_event_metadata_only
      CHECK (aios_audit.metadata_only(payload))
    CHECK ((payload ->> 'schemaVersion') = 'c18-audit-event.v1')
    CHECK ((payload ->> 'tenantId') IS NOT DISTINCT FROM tenant_id)
    CHECK ((payload ->> 'tenantKind') IS NOT DISTINCT FROM tenant_kind)
    CHECK ((payload ->> 'retentionClass') = 'AUDIT_7Y'),
  created_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, event_id),
  UNIQUE (tenant_id, sequence),
  UNIQUE (tenant_id, event_hash),
  FOREIGN KEY (tenant_id, tenant_kind)
    REFERENCES aios_core.tenant_registry(tenant_id, tenant_kind)
    ON DELETE RESTRICT
);

CREATE TABLE aios_audit.audit_delivery_intent (
  tenant_id text NOT NULL,
  tenant_kind text NOT NULL CHECK (tenant_kind = 'SYNTHETIC'),
  event_id text NOT NULL,
  event jsonb NOT NULL
    CHECK (jsonb_typeof(event) = 'object')
    CONSTRAINT audit_delivery_intent_metadata_only
      CHECK (aios_audit.metadata_only(event))
    CHECK ((event ->> 'id') IS NOT DISTINCT FROM event_id)
    CHECK (
      (event ->> 'type') =
        'product.aios.audit-evidence-recorded.v1'
    )
    CHECK ((event ->> 'tenantkind') IS NOT DISTINCT FROM tenant_kind),
  retention_class text NOT NULL CHECK (retention_class = 'AUDIT_7Y'),
  legal_hold boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, event_id),
  FOREIGN KEY (tenant_id, event_id)
    REFERENCES aios_audit.audit_event(tenant_id, event_id)
    ON DELETE RESTRICT
    DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY (tenant_id, tenant_kind)
    REFERENCES aios_core.tenant_registry(tenant_id, tenant_kind)
    ON DELETE RESTRICT
);

ALTER TABLE aios_audit.audit_event
  ADD CONSTRAINT audit_event_delivery_intent_pair
  FOREIGN KEY (tenant_id, event_id)
  REFERENCES aios_audit.audit_delivery_intent(tenant_id, event_id)
  ON DELETE RESTRICT
  DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE aios_audit.audit_outbox (
  tenant_id text NOT NULL,
  tenant_kind text NOT NULL CHECK (tenant_kind = 'SYNTHETIC'),
  event_id text NOT NULL,
  status text NOT NULL
    CHECK (status IN ('PENDING', 'PROCESSING', 'FAILED', 'PUBLISHED')),
  attempt_count bigint NOT NULL DEFAULT 0
    CHECK (attempt_count BETWEEN 0 AND 9007199254740991),
  lease_version bigint NOT NULL DEFAULT 0
    CHECK (lease_version BETWEEN 0 AND 9007199254740991),
  leased_by text,
  lease_until timestamptz,
  available_at timestamptz NOT NULL,
  published_at timestamptz,
  last_error_code text,
  created_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, event_id),
  FOREIGN KEY (tenant_id, event_id)
    REFERENCES aios_audit.audit_delivery_intent(tenant_id, event_id)
    ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, tenant_kind)
    REFERENCES aios_core.tenant_registry(tenant_id, tenant_kind)
    ON DELETE RESTRICT,
  CHECK (
    leased_by IS NULL
    OR char_length(btrim(leased_by)) BETWEEN 1 AND 128
  ),
  CHECK (
    last_error_code IS NULL
    OR last_error_code ~ '^[A-Z][A-Z0-9_]{0,63}$'
  ),
  CONSTRAINT audit_outbox_state_shape CHECK (
    (
      status IN ('PENDING', 'FAILED')
      AND leased_by IS NULL
      AND lease_until IS NULL
      AND published_at IS NULL
    )
    OR (
      status = 'PROCESSING'
      AND leased_by IS NOT NULL
      AND lease_until IS NOT NULL
      AND published_at IS NULL
    )
    OR (
      status = 'PUBLISHED'
      AND leased_by IS NULL
      AND lease_until IS NULL
      AND published_at IS NOT NULL
      AND last_error_code IS NULL
    )
  )
);

CREATE TABLE aios_audit.audit_command_receipt (
  tenant_id text NOT NULL,
  tenant_kind text NOT NULL CHECK (tenant_kind = 'SYNTHETIC'),
  idempotency_key text NOT NULL
    CHECK (char_length(btrim(idempotency_key)) BETWEEN 1 AND 128),
  request_hash text NOT NULL
    CHECK (request_hash ~ '^sha256:[a-f0-9]{64}$'),
  event_id text NOT NULL,
  created_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, idempotency_key),
  UNIQUE (tenant_id, event_id),
  FOREIGN KEY (tenant_id, event_id)
    REFERENCES aios_audit.audit_event(tenant_id, event_id)
    ON DELETE RESTRICT
    DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY (tenant_id, tenant_kind)
    REFERENCES aios_core.tenant_registry(tenant_id, tenant_kind)
    ON DELETE RESTRICT
);

ALTER TABLE aios_audit.audit_event
  ADD CONSTRAINT audit_event_receipt_pair
  FOREIGN KEY (tenant_id, event_id)
  REFERENCES aios_audit.audit_command_receipt(tenant_id, event_id)
  ON DELETE RESTRICT
  DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE aios_audit.audit_head
  ADD CONSTRAINT audit_head_event_ref
  FOREIGN KEY (tenant_id, last_event_id)
  REFERENCES aios_audit.audit_event(tenant_id, event_id)
  ON DELETE RESTRICT
  DEFERRABLE INITIALLY DEFERRED;

CREATE INDEX audit_event_retention_query_idx
  ON aios_audit.audit_event (tenant_id, created_at, sequence);

CREATE INDEX audit_outbox_delivery_idx
  ON aios_audit.audit_outbox (
    tenant_id,
    status,
    available_at,
    created_at,
    event_id
  );

CREATE INDEX audit_outbox_published_retention_idx
  ON aios_audit.audit_outbox (tenant_id, published_at, event_id)
  WHERE status = 'PUBLISHED';

CREATE FUNCTION aios_audit.reject_append_only_change()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION 'C18 append-only history cannot be changed'
    USING ERRCODE = '42501',
          CONSTRAINT = 'audit_append_only_guard';
END;
$$;

CREATE FUNCTION aios_audit.enforce_head_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'C18 Audit Head cannot be deleted'
      USING ERRCODE = '42501',
            CONSTRAINT = 'audit_head_delete_guard';
  END IF;

  IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
     OR NEW.tenant_kind IS DISTINCT FROM OLD.tenant_kind
     OR NEW.last_sequence <> OLD.last_sequence + 1
     OR NEW.updated_at < OLD.updated_at
     OR NOT EXISTS (
       SELECT 1
         FROM aios_audit.audit_event AS event
        WHERE event.tenant_id = NEW.tenant_id
          AND event.event_id = NEW.last_event_id
          AND event.sequence = NEW.last_sequence
          AND event.previous_event_hash = OLD.last_event_hash
          AND event.event_hash = NEW.last_event_hash
     ) THEN
    RAISE EXCEPTION 'C18 Audit Head must advance by one verified event'
      USING ERRCODE = '23514',
            CONSTRAINT = 'audit_head_transition_guard';
  END IF;
  RETURN NEW;
END;
$$;

CREATE FUNCTION aios_audit.enforce_outbox_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    IF pg_has_role(
         current_user,
         'aios_c18_retention_worker',
         'MEMBER'
       )
       AND OLD.status = 'PUBLISHED'
       AND OLD.published_at <= statement_timestamp() - interval '30 days'
       AND EXISTS (
         SELECT 1
           FROM aios_audit.audit_delivery_intent AS intent
          WHERE intent.tenant_id = OLD.tenant_id
            AND intent.event_id = OLD.event_id
            AND intent.legal_hold = false
       ) THEN
      RETURN OLD;
    END IF;
    RAISE EXCEPTION 'C18 Outbox deletion is not retention-eligible'
      USING ERRCODE = '42501',
            CONSTRAINT = 'audit_outbox_delete_guard';
  END IF;

  IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
     OR NEW.tenant_kind IS DISTINCT FROM OLD.tenant_kind
     OR NEW.event_id IS DISTINCT FROM OLD.event_id
     OR NEW.created_at IS DISTINCT FROM OLD.created_at
     OR (
       NEW.status = 'PROCESSING'
       AND NOT (
         OLD.status IN ('PENDING', 'FAILED', 'PROCESSING')
         AND NEW.attempt_count = OLD.attempt_count + 1
         AND NEW.lease_version = OLD.lease_version + 1
         AND NEW.leased_by IS NOT NULL
         AND NEW.lease_until IS NOT NULL
         AND NEW.lease_until > statement_timestamp()
         AND NEW.lease_until <=
           statement_timestamp() + interval '300 seconds'
         AND NEW.available_at IS NOT DISTINCT FROM OLD.available_at
         AND NEW.published_at IS NULL
         AND NEW.last_error_code IS NULL
         AND (
           (
             OLD.status IN ('PENDING', 'FAILED')
             AND OLD.available_at <= statement_timestamp()
           )
           OR (
             OLD.status = 'PROCESSING'
             AND OLD.lease_until <= statement_timestamp()
           )
         )
       )
     )
     OR (
       NEW.status = 'PUBLISHED'
       AND NOT (
         OLD.status = 'PROCESSING'
         AND NEW.attempt_count = OLD.attempt_count
         AND NEW.lease_version = OLD.lease_version
         AND NEW.leased_by IS NULL
         AND NEW.lease_until IS NULL
         AND OLD.lease_until >= statement_timestamp()
         AND NEW.available_at IS NOT DISTINCT FROM OLD.available_at
         AND NEW.published_at IS NOT DISTINCT FROM statement_timestamp()
         AND NEW.last_error_code IS NULL
       )
     )
     OR (
       NEW.status = 'FAILED'
       AND NOT (
         OLD.status = 'PROCESSING'
         AND NEW.attempt_count = OLD.attempt_count
         AND NEW.lease_version = OLD.lease_version
         AND NEW.leased_by IS NULL
         AND NEW.lease_until IS NULL
         AND OLD.lease_until >= statement_timestamp()
         AND NEW.published_at IS NULL
         AND NEW.last_error_code IS NOT NULL
         AND NEW.available_at > statement_timestamp()
         AND NEW.available_at <=
           statement_timestamp() + interval '3600 seconds'
       )
     )
     OR NEW.status = 'PENDING'
  THEN
    RAISE EXCEPTION 'C18 Outbox transition is invalid'
      USING ERRCODE = '23514',
            CONSTRAINT = 'audit_outbox_transition_guard';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER audit_event_append_only_guard
BEFORE UPDATE OR DELETE ON aios_audit.audit_event
FOR EACH ROW EXECUTE FUNCTION aios_audit.reject_append_only_change();

CREATE TRIGGER audit_delivery_intent_append_only_guard
BEFORE UPDATE OR DELETE ON aios_audit.audit_delivery_intent
FOR EACH ROW EXECUTE FUNCTION aios_audit.reject_append_only_change();

CREATE TRIGGER audit_receipt_append_only_guard
BEFORE UPDATE OR DELETE ON aios_audit.audit_command_receipt
FOR EACH ROW EXECUTE FUNCTION aios_audit.reject_append_only_change();

CREATE TRIGGER audit_head_transition_guard
BEFORE UPDATE OR DELETE ON aios_audit.audit_head
FOR EACH ROW EXECUTE FUNCTION aios_audit.enforce_head_transition();

CREATE TRIGGER audit_outbox_transition_guard
BEFORE UPDATE OR DELETE ON aios_audit.audit_outbox
FOR EACH ROW EXECUTE FUNCTION aios_audit.enforce_outbox_transition();

ALTER TABLE aios_audit.audit_head ENABLE ROW LEVEL SECURITY;
ALTER TABLE aios_audit.audit_event ENABLE ROW LEVEL SECURITY;
ALTER TABLE aios_audit.audit_delivery_intent ENABLE ROW LEVEL SECURITY;
ALTER TABLE aios_audit.audit_outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE aios_audit.audit_command_receipt ENABLE ROW LEVEL SECURITY;

ALTER TABLE aios_audit.audit_head FORCE ROW LEVEL SECURITY;
ALTER TABLE aios_audit.audit_event FORCE ROW LEVEL SECURITY;
ALTER TABLE aios_audit.audit_delivery_intent FORCE ROW LEVEL SECURITY;
ALTER TABLE aios_audit.audit_outbox FORCE ROW LEVEL SECURITY;
ALTER TABLE aios_audit.audit_command_receipt FORCE ROW LEVEL SECURITY;

COMMIT;
