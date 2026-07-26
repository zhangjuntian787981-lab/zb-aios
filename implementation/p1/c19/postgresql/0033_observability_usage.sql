BEGIN;

CREATE SCHEMA aios_observability;

CREATE TABLE aios_observability.telemetry_signal (
  tenant_id text NOT NULL,
  tenant_kind text NOT NULL DEFAULT 'SYNTHETIC',
  signal_id text NOT NULL,
  idempotency_key text NOT NULL,
  request_hash text NOT NULL,
  principal_id text NOT NULL,
  task_ref text NOT NULL,
  trace_id text NOT NULL,
  span_id text NOT NULL,
  parent_span_id text NOT NULL,
  module text NOT NULL,
  operation text NOT NULL,
  signal_type text NOT NULL,
  status text NOT NULL,
  duration_ms bigint,
  error_code text,
  occurred_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, signal_id),
  UNIQUE (tenant_id, idempotency_key),
  FOREIGN KEY (tenant_id, tenant_kind)
    REFERENCES aios_data.tenant_data_lifecycle (tenant_id, tenant_kind)
    ON DELETE RESTRICT,
  CHECK (tenant_kind = 'SYNTHETIC'),
  CHECK (
    signal_id ~ '^sig_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
  ),
  CHECK (length(idempotency_key) BETWEEN 8 AND 128),
  CHECK (request_hash ~ '^sha256:[0-9a-f]{64}$'),
  CHECK (
    principal_id ~ '^prn_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
  ),
  CHECK (
    task_ref ~ '^tsk_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
  ),
  CHECK (
    trace_id ~ '^[0-9a-f]{32}$'
    AND trace_id <> repeat('0', 32)
  ),
  CHECK (span_id ~ '^[0-9a-f]{16}$' AND span_id <> repeat('0', 16)),
  CHECK (
    parent_span_id ~ '^[0-9a-f]{16}$'
    AND parent_span_id <> repeat('0', 16)
  ),
  CHECK (module IN ('C14', 'C16', 'C18', 'C19')),
  CHECK (
    operation IN (
      'c14.model.route',
      'c16.tool.execute',
      'c18.audit.append',
      'c19.usage.settle'
    )
  ),
  CHECK (
    (module = 'C14' AND operation = 'c14.model.route')
    OR (module = 'C16' AND operation = 'c16.tool.execute')
    OR (module = 'C18' AND operation = 'c18.audit.append')
    OR (module = 'C19' AND operation = 'c19.usage.settle')
  ),
  CHECK (signal_type IN ('TRACE', 'SPAN', 'LOG')),
  CHECK (status IN ('OK', 'ERROR')),
  CHECK (
    (signal_type = 'LOG' AND duration_ms IS NULL)
    OR (signal_type <> 'LOG' AND duration_ms >= 0)
  ),
  CHECK (
    (status = 'OK' AND error_code IS NULL)
    OR (
      status = 'ERROR'
      AND (
        (operation = 'c14.model.route'
          AND error_code = 'MODEL_ROUTE_REJECTED')
        OR (operation = 'c16.tool.execute'
          AND error_code = 'TOOL_EXECUTION_REJECTED')
        OR (operation = 'c18.audit.append'
          AND error_code = 'AUDIT_REJECTED')
        OR (operation = 'c19.usage.settle'
          AND error_code = 'USAGE_SETTLEMENT_REJECTED')
      )
    )
  )
);

CREATE TABLE aios_observability.quota_account (
  tenant_id text NOT NULL,
  tenant_kind text NOT NULL DEFAULT 'SYNTHETIC',
  quota_scope text NOT NULL,
  quota_subject_id text NOT NULL,
  principal_id text,
  quota_period text NOT NULL,
  quota_limit_micros bigint NOT NULL,
  quota_threshold_basis_points integer NOT NULL,
  reserved_micros bigint NOT NULL DEFAULT 0,
  consumed_micros bigint NOT NULL DEFAULT 0,
  denied_count bigint NOT NULL DEFAULT 0,
  updated_at timestamptz NOT NULL,
  PRIMARY KEY (
    tenant_id,
    quota_scope,
    quota_subject_id,
    quota_period
  ),
  FOREIGN KEY (tenant_id, tenant_kind)
    REFERENCES aios_data.tenant_data_lifecycle (tenant_id, tenant_kind)
    ON DELETE RESTRICT,
  CHECK (tenant_kind = 'SYNTHETIC'),
  CHECK (
    (
      quota_scope = 'TENANT'
      AND quota_subject_id = tenant_id
      AND principal_id IS NULL
    )
    OR (
      quota_scope = 'PRINCIPAL'
      AND quota_subject_id = principal_id
      AND principal_id
        ~ '^prn_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    )
  ),
  CHECK (quota_period ~ '^[0-9]{4}-(0[1-9]|1[0-2])$'),
  CHECK (quota_limit_micros > 0),
  CHECK (quota_threshold_basis_points BETWEEN 1 AND 10000),
  CHECK (reserved_micros >= 0),
  CHECK (consumed_micros >= 0),
  CHECK (denied_count >= 0),
  CHECK (reserved_micros + consumed_micros <= quota_limit_micros)
);

CREATE TABLE aios_observability.quota_reservation (
  tenant_id text NOT NULL,
  tenant_kind text NOT NULL DEFAULT 'SYNTHETIC',
  reservation_id text NOT NULL,
  principal_id text NOT NULL,
  reserve_idempotency_key text NOT NULL,
  reserve_request_hash text NOT NULL,
  plan_ref text NOT NULL,
  task_ref text NOT NULL,
  dimension_type text NOT NULL,
  resource_ref text NOT NULL,
  meter_type text NOT NULL,
  unit text NOT NULL,
  max_quantity bigint NOT NULL,
  rate_version text NOT NULL,
  unit_rate_micros bigint NOT NULL,
  reserved_cost_micros bigint NOT NULL,
  quota_period text NOT NULL,
  catalog_version text NOT NULL,
  catalog_sha256 text NOT NULL,
  reserve_trace_id text NOT NULL,
  reserve_span_id text NOT NULL,
  reserve_parent_span_id text NOT NULL,
  reserve_input_traceparent text NOT NULL,
  reserve_output_traceparent text NOT NULL,
  reserve_tracestate text,
  state text NOT NULL,
  created_at timestamptz NOT NULL,
  settle_idempotency_key text,
  settle_request_hash text,
  receipt_ref text,
  meter_key text,
  quantity bigint,
  booked_cost_micros bigint,
  supplier_cost_micros bigint,
  variance_micros bigint,
  source_module text,
  source_evidence_ref text,
  source_evidence_sha256 text,
  audit_evidence_ref text,
  audit_evidence_sha256 text,
  settle_trace_id text,
  settle_span_id text,
  settle_parent_span_id text,
  settle_input_traceparent text,
  settle_output_traceparent text,
  settle_tracestate text,
  occurred_at timestamptz,
  settled_at timestamptz,
  release_idempotency_key text,
  release_request_hash text,
  release_output_traceparent text,
  release_tracestate text,
  released_at timestamptz,
  PRIMARY KEY (tenant_id, reservation_id),
  UNIQUE (tenant_id, reserve_idempotency_key),
  UNIQUE (tenant_id, settle_idempotency_key),
  UNIQUE (tenant_id, release_idempotency_key),
  UNIQUE (tenant_id, meter_key),
  FOREIGN KEY (tenant_id, tenant_kind)
    REFERENCES aios_data.tenant_data_lifecycle (tenant_id, tenant_kind)
    ON DELETE RESTRICT,
  CHECK (tenant_kind = 'SYNTHETIC'),
  CHECK (
    reservation_id ~ '^qrs_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
  ),
  CHECK (length(reserve_idempotency_key) BETWEEN 8 AND 128),
  CHECK (
    principal_id ~ '^prn_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
  ),
  CHECK (reserve_request_hash ~ '^sha256:[0-9a-f]{64}$'),
  CHECK (
    task_ref ~ '^tsk_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
  ),
  CHECK (dimension_type IN ('MODEL', 'TOOL', 'SANDBOX')),
  CHECK (
    (dimension_type = 'MODEL' AND meter_type = 'MODEL_TOKEN')
    OR (dimension_type = 'TOOL' AND meter_type = 'TOOL_CALL')
    OR (
      dimension_type = 'SANDBOX'
      AND meter_type = 'SANDBOX_VCPU_MILLISECOND'
    )
  ),
  CHECK (unit IN ('TOKEN', 'CALL', 'VCPU_MILLISECOND')),
  CHECK (max_quantity > 0),
  CHECK (unit_rate_micros >= 0),
  CHECK (reserved_cost_micros = max_quantity * unit_rate_micros),
  CHECK (catalog_sha256 ~ '^sha256:[0-9a-f]{64}$'),
  CHECK (
    reserve_trace_id ~ '^[0-9a-f]{32}$'
    AND reserve_trace_id <> repeat('0', 32)
  ),
  CHECK (
    reserve_span_id ~ '^[0-9a-f]{16}$'
    AND reserve_span_id <> repeat('0', 16)
  ),
  CHECK (
    reserve_parent_span_id ~ '^[0-9a-f]{16}$'
    AND reserve_parent_span_id <> repeat('0', 16)
  ),
  CHECK (
    reserve_input_traceparent
      ~ '^00-[0-9a-f]{32}-[0-9a-f]{16}-(00|01)$'
    AND substring(reserve_input_traceparent FROM 4 FOR 32)
      = reserve_trace_id
    AND substring(reserve_input_traceparent FROM 37 FOR 16)
      = reserve_parent_span_id
  ),
  CHECK (
    reserve_output_traceparent
      ~ '^00-[0-9a-f]{32}-[0-9a-f]{16}-(00|01)$'
    AND substring(reserve_output_traceparent FROM 4 FOR 32)
      = reserve_trace_id
    AND substring(reserve_output_traceparent FROM 37 FOR 16)
      = reserve_span_id
    AND right(reserve_output_traceparent, 2)
      = right(reserve_input_traceparent, 2)
  ),
  CHECK (
    reserve_tracestate IS NULL
    OR (
      length(reserve_tracestate) BETWEEN 1 AND 512
      AND reserve_tracestate !~* (
        '(basic|bearer)[[:space:]]+[a-z0-9._~+/-]{4,}'
        '|(api[_-]?key|access[_-]?key|client[_-]?secret'
        '|password|secret|token)[[:space:]]*[:=]'
        '|sk-[a-z0-9_-]{8,}'
        '|gh[pousr]_[a-z0-9]{8,}'
        '|-----BEGIN [A-Z ]+PRIVATE KEY-----'
      )
    )
  ),
  CHECK (state IN ('RESERVED', 'SETTLED', 'RELEASED')),
  CHECK (
    (
      state = 'RESERVED'
      AND settle_idempotency_key IS NULL
      AND settle_request_hash IS NULL
      AND receipt_ref IS NULL
      AND meter_key IS NULL
      AND quantity IS NULL
      AND booked_cost_micros IS NULL
      AND supplier_cost_micros IS NULL
      AND variance_micros IS NULL
      AND source_module IS NULL
      AND source_evidence_ref IS NULL
      AND source_evidence_sha256 IS NULL
      AND audit_evidence_ref IS NULL
      AND audit_evidence_sha256 IS NULL
      AND settle_trace_id IS NULL
      AND settle_span_id IS NULL
      AND settle_parent_span_id IS NULL
      AND settle_input_traceparent IS NULL
      AND settle_output_traceparent IS NULL
      AND settle_tracestate IS NULL
      AND occurred_at IS NULL
      AND settled_at IS NULL
      AND release_idempotency_key IS NULL
      AND release_request_hash IS NULL
      AND release_output_traceparent IS NULL
      AND release_tracestate IS NULL
      AND released_at IS NULL
    )
    OR (
      state = 'SETTLED'
      AND length(settle_idempotency_key) BETWEEN 8 AND 128
      AND settle_request_hash ~ '^sha256:[0-9a-f]{64}$'
      AND length(receipt_ref) BETWEEN 3 AND 256
      AND meter_key ~ '^[a-z0-9][a-z0-9-]{7,127}$'
      AND quantity BETWEEN 0 AND max_quantity
      AND booked_cost_micros = quantity * unit_rate_micros
      AND booked_cost_micros BETWEEN 0 AND reserved_cost_micros
      AND supplier_cost_micros >= 0
      AND variance_micros = supplier_cost_micros - booked_cost_micros
      AND source_module IN ('C14', 'C16', 'C19')
      AND source_evidence_sha256 ~ '^sha256:[0-9a-f]{64}$'
      AND audit_evidence_sha256 ~ '^sha256:[0-9a-f]{64}$'
      AND settle_trace_id ~ '^[0-9a-f]{32}$'
      AND settle_trace_id <> repeat('0', 32)
      AND settle_span_id ~ '^[0-9a-f]{16}$'
      AND settle_span_id <> repeat('0', 16)
      AND settle_parent_span_id ~ '^[0-9a-f]{16}$'
      AND settle_parent_span_id <> repeat('0', 16)
      AND settle_input_traceparent
        ~ '^00-[0-9a-f]{32}-[0-9a-f]{16}-(00|01)$'
      AND substring(settle_input_traceparent FROM 4 FOR 32)
        = settle_trace_id
      AND substring(settle_input_traceparent FROM 37 FOR 16)
        = settle_parent_span_id
      AND settle_output_traceparent
        ~ '^00-[0-9a-f]{32}-[0-9a-f]{16}-(00|01)$'
      AND substring(settle_output_traceparent FROM 4 FOR 32)
        = settle_trace_id
      AND substring(settle_output_traceparent FROM 37 FOR 16)
        = settle_span_id
      AND right(settle_output_traceparent, 2)
        = right(settle_input_traceparent, 2)
      AND (
        settle_tracestate IS NULL
        OR (
          length(settle_tracestate) BETWEEN 1 AND 512
          AND settle_tracestate !~* (
            '(basic|bearer)[[:space:]]+[a-z0-9._~+/-]{4,}'
            '|(api[_-]?key|access[_-]?key|client[_-]?secret'
            '|password|secret|token)[[:space:]]*[:=]'
            '|sk-[a-z0-9_-]{8,}'
            '|gh[pousr]_[a-z0-9]{8,}'
            '|-----BEGIN [A-Z ]+PRIVATE KEY-----'
          )
        )
      )
      AND occurred_at IS NOT NULL
      AND settled_at IS NOT NULL
      AND occurred_at >= created_at
      AND settled_at >= occurred_at
      AND release_idempotency_key IS NULL
      AND release_request_hash IS NULL
      AND release_output_traceparent IS NULL
      AND release_tracestate IS NULL
      AND released_at IS NULL
    )
    OR (
      state = 'RELEASED'
      AND settle_idempotency_key IS NULL
      AND settle_request_hash IS NULL
      AND receipt_ref IS NULL
      AND meter_key IS NULL
      AND quantity IS NULL
      AND booked_cost_micros IS NULL
      AND supplier_cost_micros IS NULL
      AND variance_micros IS NULL
      AND source_module IS NULL
      AND source_evidence_ref IS NULL
      AND source_evidence_sha256 IS NULL
      AND audit_evidence_ref IS NULL
      AND audit_evidence_sha256 IS NULL
      AND settle_trace_id IS NULL
      AND settle_span_id IS NULL
      AND settle_parent_span_id IS NULL
      AND settle_input_traceparent IS NULL
      AND settle_output_traceparent IS NULL
      AND settle_tracestate IS NULL
      AND occurred_at IS NULL
      AND settled_at IS NULL
      AND length(release_idempotency_key) BETWEEN 8 AND 128
      AND release_request_hash ~ '^sha256:[0-9a-f]{64}$'
      AND release_output_traceparent
        ~ '^00-[0-9a-f]{32}-[0-9a-f]{16}-(00|01)$'
      AND (
        release_tracestate IS NULL
        OR (
          length(release_tracestate) BETWEEN 1 AND 512
          AND release_tracestate !~* (
            '(basic|bearer)[[:space:]]+[a-z0-9._~+/-]{4,}'
            '|(api[_-]?key|access[_-]?key|client[_-]?secret'
            '|password|secret|token)[[:space:]]*[:=]'
            '|sk-[a-z0-9_-]{8,}'
            '|gh[pousr]_[a-z0-9]{8,}'
            '|-----BEGIN [A-Z ]+PRIVATE KEY-----'
          )
        )
      )
      AND released_at >= created_at
    )
  )
);

CREATE TABLE aios_observability.usage_ledger (
  tenant_id text NOT NULL,
  tenant_kind text NOT NULL DEFAULT 'SYNTHETIC',
  event_id text NOT NULL,
  event_type text NOT NULL,
  reservation_id text NOT NULL,
  principal_id text NOT NULL,
  task_ref text NOT NULL,
  dimension_type text NOT NULL,
  resource_ref text NOT NULL,
  meter_type text NOT NULL,
  unit text NOT NULL,
  quantity bigint NOT NULL,
  cost_micros bigint NOT NULL,
  rate_version text NOT NULL,
  receipt_ref text,
  meter_key text,
  supplier_cost_micros bigint,
  variance_micros bigint,
  trace_id text NOT NULL,
  span_id text NOT NULL,
  occurred_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, event_id),
  UNIQUE (tenant_id, reservation_id, event_type),
  UNIQUE (tenant_id, meter_key),
  FOREIGN KEY (tenant_id, tenant_kind)
    REFERENCES aios_data.tenant_data_lifecycle (tenant_id, tenant_kind)
    ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, reservation_id)
    REFERENCES aios_observability.quota_reservation (
      tenant_id,
      reservation_id
    )
    ON DELETE RESTRICT,
  CHECK (tenant_kind = 'SYNTHETIC'),
  CHECK (
    event_id ~ '^ule_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
  ),
  CHECK (
    event_type IN (
      'QUOTA_RESERVED',
      'QUOTA_RELEASED',
      'USAGE_SETTLED'
    )
  ),
  CHECK (
    principal_id ~ '^prn_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
  ),
  CHECK (dimension_type IN ('MODEL', 'TOOL', 'SANDBOX')),
  CHECK (
    (
      dimension_type = 'MODEL'
      AND meter_type = 'MODEL_TOKEN'
      AND unit = 'TOKEN'
    )
    OR (
      dimension_type = 'TOOL'
      AND meter_type = 'TOOL_CALL'
      AND unit = 'CALL'
    )
    OR (
      dimension_type = 'SANDBOX'
      AND meter_type = 'SANDBOX_VCPU_MILLISECOND'
      AND unit = 'VCPU_MILLISECOND'
    )
  ),
  CHECK (quantity >= 0),
  CHECK (cost_micros >= 0),
  CHECK (
    (
      event_type IN ('QUOTA_RESERVED', 'QUOTA_RELEASED')
      AND receipt_ref IS NULL
      AND meter_key IS NULL
      AND supplier_cost_micros IS NULL
      AND variance_micros IS NULL
    )
    OR (
      event_type = 'USAGE_SETTLED'
      AND length(receipt_ref) BETWEEN 3 AND 256
      AND meter_key ~ '^[a-z0-9][a-z0-9-]{7,127}$'
      AND supplier_cost_micros >= 0
      AND variance_micros = supplier_cost_micros - cost_micros
    )
  ),
  CHECK (
    trace_id ~ '^[0-9a-f]{32}$'
    AND trace_id <> repeat('0', 32)
  ),
  CHECK (
    span_id ~ '^[0-9a-f]{16}$'
    AND span_id <> repeat('0', 16)
  )
);

CREATE FUNCTION aios_observability.reject_append_only_change()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
  RAISE EXCEPTION 'C19 append-only relation cannot be changed'
    USING ERRCODE = 'integrity_constraint_violation';
END;
$$;

CREATE FUNCTION aios_observability.enforce_reservation_transition()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
  IF OLD.state <> 'RESERVED'
     OR NEW.state NOT IN ('SETTLED', 'RELEASED') THEN
    RAISE EXCEPTION 'C19 reservation transition is invalid'
      USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF (
    OLD.tenant_id,
    OLD.tenant_kind,
    OLD.reservation_id,
    OLD.principal_id,
    OLD.reserve_idempotency_key,
    OLD.reserve_request_hash,
    OLD.plan_ref,
    OLD.task_ref,
    OLD.dimension_type,
    OLD.resource_ref,
    OLD.meter_type,
    OLD.unit,
    OLD.max_quantity,
    OLD.rate_version,
    OLD.unit_rate_micros,
    OLD.reserved_cost_micros,
    OLD.quota_period,
    OLD.catalog_version,
    OLD.catalog_sha256,
    OLD.reserve_trace_id,
    OLD.reserve_span_id,
    OLD.reserve_parent_span_id,
    OLD.reserve_input_traceparent,
    OLD.reserve_output_traceparent,
    OLD.reserve_tracestate,
    OLD.created_at
  ) IS DISTINCT FROM (
    NEW.tenant_id,
    NEW.tenant_kind,
    NEW.reservation_id,
    NEW.principal_id,
    NEW.reserve_idempotency_key,
    NEW.reserve_request_hash,
    NEW.plan_ref,
    NEW.task_ref,
    NEW.dimension_type,
    NEW.resource_ref,
    NEW.meter_type,
    NEW.unit,
    NEW.max_quantity,
    NEW.rate_version,
    NEW.unit_rate_micros,
    NEW.reserved_cost_micros,
    NEW.quota_period,
    NEW.catalog_version,
    NEW.catalog_sha256,
    NEW.reserve_trace_id,
    NEW.reserve_span_id,
    NEW.reserve_parent_span_id,
    NEW.reserve_input_traceparent,
    NEW.reserve_output_traceparent,
    NEW.reserve_tracestate,
    NEW.created_at
  ) THEN
    RAISE EXCEPTION 'C19 reservation binding is immutable'
      USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  RETURN NEW;
END;
$$;

CREATE FUNCTION aios_observability.enforce_quota_account_transition()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.reserved_micros <> 0
       OR NEW.consumed_micros <> 0
       OR NEW.denied_count <> 0 THEN
      RAISE EXCEPTION 'C19 quota account initial counters are invalid'
        USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
  END IF;
  IF (
    OLD.tenant_id,
    OLD.tenant_kind,
    OLD.quota_scope,
    OLD.quota_subject_id,
    OLD.principal_id,
    OLD.quota_period,
    OLD.quota_limit_micros,
    OLD.quota_threshold_basis_points
  ) IS DISTINCT FROM (
    NEW.tenant_id,
    NEW.tenant_kind,
    NEW.quota_scope,
    NEW.quota_subject_id,
    NEW.principal_id,
    NEW.quota_period,
    NEW.quota_limit_micros,
    NEW.quota_threshold_basis_points
  )
  OR NEW.updated_at < OLD.updated_at
  OR NEW.consumed_micros < OLD.consumed_micros
  OR NEW.denied_count < OLD.denied_count
  OR NOT (
    (
      NEW.reserved_micros > OLD.reserved_micros
      AND NEW.consumed_micros = OLD.consumed_micros
      AND NEW.denied_count = OLD.denied_count
    )
    OR (
      NEW.reserved_micros < OLD.reserved_micros
      AND NEW.consumed_micros >= OLD.consumed_micros
      AND NEW.denied_count = OLD.denied_count
    )
    OR (
      NEW.reserved_micros = OLD.reserved_micros
      AND NEW.consumed_micros = OLD.consumed_micros
      AND NEW.denied_count >= OLD.denied_count
    )
  ) THEN
    RAISE EXCEPTION 'C19 quota account transition is invalid'
      USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  RETURN NEW;
END;
$$;

CREATE FUNCTION aios_observability.validate_usage_ledger_event()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
  reservation aios_observability.quota_reservation%ROWTYPE;
BEGIN
  SELECT *
    INTO reservation
    FROM aios_observability.quota_reservation
   WHERE tenant_id = NEW.tenant_id
     AND reservation_id = NEW.reservation_id;
  IF NOT FOUND OR (
    NEW.task_ref,
    NEW.principal_id,
    NEW.dimension_type,
    NEW.resource_ref,
    NEW.meter_type,
    NEW.unit,
    NEW.rate_version
  ) IS DISTINCT FROM (
    reservation.task_ref,
    reservation.principal_id,
    reservation.dimension_type,
    reservation.resource_ref,
    reservation.meter_type,
    reservation.unit,
    reservation.rate_version
  ) THEN
    RAISE EXCEPTION 'C19 ledger event does not match reservation'
      USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF NEW.event_type = 'QUOTA_RESERVED' AND (
    NEW.quantity,
    NEW.cost_micros,
    NEW.trace_id,
    NEW.span_id,
    NEW.occurred_at
  ) IS DISTINCT FROM (
    reservation.max_quantity,
    reservation.reserved_cost_micros,
    reservation.reserve_trace_id,
    reservation.reserve_span_id,
    reservation.created_at
  ) THEN
    RAISE EXCEPTION 'C19 ledger event does not match reservation'
      USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF NEW.event_type = 'USAGE_SETTLED' AND (
    reservation.state <> 'SETTLED'
    OR (
      NEW.quantity,
      NEW.cost_micros,
      NEW.receipt_ref,
      NEW.meter_key,
      NEW.supplier_cost_micros,
      NEW.variance_micros,
      NEW.trace_id,
      NEW.span_id,
      NEW.occurred_at
    ) IS DISTINCT FROM (
      reservation.quantity,
      reservation.booked_cost_micros,
      reservation.receipt_ref,
      reservation.meter_key,
      reservation.supplier_cost_micros,
      reservation.variance_micros,
      reservation.settle_trace_id,
      reservation.settle_span_id,
      reservation.occurred_at
    )
  ) THEN
    RAISE EXCEPTION 'C19 ledger event does not match reservation'
      USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF NEW.event_type = 'QUOTA_RELEASED' AND (
    reservation.state <> 'RELEASED'
    OR (
      NEW.quantity,
      NEW.cost_micros,
      NEW.trace_id,
      NEW.span_id,
      NEW.occurred_at
    ) IS DISTINCT FROM (
      reservation.max_quantity,
      reservation.reserved_cost_micros,
      substring(reservation.release_output_traceparent FROM 4 FOR 32),
      substring(reservation.release_output_traceparent FROM 37 FOR 16),
      reservation.released_at
    )
  ) THEN
    RAISE EXCEPTION 'C19 ledger event does not match reservation'
      USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  RETURN NEW;
END;
$$;

CREATE FUNCTION aios_observability.validate_quota_account_balance()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
  quota_scopes text[];
  quota_subjects text[];
  scope_index integer;
  actual_reserved bigint;
  actual_consumed bigint;
  expected_reserved bigint;
  expected_consumed bigint;
BEGIN
  IF TG_TABLE_NAME = 'quota_account' THEN
    quota_scopes := ARRAY[NEW.quota_scope];
    quota_subjects := ARRAY[NEW.quota_subject_id];
  ELSE
    quota_scopes := ARRAY['TENANT', 'PRINCIPAL'];
    quota_subjects := ARRAY[NEW.tenant_id, NEW.principal_id];
  END IF;
  FOR scope_index IN 1..array_length(quota_scopes, 1)
  LOOP
    SELECT reserved_micros, consumed_micros
      INTO actual_reserved, actual_consumed
      FROM aios_observability.quota_account
     WHERE tenant_id = NEW.tenant_id
       AND quota_scope = quota_scopes[scope_index]
       AND quota_subject_id = quota_subjects[scope_index]
       AND quota_period = NEW.quota_period;
    SELECT
      COALESCE(SUM(reserved_cost_micros)
        FILTER (WHERE state = 'RESERVED'), 0),
      COALESCE(SUM(booked_cost_micros)
        FILTER (WHERE state = 'SETTLED'), 0)
      INTO expected_reserved, expected_consumed
      FROM aios_observability.quota_reservation
     WHERE tenant_id = NEW.tenant_id
       AND quota_period = NEW.quota_period
       AND (
         quota_scopes[scope_index] = 'TENANT'
         OR principal_id = quota_subjects[scope_index]
       );
    IF (
      actual_reserved,
      actual_consumed
    ) IS DISTINCT FROM (
      expected_reserved,
      expected_consumed
    ) THEN
      RAISE EXCEPTION 'C19 quota account does not reconcile'
        USING ERRCODE = 'integrity_constraint_violation';
    END IF;
  END LOOP;
  RETURN NEW;
END;
$$;

CREATE TRIGGER telemetry_signal_append_only
BEFORE UPDATE OR DELETE ON aios_observability.telemetry_signal
FOR EACH ROW EXECUTE FUNCTION
  aios_observability.reject_append_only_change();

CREATE TRIGGER usage_ledger_append_only
BEFORE UPDATE OR DELETE ON aios_observability.usage_ledger
FOR EACH ROW EXECUTE FUNCTION
  aios_observability.reject_append_only_change();

CREATE TRIGGER quota_reservation_transition
BEFORE UPDATE ON aios_observability.quota_reservation
FOR EACH ROW EXECUTE FUNCTION
  aios_observability.enforce_reservation_transition();

CREATE TRIGGER quota_account_transition
BEFORE INSERT OR UPDATE ON aios_observability.quota_account
FOR EACH ROW EXECUTE FUNCTION
  aios_observability.enforce_quota_account_transition();

CREATE CONSTRAINT TRIGGER quota_account_balance_deferred
AFTER INSERT OR UPDATE ON aios_observability.quota_account
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION
  aios_observability.validate_quota_account_balance();

CREATE CONSTRAINT TRIGGER quota_reservation_balance_deferred
AFTER INSERT OR UPDATE ON aios_observability.quota_reservation
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION
  aios_observability.validate_quota_account_balance();

CREATE TRIGGER usage_ledger_binding
BEFORE INSERT ON aios_observability.usage_ledger
FOR EACH ROW EXECUTE FUNCTION
  aios_observability.validate_usage_ledger_event();

ALTER TABLE aios_observability.telemetry_signal
  ENABLE ROW LEVEL SECURITY;
ALTER TABLE aios_observability.telemetry_signal
  FORCE ROW LEVEL SECURITY;
ALTER TABLE aios_observability.quota_account
  ENABLE ROW LEVEL SECURITY;
ALTER TABLE aios_observability.quota_account
  FORCE ROW LEVEL SECURITY;
ALTER TABLE aios_observability.quota_reservation
  ENABLE ROW LEVEL SECURITY;
ALTER TABLE aios_observability.quota_reservation
  FORCE ROW LEVEL SECURITY;
ALTER TABLE aios_observability.usage_ledger
  ENABLE ROW LEVEL SECURITY;
ALTER TABLE aios_observability.usage_ledger
  FORCE ROW LEVEL SECURITY;

COMMIT;
