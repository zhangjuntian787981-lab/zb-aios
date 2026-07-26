BEGIN;

CREATE SCHEMA aios_orchestration;

CREATE TABLE aios_orchestration.task_state (
  tenant_id text NOT NULL,
  tenant_kind text NOT NULL,
  task_id text NOT NULL,
  human_principal_id text NOT NULL,
  workload_actor_principal_id text NOT NULL,
  version bigint NOT NULL,
  state_sha256 text NOT NULL,
  task jsonb NOT NULL,
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, task_id),
  FOREIGN KEY (tenant_id, tenant_kind)
    REFERENCES aios_data.tenant_data_lifecycle (tenant_id, tenant_kind)
    ON DELETE RESTRICT,
  CHECK (tenant_kind = 'SYNTHETIC'),
  CHECK (
    task_id ~ '^tsk_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
  ),
  CHECK (length(human_principal_id) BETWEEN 1 AND 256),
  CHECK (length(workload_actor_principal_id) BETWEEN 1 AND 256),
  CHECK (version > 0),
  CHECK (state_sha256 ~ '^sha256:[a-f0-9]{64}$'),
  CHECK (created_at <= updated_at),
  CHECK (jsonb_typeof(task) = 'object'),
  CHECK (
    (task ->> 'schemaVersion')
      IS NOT DISTINCT FROM 'c12-task-state.v1'
  ),
  CHECK ((task ->> 'tenantId') IS NOT DISTINCT FROM tenant_id),
  CHECK ((task ->> 'tenantKind') IS NOT DISTINCT FROM tenant_kind),
  CHECK ((task ->> 'taskId') IS NOT DISTINCT FROM task_id),
  CHECK (
    (task ->> 'ownerHumanPrincipalId')
      IS NOT DISTINCT FROM human_principal_id
  ),
  CHECK (
    (task ->> 'workloadActorPrincipalId')
      IS NOT DISTINCT FROM workload_actor_principal_id
  ),
  CHECK ((task ->> 'version')::bigint IS NOT DISTINCT FROM version),
  CHECK (
    (task ->> 'stateSha256') IS NOT DISTINCT FROM state_sha256
  ),
  CHECK (
    (task ->> 'createdAt')::timestamptz
      IS NOT DISTINCT FROM created_at
  ),
  CHECK (
    (task ->> 'updatedAt')::timestamptz
      IS NOT DISTINCT FROM updated_at
  )
);

CREATE TABLE aios_orchestration.command_receipt (
  tenant_id text NOT NULL,
  tenant_kind text NOT NULL,
  human_principal_id text NOT NULL,
  workload_actor_principal_id text NOT NULL,
  idempotency_key text NOT NULL,
  operation text NOT NULL,
  request_sha256 text NOT NULL,
  task_id text NOT NULL,
  result_version bigint NOT NULL,
  result_state_sha256 text NOT NULL,
  receipt_sha256 text NOT NULL,
  task jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
  PRIMARY KEY (
    tenant_id,
    human_principal_id,
    workload_actor_principal_id,
    idempotency_key
  ),
  FOREIGN KEY (tenant_id, task_id)
    REFERENCES aios_orchestration.task_state (tenant_id, task_id)
    ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, tenant_kind)
    REFERENCES aios_data.tenant_data_lifecycle (tenant_id, tenant_kind)
    ON DELETE RESTRICT,
  CHECK (tenant_kind = 'SYNTHETIC'),
  CHECK (length(human_principal_id) BETWEEN 1 AND 256),
  CHECK (length(workload_actor_principal_id) BETWEEN 1 AND 256),
  CHECK (length(idempotency_key) BETWEEN 1 AND 128),
  CHECK (
    operation IN ('START', 'ADVANCE', 'RESUME_HUMAN_DECISION')
  ),
  CHECK (request_sha256 ~ '^sha256:[a-f0-9]{64}$'),
  CHECK (
    task_id ~ '^tsk_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
  ),
  CHECK (result_version > 0),
  CHECK (result_state_sha256 ~ '^sha256:[a-f0-9]{64}$'),
  CHECK (receipt_sha256 ~ '^sha256:[a-f0-9]{64}$'),
  CHECK (jsonb_typeof(task) = 'object'),
  CHECK ((task ->> 'tenantId') IS NOT DISTINCT FROM tenant_id),
  CHECK ((task ->> 'tenantKind') IS NOT DISTINCT FROM tenant_kind),
  CHECK ((task ->> 'taskId') IS NOT DISTINCT FROM task_id),
  CHECK (
    (task ->> 'ownerHumanPrincipalId')
      IS NOT DISTINCT FROM human_principal_id
  ),
  CHECK (
    (task ->> 'workloadActorPrincipalId')
      IS NOT DISTINCT FROM workload_actor_principal_id
  ),
  CHECK (
    (task ->> 'version')::bigint
      IS NOT DISTINCT FROM result_version
  ),
  CHECK (
    (task ->> 'stateSha256')
      IS NOT DISTINCT FROM result_state_sha256
  )
);

CREATE INDEX command_receipt_task_idx
  ON aios_orchestration.command_receipt (
    tenant_id,
    task_id,
    result_version
  );

CREATE FUNCTION aios_orchestration.enforce_task_state_write()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.version <> 1 THEN
      RAISE EXCEPTION 'C12 task must start at version one'
        USING ERRCODE = '23000';
    END IF;
    RETURN NEW;
  END IF;

  IF
    NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
    OR NEW.tenant_kind IS DISTINCT FROM OLD.tenant_kind
    OR NEW.task_id IS DISTINCT FROM OLD.task_id
    OR NEW.human_principal_id IS DISTINCT FROM OLD.human_principal_id
    OR NEW.workload_actor_principal_id
      IS DISTINCT FROM OLD.workload_actor_principal_id
    OR NEW.created_at IS DISTINCT FROM OLD.created_at
    OR NEW.version <> OLD.version + 1
  THEN
    RAISE EXCEPTION 'C12 task identity or version changed'
      USING ERRCODE = '23000';
  END IF;
  RETURN NEW;
END
$$;

CREATE TRIGGER task_state_write_guard
BEFORE INSERT OR UPDATE ON aios_orchestration.task_state
FOR EACH ROW EXECUTE FUNCTION
  aios_orchestration.enforce_task_state_write();

CREATE FUNCTION aios_orchestration.reject_command_receipt_mutation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
  RAISE EXCEPTION 'C12 command receipts are append only'
    USING ERRCODE = '23000';
END
$$;

CREATE TRIGGER command_receipt_append_only
BEFORE UPDATE OR DELETE ON aios_orchestration.command_receipt
FOR EACH ROW EXECUTE FUNCTION
  aios_orchestration.reject_command_receipt_mutation();

ALTER TABLE aios_orchestration.task_state
  ENABLE ROW LEVEL SECURITY;
ALTER TABLE aios_orchestration.task_state
  FORCE ROW LEVEL SECURITY;
ALTER TABLE aios_orchestration.command_receipt
  ENABLE ROW LEVEL SECURITY;
ALTER TABLE aios_orchestration.command_receipt
  FORCE ROW LEVEL SECURITY;

COMMIT;
