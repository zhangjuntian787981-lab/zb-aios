BEGIN;

ALTER TABLE aios_decision.effect_outbox
  ADD COLUMN execution_started_at timestamptz;

ALTER TABLE aios_decision.effect_outbox
  ADD CONSTRAINT c15_effect_execution_start_time
  CHECK (
    execution_started_at IS NULL
    OR execution_started_at >= created_at
  );

CREATE FUNCTION aios_decision.guard_effect_execution_start()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
  IF TG_TABLE_NAME = 'effect_outbox' THEN
    IF NEW.execution_started_at IS NOT NULL THEN
      RAISE EXCEPTION 'C15 execution start cannot be caller supplied'
        USING ERRCODE = '23514',
              CONSTRAINT = 'c15_effect_execution_start_insert_guard';
    END IF;
    RETURN NEW;
  END IF;

  PERFORM pg_advisory_xact_lock(
    hashtextextended(NEW.tenant_id || '|' || NEW.decision_id, 0)
  );
  IF EXISTS (
    SELECT 1
      FROM aios_decision.workflow_effect AS workflow
      JOIN aios_decision.effect_outbox AS outbox
        ON outbox.tenant_id = workflow.tenant_id
       AND outbox.effect_id = workflow.effect_id
     WHERE workflow.tenant_id = NEW.tenant_id
       AND workflow.decision_id = NEW.decision_id
       AND outbox.execution_started_at IS NOT NULL
  ) THEN
    RAISE EXCEPTION 'C15 execution already started'
      USING ERRCODE = '23514',
            CONSTRAINT = 'c15_decision_execution_started_guard';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER c15_effect_execution_start_insert_guard
BEFORE INSERT ON aios_decision.effect_outbox
FOR EACH ROW EXECUTE FUNCTION
  aios_decision.guard_effect_execution_start();

CREATE TRIGGER c15_withdrawal_execution_start_guard
BEFORE INSERT ON aios_decision.decision_withdrawal
FOR EACH ROW EXECUTE FUNCTION
  aios_decision.guard_effect_execution_start();

CREATE OR REPLACE FUNCTION aios_decision.enforce_outbox_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'C15 Outbox history cannot be deleted'
      USING ERRCODE = '42501',
            CONSTRAINT = 'c15_outbox_delete_guard';
  END IF;
  IF TG_ARGV[0] = 'effect_id'
     AND OLD.status = 'PROCESSING'
     AND NEW.status = 'PROCESSING'
     AND to_jsonb(OLD) ->> 'execution_started_at' IS NULL
     AND to_jsonb(NEW) ->> 'execution_started_at' IS NOT NULL
     AND NEW.tenant_id IS NOT DISTINCT FROM OLD.tenant_id
     AND NEW.tenant_kind IS NOT DISTINCT FROM OLD.tenant_kind
     AND to_jsonb(NEW) ->> 'effect_id' IS NOT DISTINCT FROM
       to_jsonb(OLD) ->> 'effect_id'
     AND NEW.attempt_count = OLD.attempt_count
     AND NEW.lease_version = OLD.lease_version
     AND NEW.leased_by IS NOT DISTINCT FROM OLD.leased_by
     AND NEW.lease_until IS NOT DISTINCT FROM OLD.lease_until
     AND NEW.lease_proof_sha256 IS NOT DISTINCT FROM
       OLD.lease_proof_sha256
     AND NEW.available_at IS NOT DISTINCT FROM OLD.available_at
     AND NEW.published_at IS NOT DISTINCT FROM OLD.published_at
     AND NEW.last_error_code IS NOT DISTINCT FROM OLD.last_error_code
     AND NEW.created_at IS NOT DISTINCT FROM OLD.created_at
     AND (to_jsonb(NEW) ->> 'execution_started_at')::timestamptz
       <= clock_timestamp() THEN
    RETURN NEW;
  END IF;
  IF TG_ARGV[0] = 'effect_id'
     AND OLD.status = 'PROCESSING'
     AND NEW.status = 'PUBLISHED'
     AND NOT EXISTS (
       SELECT 1
         FROM aios_decision.workflow_effect AS effect
        WHERE effect.tenant_id = NEW.tenant_id
          AND effect.effect_id = to_jsonb(NEW) ->> 'effect_id'
          AND effect.status IN (
            'SUCCEEDED',
            'COMPENSATED',
            'COMPENSATION_FAILED'
          )
     ) THEN
    RAISE EXCEPTION 'C15 Effect must be terminal before publication'
      USING ERRCODE = '23514',
            CONSTRAINT = 'c15_effect_terminal_before_publish';
  END IF;
  IF TG_ARGV[0] = 'intent_id'
     AND OLD.status = 'PROCESSING'
     AND NEW.status = 'PUBLISHED'
     AND NOT EXISTS (
       SELECT 1
         FROM aios_audit.audit_command_receipt AS receipt
         JOIN aios_audit.audit_event AS event
           ON event.tenant_id = receipt.tenant_id
          AND event.event_id = receipt.event_id
        WHERE receipt.tenant_id = NEW.tenant_id
          AND receipt.idempotency_key =
            to_jsonb(NEW) ->> 'intent_id'
          AND to_jsonb(NEW) ->> 'c18_receipt_key' =
            receipt.idempotency_key
          AND to_jsonb(NEW) ->> 'c18_event_id' = event.event_id
          AND to_jsonb(NEW) ->> 'c18_event_hash' = event.event_hash
     ) THEN
    RAISE EXCEPTION 'C15 publication requires a persisted C18 receipt'
      USING ERRCODE = '23514',
            CONSTRAINT = 'c15_c18_receipt_guard';
  END IF;
  IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
     OR NEW.tenant_kind IS DISTINCT FROM OLD.tenant_kind
     OR (to_jsonb(NEW) ->> TG_ARGV[0]) IS DISTINCT FROM
       (to_jsonb(OLD) ->> TG_ARGV[0])
     OR NEW.created_at IS DISTINCT FROM OLD.created_at
     OR NEW.attempt_count < OLD.attempt_count
     OR NEW.lease_version < OLD.lease_version
     OR (
       TG_ARGV[0] = 'effect_id'
       AND (to_jsonb(NEW) ->> 'execution_started_at') IS DISTINCT FROM
         (to_jsonb(OLD) ->> 'execution_started_at')
     )
     OR (
       OLD.status IN ('PENDING', 'FAILED')
       AND NOT (
         NEW.status = 'PROCESSING'
         AND NEW.attempt_count = OLD.attempt_count + 1
         AND NEW.lease_version = OLD.lease_version + 1
         AND NEW.leased_by IS NOT NULL
         AND NEW.lease_until > statement_timestamp()
         AND NEW.available_at IS NOT DISTINCT FROM OLD.available_at
         AND NEW.published_at IS NOT DISTINCT FROM OLD.published_at
         AND NEW.last_error_code IS NULL
       )
     )
     OR (
       OLD.status = 'PROCESSING'
       AND NOT (
         (
           NEW.status = 'PROCESSING'
           AND OLD.lease_until <= statement_timestamp()
           AND NEW.attempt_count = OLD.attempt_count + 1
           AND NEW.lease_version = OLD.lease_version + 1
           AND NEW.leased_by IS NOT NULL
           AND NEW.lease_until > statement_timestamp()
           AND NEW.available_at IS NOT DISTINCT FROM OLD.available_at
           AND NEW.published_at IS NOT DISTINCT FROM OLD.published_at
           AND NEW.last_error_code IS NULL
         )
         OR (
           NEW.status = 'FAILED'
           AND NEW.attempt_count = OLD.attempt_count
           AND NEW.lease_version = OLD.lease_version
           AND NEW.available_at >= statement_timestamp()
           AND NEW.available_at <=
             statement_timestamp() + interval '1 hour'
           AND NEW.last_error_code IS NOT NULL
         )
         OR (
           NEW.status = 'PUBLISHED'
           AND NEW.attempt_count = OLD.attempt_count
           AND NEW.lease_version = OLD.lease_version
           AND NEW.available_at IS NOT DISTINCT FROM OLD.available_at
           AND NEW.published_at >= statement_timestamp()
           AND NEW.last_error_code IS NULL
         )
       )
     )
     OR OLD.status = 'PUBLISHED' THEN
    RAISE EXCEPTION 'C15 Outbox transition is invalid'
      USING ERRCODE = '23514',
            CONSTRAINT = 'c15_outbox_transition_guard';
  END IF;
  RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION
  aios_decision.claim_effect_outbox(
    p_tenant_id text,
    p_worker_id text,
    p_limit integer,
    p_lease_seconds integer
  )
RETURNS TABLE (
  tenant_id text,
  tenant_kind text,
  effect_id text,
  outbox_status text,
  attempt_count bigint,
  lease_version bigint,
  leased_by text,
  lease_until timestamptz,
  lease_token text,
  available_at timestamptz,
  published_at timestamptz,
  last_error_code text,
  outbox_created_at timestamptz,
  effect jsonb,
  status text,
  commit_receipt jsonb,
  readback_receipt jsonb,
  compensation_receipt jsonb,
  updated_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  candidate_effect_ids text[];
BEGIN
  IF aios_data.acquire_runtime_fence() IS NOT TRUE
     OR aios_data.runtime_scope_allows(
       p_tenant_id,
       'SYNTHETIC'
     ) IS NOT TRUE
     OR char_length(btrim(p_worker_id)) NOT BETWEEN 1 AND 128
     OR p_limit NOT BETWEEN 1 AND 100
     OR p_lease_seconds NOT BETWEEN 1 AND 300 THEN
    RAISE EXCEPTION 'C15 Effect claim is invalid'
      USING ERRCODE = '42501',
            CONSTRAINT = 'c15_worker_scope_guard';
  END IF;

  SELECT coalesce(
           array_agg(candidate.effect_id ORDER BY candidate.created_at,
                     candidate.effect_id),
           ARRAY[]::text[]
         )
    INTO candidate_effect_ids
    FROM (
      SELECT outbox.effect_id,
             outbox.created_at
        FROM aios_decision.effect_outbox AS outbox
       WHERE outbox.tenant_id = p_tenant_id
         AND (
           (
             outbox.status IN ('PENDING', 'FAILED')
             AND outbox.available_at <= statement_timestamp()
           )
           OR (
             outbox.status = 'PROCESSING'
             AND outbox.lease_until <= statement_timestamp()
           )
         )
       ORDER BY outbox.created_at, outbox.effect_id
       FOR UPDATE SKIP LOCKED
       LIMIT p_limit
    ) AS candidate;

  PERFORM pg_advisory_xact_lock(
    hashtextextended(workflow.tenant_id || '|' || workflow.decision_id, 0)
  )
    FROM aios_decision.workflow_effect AS workflow
   WHERE workflow.tenant_id = p_tenant_id
     AND workflow.effect_id = ANY(candidate_effect_ids);

  IF EXISTS (
    SELECT 1
      FROM unnest(candidate_effect_ids) AS candidate(effect_id)
      LEFT JOIN aios_decision.workflow_effect AS workflow
        ON workflow.tenant_id = p_tenant_id
       AND workflow.effect_id = candidate.effect_id
      LEFT JOIN aios_decision.effect_outbox AS outbox
        ON outbox.tenant_id = p_tenant_id
       AND outbox.effect_id = candidate.effect_id
      LEFT JOIN aios_decision.synthetic_test_decision AS decision
        ON decision.tenant_id = workflow.tenant_id
       AND decision.decision_id = workflow.decision_id
     WHERE workflow.effect_id IS NULL
        OR outbox.effect_id IS NULL
        OR workflow.status <> 'QUEUED'
        OR workflow.effect ->> 'decisionId' <> workflow.decision_id
        OR workflow.effect ->> 'decisionSha256' <>
             workflow.decision_sha256
        OR workflow.effect ->> 'artifactId' <> workflow.artifact_id
        OR workflow.effect ->> 'artifactSha256' <>
             workflow.artifact_sha256
        OR workflow.effect ->> 'effectSha256' <> workflow.effect_sha256
        OR (
          outbox.execution_started_at IS NULL
          AND (
            decision.decision_id IS NULL
            OR decision.decision_sha256 <> workflow.decision_sha256
            OR decision.artifact_id <> workflow.artifact_id
            OR decision.artifact_sha256 <> workflow.artifact_sha256
            OR decision.outcome <> 'APPROVE'
            OR decision.decision ->> 'status' <> 'ACTIVE'
            OR decision.expires_at <= statement_timestamp()
            OR EXISTS (
              SELECT 1
                FROM aios_decision.decision_withdrawal AS withdrawal
               WHERE withdrawal.tenant_id = workflow.tenant_id
                 AND withdrawal.decision_id = workflow.decision_id
            )
          )
        )
  ) THEN
    RAISE EXCEPTION 'C15 Decision cannot authorize Effect claim'
      USING ERRCODE = '23514',
            CONSTRAINT = 'c15_effect_decision_active_guard';
  END IF;

  RETURN QUERY
  WITH candidates AS MATERIALIZED (
    SELECT outbox.tenant_id,
           outbox.effect_id,
           gen_random_uuid()::text AS lease_token
      FROM aios_decision.effect_outbox AS outbox
     WHERE outbox.tenant_id = p_tenant_id
       AND outbox.effect_id = ANY(candidate_effect_ids)
     ORDER BY outbox.created_at, outbox.effect_id
  ),
  claimed AS (
    UPDATE aios_decision.effect_outbox AS outbox
       SET status = 'PROCESSING',
           attempt_count = outbox.attempt_count + 1,
           lease_version = outbox.lease_version + 1,
           leased_by = p_worker_id,
           lease_until = statement_timestamp()
             + make_interval(secs => p_lease_seconds),
           lease_proof_sha256 = 'sha256:' || encode(
             sha256(convert_to(candidates.lease_token, 'UTF8')),
             'hex'
           ),
           last_error_code = NULL
      FROM candidates
     WHERE outbox.tenant_id = candidates.tenant_id
       AND outbox.effect_id = candidates.effect_id
    RETURNING outbox.*, candidates.lease_token
  )
  SELECT claimed.tenant_id,
         claimed.tenant_kind,
         claimed.effect_id,
         claimed.status,
         claimed.attempt_count,
         claimed.lease_version,
         claimed.leased_by,
         claimed.lease_until,
         claimed.lease_token,
         claimed.available_at,
         claimed.published_at,
         claimed.last_error_code,
         claimed.created_at,
         workflow.effect,
         workflow.status,
         workflow.commit_receipt,
         workflow.readback_receipt,
         workflow.compensation_receipt,
         workflow.updated_at
    FROM claimed
    JOIN aios_decision.workflow_effect AS workflow
      ON workflow.tenant_id = claimed.tenant_id
     AND workflow.effect_id = claimed.effect_id
   ORDER BY claimed.created_at, claimed.effect_id;
END;
$$;

CREATE OR REPLACE FUNCTION
  aios_decision.assert_effect_execution_authorized(
    p_tenant_id text,
    p_effect_id text,
    p_effect_sha256 text,
    p_worker_id text,
    p_lease_version bigint,
    p_lease_token text
  )
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  current_execution_started_at timestamptz;
  v_execution_started_at timestamptz;
  changed_rows integer;
BEGIN
  IF aios_data.acquire_runtime_fence() IS NOT TRUE
     OR aios_data.runtime_scope_allows(
       p_tenant_id,
       'SYNTHETIC'
     ) IS NOT TRUE THEN
    RAISE EXCEPTION 'C15 Effect execution escaped scope'
      USING ERRCODE = '42501',
            CONSTRAINT = 'c15_worker_scope_guard';
  END IF;

  SELECT outbox.execution_started_at
    INTO current_execution_started_at
    FROM aios_decision.effect_outbox AS outbox
   WHERE outbox.tenant_id = p_tenant_id
     AND outbox.effect_id = p_effect_id
     AND outbox.status = 'PROCESSING'
     AND outbox.leased_by = p_worker_id
     AND outbox.lease_version = p_lease_version
     AND outbox.lease_until > clock_timestamp()
     AND outbox.lease_proof_sha256 = 'sha256:' || encode(
       sha256(convert_to(p_lease_token, 'UTF8')),
       'hex'
     )
   FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'C15 Effect lease is stale'
      USING ERRCODE = '23514',
            CONSTRAINT = 'c15_worker_lease_guard';
  END IF;

  PERFORM 1
    FROM aios_decision.workflow_effect AS workflow
   WHERE workflow.tenant_id = p_tenant_id
     AND workflow.effect_id = p_effect_id
     AND workflow.status = 'QUEUED'
   FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'C15 Effect is already terminal'
      USING ERRCODE = '23514',
            CONSTRAINT = 'c15_effect_terminal_guard';
  END IF;

  IF NOT EXISTS (
    SELECT 1
      FROM aios_decision.workflow_effect AS workflow
     WHERE workflow.tenant_id = p_tenant_id
       AND workflow.effect_id = p_effect_id
       AND workflow.effect_sha256 = p_effect_sha256
       AND workflow.effect ->> 'effectSha256' = workflow.effect_sha256
  ) THEN
    RAISE EXCEPTION 'C15 claimed Effect binding changed'
      USING ERRCODE = '23514',
            CONSTRAINT = 'c15_claimed_effect_guard';
  END IF;

  IF current_execution_started_at IS NOT NULL THEN
    RETURN;
  END IF;

  PERFORM pg_advisory_xact_lock(
    hashtextextended(workflow.tenant_id || '|' || workflow.decision_id, 0)
  )
    FROM aios_decision.workflow_effect AS workflow
   WHERE workflow.tenant_id = p_tenant_id
     AND workflow.effect_id = p_effect_id;

  PERFORM 1
    FROM aios_decision.effect_outbox AS outbox
   WHERE outbox.tenant_id = p_tenant_id
     AND outbox.effect_id = p_effect_id
     AND outbox.status = 'PROCESSING'
     AND outbox.leased_by = p_worker_id
     AND outbox.lease_version = p_lease_version
     AND outbox.lease_until > clock_timestamp()
     AND outbox.lease_proof_sha256 = 'sha256:' || encode(
       sha256(convert_to(p_lease_token, 'UTF8')),
       'hex'
     );
  IF NOT FOUND THEN
    RAISE EXCEPTION 'C15 Effect lease is stale'
      USING ERRCODE = '23514',
            CONSTRAINT = 'c15_worker_lease_guard';
  END IF;

  v_execution_started_at := clock_timestamp();
  IF NOT EXISTS (
    SELECT 1
      FROM aios_decision.workflow_effect AS workflow
      JOIN aios_decision.synthetic_test_decision AS decision
        ON decision.tenant_id = workflow.tenant_id
       AND decision.decision_id = workflow.decision_id
     WHERE workflow.tenant_id = p_tenant_id
       AND workflow.effect_id = p_effect_id
       AND decision.decision_sha256 = workflow.decision_sha256
       AND decision.artifact_id = workflow.artifact_id
       AND decision.artifact_sha256 = workflow.artifact_sha256
       AND decision.outcome = 'APPROVE'
       AND decision.decision ->> 'status' = 'ACTIVE'
       AND decision.expires_at > v_execution_started_at
       AND workflow.effect ->> 'decisionId' = workflow.decision_id
       AND workflow.effect ->> 'decisionSha256' =
             workflow.decision_sha256
       AND workflow.effect ->> 'artifactId' = workflow.artifact_id
       AND workflow.effect ->> 'artifactSha256' =
             workflow.artifact_sha256
       AND NOT EXISTS (
         SELECT 1
           FROM aios_decision.decision_withdrawal AS withdrawal
          WHERE withdrawal.tenant_id = workflow.tenant_id
            AND withdrawal.decision_id = workflow.decision_id
       )
  ) THEN
    RAISE EXCEPTION 'C15 Decision cannot authorize Effect execution'
      USING ERRCODE = '23514',
            CONSTRAINT = 'c15_effect_decision_active_guard';
  END IF;

  UPDATE aios_decision.effect_outbox AS outbox
     SET execution_started_at = v_execution_started_at
   WHERE outbox.tenant_id = p_tenant_id
     AND outbox.effect_id = p_effect_id
     AND outbox.execution_started_at IS NULL;
  GET DIAGNOSTICS changed_rows = ROW_COUNT;
  IF changed_rows <> 1 THEN
    RAISE EXCEPTION 'C15 Effect execution start conflicted'
      USING ERRCODE = '23514',
            CONSTRAINT = 'c15_outbox_transition_guard';
  END IF;
END;
$$;

CREATE OR REPLACE FUNCTION aios_decision.complete_effect(
  p_tenant_id text,
  p_effect_id text,
  p_effect_sha256 text,
  p_worker_id text,
  p_lease_version bigint,
  p_lease_token text,
  p_terminal_status text,
  p_commit_receipt jsonb,
  p_readback_receipt jsonb,
  p_compensation_receipt jsonb,
  p_audit_intent_id text
)
RETURNS SETOF aios_decision.workflow_effect
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  changed_rows integer;
  current_execution_started_at timestamptz;
BEGIN
  IF aios_data.acquire_runtime_fence() IS NOT TRUE
     OR aios_data.runtime_scope_allows(
       p_tenant_id,
       'SYNTHETIC'
     ) IS NOT TRUE THEN
    RAISE EXCEPTION 'C15 Effect completion escaped scope'
      USING ERRCODE = '42501',
            CONSTRAINT = 'c15_worker_scope_guard';
  END IF;

  SELECT outbox.execution_started_at
    INTO current_execution_started_at
    FROM aios_decision.effect_outbox AS outbox
   WHERE outbox.tenant_id = p_tenant_id
     AND outbox.effect_id = p_effect_id
     AND outbox.status = 'PROCESSING'
     AND outbox.leased_by = p_worker_id
     AND outbox.lease_version = p_lease_version
     AND outbox.lease_until > statement_timestamp()
     AND outbox.lease_proof_sha256 = 'sha256:' || encode(
       sha256(convert_to(p_lease_token, 'UTF8')),
       'hex'
     )
   FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'C15 Effect lease is stale'
      USING ERRCODE = '23514',
            CONSTRAINT = 'c15_worker_lease_guard';
  END IF;
  PERFORM 1
    FROM aios_decision.workflow_effect AS workflow
   WHERE workflow.tenant_id = p_tenant_id
     AND workflow.effect_id = p_effect_id
     AND workflow.status = 'QUEUED'
   FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'C15 Effect is already terminal'
      USING ERRCODE = '23514',
            CONSTRAINT = 'c15_effect_terminal_guard';
  END IF;
  IF NOT EXISTS (
    SELECT 1
      FROM aios_decision.workflow_effect AS workflow
     WHERE workflow.tenant_id = p_tenant_id
       AND workflow.effect_id = p_effect_id
       AND workflow.effect_sha256 = p_effect_sha256
  ) THEN
    RAISE EXCEPTION 'C15 claimed Effect binding changed'
      USING ERRCODE = '23514',
            CONSTRAINT = 'c15_claimed_effect_guard';
  END IF;
  IF current_execution_started_at IS NULL THEN
    RAISE EXCEPTION 'C15 Effect execution has not started'
      USING ERRCODE = '23514',
            CONSTRAINT = 'c15_effect_terminal_guard';
  END IF;
  IF p_terminal_status NOT IN (
       'SUCCEEDED',
       'COMPENSATED',
       'COMPENSATION_FAILED'
     )
     OR NOT EXISTS (
       SELECT 1
         FROM aios_decision.audit_intent AS intent
         JOIN aios_decision.workflow_effect AS workflow
           ON workflow.tenant_id = intent.tenant_id
          AND workflow.effect_id = p_effect_id
        WHERE intent.tenant_id = p_tenant_id
          AND intent.intent_id = p_audit_intent_id
          AND intent.event_type =
            'SYNTHETIC_EFFECT_' || p_terminal_status
          AND intent.subject_id = workflow.effect_id
          AND intent.subject_sha256 = workflow.effect_sha256
          AND intent.metadata ->> 'artifactId' = workflow.artifact_id
          AND intent.metadata ->> 'artifactSha256' =
            workflow.artifact_sha256
          AND intent.metadata ->> 'decisionId' = workflow.decision_id
          AND intent.metadata ->> 'decisionSha256' =
            workflow.decision_sha256
          AND intent.metadata ->> 'effectId' = workflow.effect_id
          AND intent.metadata ->> 'effectKey' = workflow.effect_key
     ) THEN
    RAISE EXCEPTION 'C15 terminal Audit Intent is not bound'
      USING ERRCODE = '23514',
            CONSTRAINT = 'c15_effect_audit_binding_guard';
  END IF;

  UPDATE aios_decision.workflow_effect AS workflow
     SET status = p_terminal_status,
         commit_receipt = p_commit_receipt,
         readback_receipt = p_readback_receipt,
         compensation_receipt = p_compensation_receipt,
         terminal_audit_intent_id = p_audit_intent_id,
         updated_at = statement_timestamp()
   WHERE workflow.tenant_id = p_tenant_id
     AND workflow.effect_id = p_effect_id
     AND workflow.status = 'QUEUED';
  GET DIAGNOSTICS changed_rows = ROW_COUNT;
  IF changed_rows <> 1 THEN
    RAISE EXCEPTION 'C15 Effect is already terminal'
      USING ERRCODE = '23514',
            CONSTRAINT = 'c15_effect_terminal_guard';
  END IF;

  UPDATE aios_decision.effect_outbox AS outbox
     SET status = 'PUBLISHED',
         leased_by = NULL,
         lease_until = NULL,
         lease_proof_sha256 = NULL,
         published_at = statement_timestamp(),
         last_error_code = NULL
   WHERE outbox.tenant_id = p_tenant_id
     AND outbox.effect_id = p_effect_id
     AND outbox.status = 'PROCESSING'
     AND outbox.leased_by = p_worker_id
     AND outbox.lease_version = p_lease_version
     AND EXISTS (
       SELECT 1
         FROM aios_decision.workflow_effect AS workflow
        WHERE workflow.tenant_id = outbox.tenant_id
          AND workflow.effect_id = outbox.effect_id
          AND workflow.status IN (
            'SUCCEEDED',
            'COMPENSATED',
            'COMPENSATION_FAILED'
          )
     );
  GET DIAGNOSTICS changed_rows = ROW_COUNT;
  IF changed_rows <> 1 THEN
    RAISE EXCEPTION 'C15 Effect lease is stale'
      USING ERRCODE = '23514',
            CONSTRAINT = 'c15_worker_lease_guard';
  END IF;

  RETURN QUERY
  SELECT workflow.*
    FROM aios_decision.workflow_effect AS workflow
   WHERE workflow.tenant_id = p_tenant_id
     AND workflow.effect_id = p_effect_id;
END;
$$;

ALTER FUNCTION aios_decision.guard_effect_execution_start()
  OWNER TO aios_c15_owner;

REVOKE ALL ON FUNCTION aios_decision.guard_effect_execution_start()
  FROM PUBLIC;

COMMIT;
