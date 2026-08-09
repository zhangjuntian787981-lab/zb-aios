BEGIN;

CREATE OR REPLACE FUNCTION aios_decision.claim_effect_outbox(
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
      LEFT JOIN aios_decision.synthetic_test_decision AS decision
        ON decision.tenant_id = workflow.tenant_id
       AND decision.decision_id = workflow.decision_id
     WHERE workflow.effect_id IS NULL
        OR workflow.status <> 'QUEUED'
        OR decision.decision_id IS NULL
        OR decision.decision_sha256 <> workflow.decision_sha256
        OR decision.artifact_id <> workflow.artifact_id
        OR decision.artifact_sha256 <> workflow.artifact_sha256
        OR decision.outcome <> 'APPROVE'
        OR decision.decision ->> 'status' <> 'ACTIVE'
        OR decision.expires_at <= statement_timestamp()
        OR workflow.effect ->> 'decisionId' <> workflow.decision_id
        OR workflow.effect ->> 'decisionSha256' <>
             workflow.decision_sha256
        OR workflow.effect ->> 'artifactId' <> workflow.artifact_id
        OR workflow.effect ->> 'artifactSha256' <>
             workflow.artifact_sha256
        OR workflow.effect ->> 'effectSha256' <> workflow.effect_sha256
        OR EXISTS (
          SELECT 1
            FROM aios_decision.decision_withdrawal AS withdrawal
           WHERE withdrawal.tenant_id = workflow.tenant_id
             AND withdrawal.decision_id = workflow.decision_id
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

CREATE FUNCTION aios_decision.assert_effect_execution_authorized(
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

  PERFORM 1
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
       AND workflow.effect ->> 'effectSha256' = workflow.effect_sha256
  ) THEN
    RAISE EXCEPTION 'C15 claimed Effect binding changed'
      USING ERRCODE = '23514',
            CONSTRAINT = 'c15_claimed_effect_guard';
  END IF;

  PERFORM pg_advisory_xact_lock(
    hashtextextended(workflow.tenant_id || '|' || workflow.decision_id, 0)
  )
    FROM aios_decision.workflow_effect AS workflow
   WHERE workflow.tenant_id = p_tenant_id
     AND workflow.effect_id = p_effect_id;

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
       AND decision.expires_at > statement_timestamp()
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
  PERFORM 1
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
  PERFORM aios_decision.assert_effect_execution_authorized(
    p_tenant_id,
    p_effect_id,
    p_effect_sha256,
    p_worker_id,
    p_lease_version,
    p_lease_token
  );
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

ALTER FUNCTION aios_decision.assert_effect_execution_authorized(
  text,text,text,text,bigint,text
) OWNER TO aios_c15_owner;

REVOKE ALL ON FUNCTION aios_decision.assert_effect_execution_authorized(
  text,text,text,text,bigint,text
) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION aios_decision.assert_effect_execution_authorized(
  text,text,text,text,bigint,text
) TO aios_c15_effect_worker;

COMMIT;
