import { randomUUID } from "node:crypto";
import {
  HumanDecisionWorkflowError,
  assertC15EffectCompletion,
  assertAuditIntentMetadataOnly,
  assertSyntheticHumanDecisionPayload,
  humanDecisionSha256,
} from "./human-decision-workflow.mjs";

const SAFE_IDENTIFIER = /^[a-z_][a-z0-9_]*$/;
const SYNTHETIC_TENANT_ID =
  /^stn_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SHA256 = /^sha256:[a-f0-9]{64}$/;
const RETRYABLE = new Set(["40001", "40P01"]);
const IDEMPOTENCY_UNIQUES = new Set([
  "command_receipt_pkey",
  "draft_artifact_tenant_id_created_by_idempotency_key_key",
  "synthetic_test_decision_tenant_id_created_by_idempotency_key_key",
  "decision_withdrawal_tenant_id_created_by_idempotency_key_key",
  "workflow_effect_tenant_id_created_by_idempotency_key_key",
]);
const ROLE_NAMES = Object.freeze([
  "aios_c15_runtime",
  "aios_c15_effect_worker",
  "aios_c15_audit_worker",
  "aios_c15_recovery_reader",
  "aios_c15_owner",
  "aios_c07_scope_runtime",
  "aios_c07_data_runtime",
  "aios_c07_lifecycle_runtime",
  "aios_c07_restore_runtime",
  "aios_c07_owner",
]);

export class PostgresHumanDecisionStoreError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "PostgresHumanDecisionStoreError";
    this.code = code;
  }
}

function fail(code, message) {
  throw new PostgresHumanDecisionStoreError(code, message);
}

function json(value) {
  return typeof value === "string" ? JSON.parse(value) : value;
}

function instant(value) {
  return value instanceof Date ? value.toISOString() : value;
}

function safeInteger(value) {
  const number = Number(value);
  if (!Number.isSafeInteger(number)) {
    fail("STORE_UNAVAILABLE", "PostgreSQL returned an unsafe integer.");
  }
  return number;
}

function clone(value) {
  return value === undefined ? undefined : structuredClone(value);
}

function validateScope(scope) {
  if (
    scope?.trustSource !== "C07_VERIFIED_TENANT_SCOPE" ||
    scope?.tenantKind !== "SYNTHETIC" ||
    !SYNTHETIC_TENANT_ID.test(scope?.tenantId ?? "") ||
    !Number.isSafeInteger(scope?.lifecycleVersion) ||
    scope.lifecycleVersion < 1 ||
    typeof scope?.correlationId !== "string" ||
    !scope.correlationId ||
    typeof scope?.decisionId !== "string" ||
    !scope.decisionId ||
    typeof scope?.evidenceRef !== "string" ||
    !scope.evidenceRef ||
    typeof scope?.policyVersion !== "string" ||
    !scope.policyVersion
  ) {
    fail("TENANT_SCOPE_VIOLATION", "C15 requires a C07 Tenant scope.");
  }
  return scope;
}

function validateBase(command, operation) {
  if (
    command?.tenantId === undefined ||
    command.tenantId !== command?.auditIntent?.tenantId ||
    command.operation !== operation ||
    typeof command.idempotencyKey !== "string" ||
    !command.idempotencyKey ||
    command.idempotencyKey.length > 128 ||
    !SHA256.test(command.requestHash ?? "")
  ) {
    fail("INVALID_INPUT", "C15 command metadata is invalid.");
  }
  assertAuditIntentMetadataOnly(command.auditIntent);
}

function without(value, field) {
  const body = clone(value);
  delete body[field];
  return body;
}

function validateArtifactCommand(command) {
  validateBase(command, "PREPARE");
  const value = command.artifact;
  if (
    value?.tenantId !== command.tenantId ||
    value?.tenantKind !== "SYNTHETIC" ||
    value?.schemaVersion !== "c15-draft-artifact.v1" ||
    value?.artifactKind !== "SYNTHETIC_DRAFT" ||
    value?.candidate?.operationId !== "SYNTHETIC_PREVIEW_EFFECT" ||
    !SHA256.test(value?.artifactSha256 ?? "") ||
    humanDecisionSha256(without(value, "artifactSha256")) !==
      value.artifactSha256
  ) {
    fail("INTEGRITY_VIOLATION", "C15 DraftArtifact is invalid.");
  }
  assertSyntheticHumanDecisionPayload(value);
}

function validateDecisionCommand(command) {
  validateBase(command, "DECIDE");
  const value = command.decision;
  if (
    value?.tenantId !== command.tenantId ||
    value?.tenantKind !== "SYNTHETIC" ||
    value?.schemaVersion !== "c15-synthetic-test-decision.v1" ||
    value?.decisionType !== "SYNTHETIC_TEST_DECISION" ||
    value?.outcome !== "APPROVE" ||
    value?.status !== "ACTIVE" ||
    value?.productionReusable !== false ||
    value?.externalEffectCount !== 0 ||
    !SHA256.test(value?.decisionSha256 ?? "") ||
    humanDecisionSha256(without(value, "decisionSha256")) !==
      value.decisionSha256
  ) {
    fail("INTEGRITY_VIOLATION", "C15 Synthetic Test Decision is invalid.");
  }
  assertSyntheticHumanDecisionPayload(value);
}

function validateEffectCommand(command) {
  validateBase(command, "EXECUTE");
  const value = command.effect;
  if (
    value?.tenantId !== command.tenantId ||
    value?.tenantKind !== "SYNTHETIC" ||
    value?.schemaVersion !== "c15-synthetic-effect.v1" ||
    value?.operationId !== "SYNTHETIC_PREVIEW_EFFECT" ||
    value?.status !== "QUEUED" ||
    value?.externalEffectCount !== 0 ||
    !SHA256.test(value?.effectSha256 ?? "") ||
    humanDecisionSha256(without(value, "effectSha256")) !==
      value.effectSha256
  ) {
    fail("INTEGRITY_VIOLATION", "C15 Synthetic effect is invalid.");
  }
  assertSyntheticHumanDecisionPayload(value);
}

function artifactFromRow(row, replayed = false) {
  if (!row) return null;
  return Object.freeze({ ...clone(json(row.artifact)), replayed });
}

function decisionFromRow(row, replayed = false) {
  if (!row) return null;
  const value = clone(json(row.decision));
  if (row.withdrawn_at) {
    value.status = "WITHDRAWN";
    value.withdrawnAt = instant(row.withdrawn_at);
    value.withdrawalAuthorization = clone(
      json(row.withdrawal_authorization),
    );
  }
  return Object.freeze({ ...value, replayed });
}

function effectFromRow(row, replayed = false) {
  if (!row) return null;
  const value = clone(json(row.effect));
  value.status = row.status;
  value.commitReceipt = clone(json(row.commit_receipt));
  value.readbackReceipt = clone(json(row.readback_receipt));
  value.compensationReceipt = clone(json(row.compensation_receipt));
  value.updatedAt = instant(row.updated_at);
  return Object.freeze({ ...value, replayed });
}

function effectOutboxFromRow(row) {
  return Object.freeze({
    tenantId: row.tenant_id,
    tenantKind: row.tenant_kind,
    effectId: row.effect_id,
    status: row.outbox_status ?? row.status,
    attemptCount: safeInteger(row.attempt_count),
    leaseVersion: safeInteger(row.lease_version),
    leasedBy: row.leased_by,
    leaseUntil: instant(row.lease_until),
    availableAt: instant(row.available_at),
    publishedAt: instant(row.published_at),
    lastErrorCode: row.last_error_code,
    createdAt: instant(row.outbox_created_at ?? row.created_at),
    ...(row.effect ? { effect: effectFromRow(row) } : {}),
  });
}

function auditIntentFromRow(row) {
  if (!row) return null;
  return Object.freeze({
    ...clone(json(row.metadata)),
    intentSha256: row.intent_sha256,
    createdAt: instant(row.intent_created_at ?? row.created_at),
  });
}

function auditOutboxFromRow(row) {
  return Object.freeze({
    tenantId: row.tenant_id,
    tenantKind: row.tenant_kind,
    intentId: row.intent_id,
    status: row.outbox_status ?? row.status,
    attemptCount: safeInteger(row.attempt_count),
    leaseVersion: safeInteger(row.lease_version),
    leasedBy: row.leased_by,
    leaseUntil: instant(row.lease_until),
    availableAt: instant(row.available_at),
    publishedAt: instant(row.published_at),
    lastErrorCode: row.last_error_code,
    createdAt: instant(row.outbox_created_at ?? row.created_at),
    ...(row.metadata ? { intent: auditIntentFromRow(row) } : {}),
  });
}

function databaseFailure(error) {
  if (
    error instanceof PostgresHumanDecisionStoreError ||
    error instanceof HumanDecisionWorkflowError
  ) {
    return error;
  }
  if (
    [
      "c15_append_only_guard",
      "c15_effect_delete_guard",
      "c15_outbox_delete_guard",
    ].includes(error?.constraint)
  ) {
    return new PostgresHumanDecisionStoreError(
      "APPEND_ONLY_VIOLATION",
      "C15 frozen history cannot be changed.",
    );
  }
  if (error?.code === "42501") {
    return new PostgresHumanDecisionStoreError(
      "TENANT_SCOPE_VIOLATION",
      "PostgreSQL rejected C15 Tenant scope or immutable history.",
    );
  }
  if (error?.constraint === "c15_effect_transition_guard") {
    return new PostgresHumanDecisionStoreError(
      "STALE_EFFECT",
      "C15 effect transition is stale.",
    );
  }
  if (error?.constraint === "c15_outbox_transition_guard") {
    return new PostgresHumanDecisionStoreError(
      "STALE_OUTBOX_LEASE",
      "C15 Outbox transition is stale.",
    );
  }
  if (
    error?.code === "23505" &&
    error?.constraint ===
      "workflow_effect_tenant_id_effect_key_key"
  ) {
    return new PostgresHumanDecisionStoreError(
      "EFFECT_KEY_CONFLICT",
      "C15 effect key already exists.",
    );
  }
  if (["23503", "23514", "23000"].includes(error?.code)) {
    return new PostgresHumanDecisionStoreError(
      "INTEGRITY_VIOLATION",
      "C15 PostgreSQL invariant failed.",
    );
  }
  return new PostgresHumanDecisionStoreError(
    "STORE_UNAVAILABLE",
    "C15 PostgreSQL storage operation failed.",
  );
}

async function rollback(client) {
  try {
    await client.query("ROLLBACK");
  } catch {
    // Preserve the first failure.
  }
}

export function createPostgresHumanDecisionStore({
  runtimePool,
  effectWorkerPool,
  auditWorkerPool,
  recoveryPool,
  scopePool,
  schema = "aios_decision",
  scopeSchema = "aios_data",
  maxSerializableRetries = 10,
}) {
  if (
    typeof runtimePool?.connect !== "function" ||
    typeof effectWorkerPool?.connect !== "function" ||
    typeof auditWorkerPool?.connect !== "function" ||
    typeof recoveryPool?.connect !== "function" ||
    typeof scopePool?.connect !== "function" ||
    new Set([
      runtimePool,
      effectWorkerPool,
      auditWorkerPool,
      recoveryPool,
      scopePool,
    ]).size !== 5 ||
    !SAFE_IDENTIFIER.test(schema) ||
    !SAFE_IDENTIFIER.test(scopeSchema) ||
    !Number.isSafeInteger(maxSerializableRetries) ||
    maxSerializableRetries < 0 ||
    maxSerializableRetries > 10
  ) {
    fail("INVALID_CONFIGURATION", "C15 PostgreSQL pools are invalid.");
  }
  const table = (name) => `"${schema}"."${name}"`;
  const signer =
    `"${scopeSchema}"."issue_runtime_scope_signature"`;
  const fence = `"${scopeSchema}"."acquire_runtime_fence"`;

  async function connect(pool, requiredRole) {
    let client;
    try {
      client = await pool.connect();
      const checks = ROLE_NAMES.map(
        (role, index) =>
          `pg_has_role(identity.current_name, '${role}', 'MEMBER')
             AS current_role_${index},
           pg_has_role(identity.session_name, '${role}', 'MEMBER')
             AS session_role_${index}`,
      ).join(",\n");
      const result = await client.query(
        `WITH identity AS (
           SELECT current_user::text AS current_name,
                  session_user::text AS session_name
         )
         SELECT identity.*,
                active.rolsuper AS current_super,
                active.rolbypassrls AS current_bypassrls,
                login.rolsuper AS session_super,
                login.rolbypassrls AS session_bypassrls,
                ${checks}
           FROM identity
           JOIN pg_roles AS active ON active.rolname=identity.current_name
           JOIN pg_roles AS login ON login.rolname=identity.session_name`,
      );
      const row = result.rows[0];
      const expected = ROLE_NAMES.indexOf(requiredRole);
      if (
        !row ||
        expected < 0 ||
        row.current_super ||
        row.current_bypassrls ||
        row.session_super ||
        row.session_bypassrls ||
        ROLE_NAMES.some(
          (_role, index) =>
            row[`current_role_${index}`] !== (index === expected) ||
            row[`session_role_${index}`] !== (index === expected),
        )
      ) {
        client.release(
          new Error("C15 rejected an unsafe PostgreSQL role."),
        );
        client = null;
        fail(
          "INVALID_CONFIGURATION",
          "C15 PostgreSQL pool role is unsafe.",
        );
      }
      return client;
    } catch (error) {
      if (client) {
        client.release(
          new Error("C15 could not verify the PostgreSQL role."),
        );
      }
      throw error;
    }
  }

  async function assertScopeCleared(client) {
    const result = await client.query(
      `SELECT current_setting('aios.tenant_id', true) AS tenant_id,
              current_setting('aios.tenant_kind', true) AS tenant_kind,
              current_setting('aios.lifecycle_version', true)
                AS lifecycle_version,
              current_setting('aios.correlation_id', true)
                AS correlation_id,
              current_setting('aios.decision_id', true) AS decision_id,
              current_setting('aios.evidence_ref', true) AS evidence_ref,
              current_setting('aios.policy_version', true)
                AS policy_version,
              current_setting('aios.scope_signature', true)
                AS scope_signature`,
    );
    if (
      Object.values(result.rows[0]).some(
        (value) => value !== null && value !== "",
      )
    ) {
      fail(
        "CONNECTION_CONTEXT_LEAK",
        "C15 PostgreSQL connection retained Tenant scope.",
      );
    }
  }

  async function signScope(scope, backendPid, transactionId) {
    const client = await connect(scopePool, "aios_c07_scope_runtime");
    try {
      const nonce = randomUUID();
      const result = await client.query(
        `SELECT ${signer}(
           $1,$2,$3,$4,$5,$6,$7,$8,$9::xid8,15,$10::uuid
         ) AS signed_scope`,
        [
          scope.tenantId,
          scope.tenantKind,
          scope.lifecycleVersion,
          scope.correlationId,
          scope.decisionId,
          scope.evidenceRef,
          scope.policyVersion,
          backendPid,
          transactionId,
          nonce,
        ],
      );
      const signed = json(result.rows[0]?.signed_scope);
      if (
        !/^[a-f0-9]{64}$/.test(signed?.signature ?? "") ||
        !Number.isSafeInteger(Number(signed?.expires_epoch_ms))
      ) {
        fail("TENANT_SCOPE_VIOLATION", "C07 scope signature is invalid.");
      }
      return {
        nonce,
        expiresEpochMs: String(signed.expires_epoch_ms),
        signature: signed.signature,
      };
    } finally {
      client.release();
    }
  }

  async function runScoped(pool, role, scope, begin, reducer) {
    const client = await connect(pool, role);
    let started = false;
    let discard = false;
    try {
      await client.query(begin);
      started = true;
      const transaction = await client.query(
        `SELECT pg_backend_pid() AS backend_pid,
                pg_current_xact_id()::text AS transaction_id`,
      );
      const backendPid = transaction.rows[0].backend_pid;
      const transactionId = transaction.rows[0].transaction_id;
      const signed = await signScope(scope, backendPid, transactionId);
      await client.query(
        `SELECT set_config('aios.tenant_id',$1,true),
                set_config('aios.tenant_kind',$2,true),
                set_config('aios.lifecycle_version',$3,true),
                set_config('aios.correlation_id',$4,true),
                set_config('aios.decision_id',$5,true),
                set_config('aios.evidence_ref',$6,true),
                set_config('aios.policy_version',$7,true),
                set_config('aios.backend_pid',$8,true),
                set_config('aios.transaction_id',$9,true),
                set_config('aios.expires_epoch_ms',$10,true),
                set_config('aios.scope_nonce',$11,true),
                set_config('aios.scope_signature',$12,true)`,
        [
          scope.tenantId,
          scope.tenantKind,
          String(scope.lifecycleVersion),
          scope.correlationId,
          scope.decisionId,
          scope.evidenceRef,
          scope.policyVersion,
          String(backendPid),
          transactionId,
          signed.expiresEpochMs,
          signed.nonce,
          signed.signature,
        ],
      );
      const acquired = await client.query(
        `SELECT ${fence}() AS acquired`,
      );
      if (acquired.rows[0]?.acquired !== true) {
        fail(
          "TENANT_SCOPE_VIOLATION",
          "C15 PostgreSQL Tenant fence was not acquired.",
        );
      }
      const value = await reducer(client);
      await client.query("COMMIT");
      started = false;
      await assertScopeCleared(client);
      return value;
    } catch (error) {
      if (started) await rollback(client);
      try {
        await assertScopeCleared(client);
      } catch {
        discard = true;
      }
      throw error;
    } finally {
      client.release(
        discard
          ? new Error("C15 discarded a scoped PostgreSQL connection.")
          : undefined,
      );
    }
  }

  async function insertAudit(client, audit) {
    const createdAt = audit.occurredAt;
    await client.query(
      `INSERT INTO ${table("audit_intent")} (
         tenant_id,tenant_kind,intent_id,event_type,subject_id,
         subject_sha256,intent_sha256,metadata,created_at
       ) VALUES (
         $1,'SYNTHETIC',$2,$3,$4,$5,$6,$7::jsonb,$8::timestamptz
       )`,
      [
        audit.tenantId,
        audit.intentId,
        audit.eventType,
        audit.subjectId,
        audit.subjectSha256,
        humanDecisionSha256(audit),
        JSON.stringify(audit),
        createdAt,
      ],
    );
    await client.query(
      `INSERT INTO ${table("audit_outbox")} (
         tenant_id,tenant_kind,intent_id,status,attempt_count,
         lease_version,leased_by,lease_until,available_at,published_at,
         last_error_code,created_at
       ) VALUES (
         $1,'SYNTHETIC',$2,'PENDING',0,0,NULL,NULL,
         $3::timestamptz,NULL,NULL,$3::timestamptz
       )`,
      [audit.tenantId, audit.intentId, createdAt],
    );
  }

  async function insertReceipt(
    client,
    command,
    subjectId,
    response,
  ) {
    await client.query(
      `INSERT INTO ${table("command_receipt")} (
         tenant_id,tenant_kind,idempotency_key,operation,request_hash,
         subject_id,audit_intent_id,response,created_at
       ) VALUES (
         $1,'SYNTHETIC',$2,$3,$4,$5,$6,$7::jsonb,$8::timestamptz
       )`,
      [
        command.tenantId,
        command.idempotencyKey,
        command.operation,
        command.requestHash,
        subjectId,
        command.auditIntent.intentId,
        JSON.stringify(response),
        command.auditIntent.occurredAt,
      ],
    );
  }

  async function writeCommand(scope, command, reducer, view) {
    const trusted = validateScope(scope);
    if (command.tenantId !== trusted.tenantId) {
      fail("TENANT_SCOPE_VIOLATION", "C15 command escaped Tenant scope.");
    }
    for (let attempt = 0; ; attempt += 1) {
      try {
        return await runScoped(
          runtimePool,
          "aios_c15_runtime",
          trusted,
          "BEGIN ISOLATION LEVEL SERIALIZABLE",
          async (client) => {
            const prior = await client.query(
              `SELECT operation,request_hash,response
                 FROM ${table("command_receipt")}
                WHERE tenant_id=$1 AND idempotency_key=$2`,
              [trusted.tenantId, command.idempotencyKey],
            );
            if (prior.rowCount === 1) {
              if (
                prior.rows[0].operation !== command.operation ||
                prior.rows[0].request_hash !== command.requestHash
              ) {
                fail(
                  "IDEMPOTENCY_CONFLICT",
                  "C15 idempotency key was reused.",
                );
              }
              return view({ response: json(prior.rows[0].response) }, true);
            }
            return reducer(client);
          },
        );
      } catch (error) {
        if (
          attempt < maxSerializableRetries &&
          (RETRYABLE.has(error?.code) ||
            (error?.code === "23505" &&
              IDEMPOTENCY_UNIQUES.has(error?.constraint)))
        ) {
          continue;
        }
        throw databaseFailure(error);
      }
    }
  }

  function responseArtifact(row, replayed) {
    return replayed
      ? Object.freeze({ ...clone(json(row.response)), replayed: true })
      : artifactFromRow(row);
  }
  function responseDecision(row, replayed) {
    return replayed
      ? Object.freeze({ ...clone(json(row.response)), replayed: true })
      : decisionFromRow(row);
  }
  function responseEffect(row, replayed) {
    return replayed
      ? Object.freeze({ ...clone(json(row.response)), replayed: true })
      : effectFromRow(row);
  }

  async function createArtifact(scope, command) {
    validateArtifactCommand(command);
    return writeCommand(
      scope,
      command,
      async (client) => {
        await insertAudit(client, command.auditIntent);
        const value = command.artifact;
        const result = await client.query(
          `INSERT INTO ${table("draft_artifact")} (
             tenant_id,tenant_kind,artifact_id,artifact_sha256,
             workflow_ref,workflow_version,binding_sha256,artifact,
             created_by_idempotency_key,created_audit_intent_id,created_at
           ) VALUES (
             $1,'SYNTHETIC',$2,$3,$4,$5,$6,$7::jsonb,$8,$9,
             $10::timestamptz
           )
           RETURNING *`,
          [
            command.tenantId,
            value.artifactId,
            value.artifactSha256,
            value.workflowRef,
            value.workflowVersion,
            value.bindingSha256,
            JSON.stringify(value),
            command.idempotencyKey,
            command.auditIntent.intentId,
            value.createdAt,
          ],
        );
        await insertReceipt(
          client,
          command,
          value.artifactId,
          value,
        );
        return artifactFromRow(result.rows[0]);
      },
      responseArtifact,
    );
  }

  async function getArtifact(scope, artifactId) {
    const trusted = validateScope(scope);
    try {
      return await runScoped(
        runtimePool,
        "aios_c15_runtime",
        trusted,
        "BEGIN",
        async (client) => {
          const result = await client.query(
            `SELECT * FROM ${table("draft_artifact")}
              WHERE tenant_id=$1 AND artifact_id=$2`,
            [trusted.tenantId, artifactId],
          );
          return artifactFromRow(result.rows[0]);
        },
      );
    } catch (error) {
      throw databaseFailure(error);
    }
  }

  async function createDecision(scope, command) {
    validateDecisionCommand(command);
    return writeCommand(
      scope,
      command,
      async (client) => {
        const value = command.decision;
        const artifact = await client.query(
          `SELECT artifact_sha256
             FROM ${table("draft_artifact")}
            WHERE tenant_id=$1 AND artifact_id=$2`,
          [command.tenantId, value.artifactId],
        );
        if (
          artifact.rowCount !== 1 ||
          artifact.rows[0].artifact_sha256 !== value.artifactSha256
        ) {
          fail("INTEGRITY_VIOLATION", "Decision Artifact is missing.");
        }
        await insertAudit(client, command.auditIntent);
        const result = await client.query(
          `INSERT INTO ${table("synthetic_test_decision")} (
             tenant_id,tenant_kind,decision_id,decision_sha256,
             artifact_id,artifact_sha256,outcome,decision,
             created_by_idempotency_key,created_audit_intent_id,
             decided_at,expires_at
           ) VALUES (
             $1,'SYNTHETIC',$2,$3,$4,$5,'APPROVE',$6::jsonb,$7,$8,
             $9::timestamptz,$10::timestamptz
           )
           RETURNING *,NULL::timestamptz AS withdrawn_at,
                     NULL::jsonb AS withdrawal_authorization`,
          [
            command.tenantId,
            value.decisionId,
            value.decisionSha256,
            value.artifactId,
            value.artifactSha256,
            JSON.stringify(value),
            command.idempotencyKey,
            command.auditIntent.intentId,
            value.decidedAt,
            value.expiresAt,
          ],
        );
        await insertReceipt(
          client,
          command,
          value.decisionId,
          value,
        );
        return decisionFromRow(result.rows[0]);
      },
      responseDecision,
    );
  }

  async function selectDecision(client, tenantId, decisionId, lock = "") {
    return client.query(
      `SELECT decision.*,
              withdrawal.withdrawn_at,
              withdrawal.withdrawal_authorization
         FROM ${table("synthetic_test_decision")} AS decision
         LEFT JOIN ${table("decision_withdrawal")} AS withdrawal
           ON withdrawal.tenant_id=decision.tenant_id
          AND withdrawal.decision_id=decision.decision_id
        WHERE decision.tenant_id=$1 AND decision.decision_id=$2
        ${lock}`,
      [tenantId, decisionId],
    );
  }

  async function getDecision(scope, decisionId) {
    const trusted = validateScope(scope);
    try {
      return await runScoped(
        runtimePool,
        "aios_c15_runtime",
        trusted,
        "BEGIN",
        async (client) => {
          const result = await selectDecision(
            client,
            trusted.tenantId,
            decisionId,
          );
          return decisionFromRow(result.rows[0]);
        },
      );
    } catch (error) {
      throw databaseFailure(error);
    }
  }

  async function withdrawDecision(scope, command) {
    validateBase(command, "WITHDRAW");
    if (
      typeof command.decisionId !== "string" ||
      !SHA256.test(command.decisionSha256 ?? "") ||
      typeof command.withdrawnAt !== "string" ||
      command.auditIntent.subjectId !== command.decisionId ||
      typeof command.withdrawalAuthorization !== "object"
    ) {
      fail("INVALID_INPUT", "C15 withdrawal is invalid.");
    }
    return writeCommand(
      scope,
      command,
      async (client) => {
        await client.query(
          `SELECT pg_advisory_xact_lock(
             hashtextextended($1 || '|' || $2,0)
           )`,
          [command.tenantId, command.decisionId],
        );
        const selected = await selectDecision(
          client,
          command.tenantId,
          command.decisionId,
        );
        const current = decisionFromRow(selected.rows[0]);
        if (!current) {
          fail("DECISION_NOT_FOUND", "C15 decision was not found.");
        }
        if (current.status !== "ACTIVE") {
          fail("DECISION_NOT_ACTIVE", "C15 decision is not active.");
        }
        if (
          current.decisionSha256 !== command.decisionSha256 ||
          command.auditIntent.decisionSha256 !==
            current.decisionSha256
        ) {
          fail("DECISION_TAMPERED", "C15 withdrawal hash changed.");
        }
        const queued = await client.query(
          `SELECT 1
             FROM ${table("workflow_effect")}
            WHERE tenant_id=$1 AND decision_id=$2
            LIMIT 1`,
          [command.tenantId, current.decisionId],
        );
        if (queued.rowCount > 0) {
          fail(
            "DECISION_ALREADY_EXECUTING",
            "C15 cannot withdraw after execution was queued.",
          );
        }
        await insertAudit(client, command.auditIntent);
        await client.query(
          `INSERT INTO ${table("decision_withdrawal")} (
             tenant_id,tenant_kind,decision_id,decision_sha256,
             withdrawal_authorization,created_by_idempotency_key,
             created_audit_intent_id,withdrawn_at
           ) VALUES (
             $1,'SYNTHETIC',$2,$3,$4::jsonb,$5,$6,$7::timestamptz
           )`,
          [
            command.tenantId,
            current.decisionId,
            current.decisionSha256,
            JSON.stringify(command.withdrawalAuthorization),
            command.idempotencyKey,
            command.auditIntent.intentId,
            command.withdrawnAt,
          ],
        );
        const response = {
          ...clone(current),
          status: "WITHDRAWN",
          withdrawnAt: command.withdrawnAt,
          withdrawalAuthorization: clone(
            command.withdrawalAuthorization,
          ),
          replayed: false,
        };
        await insertReceipt(
          client,
          command,
          current.decisionId,
          response,
        );
        return Object.freeze(response);
      },
      responseDecision,
    );
  }

  async function queueEffect(scope, command) {
    validateEffectCommand(command);
    return writeCommand(
      scope,
      command,
      async (client) => {
        const value = command.effect;
        await client.query(
          `SELECT pg_advisory_xact_lock(
             hashtextextended($1 || '|' || $2,0)
           )`,
          [command.tenantId, value.decisionId],
        );
        const decisionResult = await selectDecision(
          client,
          command.tenantId,
          value.decisionId,
        );
        const decision = decisionFromRow(decisionResult.rows[0]);
        if (
          !decision ||
          decision.status !== "ACTIVE" ||
          decision.decisionSha256 !== value.decisionSha256 ||
          decision.artifactId !== value.artifactId ||
          decision.artifactSha256 !== value.artifactSha256
        ) {
          fail(
            "DECISION_NOT_ACTIVE",
            "C15 decision cannot authorize execution.",
          );
        }
        if (
          decision.identityBinding.humanPrincipalId !==
            value.executionIdentity.humanPrincipalId ||
          decision.identityBinding.humanSecurityEpoch !==
            value.executionIdentity.humanSecurityEpoch ||
          decision.identityBinding.workloadActorPrincipalId !==
            value.executionIdentity.workloadActorPrincipalId ||
          decision.identityBinding.workloadActorSecurityEpoch !==
            value.executionIdentity.workloadActorSecurityEpoch
        ) {
          fail(
            "DECISION_AUTHORITY_REVOKED",
            "C15 execution authority changed.",
          );
        }
        const time = await client.query(
          `SELECT $1::timestamptz > statement_timestamp() AS active`,
          [decision.expiresAt],
        );
        if (time.rows[0]?.active !== true) {
          fail("DECISION_NOT_ACTIVE", "C15 decision expired.");
        }
        await insertAudit(client, command.auditIntent);
        const result = await client.query(
          `INSERT INTO ${table("workflow_effect")} (
             tenant_id,tenant_kind,effect_id,effect_key,effect_sha256,
             decision_id,decision_sha256,artifact_id,artifact_sha256,
             expected_readback_sha256,status,effect,commit_receipt,
             readback_receipt,compensation_receipt,
             terminal_audit_intent_id,created_by_idempotency_key,
             created_audit_intent_id,created_at,updated_at
           ) VALUES (
             $1,'SYNTHETIC',$2,$3,$4,$5,$6,$7,$8,$9,'QUEUED',
             $10::jsonb,NULL,NULL,NULL,NULL,$11,$12,
             $13::timestamptz,$13::timestamptz
           )
           RETURNING *`,
          [
            command.tenantId,
            value.effectId,
            value.effectKey,
            value.effectSha256,
            value.decisionId,
            value.decisionSha256,
            value.artifactId,
            value.artifactSha256,
            value.expectedReadbackSha256,
            JSON.stringify(value),
            command.idempotencyKey,
            command.auditIntent.intentId,
            value.createdAt,
          ],
        );
        await client.query(
          `INSERT INTO ${table("effect_outbox")} (
             tenant_id,tenant_kind,effect_id,status,attempt_count,
             lease_version,leased_by,lease_until,available_at,
             published_at,last_error_code,created_at
           ) VALUES (
             $1,'SYNTHETIC',$2,'PENDING',0,0,NULL,NULL,
             statement_timestamp(),NULL,NULL,statement_timestamp()
           )`,
          [command.tenantId, value.effectId],
        );
        await insertReceipt(
          client,
          command,
          value.effectId,
          value,
        );
        return effectFromRow(result.rows[0]);
      },
      responseEffect,
    );
  }

  async function getEffect(scope, effectId) {
    const trusted = validateScope(scope);
    try {
      return await runScoped(
        runtimePool,
        "aios_c15_runtime",
        trusted,
        "BEGIN",
        async (client) => {
          const result = await client.query(
            `SELECT * FROM ${table("workflow_effect")}
              WHERE tenant_id=$1 AND effect_id=$2`,
            [trusted.tenantId, effectId],
          );
          return effectFromRow(result.rows[0]);
        },
      );
    } catch (error) {
      throw databaseFailure(error);
    }
  }

  function validateLease(input) {
    if (
      typeof input?.workerId !== "string" ||
      !input.workerId ||
      !Number.isSafeInteger(input?.limit) ||
      input.limit < 1 ||
      input.limit > 100 ||
      !Number.isSafeInteger(input?.leaseDurationSeconds) ||
      input.leaseDurationSeconds < 1 ||
      input.leaseDurationSeconds > 300
    ) {
      fail("INVALID_INPUT", "C15 Outbox lease is invalid.");
    }
  }

  async function claimEffects(scope, input) {
    const trusted = validateScope(scope);
    validateLease(input);
    try {
      return await runScoped(
        effectWorkerPool,
        "aios_c15_effect_worker",
        trusted,
        "BEGIN",
        async (client) => {
          const result = await client.query(
            `WITH candidates AS (
               SELECT tenant_id,effect_id
                 FROM ${table("effect_outbox")}
                WHERE tenant_id=$1
                  AND (
                    (
                      status IN ('PENDING','FAILED')
                      AND available_at <= statement_timestamp()
                    )
                    OR (
                      status='PROCESSING'
                      AND lease_until <= statement_timestamp()
                    )
                  )
                ORDER BY created_at,effect_id
                FOR UPDATE SKIP LOCKED
                LIMIT $2
             ), claimed AS (
               UPDATE ${table("effect_outbox")} AS outbox
                  SET status='PROCESSING',
                      attempt_count=attempt_count+1,
                      lease_version=lease_version+1,
                      leased_by=$3,
                      lease_until=statement_timestamp()
                        + make_interval(secs => $4::double precision),
                      last_error_code=NULL
                 FROM candidates
                WHERE outbox.tenant_id=candidates.tenant_id
                  AND outbox.effect_id=candidates.effect_id
               RETURNING outbox.*
             )
             SELECT effect.*,claimed.status AS outbox_status,
                    claimed.attempt_count,claimed.lease_version,
                    claimed.leased_by,claimed.lease_until,
                    claimed.available_at,claimed.published_at,
                    claimed.last_error_code,
                    claimed.created_at AS outbox_created_at
               FROM claimed
               JOIN ${table("workflow_effect")} AS effect
                 ON effect.tenant_id=claimed.tenant_id
                AND effect.effect_id=claimed.effect_id
              ORDER BY claimed.created_at,claimed.effect_id`,
            [
              trusted.tenantId,
              input.limit,
              input.workerId,
              input.leaseDurationSeconds,
            ],
          );
          return Object.freeze(result.rows.map(effectOutboxFromRow));
        },
      );
    } catch (error) {
      throw databaseFailure(error);
    }
  }

  function validateCompletion(input) {
    if (
      typeof input?.effectId !== "string" ||
      typeof input?.workerId !== "string" ||
      !Number.isSafeInteger(input?.leaseVersion) ||
      !["SUCCEEDED", "COMPENSATED", "COMPENSATION_FAILED"].includes(
        input?.terminalStatus,
      ) ||
      typeof input?.commitReceipt !== "object" ||
      typeof input?.readbackReceipt !== "object" ||
      !input?.auditIntent
    ) {
      fail("INVALID_INPUT", "C15 effect completion is invalid.");
    }
    assertAuditIntentMetadataOnly(input.auditIntent);
  }

  async function completeEffect(scope, input) {
    const trusted = validateScope(scope);
    validateCompletion(input);
    try {
      return await runScoped(
        effectWorkerPool,
        "aios_c15_effect_worker",
        trusted,
        "BEGIN",
        async (client) => {
          const lease = await client.query(
            `SELECT *
               FROM ${table("effect_outbox")}
              WHERE tenant_id=$1 AND effect_id=$2
                AND status='PROCESSING'
                AND leased_by=$3 AND lease_version=$4
                AND lease_until >= statement_timestamp()
              FOR UPDATE`,
            [
              trusted.tenantId,
              input.effectId,
              input.workerId,
              input.leaseVersion,
            ],
          );
          if (lease.rowCount !== 1) {
            fail("STALE_OUTBOX_LEASE", "C15 effect lease is stale.");
          }
          const effectBefore = await client.query(
            `SELECT * FROM ${table("workflow_effect")}
              WHERE tenant_id=$1 AND effect_id=$2 AND status='QUEUED'`,
            [trusted.tenantId, input.effectId],
          );
          if (effectBefore.rowCount !== 1) {
            fail("STALE_EFFECT", "C15 effect is already terminal.");
          }
          assertC15EffectCompletion(
            effectFromRow(effectBefore.rows[0]),
            input,
          );
          await insertAudit(client, input.auditIntent);
          const result = await client.query(
            `UPDATE ${table("workflow_effect")}
                SET status=$3,
                    commit_receipt=$4::jsonb,
                    readback_receipt=$5::jsonb,
                    compensation_receipt=$6::jsonb,
                    terminal_audit_intent_id=$7,
                    updated_at=statement_timestamp()
              WHERE tenant_id=$1 AND effect_id=$2 AND status='QUEUED'
              RETURNING *`,
            [
              trusted.tenantId,
              input.effectId,
              input.terminalStatus,
              JSON.stringify(input.commitReceipt),
              JSON.stringify(input.readbackReceipt),
              input.compensationReceipt === null
                ? null
                : JSON.stringify(input.compensationReceipt),
              input.auditIntent.intentId,
            ],
          );
          if (result.rowCount !== 1) {
            fail("STALE_EFFECT", "C15 effect is already terminal.");
          }
          const completed = await client.query(
            `UPDATE ${table("effect_outbox")}
                SET status='PUBLISHED',leased_by=NULL,lease_until=NULL,
                    published_at=statement_timestamp(),last_error_code=NULL
              WHERE tenant_id=$1 AND effect_id=$2
                AND status='PROCESSING'
                AND leased_by=$3 AND lease_version=$4
              RETURNING effect_id`,
            [
              trusted.tenantId,
              input.effectId,
              input.workerId,
              input.leaseVersion,
            ],
          );
          if (completed.rowCount !== 1) {
            fail("STALE_OUTBOX_LEASE", "C15 effect lease is stale.");
          }
          return effectFromRow(result.rows[0]);
        },
      );
    } catch (error) {
      throw databaseFailure(error);
    }
  }

  function validateFailure(input, key) {
    if (
      typeof input?.[key] !== "string" ||
      typeof input?.workerId !== "string" ||
      !Number.isSafeInteger(input?.leaseVersion) ||
      !Number.isSafeInteger(input?.retryDelaySeconds) ||
      input.retryDelaySeconds < 0 ||
      input.retryDelaySeconds > 3600 ||
      !/^[A-Z][A-Z0-9_]{0,63}$/.test(input?.errorCode ?? "")
    ) {
      fail("INVALID_INPUT", "C15 Outbox failure is invalid.");
    }
  }

  async function failEffect(scope, input) {
    const trusted = validateScope(scope);
    validateFailure(input, "effectId");
    try {
      return await runScoped(
        effectWorkerPool,
        "aios_c15_effect_worker",
        trusted,
        "BEGIN",
        async (client) => {
          const result = await client.query(
            `UPDATE ${table("effect_outbox")}
                SET status='FAILED',leased_by=NULL,lease_until=NULL,
                    available_at=statement_timestamp()
                      + make_interval(secs => $5::double precision),
                    published_at=NULL,last_error_code=$6
              WHERE tenant_id=$1 AND effect_id=$2
                AND status='PROCESSING'
                AND leased_by=$3 AND lease_version=$4
                AND lease_until >= statement_timestamp()
              RETURNING *`,
            [
              trusted.tenantId,
              input.effectId,
              input.workerId,
              input.leaseVersion,
              input.retryDelaySeconds,
              input.errorCode,
            ],
          );
          if (result.rowCount !== 1) {
            fail("STALE_OUTBOX_LEASE", "C15 effect lease is stale.");
          }
          return effectOutboxFromRow(result.rows[0]);
        },
      );
    } catch (error) {
      throw databaseFailure(error);
    }
  }

  async function claimAudit(scope, input) {
    const trusted = validateScope(scope);
    validateLease(input);
    try {
      return await runScoped(
        auditWorkerPool,
        "aios_c15_audit_worker",
        trusted,
        "BEGIN",
        async (client) => {
          const result = await client.query(
            `WITH candidates AS (
               SELECT tenant_id,intent_id
                 FROM ${table("audit_outbox")}
                WHERE tenant_id=$1
                  AND (
                    (
                      status IN ('PENDING','FAILED')
                      AND available_at <= statement_timestamp()
                    )
                    OR (
                      status='PROCESSING'
                      AND lease_until <= statement_timestamp()
                    )
                  )
                ORDER BY created_at,intent_id
                FOR UPDATE SKIP LOCKED
                LIMIT $2
             ), claimed AS (
               UPDATE ${table("audit_outbox")} AS outbox
                  SET status='PROCESSING',
                      attempt_count=attempt_count+1,
                      lease_version=lease_version+1,
                      leased_by=$3,
                      lease_until=statement_timestamp()
                        + make_interval(secs => $4::double precision),
                      last_error_code=NULL
                 FROM candidates
                WHERE outbox.tenant_id=candidates.tenant_id
                  AND outbox.intent_id=candidates.intent_id
               RETURNING outbox.*
             )
             SELECT intent.*,claimed.status AS outbox_status,
                    claimed.attempt_count,claimed.lease_version,
                    claimed.leased_by,claimed.lease_until,
                    claimed.available_at,claimed.published_at,
                    claimed.last_error_code,
                    claimed.created_at AS outbox_created_at,
                    intent.created_at AS intent_created_at
               FROM claimed
               JOIN ${table("audit_intent")} AS intent
                 ON intent.tenant_id=claimed.tenant_id
                AND intent.intent_id=claimed.intent_id
              ORDER BY claimed.created_at,claimed.intent_id`,
            [
              trusted.tenantId,
              input.limit,
              input.workerId,
              input.leaseDurationSeconds,
            ],
          );
          return Object.freeze(result.rows.map(auditOutboxFromRow));
        },
      );
    } catch (error) {
      throw databaseFailure(error);
    }
  }

  async function completeAudit(scope, input) {
    const trusted = validateScope(scope);
    if (
      typeof input?.intentId !== "string" ||
      typeof input?.workerId !== "string" ||
      !Number.isSafeInteger(input?.leaseVersion) ||
      input.ackIntentId !== input.intentId
    ) {
      fail("AUDIT_ACK_MISMATCH", "C18 audit ACK is invalid.");
    }
    try {
      return await runScoped(
        auditWorkerPool,
        "aios_c15_audit_worker",
        trusted,
        "BEGIN",
        async (client) => {
          const result = await client.query(
            `UPDATE ${table("audit_outbox")}
                SET status='PUBLISHED',leased_by=NULL,lease_until=NULL,
                    published_at=statement_timestamp(),last_error_code=NULL
              WHERE tenant_id=$1 AND intent_id=$2
                AND status='PROCESSING'
                AND leased_by=$3 AND lease_version=$4
                AND lease_until >= statement_timestamp()
              RETURNING *`,
            [
              trusted.tenantId,
              input.intentId,
              input.workerId,
              input.leaseVersion,
            ],
          );
          if (result.rowCount !== 1) {
            fail("STALE_OUTBOX_LEASE", "C15 audit lease is stale.");
          }
          return auditOutboxFromRow(result.rows[0]);
        },
      );
    } catch (error) {
      throw databaseFailure(error);
    }
  }

  async function failAudit(scope, input) {
    const trusted = validateScope(scope);
    validateFailure(input, "intentId");
    try {
      return await runScoped(
        auditWorkerPool,
        "aios_c15_audit_worker",
        trusted,
        "BEGIN",
        async (client) => {
          const result = await client.query(
            `UPDATE ${table("audit_outbox")}
                SET status='FAILED',leased_by=NULL,lease_until=NULL,
                    available_at=statement_timestamp()
                      + make_interval(secs => $5::double precision),
                    published_at=NULL,last_error_code=$6
              WHERE tenant_id=$1 AND intent_id=$2
                AND status='PROCESSING'
                AND leased_by=$3 AND lease_version=$4
                AND lease_until >= statement_timestamp()
              RETURNING *`,
            [
              trusted.tenantId,
              input.intentId,
              input.workerId,
              input.leaseVersion,
              input.retryDelaySeconds,
              input.errorCode,
            ],
          );
          if (result.rowCount !== 1) {
            fail("STALE_OUTBOX_LEASE", "C15 audit lease is stale.");
          }
          return auditOutboxFromRow(result.rows[0]);
        },
      );
    } catch (error) {
      throw databaseFailure(error);
    }
  }

  async function exportRecovery(scope) {
    const trusted = validateScope(scope);
    try {
      return await runScoped(
        recoveryPool,
        "aios_c15_recovery_reader",
        trusted,
        "BEGIN ISOLATION LEVEL REPEATABLE READ",
        async (client) => {
          const collections = {};
          for (const [name, order] of [
            ["draft_artifact", "artifact_id"],
            ["synthetic_test_decision", "decision_id"],
            ["decision_withdrawal", "decision_id"],
            ["workflow_effect", "effect_id"],
            ["effect_outbox", "effect_id"],
            ["audit_intent", "intent_id"],
            ["audit_outbox", "intent_id"],
            ["command_receipt", "idempotency_key"],
          ]) {
            const result = await client.query(
              `SELECT * FROM ${table(name)}
                WHERE tenant_id=$1 ORDER BY ${order}`,
              [trusted.tenantId],
            );
            collections[name] = result.rows.map((row) =>
              Object.fromEntries(
                Object.entries(row).map(([key, value]) => [
                  key,
                  value instanceof Date ? value.toISOString() : value,
                ]),
              ),
            );
          }
          const body = {
            schemaVersion: "c15-postgres-recovery.v1",
            tenantId: trusted.tenantId,
            tenantKind: "SYNTHETIC",
            collections,
          };
          return {
            ...body,
            recoverySha256: humanDecisionSha256(body),
          };
        },
      );
    } catch (error) {
      throw databaseFailure(error);
    }
  }

  return Object.freeze({
    createArtifact,
    getArtifact,
    createDecision,
    getDecision,
    withdrawDecision,
    queueEffect,
    getEffect,
    claimEffects,
    completeEffect,
    failEffect,
    claimAudit,
    completeAudit,
    failAudit,
    exportRecovery,
  });
}
