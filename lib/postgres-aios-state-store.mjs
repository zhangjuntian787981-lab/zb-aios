import { createHash, randomUUID } from "node:crypto";

const SAFE_IDENTIFIER = /^[a-z_][a-z0-9_]*$/;
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const UUID_V7 =
  "[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}";
const SYNTHETIC_TENANT_ID = new RegExp(`^stn_${UUID_V7}$`);
const RETRYABLE_SQL_STATES = new Set([
  "40001",
  "40P01",
  "57P01",
  "08000",
  "08001",
  "08003",
  "08004",
  "08006",
  "08P01",
]);
const RETRYABLE_RECEIPTS = new Set([
  "command_receipt_pkey",
  "command_receipt_tenant_id_effect_key_key",
]);
const ROLE_NAMES = Object.freeze([
  "aios_c08_runtime",
  "aios_c08_outbox_worker",
  "aios_c08_owner",
  "aios_c07_scope_runtime",
  "aios_c07_data_runtime",
  "aios_c07_lifecycle_runtime",
  "aios_c07_restore_runtime",
  "aios_c07_owner",
]);

export class AiosStateStoreError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "AiosStateStoreError";
    this.code = code;
  }
}

function fail(code, message) {
  throw new AiosStateStoreError(code, message);
}

function jsonValue(value) {
  return typeof value === "string" ? JSON.parse(value) : value;
}

function safeInteger(value) {
  const result = Number(value);
  if (!Number.isSafeInteger(result)) {
    fail("STORE_UNAVAILABLE", "PostgreSQL returned an unsafe integer.");
  }
  return result;
}

function iso(value) {
  return value instanceof Date ? value.toISOString() : value;
}

function isCanonicalInstant(value) {
  if (
    typeof value !== "string" ||
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value)
  ) {
    return false;
  }
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value;
}

function hash(value) {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

export function deriveCommandEffectKey({
  tenantId,
  commandKind,
  idempotencyKey,
}) {
  return hash(JSON.stringify([tenantId, commandKind, idempotencyKey]));
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
    fail("TENANT_SCOPE_VIOLATION", "C08 requires a C07 verified scope.");
  }
}

function validateCommand(metadata) {
  if (
    typeof metadata?.idempotencyKey !== "string" ||
    !metadata.idempotencyKey.trim() ||
    metadata.idempotencyKey.length > 128 ||
    !SHA256.test(metadata?.requestHash ?? "") ||
    typeof metadata?.commandKind !== "string" ||
    !/^[A-Z][A-Z0-9_]{0,63}$/.test(metadata.commandKind) ||
    typeof metadata?.correlationId !== "string" ||
    !metadata.correlationId.trim() ||
    metadata.correlationId.length > 128
  ) {
    fail("INVALID_INPUT", "C08 command metadata is invalid.");
  }
}

function validateLeaseInput(input) {
  const { workerId, now, leaseExpiresAt, limit = 10 } = input ?? {};
  if (
    typeof workerId !== "string" ||
    !workerId.trim() ||
    workerId.length > 128 ||
    !isCanonicalInstant(now) ||
    !isCanonicalInstant(leaseExpiresAt) ||
    Date.parse(leaseExpiresAt) <= Date.parse(now) ||
    !Number.isSafeInteger(limit) ||
    limit < 1 ||
    limit > 100
  ) {
    fail("INVALID_INPUT", "C08 Outbox lease input is invalid.");
  }
  return { workerId, now, leaseExpiresAt, limit };
}

function validateLeaseReceipt(receipt) {
  const { eventId, workerId, leaseVersion, now } = receipt ?? {};
  if (
    typeof eventId !== "string" ||
    !eventId.trim() ||
    eventId.length > 128 ||
    typeof workerId !== "string" ||
    !workerId.trim() ||
    workerId.length > 128 ||
    !Number.isSafeInteger(leaseVersion) ||
    leaseVersion < 1 ||
    !isCanonicalInstant(now)
  ) {
    fail("INVALID_INPUT", "C08 Outbox lease receipt is invalid.");
  }
}

function databaseFailure(error) {
  if (error instanceof AiosStateStoreError) return error;
  if (
    error?.name === "AiosStateError" &&
    typeof error.code === "string"
  ) {
    return error;
  }
  if (error?.code === "42501") {
    return new AiosStateStoreError(
      "TENANT_SCOPE_VIOLATION",
      "PostgreSQL rejected the C08 Tenant scope.",
    );
  }
  if (
    error?.constraint === "aios_artifact_pkey" ||
    error?.constraint === "aios_artifact_version_chain_guard"
  ) {
    return new AiosStateStoreError(
      "STALE_VERSION",
      "C08 Artifact version is stale.",
    );
  }
  if (
    error?.constraint === "aios_tool_call_one_prepared_per_run"
  ) {
    return new AiosStateStoreError(
      "TOOL_CALL_IN_FLIGHT",
      "C08 Run already has a prepared ToolCall.",
    );
  }
  if (
    error?.constraint === "aios_state_version_guard" ||
    error?.constraint?.endsWith("_transition_guard")
  ) {
    return new AiosStateStoreError(
      "VERSION_CONFLICT",
      "C08 state version or transition conflicts.",
    );
  }
  if (error?.constraint === "aios_state_event_outbox_pair_guard") {
    return new AiosStateStoreError(
      "EVIDENCE_PAIR_INVALID",
      "C08 DomainEvent and Outbox do not match.",
    );
  }
  if (error?.constraint === "aios_state_event_receipt_pair_guard") {
    return new AiosStateStoreError(
      "EVIDENCE_PAIR_INVALID",
      "C08 DomainEvent and CommandReceipt do not match.",
    );
  }
  if (error?.code === "23505") {
    return new AiosStateStoreError(
      "ID_COLLISION",
      "C08 state identifier already exists.",
    );
  }
  if (["23503", "23514", "23000"].includes(error?.code)) {
    return new AiosStateStoreError(
      "INTEGRITY_VIOLATION",
      "C08 PostgreSQL invariant failed.",
    );
  }
  return new AiosStateStoreError(
    "STORE_UNAVAILABLE",
    "C08 PostgreSQL storage operation failed.",
  );
}

function shouldRetry(error) {
  return (
    RETRYABLE_SQL_STATES.has(error?.code) ||
    RETRYABLE_RECEIPTS.has(error?.constraint)
  );
}

function shouldDiscard(error) {
  return (
    error?.code === "57P01" ||
    (typeof error?.code === "string" && error.code.startsWith("08"))
  );
}

function retryDelay(seed, attempt) {
  let value = 0;
  for (const character of seed) {
    value = (value * 31 + character.charCodeAt(0)) >>> 0;
  }
  return Math.min(5 * 2 ** attempt, 100) + (value % 5);
}

function caseFromRow(row) {
  if (!row) return null;
  return Object.freeze({
    caseId: row.case_id,
    tenantId: row.tenant_id,
    tenantKind: row.tenant_kind,
    state: row.state,
    version: safeInteger(row.version),
    goalRef: row.goal_ref,
    createdAt: iso(row.created_at),
    updatedAt: iso(row.updated_at),
  });
}

function threadFromRow(row) {
  if (!row) return null;
  return Object.freeze({
    threadId: row.thread_id,
    caseId: row.case_id,
    state: row.state,
    version: safeInteger(row.version),
    purposeRef: row.purpose_ref,
    createdAt: iso(row.created_at),
    updatedAt: iso(row.updated_at),
  });
}

function artifactFromRow(row) {
  if (!row) return null;
  return Object.freeze({
    artifactId: row.artifact_id,
    caseId: row.case_id,
    threadId: row.thread_id,
    artifactVersion: safeInteger(row.artifact_version),
    kind: row.kind,
    contentRef: row.content_ref,
    contentSha256: row.content_sha256,
    createdAt: iso(row.created_at),
  });
}

function runFromRow(row) {
  if (!row) return null;
  return Object.freeze({
    runId: row.run_id,
    caseId: row.case_id,
    threadId: row.thread_id,
    state: row.state,
    version: safeInteger(row.version),
    baseManifest: jsonValue(row.base_manifest),
    identity: jsonValue(row.identity),
    authorization: jsonValue(row.authorization_evidence),
    tenantLifecycleVersion: safeInteger(row.tenant_lifecycle_version),
    resultArtifact:
      row.result_artifact === null ? null : jsonValue(row.result_artifact),
    reconstructionHash: row.reconstruction_hash,
    createdAt: iso(row.created_at),
    updatedAt: iso(row.updated_at),
  });
}

function toolCallFromRow(row) {
  if (!row) return null;
  return Object.freeze({
    toolCallId: row.tool_call_id,
    runId: row.run_id,
    state: row.state,
    version: safeInteger(row.version),
    operationRef: row.operation_ref,
    operationVersion: row.operation_version,
    requestHash: row.request_hash,
    effectKey: row.effect_key,
    compensationRef: row.compensation_ref,
    authorization: jsonValue(row.authorization_evidence),
    receiptRef: row.receipt_ref,
    receiptHash: row.receipt_hash,
    outcome: row.outcome,
    createdAt: iso(row.created_at),
    updatedAt: iso(row.updated_at),
  });
}

function outboxFromRow(row) {
  const state =
    row.status === "PROCESSING"
      ? "LEASED"
      : row.status === "FAILED"
        ? "PENDING"
        : row.status;
  return Object.freeze({
    eventId: row.event_id,
    state,
    leaseVersion: safeInteger(row.lease_version),
    workerId: row.leased_by,
    leaseExpiresAt: iso(row.lease_until),
    lastErrorCode: row.last_error_code,
    event: jsonValue(row.event),
    createdAt: iso(row.created_at),
    availableAt: iso(row.available_at),
    publishedAt: iso(row.published_at),
  });
}

async function rollback(client) {
  try {
    await client.query("ROLLBACK");
  } catch {
    // Preserve the first failure; a broken connection is discarded below.
  }
}

export function createPostgresAiosStateStore({
  runtimePool,
  scopePool,
  outboxPool,
  schema = "aios_state",
  scopeSchema = "aios_data",
  maxSerializableRetries = 10,
}) {
  if (
    typeof runtimePool?.connect !== "function" ||
    typeof scopePool?.connect !== "function" ||
    typeof outboxPool?.connect !== "function" ||
    runtimePool === scopePool ||
    runtimePool === outboxPool ||
    outboxPool === scopePool ||
    !SAFE_IDENTIFIER.test(schema) ||
    !SAFE_IDENTIFIER.test(scopeSchema) ||
    !Number.isSafeInteger(maxSerializableRetries) ||
    maxSerializableRetries < 0 ||
    maxSerializableRetries > 10
  ) {
    fail("INVALID_CONFIGURATION", "C08 PostgreSQL pools are invalid.");
  }

  const table = (name) => `"${schema}"."${name}"`;
  const scopeFunction =
    `"${scopeSchema}"."issue_runtime_scope_signature"`;
  const fenceFunction = `"${scopeSchema}"."acquire_runtime_fence"`;

  async function connect(pool, requiredRole) {
    let client;
    try {
      client = await pool.connect();
      const roleChecks = ROLE_NAMES.map(
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
                ${roleChecks}
           FROM identity
           JOIN pg_roles AS active ON active.rolname = identity.current_name
           JOIN pg_roles AS login ON login.rolname = identity.session_name`,
      );
      const row = result.rows[0];
      const expectedIndex = ROLE_NAMES.indexOf(requiredRole);
      if (
        !row ||
        expectedIndex < 0 ||
        row.current_super ||
        row.current_bypassrls ||
        row.session_super ||
        row.session_bypassrls ||
        ROLE_NAMES.some(
          (_role, index) =>
            row[`current_role_${index}`] !== (index === expectedIndex) ||
            row[`session_role_${index}`] !== (index === expectedIndex),
        )
      ) {
        client.release(new Error("C08 rejected an unsafe PostgreSQL role."));
        client = null;
        fail(
          "INVALID_CONFIGURATION",
          "C08 PostgreSQL pool role is unsafe.",
        );
      }
      return client;
    } catch (error) {
      if (client) {
        client.release(
          new Error("C08 could not verify the PostgreSQL role."),
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
              current_setting('aios.backend_pid', true) AS backend_pid,
              current_setting('aios.transaction_id', true)
                AS transaction_id,
              current_setting('aios.expires_epoch_ms', true)
                AS expires_epoch_ms,
              current_setting('aios.scope_nonce', true) AS scope_nonce,
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
        "C08 PostgreSQL connection retained Tenant scope.",
      );
    }
  }

  async function issueScopeSignature(scope, backendPid, transactionId) {
    const client = await connect(scopePool, "aios_c07_scope_runtime");
    try {
      const nonce = randomUUID();
      const result = await client.query(
        `SELECT ${scopeFunction}(
           $1, $2, $3, $4, $5, $6, $7, $8, $9::xid8, 15, $10::uuid
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
      const signed = jsonValue(result.rows[0]?.signed_scope);
      if (
        !Number.isSafeInteger(Number(signed?.expires_epoch_ms)) ||
        !/^[0-9a-f]{64}$/.test(signed?.signature ?? "")
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

  async function runScoped(
    pool,
    requiredRole,
    scope,
    begin,
    reducer,
    sessionLockKey = null,
  ) {
    const client = await connect(pool, requiredRole);
    let started = false;
    let discard = false;
    let sessionLockAcquired = false;
    try {
      if (sessionLockKey !== null) {
        await client.query(
          `SELECT pg_advisory_lock(hashtextextended($1, 0))`,
          [sessionLockKey],
        );
        sessionLockAcquired = true;
      }
      await client.query(begin);
      started = true;
      const transaction = await client.query(
        `SELECT pg_backend_pid() AS backend_pid,
                pg_current_xact_id()::text AS transaction_id`,
      );
      const backendPid = transaction.rows[0].backend_pid;
      const transactionId = transaction.rows[0].transaction_id;
      const signed = await issueScopeSignature(
        scope,
        backendPid,
        transactionId,
      );
      await client.query(
        `SELECT set_config('aios.tenant_id', $1, true),
                set_config('aios.tenant_kind', $2, true),
                set_config('aios.lifecycle_version', $3, true),
                set_config('aios.correlation_id', $4, true),
                set_config('aios.decision_id', $5, true),
                set_config('aios.evidence_ref', $6, true),
                set_config('aios.policy_version', $7, true),
                set_config('aios.backend_pid', $8, true),
                set_config('aios.transaction_id', $9, true),
                set_config('aios.expires_epoch_ms', $10, true),
                set_config('aios.scope_nonce', $11, true),
                set_config('aios.scope_signature', $12, true)`,
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
      const fence = await client.query(
        `SELECT ${fenceFunction}() AS acquired`,
      );
      if (fence.rows[0]?.acquired !== true) {
        fail(
          "TENANT_SCOPE_VIOLATION",
          "C08 PostgreSQL runtime fence was not acquired.",
        );
      }
      const value = await reducer(client);
      await client.query("COMMIT");
      started = false;
      await assertScopeCleared(client);
      return value;
    } catch (error) {
      discard = shouldDiscard(error);
      let waitForShutdown = null;
      if (
        discard &&
        typeof client.once === "function" &&
        typeof client.removeListener === "function"
      ) {
        waitForShutdown = new Promise((resolve) => {
          let timer;
          const settled = () => {
            clearTimeout(timer);
            client.removeListener("error", settled);
            client.removeListener("end", settled);
            resolve();
          };
          client.once("error", settled);
          client.once("end", settled);
          timer = setTimeout(settled, 250);
        });
      }
      if (started) await rollback(client);
      if (waitForShutdown) await waitForShutdown;
      if (!discard) {
        try {
          await assertScopeCleared(client);
        } catch {
          discard = true;
        }
      }
      throw error;
    } finally {
      if (sessionLockAcquired && !discard) {
        try {
          const unlocked = await client.query(
            `SELECT pg_advisory_unlock(hashtextextended($1, 0))
               AS unlocked`,
            [sessionLockKey],
          );
          if (unlocked.rows[0]?.unlocked !== true) discard = true;
        } catch {
          discard = true;
        }
      }
      client.release(
        discard ? new Error("C08 discarded a failed connection.") : undefined,
      );
    }
  }

  function transactionPort(
    client,
    scope,
    metadata,
    effectKey,
    emittedEvents,
    emittedOutbox,
  ) {
    const tenant = [scope.tenantId, scope.tenantKind];
    const find = async (name, idColumn, id, mapper, lock = "") => {
      const result = await client.query(
        `SELECT * FROM ${table(name)}
          WHERE tenant_id = $1 AND ${idColumn} = $2 ${lock}`,
        [scope.tenantId, id],
      );
      return mapper(result.rows[0]);
    };
    const ensureTenant = (value) => {
      if (
        value?.tenantId !== undefined &&
        value.tenantId !== scope.tenantId
      ) {
        fail("TENANT_SCOPE_VIOLATION", "C08 value crossed Tenant scope.");
      }
      if (
        value?.tenantKind !== undefined &&
        value.tenantKind !== "SYNTHETIC"
      ) {
        fail("TENANT_SCOPE_VIOLATION", "C08 value is not Synthetic.");
      }
    };
    const updateVersioned = async ({
      name,
      idColumn,
      id,
      expectedVersion,
      value,
      assignments,
      parameters,
      mapper,
    }) => {
      if (
        !Number.isSafeInteger(expectedVersion) ||
        value.version !== expectedVersion + 1
      ) {
        fail("VERSION_CONFLICT", "C08 version CAS input is invalid.");
      }
      const result = await client.query(
        `UPDATE ${table(name)}
            SET ${assignments}
          WHERE tenant_id = $1
            AND ${idColumn} = $2
            AND version = $3
        RETURNING *`,
        [scope.tenantId, id, expectedVersion, ...parameters],
      );
      if (result.rowCount !== 1) {
        fail("VERSION_CONFLICT", "C08 version CAS did not match.");
      }
      return mapper(result.rows[0]);
    };
    return Object.freeze({
      findCase(caseId) {
        return find("aios_case", "case_id", caseId, caseFromRow);
      },
      findThread(threadId) {
        return find(
          "aios_thread",
          "thread_id",
          threadId,
          threadFromRow,
        );
      },
      findRun(runId) {
        return find("aios_run", "run_id", runId, runFromRow, "FOR UPDATE");
      },
      async findArtifact(artifactId, artifactVersion) {
        if (!Number.isSafeInteger(artifactVersion) || artifactVersion < 1) {
          fail("INVALID_INPUT", "C08 Artifact version is invalid.");
        }
        const result = await client.query(
          `SELECT * FROM ${table("aios_artifact")}
            WHERE tenant_id=$1
              AND artifact_id=$2
              AND artifact_version=$3`,
          [scope.tenantId, artifactId, artifactVersion],
        );
        return artifactFromRow(result.rows[0]);
      },
      findToolCall(toolCallId) {
        return find(
          "aios_tool_call",
          "tool_call_id",
          toolCallId,
          toolCallFromRow,
          "FOR UPDATE",
        );
      },
      async listToolCallsByRun(runId) {
        const result = await client.query(
          `SELECT * FROM ${table("aios_tool_call")}
            WHERE tenant_id = $1 AND run_id = $2
            ORDER BY tool_call_id
            FOR SHARE`,
          [scope.tenantId, runId],
        );
        return Object.freeze(result.rows.map(toolCallFromRow));
      },
      async insertCase(value) {
        ensureTenant(value);
        const result = await client.query(
          `INSERT INTO ${table("aios_case")} (
             tenant_id, tenant_kind, case_id, state, version, goal_ref,
             created_at, updated_at
           ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
           RETURNING *`,
          [
            ...tenant,
            value.caseId,
            value.state,
            value.version,
            value.goalRef,
            value.createdAt,
            value.updatedAt,
          ],
        );
        return caseFromRow(result.rows[0]);
      },
      async insertThread(value) {
        const result = await client.query(
          `INSERT INTO ${table("aios_thread")} (
             tenant_id, tenant_kind, thread_id, case_id, state, version,
             purpose_ref, created_at, updated_at
           ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
           RETURNING *`,
          [
            ...tenant,
            value.threadId,
            value.caseId,
            value.state,
            value.version,
            value.purposeRef,
            value.createdAt,
            value.updatedAt,
          ],
        );
        return threadFromRow(result.rows[0]);
      },
      async insertArtifact(value) {
        const result = await client.query(
          `INSERT INTO ${table("aios_artifact")} (
             tenant_id, tenant_kind, artifact_id, case_id, thread_id,
             artifact_version, kind, content_ref, content_sha256, created_at
           ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
           RETURNING *`,
          [
            ...tenant,
            value.artifactId,
            value.caseId,
            value.threadId,
            value.artifactVersion,
            value.kind,
            value.contentRef,
            value.contentSha256,
            value.createdAt,
          ],
        );
        return artifactFromRow(result.rows[0]);
      },
      async insertRun(value) {
        const result = await client.query(
          `INSERT INTO ${table("aios_run")} (
             tenant_id, tenant_kind, run_id, case_id, thread_id, state,
             version, base_manifest, identity, authorization_evidence,
             tenant_lifecycle_version, result_artifact,
             reconstruction_hash, created_at, updated_at
           ) VALUES (
             $1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9::jsonb,$10::jsonb,
             $11,$12::jsonb,$13,$14,$15
           ) RETURNING *`,
          [
            ...tenant,
            value.runId,
            value.caseId,
            value.threadId,
            value.state,
            value.version,
            JSON.stringify(value.baseManifest),
            JSON.stringify(value.identity),
            JSON.stringify(value.authorization),
            value.tenantLifecycleVersion,
            value.resultArtifact === null
              ? null
              : JSON.stringify(value.resultArtifact),
            value.reconstructionHash,
            value.createdAt,
            value.updatedAt,
          ],
        );
        return runFromRow(result.rows[0]);
      },
      updateRun(value, expectedVersion) {
        return updateVersioned({
          name: "aios_run",
          idColumn: "run_id",
          id: value.runId,
          expectedVersion,
          value,
          assignments:
            `state=$4, version=$5, result_artifact=$6::jsonb,
             reconstruction_hash=$7, updated_at=$8`,
          parameters: [
            value.state,
            value.version,
            value.resultArtifact === null
              ? null
              : JSON.stringify(value.resultArtifact),
            value.reconstructionHash,
            value.updatedAt,
          ],
          mapper: runFromRow,
        });
      },
      async insertToolCall(value) {
        const result = await client.query(
          `INSERT INTO ${table("aios_tool_call")} (
             tenant_id, tenant_kind, tool_call_id, run_id, state, version,
             operation_ref, operation_version, request_hash, effect_key,
             compensation_ref, authorization_evidence, receipt_ref,
             receipt_hash, outcome, created_at, updated_at
           ) VALUES (
             $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb,$13,$14,
             $15,$16,$17
           ) RETURNING *`,
          [
            ...tenant,
            value.toolCallId,
            value.runId,
            value.state,
            value.version,
            value.operationRef,
            value.operationVersion,
            value.requestHash,
            value.effectKey,
            value.compensationRef,
            JSON.stringify(value.authorization),
            value.receiptRef,
            value.receiptHash,
            value.outcome,
            value.createdAt,
            value.updatedAt,
          ],
        );
        return toolCallFromRow(result.rows[0]);
      },
      updateToolCall(value, expectedVersion) {
        return updateVersioned({
          name: "aios_tool_call",
          idColumn: "tool_call_id",
          id: value.toolCallId,
          expectedVersion,
          value,
          assignments:
            `state=$4, version=$5, receipt_ref=$6, receipt_hash=$7,
             outcome=$8, updated_at=$9`,
          parameters: [
            value.state,
            value.version,
            value.receiptRef,
            value.receiptHash,
            value.outcome,
            value.updatedAt,
          ],
          mapper: toolCallFromRow,
        });
      },
      async appendEvent(value) {
        if (emittedEvents.has(value.eventId)) {
          fail("ID_COLLISION", "C08 DomainEvent was emitted twice.");
        }
        await client.query(
          `INSERT INTO ${table("domain_event")} (
             tenant_id, tenant_kind, event_id, idempotency_key,
             request_hash, effect_key, aggregate_type, aggregate_id,
             aggregate_version, event, created_at
           ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11)`,
          [
            ...tenant,
            value.eventId,
            metadata.idempotencyKey,
            metadata.requestHash,
            effectKey,
            value.aggregateType,
            value.aggregateId,
            value.aggregateVersion,
            JSON.stringify(value.event),
            value.createdAt,
          ],
        );
        emittedEvents.add(value.eventId);
      },
      async appendOutbox(value) {
        if (emittedOutbox.has(value.eventId)) {
          fail("ID_COLLISION", "C08 Outbox event was emitted twice.");
        }
        await client.query(
          `INSERT INTO ${table("outbox")} (
             tenant_id, tenant_kind, event_id, idempotency_key,
             request_hash, effect_key, event, created_at
           ) VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8)`,
          [
            ...tenant,
            value.eventId,
            metadata.idempotencyKey,
            metadata.requestHash,
            effectKey,
            JSON.stringify(value.event),
            value.createdAt,
          ],
        );
        emittedOutbox.add(value.eventId);
      },
    });
  }

  function replay(row, metadata, effectKey) {
    if (!row) return null;
    if (
      row.request_hash !== metadata.requestHash ||
      row.effect_key !== effectKey ||
      row.command_kind !== metadata.commandKind
    ) {
      fail(
        "IDEMPOTENCY_CONFLICT",
        "C08 idempotency key was reused with different input.",
      );
    }
    return jsonValue(row.result);
  }

  async function runCommand(scope, metadata, reducer) {
    validateScope(scope);
    validateCommand(metadata);
    if (typeof reducer !== "function") {
      fail("INVALID_INPUT", "C08 command reducer is required.");
    }
    const effectKey = deriveCommandEffectKey({
      tenantId: scope.tenantId,
      commandKind: metadata.commandKind,
      idempotencyKey: metadata.idempotencyKey,
    });
    let lastError;
    for (let attempt = 0; attempt <= maxSerializableRetries; attempt += 1) {
      try {
        return await runScoped(
          runtimePool,
          "aios_c08_runtime",
          scope,
          "BEGIN ISOLATION LEVEL SERIALIZABLE",
          async (client) => {
            const existing = await client.query(
              `SELECT request_hash, effect_key, command_kind, result
                 FROM ${table("command_receipt")}
                WHERE tenant_id = $1 AND idempotency_key = $2`,
              [scope.tenantId, metadata.idempotencyKey],
            );
            const previous = replay(existing.rows[0], metadata, effectKey);
            if (previous) {
              return Object.freeze({ duplicate: true, value: previous });
            }
            const emittedEvents = new Set();
            const emittedOutbox = new Set();
            const value = await reducer(
              transactionPort(
                client,
                scope,
                metadata,
                effectKey,
                emittedEvents,
                emittedOutbox,
              ),
            );
            if (
              !value ||
              typeof value !== "object" ||
              Array.isArray(value) ||
              emittedEvents.size !== 1 ||
              emittedEvents.size !== emittedOutbox.size ||
              [...emittedEvents].some((id) => !emittedOutbox.has(id))
            ) {
              fail(
                "EVIDENCE_PAIR_INVALID",
                "C08 command requires exact Event and Outbox evidence.",
              );
            }
            await client.query(
              `INSERT INTO ${table("command_receipt")} (
                 tenant_id, tenant_kind, idempotency_key, request_hash,
                 effect_key, command_kind, correlation_id, result
               ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb)`,
              [
                scope.tenantId,
                scope.tenantKind,
                metadata.idempotencyKey,
                metadata.requestHash,
                effectKey,
                metadata.commandKind,
                metadata.correlationId,
                JSON.stringify(value),
              ],
            );
            return Object.freeze({ duplicate: false, value });
          },
          JSON.stringify([
            scope.tenantId,
            metadata.idempotencyKey,
          ]),
        );
      } catch (error) {
        lastError = error;
        if (shouldRetry(error) && attempt < maxSerializableRetries) {
          await new Promise((resolve) =>
            setTimeout(
              resolve,
              retryDelay(metadata.idempotencyKey, attempt),
            ),
          );
          continue;
        }
        throw databaseFailure(error);
      }
    }
    throw databaseFailure(lastError);
  }

  async function readRun(scope, { runId }) {
    validateScope(scope);
    if (typeof runId !== "string" || !runId.trim()) {
      fail("INVALID_INPUT", "C08 Run ID is invalid.");
    }
    try {
      return await runScoped(
        runtimePool,
        "aios_c08_runtime",
        scope,
        "BEGIN ISOLATION LEVEL REPEATABLE READ",
        async (client) => {
          const runResult = await client.query(
            `SELECT * FROM ${table("aios_run")}
              WHERE tenant_id = $1 AND run_id = $2`,
            [scope.tenantId, runId],
          );
          const run = runFromRow(runResult.rows[0]);
          if (!run) return null;
          const caseResult = await client.query(
            `SELECT * FROM ${table("aios_case")}
              WHERE tenant_id=$1 AND case_id=$2`,
            [scope.tenantId, run.caseId],
          );
          const threadResult = await client.query(
            `SELECT * FROM ${table("aios_thread")}
              WHERE tenant_id=$1 AND thread_id=$2`,
            [scope.tenantId, run.threadId],
          );
          const inputRef = run.baseManifest?.inputArtifact;
          const inputResult = await client.query(
            `SELECT * FROM ${table("aios_artifact")}
              WHERE tenant_id=$1
                AND artifact_id=$2
                AND artifact_version=$3`,
            [
              scope.tenantId,
              inputRef?.artifactId ?? "",
              inputRef?.artifactVersion ?? 0,
            ],
          );
          let resultArtifact = null;
          if (run.resultArtifact) {
            const result = await client.query(
              `SELECT * FROM ${table("aios_artifact")}
                WHERE tenant_id=$1
                  AND artifact_id=$2
                  AND artifact_version=$3`,
              [
                scope.tenantId,
                run.resultArtifact.artifactId,
                run.resultArtifact.artifactVersion,
              ],
            );
            resultArtifact = artifactFromRow(result.rows[0]);
          }
          const toolCalls = await client.query(
            `SELECT * FROM ${table("aios_tool_call")}
              WHERE tenant_id=$1 AND run_id=$2
              ORDER BY tool_call_id`,
            [scope.tenantId, runId],
          );
          return Object.freeze({
            case: caseFromRow(caseResult.rows[0]),
            thread: threadFromRow(threadResult.rows[0]),
            run,
            inputArtifact: artifactFromRow(inputResult.rows[0]),
            resultArtifact,
            toolCalls: Object.freeze(
              toolCalls.rows.map(toolCallFromRow),
            ),
          });
        },
      );
    } catch (error) {
      throw databaseFailure(error);
    }
  }

  async function readCommandReceipt(
    scope,
    { idempotencyKey, requestHash, commandKind, correlationId },
  ) {
    validateScope(scope);
    const metadata = {
      idempotencyKey,
      requestHash,
      commandKind,
      correlationId,
    };
    validateCommand(metadata);
    const effectKey = deriveCommandEffectKey({
      tenantId: scope.tenantId,
      commandKind,
      idempotencyKey,
    });
    try {
      return await runScoped(
        runtimePool,
        "aios_c08_runtime",
        scope,
        "BEGIN ISOLATION LEVEL REPEATABLE READ",
        async (client) => {
          const result = await client.query(
            `SELECT request_hash, effect_key, command_kind, result
               FROM ${table("command_receipt")}
              WHERE tenant_id = $1 AND idempotency_key = $2`,
            [scope.tenantId, idempotencyKey],
          );
          return replay(result.rows[0], metadata, effectKey);
        },
      );
    } catch (error) {
      throw databaseFailure(error);
    }
  }

  async function readTenantSnapshot(scope) {
    validateScope(scope);
    try {
      return await runScoped(
        runtimePool,
        "aios_c08_runtime",
        scope,
        "BEGIN ISOLATION LEVEL REPEATABLE READ",
        async (client) => {
          const countsResult = await client.query(
            `SELECT
               (SELECT count(*) FROM ${table("aios_case")}
                 WHERE tenant_id=$1) AS cases,
               (SELECT count(*) FROM ${table("aios_thread")}
                 WHERE tenant_id=$1) AS threads,
               (SELECT count(*) FROM ${table("aios_run")}
                 WHERE tenant_id=$1) AS runs,
               (SELECT count(*) FROM ${table("aios_artifact")}
                 WHERE tenant_id=$1) AS artifacts,
               (SELECT count(*) FROM ${table("aios_tool_call")}
                 WHERE tenant_id=$1) AS tool_calls,
               (SELECT count(*) FROM ${table("domain_event")}
                 WHERE tenant_id=$1) AS events,
               (SELECT count(*) FROM ${table("outbox")}
                 WHERE tenant_id=$1) AS outbox,
               (SELECT count(*) FROM ${table("command_receipt")}
                 WHERE tenant_id=$1) AS receipts`,
            [scope.tenantId],
          );
          const runStates = await client.query(
            `SELECT state,count(*) AS count
               FROM ${table("aios_run")}
              WHERE tenant_id=$1 GROUP BY state ORDER BY state`,
            [scope.tenantId],
          );
          const toolCallStates = await client.query(
            `SELECT state,count(*) AS count
               FROM ${table("aios_tool_call")}
              WHERE tenant_id=$1 GROUP BY state ORDER BY state`,
            [scope.tenantId],
          );
          const outboxStates = await client.query(
            `SELECT
               CASE
                 WHEN status='PROCESSING' THEN 'LEASED'
                 WHEN status='FAILED' THEN 'PENDING'
                 ELSE status
               END AS state,
               count(*) AS count
               FROM ${table("outbox")}
              WHERE tenant_id=$1
              GROUP BY state
              ORDER BY state`,
            [scope.tenantId],
          );
          const stateCounts = (rows) =>
            Object.freeze(
              Object.fromEntries(
                rows.map((row) => [row.state, safeInteger(row.count)]),
              ),
            );
          const counts = countsResult.rows[0];
          return Object.freeze({
            tenantId: scope.tenantId,
            tenantKind: "SYNTHETIC",
            counts: Object.freeze({
              cases: safeInteger(counts.cases),
              threads: safeInteger(counts.threads),
              runs: safeInteger(counts.runs),
              artifacts: safeInteger(counts.artifacts),
              toolCalls: safeInteger(counts.tool_calls),
              events: safeInteger(counts.events),
              outbox: safeInteger(counts.outbox),
              receipts: safeInteger(counts.receipts),
            }),
            runStates: stateCounts(runStates.rows),
            toolCallStates: stateCounts(toolCallStates.rows),
            outboxStates: stateCounts(outboxStates.rows),
          });
        },
      );
    } catch (error) {
      throw databaseFailure(error);
    }
  }

  async function claimOutbox(scope, input) {
    validateScope(scope);
    const lease = validateLeaseInput(input);
    try {
      return await runScoped(
        outboxPool,
        "aios_c08_outbox_worker",
        scope,
        "BEGIN",
        async (client) => {
          const result = await client.query(
            `WITH candidates AS (
               SELECT tenant_id, event_id
                 FROM ${table("outbox")}
                WHERE tenant_id = $1
                  AND (
                    (
                      status IN ('PENDING','FAILED')
                      AND available_at <= $4::timestamptz
                    )
                    OR (
                      status = 'PROCESSING'
                      AND lease_until < $4::timestamptz
                    )
                  )
                ORDER BY created_at,event_id
                FOR UPDATE SKIP LOCKED
                LIMIT $2
             )
             UPDATE ${table("outbox")} AS record
                SET status='PROCESSING',
                    attempt_count=attempt_count+1,
                    lease_version=lease_version+1,
                    leased_by=$3,
                    lease_until=$5::timestamptz,
                    last_error_code=NULL
               FROM candidates
              WHERE record.tenant_id=candidates.tenant_id
                AND record.event_id=candidates.event_id
             RETURNING record.*`,
            [
              scope.tenantId,
              lease.limit,
              lease.workerId,
              lease.now,
              lease.leaseExpiresAt,
            ],
          );
          return Object.freeze(result.rows.map(outboxFromRow));
        },
      );
    } catch (error) {
      throw databaseFailure(error);
    }
  }

  async function completeOutbox(scope, receipt) {
    validateScope(scope);
    validateLeaseReceipt(receipt);
    try {
      return await runScoped(
        outboxPool,
        "aios_c08_outbox_worker",
        scope,
        "BEGIN",
        async (client) => {
          const result = await client.query(
            `UPDATE ${table("outbox")}
                SET status='PUBLISHED',
                    leased_by=NULL,
                    lease_until=NULL,
                    last_error_code=NULL,
                    published_at=$5::timestamptz
              WHERE tenant_id=$1
                AND event_id=$2
                AND leased_by=$3
                AND lease_version=$4
                AND lease_until>=$5::timestamptz
                AND lease_until>=statement_timestamp()
                AND status='PROCESSING'
             RETURNING *`,
            [
              scope.tenantId,
              receipt.eventId,
              receipt.workerId,
              receipt.leaseVersion,
              receipt.now,
            ],
          );
          if (result.rowCount !== 1) {
            fail("STALE_OUTBOX_LEASE", "C08 Outbox lease is stale.");
          }
          return outboxFromRow(result.rows[0]);
        },
      );
    } catch (error) {
      throw databaseFailure(error);
    }
  }

  async function failOutbox(scope, receipt) {
    validateScope(scope);
    validateLeaseReceipt(receipt);
    const {
      eventId,
      workerId,
      leaseVersion,
      now,
      retryAt,
      errorCode,
    } = receipt;
    if (
      typeof errorCode !== "string" ||
      !errorCode.trim() ||
      errorCode.length > 64 ||
      !isCanonicalInstant(retryAt) ||
      Date.parse(retryAt) <= Date.parse(now)
    ) {
      fail("INVALID_INPUT", "C08 Outbox failure input is invalid.");
    }
    try {
      return await runScoped(
        outboxPool,
        "aios_c08_outbox_worker",
        scope,
        "BEGIN",
        async (client) => {
          const result = await client.query(
            `UPDATE ${table("outbox")}
                SET status='FAILED',
                    available_at=$6::timestamptz,
                    leased_by=NULL,
                    lease_until=NULL,
                    last_error_code=$7,
                    published_at=NULL
              WHERE tenant_id=$1
                AND event_id=$2
                AND leased_by=$3
                AND lease_version=$4
                AND lease_until>=$5::timestamptz
                AND lease_until>=statement_timestamp()
                AND status='PROCESSING'
             RETURNING *`,
            [
              scope.tenantId,
              eventId,
              workerId,
              leaseVersion,
              now,
              retryAt,
              errorCode,
            ],
          );
          if (result.rowCount !== 1) {
            fail("STALE_OUTBOX_LEASE", "C08 Outbox lease is stale.");
          }
          return outboxFromRow(result.rows[0]);
        },
      );
    } catch (error) {
      throw databaseFailure(error);
    }
  }

  return Object.freeze({
    claimOutbox,
    completeOutbox,
    failOutbox,
    readCommandReceipt,
    readRun,
    readTenantSnapshot,
    runCommand,
  });
}
