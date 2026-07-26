import { randomUUID } from "node:crypto";
import {
  AgentOrchestratorError,
  c12Sha256,
} from "./agent-orchestrator.mjs";

const SAFE_IDENTIFIER = /^[a-z_][a-z0-9_]*$/;
const SHA256 = /^sha256:[a-f0-9]{64}$/;
const SYNTHETIC_TENANT_ID =
  /^stn_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const TASK_ID =
  /^tsk_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
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
const ROLE_NAMES = Object.freeze([
  "aios_c12_runtime",
  "aios_c12_owner",
  "aios_c07_scope_runtime",
  "aios_c07_data_runtime",
  "aios_c07_lifecycle_runtime",
  "aios_c07_restore_runtime",
  "aios_c07_owner",
]);
const SCOPE_FIELDS = Object.freeze([
  "trustSource",
  "tenantId",
  "humanPrincipalId",
  "workloadActorPrincipalId",
  "decisionId",
  "evidenceRef",
  "policyVersion",
  "correlationId",
]);
const STATE_FIELDS = Object.freeze([
  "schemaVersion",
  "tenantId",
  "tenantKind",
  "taskId",
  "taskRef",
  "inputRef",
  "inputSha256",
  "graphRef",
  "graphVersion",
  "graphSha256",
  "catalogBindingSha256",
  "ownerHumanPrincipalId",
  "workloadActorPrincipalId",
  "status",
  "nextNodeId",
  "version",
  "budget",
  "bindings",
  "nodeRecords",
  "humanDecision",
  "createdAt",
  "updatedAt",
  "stateSha256",
]);

export class PostgresAgentOrchestratorStatePortError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "PostgresAgentOrchestratorStatePortError";
    this.code = code;
  }
}

function fail(code, message) {
  throw new PostgresAgentOrchestratorStatePortError(code, message);
}

function clone(value) {
  return value === undefined ? undefined : structuredClone(value);
}

function deepFreeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) {
    return value;
  }
  for (const nested of Object.values(value)) deepFreeze(nested);
  return Object.freeze(value);
}

function json(value) {
  return typeof value === "string" ? JSON.parse(value) : value;
}

function safeInteger(value) {
  const number = Number(value);
  if (!Number.isSafeInteger(number)) {
    fail("INTEGRITY_VIOLATION", "C12 PostgreSQL integer is unsafe.");
  }
  return number;
}

function exactKeys(value, expected) {
  return (
    value &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.keys(value).length === expected.length &&
    Object.keys(value).every((key) => expected.includes(key))
  );
}

function nonEmpty(value, max) {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= max
  );
}

function canonicalInstant(value) {
  return (
    typeof value === "string" &&
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value) &&
    Number.isFinite(Date.parse(value)) &&
    new Date(value).toISOString() === value
  );
}

function validateScope(scope) {
  if (
    !exactKeys(scope, SCOPE_FIELDS) ||
    scope.trustSource !== "C12_AUTHORIZED_SCOPE" ||
    !SYNTHETIC_TENANT_ID.test(scope.tenantId ?? "") ||
    !nonEmpty(scope.humanPrincipalId, 256) ||
    !nonEmpty(scope.workloadActorPrincipalId, 256) ||
    !nonEmpty(scope.decisionId, 256) ||
    !nonEmpty(scope.evidenceRef, 512) ||
    !nonEmpty(scope.policyVersion, 256) ||
    !nonEmpty(scope.correlationId, 128)
  ) {
    fail("AUTHORIZATION_REQUIRED", "C12 requires an authorized scope.");
  }
  return scope;
}

function validateCommand(command, fields, operations) {
  if (
    !exactKeys(command, fields) ||
    !operations.includes(command.operation) ||
    !nonEmpty(command.idempotencyKey, 128) ||
    !SHA256.test(command.requestSha256 ?? "")
  ) {
    fail("INVALID_INPUT", "C12 State Port command is invalid.");
  }
  return command;
}

function validateTaskId(value) {
  if (!TASK_ID.test(value ?? "")) {
    fail("INVALID_INPUT", "C12 task ID is invalid.");
  }
}

function validateState(state) {
  if (
    !exactKeys(state, STATE_FIELDS) ||
    state.schemaVersion !== "c12-task-state.v1" ||
    state.tenantKind !== "SYNTHETIC" ||
    !SYNTHETIC_TENANT_ID.test(state.tenantId ?? "") ||
    !TASK_ID.test(state.taskId ?? "") ||
    !nonEmpty(state.ownerHumanPrincipalId, 256) ||
    !nonEmpty(state.workloadActorPrincipalId, 256) ||
    !Number.isSafeInteger(state.version) ||
    state.version < 1 ||
    !canonicalInstant(state.createdAt) ||
    !canonicalInstant(state.updatedAt) ||
    Date.parse(state.updatedAt) < Date.parse(state.createdAt) ||
    !SHA256.test(state.stateSha256 ?? "")
  ) {
    fail("INTEGRITY_VIOLATION", "C12 task state is invalid.");
  }
  const body = clone(state);
  delete body.stateSha256;
  let actual;
  try {
    actual = c12Sha256(body);
  } catch {
    fail("INTEGRITY_VIOLATION", "C12 task state is not canonical JSON.");
  }
  if (actual !== state.stateSha256) {
    fail("INTEGRITY_VIOLATION", "C12 task state hash is invalid.");
  }
  return state;
}

function ensureStateScope(scope, state) {
  if (
    state.tenantId !== scope.tenantId ||
    state.ownerHumanPrincipalId !== scope.humanPrincipalId ||
    state.workloadActorPrincipalId !== scope.workloadActorPrincipalId
  ) {
    fail("TENANT_SCOPE_VIOLATION", "C12 state escaped its owner scope.");
  }
}

function receiptBody(scope, command, state) {
  return {
    schemaVersion: "c12-state-port-receipt.v1",
    tenantId: scope.tenantId,
    humanPrincipalId: scope.humanPrincipalId,
    workloadActorPrincipalId: scope.workloadActorPrincipalId,
    taskId: state.taskId,
    operation: command.operation,
    idempotencyKey: command.idempotencyKey,
    requestSha256: command.requestSha256,
    resultVersion: state.version,
    resultStateSha256: state.stateSha256,
  };
}

function stateView(receipt, replayed) {
  const task = clone(receipt.task);
  const publicReceipt = clone(receipt);
  delete publicReceipt.task;
  return deepFreeze({
    task,
    replayed,
    receipt: publicReceipt,
  });
}

function receiptFromRow(row, scope, command, replayed) {
  if (!row) return null;
  const state = validateState(clone(json(row.task)));
  const body = {
    schemaVersion: "c12-state-port-receipt.v1",
    tenantId: row.tenant_id,
    humanPrincipalId: row.human_principal_id,
    workloadActorPrincipalId: row.workload_actor_principal_id,
    taskId: row.task_id,
    operation: row.operation,
    idempotencyKey: row.idempotency_key,
    requestSha256: row.request_sha256,
    resultVersion: safeInteger(row.result_version),
    resultStateSha256: row.result_state_sha256,
  };
  const receipt = {
    ...body,
    receiptSha256: row.receipt_sha256,
    task: state,
  };
  if (
    body.tenantId !== scope.tenantId ||
    body.humanPrincipalId !== scope.humanPrincipalId ||
    body.workloadActorPrincipalId !==
      scope.workloadActorPrincipalId ||
    body.operation !== command.operation ||
    body.idempotencyKey !== command.idempotencyKey
  ) {
    fail("INTEGRITY_VIOLATION", "C12 receipt scope is invalid.");
  }
  if (body.requestSha256 !== command.requestSha256) {
    fail("IDEMPOTENCY_CONFLICT", "C12 idempotency key was reused.");
  }
  if (
    body.taskId !== state.taskId ||
    body.resultVersion !== state.version ||
    body.resultStateSha256 !== state.stateSha256 ||
    !SHA256.test(receipt.receiptSha256 ?? "") ||
    receipt.receiptSha256 !== c12Sha256(body)
  ) {
    fail("INTEGRITY_VIOLATION", "C12 State Port receipt is unbound.");
  }
  ensureStateScope(scope, state);
  return stateView(receipt, replayed);
}

function databaseFailure(error) {
  if (
    error instanceof PostgresAgentOrchestratorStatePortError ||
    error instanceof AgentOrchestratorError
  ) {
    return error;
  }
  if (error?.code === "42501") {
    return new PostgresAgentOrchestratorStatePortError(
      "TENANT_SCOPE_VIOLATION",
      "PostgreSQL rejected the C12 Tenant scope.",
    );
  }
  if (error?.constraint === "task_state_pkey") {
    return new PostgresAgentOrchestratorStatePortError(
      "TASK_CONFLICT",
      "C12 task already exists.",
    );
  }
  if (
    error?.constraint === "command_receipt_pkey" ||
    error?.code === "23505"
  ) {
    return new PostgresAgentOrchestratorStatePortError(
      "IDEMPOTENCY_CONFLICT",
      "C12 idempotency key conflicts.",
    );
  }
  if (
    ["22P02", "22007", "23000", "23503", "23514"].includes(
      error?.code,
    )
  ) {
    return new PostgresAgentOrchestratorStatePortError(
      "INTEGRITY_VIOLATION",
      "C12 PostgreSQL invariant failed.",
    );
  }
  return new PostgresAgentOrchestratorStatePortError(
    "STORE_UNAVAILABLE",
    "C12 PostgreSQL storage operation failed.",
  );
}

function shouldRetry(error) {
  return RETRYABLE_SQL_STATES.has(error?.code);
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

async function rollback(client) {
  try {
    await client.query("ROLLBACK");
    return true;
  } catch {
    return false;
  }
}

export function createPostgresAgentOrchestratorStatePort({
  runtimePool,
  scopePool,
  tenantRegistry,
  schema = "aios_orchestration",
  scopeSchema = "aios_data",
  maxSerializableRetries = 10,
}) {
  if (
    typeof runtimePool?.connect !== "function" ||
    typeof scopePool?.connect !== "function" ||
    runtimePool === scopePool ||
    typeof tenantRegistry?.admitNewRequest !== "function" ||
    !SAFE_IDENTIFIER.test(schema) ||
    !SAFE_IDENTIFIER.test(scopeSchema) ||
    !Number.isSafeInteger(maxSerializableRetries) ||
    maxSerializableRetries < 0 ||
    maxSerializableRetries > 10
  ) {
    fail("INVALID_CONFIGURATION", "C12 PostgreSQL configuration is invalid.");
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
        client.release(
          new Error("C12 rejected an unsafe PostgreSQL role."),
        );
        client = null;
        fail(
          "INVALID_CONFIGURATION",
          "C12 PostgreSQL pool role is unsafe.",
        );
      }
      return client;
    } catch (error) {
      if (client) {
        client.release(
          new Error("C12 could not verify the PostgreSQL role."),
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
        "C12 PostgreSQL connection retained Tenant scope.",
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
      const signed = json(result.rows[0]?.signed_scope);
      if (
        !Number.isSafeInteger(Number(signed?.expires_epoch_ms)) ||
        !/^[a-f0-9]{64}$/.test(signed?.signature ?? "")
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

  async function resolveTenantScope(scope) {
    let admission;
    try {
      admission = await tenantRegistry.admitNewRequest({
        tenantId: scope.tenantId,
        expectedTenantKind: "SYNTHETIC",
      });
    } catch {
      fail(
        "TENANT_SCOPE_VIOLATION",
        "C12 Tenant admission was rejected.",
      );
    }
    if (
      admission?.trustSource !== "VERIFIED_SERVER_CONTEXT" ||
      admission.tenantId !== scope.tenantId ||
      admission.tenantKind !== "SYNTHETIC" ||
      !Number.isSafeInteger(admission.lifecycleVersion) ||
      admission.lifecycleVersion < 1
    ) {
      fail(
        "TENANT_SCOPE_VIOLATION",
        "C12 Tenant admission is invalid.",
      );
    }
    return {
      trustSource: "C07_VERIFIED_TENANT_SCOPE",
      tenantId: scope.tenantId,
      tenantKind: "SYNTHETIC",
      lifecycleVersion: admission.lifecycleVersion,
      correlationId: scope.correlationId,
      decisionId: scope.decisionId,
      evidenceRef: scope.evidenceRef,
      policyVersion: scope.policyVersion,
    };
  }

  async function runScoped(
    scope,
    begin,
    reducer,
    sessionLockKey = null,
  ) {
    const client = await connect(runtimePool, "aios_c12_runtime");
    let started = false;
    let discard = false;
    let sessionLockAcquired = false;
    try {
      if (sessionLockKey !== null) {
        await client.query(
          "SELECT pg_advisory_lock(hashtextextended($1, 0))",
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
          "C12 PostgreSQL runtime fence was not acquired.",
        );
      }
      const value = await reducer(client);
      await client.query("COMMIT");
      started = false;
      await assertScopeCleared(client);
      return value;
    } catch (error) {
      discard = shouldDiscard(error);
      if (started && !(await rollback(client))) discard = true;
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
            "SELECT pg_advisory_unlock(hashtextextended($1, 0)) AS unlocked",
            [sessionLockKey],
          );
          if (unlocked.rows[0]?.unlocked !== true) discard = true;
        } catch {
          discard = true;
        }
      }
      client.release(
        discard
          ? new Error("C12 discarded an unsafe PostgreSQL connection.")
          : undefined,
      );
    }
  }

  async function read(scope, reducer) {
    try {
      return await runScoped(
        scope,
        "BEGIN ISOLATION LEVEL REPEATABLE READ",
        reducer,
      );
    } catch (error) {
      throw databaseFailure(error);
    }
  }

  async function mutate(
    scope,
    authorizedScope,
    idempotencyKey,
    reducer,
  ) {
    let lastError;
    const lockKey = JSON.stringify([
      scope.tenantId,
      authorizedScope.humanPrincipalId,
      authorizedScope.workloadActorPrincipalId,
      idempotencyKey,
    ]);
    for (let attempt = 0; attempt <= maxSerializableRetries; attempt += 1) {
      try {
        return await runScoped(
          scope,
          "BEGIN ISOLATION LEVEL SERIALIZABLE",
          reducer,
          lockKey,
        );
      } catch (error) {
        lastError = error;
        if (shouldRetry(error) && attempt < maxSerializableRetries) {
          await new Promise((resolve) =>
            setTimeout(
              resolve,
              retryDelay(idempotencyKey, attempt),
            ),
          );
          continue;
        }
        throw databaseFailure(error);
      }
    }
    throw databaseFailure(lastError);
  }

  async function selectReceipt(client, scope, command) {
    const result = await client.query(
      `SELECT tenant_id,tenant_kind,human_principal_id,
              workload_actor_principal_id,idempotency_key,operation,
              request_sha256,task_id,result_version,
              result_state_sha256,receipt_sha256,task
         FROM ${table("command_receipt")}
        WHERE tenant_id=$1
          AND human_principal_id=$2
          AND workload_actor_principal_id=$3
          AND idempotency_key=$4`,
      [
        scope.tenantId,
        scope.humanPrincipalId,
        scope.workloadActorPrincipalId,
        command.idempotencyKey,
      ],
    );
    return receiptFromRow(result.rows[0], scope, command, true);
  }

  async function insertReceipt(client, scope, command, state) {
    const body = receiptBody(scope, command, state);
    const receipt = {
      ...body,
      receiptSha256: c12Sha256(body),
      task: clone(state),
    };
    await client.query(
      `INSERT INTO ${table("command_receipt")} (
         tenant_id,tenant_kind,human_principal_id,
         workload_actor_principal_id,idempotency_key,operation,
         request_sha256,task_id,result_version,result_state_sha256,
         receipt_sha256,task
       ) VALUES (
         $1,'SYNTHETIC',$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb
       )`,
      [
        scope.tenantId,
        scope.humanPrincipalId,
        scope.workloadActorPrincipalId,
        command.idempotencyKey,
        command.operation,
        command.requestSha256,
        state.taskId,
        state.version,
        state.stateSha256,
        receipt.receiptSha256,
        JSON.stringify(state),
      ],
    );
    return stateView(receipt, false);
  }

  return Object.freeze({
    async replay(authorizedScope, command) {
      const scope = validateScope(authorizedScope);
      validateCommand(
        command,
        ["operation", "idempotencyKey", "requestSha256"],
        ["START", "ADVANCE", "RESUME_HUMAN_DECISION"],
      );
      const tenantScope = await resolveTenantScope(scope);
      return read(tenantScope, (client) =>
        selectReceipt(client, scope, command),
      );
    },

    async create(authorizedScope, command) {
      const scope = validateScope(authorizedScope);
      validateCommand(
        command,
        ["operation", "idempotencyKey", "requestSha256", "state"],
        ["START"],
      );
      const state = validateState(command.state);
      ensureStateScope(scope, state);
      if (state.version !== 1) {
        fail("INTEGRITY_VIOLATION", "C12 task must start at version one.");
      }
      const tenantScope = await resolveTenantScope(scope);
      return mutate(
        tenantScope,
        scope,
        command.idempotencyKey,
        async (client) => {
          const prior = await selectReceipt(client, scope, command);
          if (prior) return prior;
          await client.query(
            `INSERT INTO ${table("task_state")} (
               tenant_id,tenant_kind,task_id,human_principal_id,
               workload_actor_principal_id,version,state_sha256,task,
               created_at,updated_at
             ) VALUES (
               $1,'SYNTHETIC',$2,$3,$4,$5,$6,$7::jsonb,$8,$9
             )`,
            [
              scope.tenantId,
              state.taskId,
              scope.humanPrincipalId,
              scope.workloadActorPrincipalId,
              state.version,
              state.stateSha256,
              JSON.stringify(state),
              state.createdAt,
              state.updatedAt,
            ],
          );
          return insertReceipt(client, scope, command, state);
        },
      );
    },

    async get(authorizedScope, taskId) {
      const scope = validateScope(authorizedScope);
      validateTaskId(taskId);
      const tenantScope = await resolveTenantScope(scope);
      return read(tenantScope, async (client) => {
        const result = await client.query(
          `SELECT tenant_id,tenant_kind,task_id,human_principal_id,
                  workload_actor_principal_id,version,state_sha256,task
             FROM ${table("task_state")}
            WHERE tenant_id=$1 AND task_id=$2`,
          [scope.tenantId, taskId],
        );
        const row = result.rows[0];
        if (!row) return null;
        const state = validateState(clone(json(row.task)));
        if (
          row.tenant_id !== state.tenantId ||
          row.tenant_kind !== state.tenantKind ||
          row.task_id !== state.taskId ||
          safeInteger(row.version) !== state.version ||
          row.state_sha256 !== state.stateSha256
        ) {
          fail("INTEGRITY_VIOLATION", "C12 stored task is unbound.");
        }
        if (
          row.human_principal_id !== scope.humanPrincipalId ||
          row.workload_actor_principal_id !==
            scope.workloadActorPrincipalId
        ) {
          fail("ACCESS_DENIED", "C12 task owner does not match.");
        }
        ensureStateScope(scope, state);
        return deepFreeze(clone(state));
      });
    },

    async transact(authorizedScope, command) {
      const scope = validateScope(authorizedScope);
      validateCommand(
        command,
        [
          "operation",
          "taskId",
          "expectedVersion",
          "idempotencyKey",
          "requestSha256",
          "reduce",
        ],
        ["ADVANCE", "RESUME_HUMAN_DECISION"],
      );
      validateTaskId(command.taskId);
      if (
        !Number.isSafeInteger(command.expectedVersion) ||
        command.expectedVersion < 1
      ) {
        fail("INVALID_INPUT", "C12 expected version is invalid.");
      }
      const tenantScope = await resolveTenantScope(scope);
      return mutate(
        tenantScope,
        scope,
        command.idempotencyKey,
        async (client) => {
          const prior = await selectReceipt(client, scope, command);
          if (prior) return prior;
          const result = await client.query(
            `SELECT tenant_id,tenant_kind,task_id,human_principal_id,
                    workload_actor_principal_id,version,state_sha256,task
               FROM ${table("task_state")}
              WHERE tenant_id=$1 AND task_id=$2
              FOR UPDATE`,
            [scope.tenantId, command.taskId],
          );
          const row = result.rows[0];
          if (!row) {
            fail("TASK_NOT_FOUND", "C12 task was not found.");
          }
          const current = validateState(clone(json(row.task)));
          if (
            row.tenant_id !== current.tenantId ||
            row.tenant_kind !== current.tenantKind ||
            row.task_id !== current.taskId ||
            safeInteger(row.version) !== current.version ||
            row.state_sha256 !== current.stateSha256
          ) {
            fail("INTEGRITY_VIOLATION", "C12 stored task is unbound.");
          }
          if (
            row.human_principal_id !== scope.humanPrincipalId ||
            row.workload_actor_principal_id !==
              scope.workloadActorPrincipalId
          ) {
            fail("ACCESS_DENIED", "C12 task owner does not match.");
          }
          if (current.version !== command.expectedVersion) {
            fail("VERSION_CONFLICT", "C12 task version changed.");
          }
          if (typeof command.reduce !== "function") {
            fail(
              "INVALID_INPUT",
              "C12 transition reducer is required.",
            );
          }
          const next = command.reduce(deepFreeze(clone(current)));
          if (typeof next?.then === "function") {
            fail(
              "INVALID_INPUT",
              "C12 transition reducer must be synchronous.",
            );
          }
          validateState(next);
          if (
            next.tenantId !== current.tenantId ||
            next.tenantKind !== current.tenantKind ||
            next.taskId !== current.taskId ||
            next.ownerHumanPrincipalId !==
              current.ownerHumanPrincipalId ||
            next.workloadActorPrincipalId !==
              current.workloadActorPrincipalId ||
            next.createdAt !== current.createdAt ||
            next.version !== current.version + 1
          ) {
            fail(
              "INTEGRITY_VIOLATION",
              "C12 transition changed task identity.",
            );
          }
          const updated = await client.query(
            `UPDATE ${table("task_state")}
                SET version=$3,state_sha256=$4,task=$5::jsonb,
                    updated_at=$6
              WHERE tenant_id=$1 AND task_id=$2 AND version=$7
              RETURNING version`,
            [
              scope.tenantId,
              command.taskId,
              next.version,
              next.stateSha256,
              JSON.stringify(next),
              next.updatedAt,
              command.expectedVersion,
            ],
          );
          if (updated.rowCount !== 1) {
            fail("VERSION_CONFLICT", "C12 task version changed.");
          }
          return insertReceipt(client, scope, command, next);
        },
      );
    },
  });
}
