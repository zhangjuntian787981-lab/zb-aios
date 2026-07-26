import { randomUUID } from "node:crypto";
import {
  ModelGatewayError,
} from "./model-gateway.mjs";

const SAFE_IDENTIFIER = /^[a-z_][a-z0-9_]*$/;
const SYNTHETIC_TENANT_ID =
  /^stn_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const RETRYABLE = new Set(["40001", "40P01"]);
const ROLE_NAMES = Object.freeze([
  "aios_c14_runtime",
  "aios_c14_owner",
  "aios_c07_scope_runtime",
  "aios_c07_data_runtime",
  "aios_c07_lifecycle_runtime",
  "aios_c07_restore_runtime",
  "aios_c07_owner",
]);

export class PostgresModelGatewayStoreError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "PostgresModelGatewayStoreError";
    this.code = code;
  }
}

function fail(code, message) {
  throw new PostgresModelGatewayStoreError(code, message);
}

function jsonValue(value) {
  return typeof value === "string" ? JSON.parse(value) : value;
}

function safeInteger(value) {
  const number = Number(value);
  if (!Number.isSafeInteger(number)) {
    fail("STORE_UNAVAILABLE", "PostgreSQL returned an unsafe integer.");
  }
  return number;
}

function instant(value) {
  return value instanceof Date ? value.toISOString() : value;
}

function routeFromRow(row) {
  if (!row) return null;
  return Object.freeze({
    routeId: row.route_id,
    tenantId: row.tenant_id,
    tenantKind: row.tenant_kind,
    status: row.status,
    version: safeInteger(row.version),
    idempotencyKey: row.idempotency_key,
    requestHash: row.request_hash,
    correlationId: row.correlation_id,
    taskRef: row.task_ref,
    inputRef: row.input_ref,
    inputSha256: row.input_sha256,
    dataClassification: row.data_classification,
    requiredPlane: row.required_plane,
    tenantRegion: row.tenant_region,
    catalogVersion: row.catalog_version,
    catalogSha256: row.catalog_sha256,
    tenantPolicyVersion: row.tenant_policy_version,
    authorizationEvidence: jsonValue(row.authorization_evidence),
    identityBinding: jsonValue(row.identity_binding),
    evaluatedCandidates: jsonValue(row.evaluated_candidates),
    candidateBindings: jsonValue(row.candidate_bindings),
    selectedModel: jsonValue(row.selected_model),
    attemptReceipts: jsonValue(row.attempt_receipts),
    responseRef: row.response_ref,
    responseSha256: row.response_sha256,
    usage: jsonValue(row.usage),
    rateVersion: row.rate_version,
    costMicrousd:
      row.cost_microusd === null
        ? null
        : safeInteger(row.cost_microusd),
    failureCode: row.failure_code,
    reservedInputTokens: safeInteger(row.reserved_input_tokens),
    reservedOutputTokens: safeInteger(row.reserved_output_tokens),
    reservedCostMicrousd: safeInteger(row.reserved_cost_microusd),
    createdAt: instant(row.created_at),
    updatedAt: instant(row.updated_at),
  });
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
    fail("TENANT_SCOPE_VIOLATION", "C14 requires C07 Tenant scope.");
  }
}

function validateMetadata(metadata) {
  if (
    typeof metadata?.idempotencyKey !== "string" ||
    !metadata.idempotencyKey ||
    metadata.idempotencyKey.length > 256 ||
    !SHA256.test(metadata?.requestHash ?? "") ||
    typeof metadata?.correlationId !== "string" ||
    !metadata.correlationId
  ) {
    fail("INVALID_INPUT", "C14 route metadata is invalid.");
  }
}

function databaseFailure(error) {
  if (
    error instanceof PostgresModelGatewayStoreError ||
    error instanceof ModelGatewayError
  ) {
    return error;
  }
  if (error?.code === "42501") {
    return new PostgresModelGatewayStoreError(
      "TENANT_SCOPE_VIOLATION",
      "PostgreSQL rejected the C14 Tenant scope.",
    );
  }
  if (error?.constraint === "model_route_transition_guard") {
    return new PostgresModelGatewayStoreError(
      "STALE_VERSION",
      "C14 route transition is stale.",
    );
  }
  if (error?.constraint === "model_route_delete_guard") {
    return new PostgresModelGatewayStoreError(
      "APPEND_ONLY_VIOLATION",
      "C14 route history cannot be deleted.",
    );
  }
  if (["23503", "23514", "23000"].includes(error?.code)) {
    return new PostgresModelGatewayStoreError(
      "INTEGRITY_VIOLATION",
      "C14 PostgreSQL invariant failed.",
    );
  }
  return new PostgresModelGatewayStoreError(
    "STORE_UNAVAILABLE",
    "C14 PostgreSQL storage operation failed.",
  );
}

async function rollback(client) {
  try {
    await client.query("ROLLBACK");
  } catch {
    // Preserve the first error.
  }
}

export function createPostgresModelGatewayStore({
  runtimePool,
  scopePool,
  schema = "aios_model",
  scopeSchema = "aios_data",
  maxSerializableRetries = 5,
}) {
  if (
    typeof runtimePool?.connect !== "function" ||
    typeof scopePool?.connect !== "function" ||
    runtimePool === scopePool ||
    !SAFE_IDENTIFIER.test(schema) ||
    !SAFE_IDENTIFIER.test(scopeSchema) ||
    !Number.isSafeInteger(maxSerializableRetries) ||
    maxSerializableRetries < 0 ||
    maxSerializableRetries > 10
  ) {
    fail("INVALID_CONFIGURATION", "C14 PostgreSQL pools are invalid.");
  }
  const table = `"${schema}"."model_route"`;
  const scopeFunction =
    `"${scopeSchema}"."issue_runtime_scope_signature"`;
  const fenceFunction = `"${scopeSchema}"."acquire_runtime_fence"`;

  async function connect(pool, requiredRole) {
    let client;
    try {
      client = await pool.connect();
      const memberships = ROLE_NAMES.map(
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
                ${memberships}
           FROM identity
           JOIN pg_roles active ON active.rolname = identity.current_name
           JOIN pg_roles login ON login.rolname = identity.session_name`,
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
        client.release(new Error("C14 rejected an unsafe database role."));
        client = null;
        fail(
          "INVALID_CONFIGURATION",
          "C14 PostgreSQL pool role is unsafe.",
        );
      }
      return client;
    } catch (error) {
      if (client) {
        client.release(
          new Error("C14 could not verify the database role."),
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
        "C14 PostgreSQL connection retained Tenant scope.",
      );
    }
  }

  async function issueSignature(scope, backendPid, transactionId) {
    const client = await connect(
      scopePool,
      "aios_c07_scope_runtime",
    );
    try {
      const nonce = randomUUID();
      const result = await client.query(
        `SELECT ${scopeFunction}(
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

  async function scoped(scope, begin, reducer) {
    validateScope(scope);
    const client = await connect(runtimePool, "aios_c14_runtime");
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
      const signed = await issueSignature(
        scope,
        backendPid,
        transactionId,
      );
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
      const fence = await client.query(
        `SELECT ${fenceFunction}() AS acquired`,
      );
      if (fence.rows[0]?.acquired !== true) {
        fail(
          "TENANT_SCOPE_VIOLATION",
          "C14 PostgreSQL runtime fence was not acquired.",
        );
      }
      const value = await reducer(client);
      await client.query("COMMIT");
      started = false;
      await assertScopeCleared(client);
      return value;
    } catch (error) {
      discard =
        error?.code === "57P01" ||
        (typeof error?.code === "string" &&
          error.code.startsWith("08"));
      if (started) await rollback(client);
      if (!discard) {
        try {
          await assertScopeCleared(client);
        } catch {
          discard = true;
        }
      }
      throw error;
    } finally {
      client.release(
        discard ? new Error("C14 discarded a failed connection.") : undefined,
      );
    }
  }

  async function retrySerializable(operation) {
    for (let attempt = 0; ; attempt += 1) {
      try {
        return await operation();
      } catch (error) {
        if (
          !RETRYABLE.has(error?.code) ||
          attempt >= maxSerializableRetries
        ) {
          throw databaseFailure(error);
        }
        await new Promise((resolve) =>
          setTimeout(resolve, Math.min(5 * 2 ** attempt, 50)),
        );
      }
    }
  }

  return Object.freeze({
    async prepareRoute(scope, metadata, record, quota) {
      validateMetadata(metadata);
      if (
        record?.tenantId !== scope?.tenantId ||
        record?.tenantKind !== "SYNTHETIC" ||
        record?.status !== "PREPARED" ||
        record?.version !== 1 ||
        !Number.isSafeInteger(quota?.dailyTokenLimit) ||
        !Number.isSafeInteger(quota?.dailyCostMicrousdLimit)
      ) {
        fail("INVALID_INPUT", "C14 prepared route is invalid.");
      }
      return retrySerializable(() =>
        scoped(
          scope,
          "BEGIN ISOLATION LEVEL SERIALIZABLE",
          async (client) => {
            await client.query(
              `SELECT pg_advisory_xact_lock(
                 hashtextextended($1 || ':' || $2, 0)
               )`,
              [scope.tenantId, record.createdAt.slice(0, 10)],
            );
            const existing = await client.query(
              `SELECT * FROM ${table}
                WHERE tenant_id=$1 AND idempotency_key=$2`,
              [scope.tenantId, metadata.idempotencyKey],
            );
            if (existing.rowCount === 1) {
              const route = routeFromRow(existing.rows[0]);
              if (route.requestHash !== metadata.requestHash) {
                fail(
                  "IDEMPOTENCY_CONFLICT",
                  "C14 idempotency key has another request hash.",
                );
              }
              return { duplicate: true, route };
            }
            const usage = await client.query(
              `SELECT
                 COALESCE(SUM(
                   CASE
                     WHEN status='SUCCEEDED'
                     THEN (usage->>'totalTokens')::bigint
                     ELSE reserved_input_tokens + reserved_output_tokens
                   END
                 ),0)::text AS tokens,
                 COALESCE(SUM(
                   CASE
                     WHEN status='SUCCEEDED' THEN cost_microusd
                     ELSE reserved_cost_microusd
                   END
                 ),0)::text AS cost
               FROM ${table}
              WHERE tenant_id=$1
                AND status <> 'FAILED'
                AND created_at >= $2::date
                AND created_at < ($2::date + INTERVAL '1 day')`,
              [scope.tenantId, record.createdAt.slice(0, 10)],
            );
            const tokens = safeInteger(usage.rows[0].tokens);
            const cost = safeInteger(usage.rows[0].cost);
            if (
              tokens +
                  record.reservedInputTokens +
                  record.reservedOutputTokens >
                quota.dailyTokenLimit ||
              cost + record.reservedCostMicrousd >
                quota.dailyCostMicrousdLimit
            ) {
              fail("QUOTA_EXCEEDED", "C14 Tenant quota is exhausted.");
            }
            const values = [
              record.tenantId,
              record.tenantKind,
              record.routeId,
              record.status,
              record.version,
              record.idempotencyKey,
              record.requestHash,
              record.correlationId,
              record.taskRef,
              record.inputRef,
              record.inputSha256,
              record.dataClassification,
              record.requiredPlane,
              record.tenantRegion,
              record.catalogVersion,
              record.catalogSha256,
              record.tenantPolicyVersion,
              JSON.stringify(record.authorizationEvidence),
              JSON.stringify(record.identityBinding),
              JSON.stringify(record.evaluatedCandidates),
              JSON.stringify(record.candidateBindings),
              record.reservedInputTokens,
              record.reservedOutputTokens,
              record.reservedCostMicrousd,
              record.createdAt,
              record.updatedAt,
            ];
            const inserted = await client.query(
              `INSERT INTO ${table} (
                 tenant_id,tenant_kind,route_id,status,version,
                 idempotency_key,request_hash,correlation_id,task_ref,
                 input_ref,input_sha256,data_classification,required_plane,
                 tenant_region,catalog_version,catalog_sha256,
                 tenant_policy_version,authorization_evidence,
                 identity_binding,evaluated_candidates,candidate_bindings,
                 reserved_input_tokens,reserved_output_tokens,
                 reserved_cost_microusd,created_at,updated_at
               ) VALUES (
                 $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,
                 $16,$17,$18::jsonb,$19::jsonb,$20::jsonb,$21::jsonb,
                 $22,$23,$24,$25,$26
               ) RETURNING *`,
              values,
            );
            return {
              duplicate: false,
              route: routeFromRow(inserted.rows[0]),
            };
          },
        ),
      );
    },
    async completeRoute(scope, routeId, expectedVersion, completion) {
      return retrySerializable(() =>
        scoped(scope, "BEGIN", async (client) => {
          const updated = await client.query(
            `UPDATE ${table}
                SET status='SUCCEEDED',
                    version=version+1,
                    selected_model=$4::jsonb,
                    attempt_receipts=$5::jsonb,
                    response_ref=$6,
                    response_sha256=$7,
                    usage=$8::jsonb,
                    rate_version=$9,
                    cost_microusd=$10,
                    updated_at=$11
              WHERE tenant_id=$1
                AND route_id=$2
                AND status='PREPARED'
                AND version=$3
            RETURNING *`,
            [
              scope.tenantId,
              routeId,
              expectedVersion,
              JSON.stringify(completion.selectedModel),
              JSON.stringify(completion.attemptReceipts),
              completion.responseRef,
              completion.responseSha256,
              JSON.stringify(completion.usage),
              completion.rateVersion,
              completion.costMicrousd,
              completion.updatedAt,
            ],
          );
          if (updated.rowCount === 1) {
            return routeFromRow(updated.rows[0]);
          }
          const existing = await client.query(
            `SELECT * FROM ${table}
              WHERE tenant_id=$1 AND route_id=$2`,
            [scope.tenantId, routeId],
          );
          const route = routeFromRow(existing.rows[0]);
          if (route?.status === "SUCCEEDED") return route;
          fail("STALE_VERSION", "C14 route version is stale.");
        }),
      );
    },
    async failRoute(scope, routeId, expectedVersion, failure) {
      return retrySerializable(() =>
        scoped(scope, "BEGIN", async (client) => {
          const updated = await client.query(
            `UPDATE ${table}
                SET status='FAILED',
                    version=version+1,
                    attempt_receipts=$4::jsonb,
                    failure_code=$5,
                    updated_at=$6
              WHERE tenant_id=$1
                AND route_id=$2
                AND status='PREPARED'
                AND version=$3
            RETURNING *`,
            [
              scope.tenantId,
              routeId,
              expectedVersion,
              JSON.stringify(failure.attemptReceipts),
              failure.failureCode,
              failure.updatedAt,
            ],
          );
          if (updated.rowCount === 1) {
            return routeFromRow(updated.rows[0]);
          }
          const existing = await client.query(
            `SELECT * FROM ${table}
              WHERE tenant_id=$1 AND route_id=$2`,
            [scope.tenantId, routeId],
          );
          const route = routeFromRow(existing.rows[0]);
          if (route?.status === "FAILED") return route;
          fail("STALE_VERSION", "C14 route version is stale.");
        }),
      );
    },
    async readRoute(scope, routeId) {
      try {
        return await scoped(
          scope,
          "BEGIN",
          async (client) => {
            const result = await client.query(
              `SELECT * FROM ${table}
                WHERE tenant_id=$1 AND route_id=$2`,
              [scope.tenantId, routeId],
            );
            return routeFromRow(result.rows[0]);
          },
        );
      } catch (error) {
        throw databaseFailure(error);
      }
    },
  });
}
