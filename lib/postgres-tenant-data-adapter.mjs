import { randomUUID } from "node:crypto";
import { TenantDataIsolationError } from "./tenant-data-boundary.mjs";

const SAFE_IDENTIFIER = /^[a-z_][a-z0-9_]*$/;
const UUID_V7 =
  "[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}";
const SYNTHETIC_TENANT_ID = new RegExp(`^stn_${UUID_V7}$`);
const EXPECTED_STATE = Object.freeze({
  "product.tenant.provisioning-requested.v1": "PROVISIONING",
  "product.tenant.activated.v1": "ACTIVE",
  "product.tenant.suspended.v1": "SUSPENDED",
  "product.tenant.resume-requested.v1": "PROVISIONING",
  "product.tenant.deletion-requested.v1": "DELETING",
  "product.tenant.deleted.v1": "DELETED",
});

function fail(code, message) {
  throw new TenantDataIsolationError(code, message);
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

function databaseError(error) {
  if (error instanceof TenantDataIsolationError) return error;
  if (error?.code === "42501" || error?.code === "23503") {
    return new TenantDataIsolationError(
      "TENANT_SCOPE_VIOLATION",
      "PostgreSQL Tenant scope rejected the operation.",
    );
  }
  if (["22023", "22P02", "22003"].includes(error?.code)) {
    return new TenantDataIsolationError(
      "INVALID_INPUT",
      "PostgreSQL input is invalid.",
    );
  }
  if (error?.code === "23505") {
    return new TenantDataIsolationError(
      "LIFECYCLE_EVENT_CONFLICT",
      "Lifecycle evidence conflicts with stored evidence.",
    );
  }
  if (error?.code === "P0701") {
    return new TenantDataIsolationError(
      "INVALID_LIFECYCLE_EVENT",
      "PostgreSQL lifecycle evidence is invalid.",
    );
  }
  if (error?.code === "P0702") {
    return new TenantDataIsolationError(
      "STALE_LIFECYCLE_EVENT",
      "PostgreSQL lifecycle evidence is stale.",
    );
  }
  if (error?.code === "P0703") {
    return new TenantDataIsolationError(
      "LIFECYCLE_EVENT_CONFLICT",
      "PostgreSQL lifecycle evidence conflicts with stored evidence.",
    );
  }
  return new TenantDataIsolationError(
    "STORE_UNAVAILABLE",
    "PostgreSQL storage operation failed.",
  );
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
    fail("TENANT_SCOPE_VIOLATION", "PostgreSQL scope is not C07 verified.");
  }
}

function validateLifecycleEvent(event) {
  const expectedState = EXPECTED_STATE[event?.type];
  if (
    !expectedState ||
    event?.specversion !== "1.0" ||
    event?.source !== "/aios-core/tenant-registry" ||
    event?.subject !== event?.data?.tenant_id ||
    event?.tenantkind !== "SYNTHETIC" ||
    event?.synthetic !== true ||
    expectedState !== event?.data?.state ||
    !SYNTHETIC_TENANT_ID.test(event?.subject ?? "") ||
    !Number.isSafeInteger(event?.data?.lifecycle_version) ||
    event.data.lifecycle_version < 1 ||
    !Number.isSafeInteger(event?.data?.generation) ||
    event.data.generation < 1 ||
    typeof event?.data?.operation_id !== "string" ||
    !event.data.operation_id ||
    typeof event?.id !== "string" ||
    !event.id
  ) {
    fail("INVALID_LIFECYCLE_EVENT", "PostgreSQL lifecycle event is invalid.");
  }
  return expectedState;
}

function validateVector(value) {
  if (
    !Array.isArray(value) ||
    value.length < 1 ||
    value.length > 2048 ||
    value.some((item) => typeof item !== "number" || !Number.isFinite(item))
  ) {
    fail("INVALID_INPUT", "Embedding is invalid.");
  }
  return `[${value.join(",")}]`;
}

function validateLimit(value) {
  if (!Number.isSafeInteger(value) || value < 1 || value > 100) {
    fail("INVALID_INPUT", "Query limit is invalid.");
  }
}

async function rollback(client) {
  try {
    await client.query("ROLLBACK");
  } catch {
    // Preserve the original failure and discard the connection below.
  }
}

export function createPostgresTenantDataAdapter({
  runtimePool,
  scopePool,
  lifecyclePool = runtimePool,
  controlPool = lifecyclePool,
  schema = "aios_data",
  readOnly = false,
}) {
  if (
    typeof runtimePool?.connect !== "function" ||
    typeof scopePool?.connect !== "function" ||
    typeof lifecyclePool?.connect !== "function" ||
    typeof controlPool?.connect !== "function" ||
    runtimePool === scopePool ||
    (
      !readOnly &&
      (runtimePool === lifecyclePool || scopePool === lifecyclePool)
    ) ||
    typeof readOnly !== "boolean" ||
    !SAFE_IDENTIFIER.test(schema)
  ) {
    fail("INVALID_CONFIGURATION", "C07 PostgreSQL pools are invalid.");
  }
  const table = (name) => `"${schema}"."${name}"`;
  const runtimeSignatureFunction =
    `"${schema}"."issue_runtime_scope_signature"`;
  const lifecycleProjectionFunction =
    `"${schema}"."project_tenant_lifecycle_event"`;

  async function connect(pool, requiredRole) {
    let client;
    try {
      client = await pool.connect();
      const result = await client.query(
        `WITH identity AS (
           SELECT current_user::text AS current_user_name,
                  session_user::text AS session_user_name
         )
         SELECT
           identity.current_user_name,
           identity.session_user_name,
           active_role.rolsuper AS current_super,
           active_role.rolbypassrls AS current_bypassrls,
           login_role.rolsuper AS session_super,
           login_role.rolbypassrls AS session_bypassrls,
           pg_has_role(
             identity.current_user_name,
             'aios_c07_data_runtime',
             'MEMBER'
           ) AS current_data_member,
           pg_has_role(
             identity.current_user_name,
             'aios_c07_scope_runtime',
             'MEMBER'
           ) AS current_scope_member,
           pg_has_role(
             identity.current_user_name,
             'aios_c07_lifecycle_runtime',
             'MEMBER'
           ) AS current_lifecycle_member,
           pg_has_role(
             identity.current_user_name,
             'aios_c07_restore_runtime',
             'MEMBER'
           ) AS current_restore_member,
           pg_has_role(
             identity.current_user_name,
             'aios_c07_owner',
             'MEMBER'
           ) AS current_owner_member,
           pg_has_role(
             identity.session_user_name,
             'aios_c07_data_runtime',
             'MEMBER'
           ) AS session_data_member,
           pg_has_role(
             identity.session_user_name,
             'aios_c07_scope_runtime',
             'MEMBER'
           ) AS session_scope_member,
           pg_has_role(
             identity.session_user_name,
             'aios_c07_lifecycle_runtime',
             'MEMBER'
           ) AS session_lifecycle_member,
           pg_has_role(
             identity.session_user_name,
             'aios_c07_restore_runtime',
             'MEMBER'
           ) AS session_restore_member,
           pg_has_role(
             identity.session_user_name,
             'aios_c07_owner',
             'MEMBER'
           ) AS session_owner_member
           FROM identity
           JOIN pg_roles AS active_role
             ON active_role.rolname = identity.current_user_name
           JOIN pg_roles AS login_role
             ON login_role.rolname = identity.session_user_name`,
      );
      const attributes = result.rows[0];
      const expectedMembership = {
        data: requiredRole === "aios_c07_data_runtime",
        scope: requiredRole === "aios_c07_scope_runtime",
        lifecycle:
          requiredRole === "aios_c07_lifecycle_runtime",
        restore: requiredRole === "aios_c07_restore_runtime",
      };
      if (
        !attributes ||
        attributes.current_super ||
        attributes.current_bypassrls ||
        attributes.session_super ||
        attributes.session_bypassrls ||
        attributes.current_owner_member ||
        attributes.session_owner_member ||
        Object.entries(expectedMembership).some(
          ([name, expected]) =>
            attributes[`current_${name}_member`] !== expected ||
            attributes[`session_${name}_member`] !== expected,
        )
      ) {
        client.release(
          new Error("C07 rejected an unsafe PostgreSQL role."),
        );
        client = null;
        fail(
          "INVALID_CONFIGURATION",
          "PostgreSQL pool role is unsafe.",
        );
      }
      return client;
    } catch (error) {
      if (client) {
        client.release(
          new Error("C07 could not verify the PostgreSQL role."),
        );
      }
      throw databaseError(error);
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
    const row = result.rows[0];
    if (
      Object.values(row).some((value) => value !== null && value !== "")
    ) {
      fail(
        "CONNECTION_CONTEXT_LEAK",
        "PostgreSQL connection retained Tenant scope.",
      );
    }
  }

  async function issueRuntimeSignature(scope, backendPid, transactionId) {
    const client = await connect(scopePool, "aios_c07_scope_runtime");
    try {
      const nonce = randomUUID();
      const result = await client.query(
        `SELECT ${runtimeSignatureFunction}(
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
        !/^[a-f0-9]{64}$/.test(signed?.signature ?? "")
      ) {
        fail(
          "TENANT_SCOPE_VIOLATION",
          "PostgreSQL scope signature is invalid.",
        );
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
    scope,
    reducer,
    isolation = "",
    signedRuntime = false,
    configureLifecycleScope = true,
  ) {
    let requiredRole = "aios_c07_lifecycle_runtime";
    if (signedRuntime) {
      requiredRole = readOnly
        ? "aios_c07_restore_runtime"
        : "aios_c07_data_runtime";
    }
    const client = await connect(pool, requiredRole);
    let started = false;
    let discard = false;
    try {
      if (signedRuntime && readOnly) {
        const setting = await client.query(
          "SHOW default_transaction_read_only",
        );
        if (setting.rows[0]?.default_transaction_read_only !== "on") {
          fail(
            "INVALID_CONFIGURATION",
            "Read-only Adapter requires a read-only PostgreSQL endpoint.",
          );
        }
      }
      await client.query(`BEGIN${isolation}`);
      started = true;
      if (signedRuntime) {
        const transaction = await client.query(
          `SELECT pg_backend_pid() AS backend_pid,
                  pg_current_xact_id()::text AS transaction_id`,
        );
        const backendPid = transaction.rows[0].backend_pid;
        const transactionId = transaction.rows[0].transaction_id;
        const signed = await issueRuntimeSignature(
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
        if (!readOnly) {
          const fence = await client.query(
            `SELECT "${schema}"."acquire_runtime_fence"() AS acquired`,
          );
          if (fence.rows[0]?.acquired !== true) {
            fail(
              "TENANT_SCOPE_VIOLATION",
              "PostgreSQL runtime fence was not acquired.",
            );
          }
        }
      } else if (configureLifecycleScope) {
        await client.query(
          `SELECT set_config('aios.tenant_id', $1, true),
                  set_config('aios.tenant_kind', $2, true),
                  set_config('aios.lifecycle_version', $3, true),
                  set_config('aios.correlation_id', $4, true)`,
          [
            scope.tenantId,
            scope.tenantKind,
            String(scope.lifecycleVersion),
            scope.correlationId,
          ],
        );
      }
      const result = await reducer(client);
      await client.query("COMMIT");
      started = false;
      await assertScopeCleared(client);
      return result;
    } catch (error) {
      if (started) await rollback(client);
      try {
        await assertScopeCleared(client);
      } catch {
        discard = true;
      }
      throw databaseError(error);
    } finally {
      client.release(discard ? new Error("C07 context cleanup failed.") : undefined);
    }
  }

  async function execute(scope, operation) {
    validateScope(scope);
    if (readOnly && operation.mode !== "READ") {
      fail("STORE_UNAVAILABLE", "PostgreSQL endpoint is read-only.");
    }
    const parameters = [scope.tenantId, scope.tenantKind];
    const { input } = operation;
    return runScoped(runtimePool, scope, async (client) => {
      if (operation.kind === "SQL_PUT") {
        const result = await client.query(
          `INSERT INTO ${table("tenant_sql_record")} (
             tenant_id, tenant_kind, resource_id, value
           ) VALUES ($1, $2, $3, $4::jsonb)
           ON CONFLICT (tenant_id, resource_id)
           DO UPDATE SET value = EXCLUDED.value,
                         updated_at = statement_timestamp()
           RETURNING resource_id, value, updated_at`,
          [...parameters, operation.resourceId, JSON.stringify(input.value)],
        );
        return Object.freeze({
          resourceId: result.rows[0].resource_id,
          value: jsonValue(result.rows[0].value),
          updatedAt: result.rows[0].updated_at.toISOString(),
        });
      }
      if (operation.kind === "SQL_GET") {
        const result = await client.query(
          `SELECT resource_id, value, updated_at
             FROM ${table("tenant_sql_record")}
            WHERE tenant_id = $1
              AND tenant_kind = $2
              AND resource_id = $3`,
          [...parameters, operation.resourceId],
        );
        if (!result.rows[0]) return null;
        return Object.freeze({
          resourceId: result.rows[0].resource_id,
          value: jsonValue(result.rows[0].value),
          updatedAt: result.rows[0].updated_at.toISOString(),
        });
      }
      if (operation.kind === "VECTOR_UPSERT") {
        const embedding = validateVector(input.embedding);
        const result = await client.query(
          `INSERT INTO ${table("tenant_vector_record")} (
             tenant_id, tenant_kind, resource_id, embedding, metadata
           ) VALUES ($1, $2, $3, $4::vector, $5::jsonb)
           ON CONFLICT (tenant_id, resource_id)
           DO UPDATE SET embedding = EXCLUDED.embedding,
                         metadata = EXCLUDED.metadata,
                         updated_at = statement_timestamp()
           RETURNING resource_id, metadata, updated_at`,
          [
            ...parameters,
            operation.resourceId,
            embedding,
            JSON.stringify(input.metadata),
          ],
        );
        return Object.freeze({
          resourceId: result.rows[0].resource_id,
          metadata: jsonValue(result.rows[0].metadata),
          updatedAt: result.rows[0].updated_at.toISOString(),
        });
      }
      if (operation.kind === "VECTOR_SEARCH") {
        validateLimit(input.limit);
        const embedding = validateVector(input.embedding);
        const result = await client.query(
          `SELECT resource_id,
                  metadata,
                  embedding <=> $3::vector AS distance
             FROM ${table("tenant_vector_record")}
            WHERE tenant_id = $1
              AND tenant_kind = $2
            ORDER BY embedding <=> $3::vector, resource_id
            LIMIT $4`,
          [...parameters, embedding, input.limit],
        );
        return Object.freeze(
          result.rows.map((row) =>
            Object.freeze({
              resourceId: row.resource_id,
              metadata: jsonValue(row.metadata),
              distance: Number(row.distance),
            }),
          ),
        );
      }
      if (operation.kind === "SEARCH_INDEX") {
        if (
          typeof input.text !== "string" ||
          !input.text ||
          input.text.length > 1_048_576
        ) {
          fail("INVALID_INPUT", "Search text is invalid.");
        }
        const result = await client.query(
          `INSERT INTO ${table("tenant_search_record")} (
             tenant_id, tenant_kind, resource_id, content, metadata
           ) VALUES ($1, $2, $3, $4, $5::jsonb)
           ON CONFLICT (tenant_id, resource_id)
           DO UPDATE SET content = EXCLUDED.content,
                         metadata = EXCLUDED.metadata,
                         updated_at = statement_timestamp()
           RETURNING resource_id, metadata, updated_at`,
          [
            ...parameters,
            operation.resourceId,
            input.text,
            JSON.stringify(input.metadata),
          ],
        );
        return Object.freeze({
          resourceId: result.rows[0].resource_id,
          metadata: jsonValue(result.rows[0].metadata),
          updatedAt: result.rows[0].updated_at.toISOString(),
        });
      }
      if (operation.kind === "SEARCH_QUERY") {
        if (
          typeof input.query !== "string" ||
          !input.query ||
          input.query.length > 1024
        ) {
          fail("INVALID_INPUT", "Search query is invalid.");
        }
        validateLimit(input.limit);
        const result = await client.query(
          `SELECT resource_id,
                  metadata,
                  ts_rank(
                    search_document,
                    plainto_tsquery('simple', $3)
                  ) AS rank
             FROM ${table("tenant_search_record")}
            WHERE tenant_id = $1
              AND tenant_kind = $2
              AND search_document @@ plainto_tsquery('simple', $3)
            ORDER BY rank DESC, resource_id
            LIMIT $4`,
          [...parameters, input.query, input.limit],
        );
        return Object.freeze(
          result.rows.map((row) =>
            Object.freeze({
              resourceId: row.resource_id,
              metadata: jsonValue(row.metadata),
              rank: Number(row.rank),
            }),
          ),
        );
      }
      if (operation.kind === "CACHE_PUT") {
        if (
          typeof input.cacheKey !== "string" ||
          !input.cacheKey ||
          input.cacheKey.length > 256 ||
          !Number.isSafeInteger(input.ttlSeconds) ||
          input.ttlSeconds < 1 ||
          input.ttlSeconds > 86_400
        ) {
          fail("INVALID_INPUT", "Cache input is invalid.");
        }
        const result = await client.query(
          `INSERT INTO ${table("tenant_cache_record")} (
             tenant_id, tenant_kind, cache_key, value, expires_at
           ) VALUES (
             $1, $2, $3, $4::jsonb,
             statement_timestamp() + ($5 * interval '1 second')
           )
           ON CONFLICT (tenant_id, cache_key)
           DO UPDATE SET value = EXCLUDED.value,
                         expires_at = EXCLUDED.expires_at,
                         updated_at = statement_timestamp()
           RETURNING cache_key, expires_at`,
          [
            ...parameters,
            input.cacheKey,
            JSON.stringify(input.value),
            input.ttlSeconds,
          ],
        );
        return Object.freeze({
          cacheKey: result.rows[0].cache_key,
          expiresAt: result.rows[0].expires_at.toISOString(),
        });
      }
      if (operation.kind === "CACHE_GET") {
        if (
          typeof input.cacheKey !== "string" ||
          !input.cacheKey ||
          input.cacheKey.length > 256
        ) {
          fail("INVALID_INPUT", "Cache key is invalid.");
        }
        const result = await client.query(
          `SELECT cache_key, value, expires_at
             FROM ${table("tenant_cache_record")}
            WHERE tenant_id = $1
              AND tenant_kind = $2
              AND cache_key = $3
              AND expires_at > statement_timestamp()`,
          [...parameters, input.cacheKey],
        );
        if (!result.rows[0]) return null;
        return Object.freeze({
          cacheKey: result.rows[0].cache_key,
          value: jsonValue(result.rows[0].value),
          expiresAt: result.rows[0].expires_at.toISOString(),
        });
      }
      fail("UNKNOWN_OPERATION", "PostgreSQL operation is not registered.");
    }, "", true);
  }

  async function project(event) {
    if (readOnly) {
      fail(
        "STORE_UNAVAILABLE",
        "Read-only PostgreSQL endpoint cannot project lifecycle events.",
      );
    }
    const nextState = validateLifecycleEvent(event);
    const scope = {
      tenantId: event.subject,
      tenantKind: "SYNTHETIC",
      lifecycleVersion: event.data.lifecycle_version,
      correlationId: event.correlationid,
    };
    return runScoped(
      lifecyclePool,
      scope,
      async (client) => {
        const projected = await client.query(
          `SELECT ${lifecycleProjectionFunction}($1) AS receipt`,
          [event.id],
        );
        const receipt = jsonValue(projected.rows[0]?.receipt);
        const lifecycleVersion = safeInteger(receipt?.lifecycleVersion);
        const generation = safeInteger(receipt?.generation);
        if (
          receipt?.tenantId !== event.subject ||
          receipt?.eventId !== event.id ||
          lifecycleVersion !== event.data.lifecycle_version ||
          generation !== event.data.generation ||
          receipt?.operationId !== event.data.operation_id ||
          receipt?.state !== nextState ||
          receipt?.status !== "SUCCEEDED" ||
          typeof receipt?.duplicate !== "boolean"
        ) {
          fail(
            "STORE_UNAVAILABLE",
            "PostgreSQL lifecycle projection receipt is invalid.",
          );
        }
        return Object.freeze({
          tenantId: receipt.tenantId,
          eventId: receipt.eventId,
          lifecycleVersion,
          generation,
          operationId: receipt.operationId,
          state: receipt.state,
          status: receipt.status,
          duplicate: receipt.duplicate,
        });
      },
      " ISOLATION LEVEL READ COMMITTED",
      false,
      false,
    );
  }

  async function snapshot() {
    fail(
      "STORE_UNAVAILABLE",
      "PostgreSQL lifecycle runtime snapshots are retired.",
    );
  }

  return Object.freeze({
    id: "c07.postgres",
    paths: Object.freeze(["SQL", "VECTOR", "SEARCH", "CACHE", "POOL"]),
    execute,
    project,
    snapshot,
  });
}
