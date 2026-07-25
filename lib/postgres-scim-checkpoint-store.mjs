import { AsyncLocalStorage } from "node:async_hooks";
import { createHash } from "node:crypto";

const SAFE_IDENTIFIER = /^[a-z_][a-z0-9_]*$/;
const TENANT_ID =
  /^stn_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const PROVIDER_CONNECTION_ID =
  /^idp_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const EXTERNAL_ID = /^[A-Za-z0-9._:@/+~-]+$/;
const USER_NAME = /^[A-Za-z0-9._@+-]+$/;
const RESOURCE_ID = /^[A-Za-z0-9._~-]+$/;
const ACCOUNT_STATES = new Set(["ACTIVE", "SUSPENDED", "TERMINATED"]);
const CHECKPOINT_STATUSES = new Set(["PENDING", "CONFIRMED"]);

export class PostgresScimCheckpointStoreError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "PostgresScimCheckpointStoreError";
    this.code = code;
  }
}

function fail(code, message) {
  throw new PostgresScimCheckpointStoreError(code, message);
}

function unavailable() {
  return new PostgresScimCheckpointStoreError(
    "CHECKPOINT_STORE_UNAVAILABLE",
    "SCIM checkpoint storage operation failed.",
  );
}

function validText(value, maximum, pattern) {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= maximum &&
    (!pattern || pattern.test(value))
  );
}

function validateExternalId(value) {
  if (!validText(value, 256, EXTERNAL_ID)) {
    fail("INVALID_CHECKPOINT", "SCIM checkpoint externalId is invalid.");
  }
}

function exactKeys(value, allowed) {
  return (
    value &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.keys(value).every((key) => allowed.includes(key)) &&
    allowed.every((key) => Object.hasOwn(value, key))
  );
}

function validateCheckpoint(value, externalId) {
  if (
    !exactKeys(value, [
      "externalId",
      "userName",
      "sourceRevision",
      "desiredState",
      "profile",
      "status",
      "resourceId",
    ]) ||
    value.externalId !== externalId ||
    !validText(value.userName, 128, USER_NAME) ||
    !Number.isSafeInteger(value.sourceRevision) ||
    value.sourceRevision < 1 ||
    !ACCOUNT_STATES.has(value.desiredState) ||
    !CHECKPOINT_STATUSES.has(value.status) ||
    (value.resourceId !== null &&
      !validText(value.resourceId, 128, RESOURCE_ID)) ||
    !exactKeys(value.profile, ["givenName", "familyName", "email"]) ||
    !validText(value.profile.givenName, 128) ||
    !validText(value.profile.familyName, 128) ||
    !validText(value.profile.email, 254, /^[^\s@]+@[^\s@]+$/)
  ) {
    fail("INVALID_CHECKPOINT", "SCIM checkpoint is invalid.");
  }
}

function advisoryKey({ tenantId, providerConnectionId }, externalId) {
  return createHash("sha256")
    .update("c04-scim-checkpoint\0")
    .update(tenantId)
    .update("\0")
    .update(providerConnectionId)
    .update("\0")
    .update(externalId)
    .digest()
    .readBigInt64BE(0)
    .toString();
}

function checkpointFromRow(row) {
  if (!row) return null;
  const profile =
    typeof row.profile === "string" ? JSON.parse(row.profile) : row.profile;
  return {
    externalId: row.external_id,
    userName: row.user_name,
    sourceRevision: Number(row.source_revision),
    desiredState: row.desired_state,
    profile,
    status: row.status,
    resourceId: row.resource_id,
  };
}

async function rollback(client) {
  try {
    await client.query("ROLLBACK");
  } catch {
    // Preserve the original storage or reducer failure.
  }
}

export function createPostgresScimCheckpointStore({
  pool,
  tenantId,
  providerConnectionId,
  schema = "aios_core",
}) {
  if (
    typeof pool?.connect !== "function" ||
    !SAFE_IDENTIFIER.test(schema) ||
    !validText(tenantId, 64, TENANT_ID) ||
    !validText(providerConnectionId, 64, PROVIDER_CONNECTION_ID)
  ) {
    fail(
      "INVALID_CHECKPOINT_STORE",
      "A PostgreSQL pool, trusted namespace, and safe schema are required.",
    );
  }

  const namespace = Object.freeze({ tenantId, providerConnectionId });
  const checkpoints = `"${schema}"."scim_provisioning_checkpoint"`;
  const lockContext = new AsyncLocalStorage();

  async function transact(externalId, reducer) {
    validateExternalId(externalId);
    if (typeof reducer !== "function") {
      fail("INVALID_CHECKPOINT", "SCIM checkpoint reducer is required.");
    }
    const context = lockContext.getStore();
    if (
      !context ||
      context.active !== true ||
      context.externalId !== externalId
    ) {
      fail(
        "CHECKPOINT_LOCK_REQUIRED",
        "SCIM checkpoint transaction requires its exclusive lock.",
      );
    }

    const { client } = context;
    let reducerFailure;
    try {
      await client.query("BEGIN");
      const selected = await client.query(
        `SELECT external_id,
                user_name,
                source_revision,
                desired_state,
                profile,
                status,
                resource_id
           FROM ${checkpoints}
          WHERE tenant_id = $1
            AND provider_connection_id = $2
            AND external_id = $3
          FOR UPDATE`,
        [namespace.tenantId, namespace.providerConnectionId, externalId],
      );
      const current = checkpointFromRow(selected.rows[0]);
      let reduced;
      try {
        reduced = reducer(
          current === null ? null : structuredClone(current),
        );
      } catch (error) {
        reducerFailure = error;
        throw error;
      }
      if (
        !exactKeys(reduced, ["next", "value"]) ||
        reduced?.next === null
      ) {
        fail(
          "INVALID_CHECKPOINT",
          "SCIM checkpoint reducer result is invalid.",
        );
      }
      validateCheckpoint(reduced.next, externalId);
      const next = reduced.next;
      const parameters = [
        namespace.tenantId,
        namespace.providerConnectionId,
        next.externalId,
        next.userName,
        next.sourceRevision,
        next.desiredState,
        next.profile,
        next.status,
        next.resourceId,
      ];

      if (current === null) {
        await client.query(
          `INSERT INTO ${checkpoints} (
             tenant_id,
             provider_connection_id,
             external_id,
             user_name,
             source_revision,
             desired_state,
             profile,
             status,
             resource_id,
             created_at,
             updated_at
           )
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9,
                   statement_timestamp(), statement_timestamp())`,
          parameters,
        );
      } else {
        const updated = await client.query(
          `UPDATE ${checkpoints}
              SET user_name = $4,
                  source_revision = $5,
                  desired_state = $6,
                  profile = $7,
                  status = $8,
                  resource_id = $9,
                  updated_at = statement_timestamp()
            WHERE tenant_id = $1
              AND provider_connection_id = $2
              AND external_id = $3`,
          parameters,
        );
        if (updated.rowCount !== 1) throw unavailable();
      }
      await client.query("COMMIT");
      return structuredClone(reduced.value);
    } catch (error) {
      await rollback(client);
      if (
        error === reducerFailure ||
        error instanceof PostgresScimCheckpointStoreError
      ) {
        throw error;
      }
      throw unavailable();
    }
  }

  async function runExclusive(externalId, operation) {
    validateExternalId(externalId);
    if (typeof operation !== "function") {
      fail("INVALID_CHECKPOINT", "SCIM checkpoint operation is required.");
    }
    if (lockContext.getStore()?.active === true) {
      fail(
        "CHECKPOINT_LOCK_REQUIRED",
        "Nested SCIM checkpoint locks are not supported.",
      );
    }

    let client;
    try {
      client = await pool.connect();
    } catch {
      throw unavailable();
    }

    const key = advisoryKey(namespace, externalId);
    try {
      await client.query("SELECT pg_advisory_lock($1::bigint)", [key]);
    } catch {
      client.release(true);
      throw unavailable();
    }

    let value;
    let operationFailure;
    const context = { client, externalId, active: true };
    try {
      value = await lockContext.run(
        context,
        operation,
      );
    } catch (error) {
      operationFailure = error;
    }
    context.active = false;

    let unlockFailure = false;
    try {
      const unlocked = await client.query(
        "SELECT pg_advisory_unlock($1::bigint) AS unlocked",
        [key],
      );
      unlockFailure = unlocked.rows[0]?.unlocked !== true;
    } catch {
      unlockFailure = true;
    }
    client.release(unlockFailure);

    if (operationFailure) throw operationFailure;
    if (unlockFailure) throw unavailable();
    return value;
  }

  return Object.freeze({ transact, runExclusive });
}
