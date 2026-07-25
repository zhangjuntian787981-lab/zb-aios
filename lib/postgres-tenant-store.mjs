import {
  TenantRegistryError,
} from "./tenant-registry.mjs";

const SAFE_IDENTIFIER = /^[a-z_][a-z0-9_]*$/;
const TRANSIENT_SQL_STATES = new Set(["23505", "40001", "40P01"]);

function fail(code, message) {
  throw new TenantRegistryError(code, message);
}

function jsonValue(value) {
  return typeof value === "string" ? JSON.parse(value) : value;
}

function iso(value) {
  return value instanceof Date ? value.toISOString() : value;
}

function tenantFromRow(row) {
  return {
    tenantId: row.tenant_id,
    tenantKind: row.tenant_kind,
    state: row.state,
    lifecycleVersion: Number(row.lifecycle_version),
    generation: Number(row.generation),
    creationKey: row.creation_key,
    fixtureRef: {
      fixtureId: row.origin_ref.replace(/^fixture:\/\//, ""),
      sha256: row.origin_hash,
    },
    configRefs: jsonValue(row.config_refs),
    resourceNamespaceId: row.resource_namespace_id,
    operationId: row.operation_id,
    createdAt: iso(row.created_at),
    updatedAt: iso(row.updated_at),
  };
}

function projectionFromRow(row) {
  return {
    tenantId: row.tenant_id,
    generation: Number(row.generation),
    projection: row.projection,
    desiredAction: row.desired_action,
    status: row.status,
    attemptCount: row.attempt_count,
    lastErrorCode: row.last_error_code,
    sourceEventId: row.source_event_id,
    updatedAt: iso(row.updated_at),
  };
}

async function rollback(client) {
  try {
    await client.query("ROLLBACK");
  } catch {
    // The original failure is more useful than a rollback failure.
  }
}

function storeFailure(error) {
  if (error instanceof TenantRegistryError) return error;
  return new TenantRegistryError(
    "STORE_UNAVAILABLE",
    "Tenant Registry storage operation failed.",
  );
}

export function createPostgresTenantStore({
  pool,
  schema = "aios_core",
  maxSerializableRetries = 3,
}) {
  if (!pool?.connect || !SAFE_IDENTIFIER.test(schema)) {
    fail("INVALID_STORE", "A PostgreSQL pool and safe schema are required.");
  }
  if (
    !Number.isInteger(maxSerializableRetries) ||
    maxSerializableRetries < 0 ||
    maxSerializableRetries > 10
  ) {
    fail("INVALID_STORE", "Invalid serializable retry limit.");
  }

  const table = (name) => `"${schema}"."${name}"`;

  async function connect() {
    try {
      return await pool.connect();
    } catch (error) {
      throw storeFailure(error);
    }
  }

  function transactionPort(client) {
    return Object.freeze({
      async findTenantByCreationKey(creationKey) {
        const result = await client.query(
          `SELECT *
             FROM ${table("tenant_registry")}
            WHERE creation_key = $1
            FOR UPDATE`,
          [creationKey],
        );
        return result.rows[0] ? tenantFromRow(result.rows[0]) : null;
      },

      async findTenantByOrigin(fixtureRef) {
        const result = await client.query(
          `SELECT *
             FROM ${table("tenant_registry")}
            WHERE origin_ref = $1 AND origin_hash = $2
            FOR UPDATE`,
          [`fixture://${fixtureRef.fixtureId}`, fixtureRef.sha256],
        );
        return result.rows[0] ? tenantFromRow(result.rows[0]) : null;
      },

      async loadTenantForUpdate(tenantId) {
        const result = await client.query(
          `SELECT *
             FROM ${table("tenant_registry")}
            WHERE tenant_id = $1
            FOR UPDATE`,
          [tenantId],
        );
        return result.rows[0] ? tenantFromRow(result.rows[0]) : null;
      },

      async insertTenant(tenant) {
        await client.query(
          `INSERT INTO ${table("tenant_registry")} (
             tenant_id,
             tenant_kind,
             state,
             lifecycle_version,
             generation,
             creation_key,
             origin_ref,
             origin_hash,
             config_refs,
             resource_namespace_id,
             operation_id,
             created_at,
             updated_at
           ) VALUES (
             $1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, $10, $11, $12, $13
           )`,
          [
            tenant.tenantId,
            tenant.tenantKind,
            tenant.state,
            tenant.lifecycleVersion,
            tenant.generation,
            tenant.creationKey,
            `fixture://${tenant.fixtureRef.fixtureId}`,
            tenant.fixtureRef.sha256,
            JSON.stringify(tenant.configRefs),
            tenant.resourceNamespaceId,
            tenant.operationId,
            tenant.createdAt,
            tenant.updatedAt,
          ],
        );
      },

      async updateTenant(tenant, previousVersion) {
        const result = await client.query(
          `UPDATE ${table("tenant_registry")}
              SET state = $1,
                  lifecycle_version = $2,
                  generation = $3,
                  config_refs = $4::jsonb,
                  operation_id = $5,
                  updated_at = $6
            WHERE tenant_id = $7
              AND lifecycle_version = $8`,
          [
            tenant.state,
            tenant.lifecycleVersion,
            tenant.generation,
            JSON.stringify(tenant.configRefs),
            tenant.operationId,
            tenant.updatedAt,
            tenant.tenantId,
            previousVersion,
          ],
        );
        if (result.rowCount !== 1) {
          fail("STALE_VERSION", "Tenant state changed; reload before retrying.");
        }
      },

      async loadProjections(tenantId, generation) {
        const result = await client.query(
          `SELECT *
             FROM ${table("tenant_projection")}
            WHERE tenant_id = $1 AND generation = $2
            ORDER BY projection`,
          [tenantId, generation],
        );
        return result.rows.map(projectionFromRow);
      },

      async replaceProjections(tenantId, generation, projections) {
        await client.query(
          `DELETE FROM ${table("tenant_projection")}
            WHERE tenant_id = $1 AND generation = $2`,
          [tenantId, generation],
        );
        for (const projection of projections) {
          await client.query(
            `INSERT INTO ${table("tenant_projection")} (
               tenant_id,
               generation,
               projection,
               desired_action,
               status,
               attempt_count,
               last_error_code,
               source_event_id,
               updated_at
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
            [
              projection.tenantId,
              projection.generation,
              projection.projection,
              projection.desiredAction,
              projection.status,
              projection.attemptCount,
              projection.lastErrorCode,
              projection.sourceEventId,
              projection.updatedAt,
            ],
          );
        }
      },

      async appendLifecycleEvent(event) {
        await client.query(
          `INSERT INTO ${table("tenant_lifecycle_event")} (
             event_id, tenant_id, tenant_kind, event, created_at
           ) VALUES ($1, $2, $3, $4::jsonb, $5)`,
          [
            event.id,
            event.subject,
            event.tenantkind,
            JSON.stringify(event),
            event.time,
          ],
        );
      },

      async appendOutbox(event) {
        await client.query(
          `INSERT INTO ${table("tenant_outbox")} (
             event_id, tenant_id, tenant_kind, event, created_at
           ) VALUES ($1, $2, $3, $4::jsonb, $5)`,
          [
            event.id,
            event.subject,
            event.tenantkind,
            JSON.stringify(event),
            event.time,
          ],
        );
      },
    });
  }

  async function runCommand(
    { idempotencyKey, commandHash },
    reducer,
  ) {
    let lastError;
    for (let attempt = 0; attempt <= maxSerializableRetries; attempt += 1) {
      const client = await connect();
      try {
        await client.query("BEGIN ISOLATION LEVEL SERIALIZABLE");
        const existing = await client.query(
          `SELECT command_hash, result
             FROM ${table("tenant_command_receipt")}
            WHERE idempotency_key = $1`,
          [idempotencyKey],
        );
        if (existing.rows[0]) {
          if (existing.rows[0].command_hash !== commandHash) {
            fail(
              "IDEMPOTENCY_CONFLICT",
              "The idempotency key was used for another command.",
            );
          }
          await client.query("COMMIT");
          return {
            duplicate: true,
            value: jsonValue(existing.rows[0].result),
          };
        }

        const value = await reducer(transactionPort(client));
        await client.query(
          `INSERT INTO ${table("tenant_command_receipt")} (
             idempotency_key, command_hash, result
           ) VALUES ($1, $2, $3::jsonb)`,
          [idempotencyKey, commandHash, JSON.stringify(value)],
        );
        await client.query("COMMIT");
        return { duplicate: false, value };
      } catch (error) {
        lastError = error;
        await rollback(client);
        if (
          TRANSIENT_SQL_STATES.has(error?.code) &&
          attempt < maxSerializableRetries
        ) {
          continue;
        }
        throw storeFailure(error);
      } finally {
        client.release();
      }
    }
    throw storeFailure(lastError);
  }

  async function readTenantSnapshot(tenantId) {
    const client = await connect();
    try {
      await client.query(
        "BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY",
      );
      const tenantResult = await client.query(
        `SELECT *
           FROM ${table("tenant_registry")}
          WHERE tenant_id = $1`,
        [tenantId],
      );
      if (!tenantResult.rows[0]) {
        await client.query("COMMIT");
        return null;
      }
      const tenant = tenantFromRow(tenantResult.rows[0]);
      const [projectionResult, lifecycleResult, outboxResult] =
        await Promise.all([
          client.query(
            `SELECT *
               FROM ${table("tenant_projection")}
              WHERE tenant_id = $1 AND generation = $2
              ORDER BY projection`,
            [tenantId, tenant.generation],
          ),
          client.query(
            `SELECT event
               FROM ${table("tenant_lifecycle_event")}
              WHERE tenant_id = $1
              ORDER BY created_at, event_id`,
            [tenantId],
          ),
          client.query(
            `SELECT event
               FROM ${table("tenant_outbox")}
              WHERE tenant_id = $1
              ORDER BY created_at, event_id`,
            [tenantId],
          ),
        ]);
      await client.query("COMMIT");
      return {
        tenant,
        projections: projectionResult.rows.map(projectionFromRow),
        lifecycleEvents: lifecycleResult.rows.map(({ event }) =>
          jsonValue(event),
        ),
        outbox: outboxResult.rows.map(({ event }) => jsonValue(event)),
      };
    } catch (error) {
      await rollback(client);
      throw storeFailure(error);
    } finally {
      client.release();
    }
  }

  async function claimOutbox({ workerId, limit, leaseSeconds }) {
    if (
      typeof workerId !== "string" ||
      !workerId.trim() ||
      workerId.length > 128 ||
      !Number.isInteger(limit) ||
      limit < 1 ||
      limit > 100 ||
      !Number.isInteger(leaseSeconds) ||
      leaseSeconds < 1 ||
      leaseSeconds > 300
    ) {
      fail("INVALID_COMMAND", "Invalid outbox claim.");
    }
    const client = await connect();
    try {
      await client.query("BEGIN");
      const result = await client.query(
        `WITH candidates AS (
           SELECT event_id
             FROM ${table("tenant_outbox")}
            WHERE (
                    status IN ('PENDING', 'FAILED')
                    AND available_at <= now()
                  )
               OR (
                    status = 'PROCESSING'
                    AND lease_until < now()
                  )
            ORDER BY created_at, event_id
            FOR UPDATE SKIP LOCKED
            LIMIT $1
         )
         UPDATE ${table("tenant_outbox")} AS outbox
            SET status = 'PROCESSING',
                leased_by = $2,
                lease_until = now() + ($3::integer * interval '1 second'),
                lease_version = lease_version + 1,
                attempt_count = attempt_count + 1
           FROM candidates
          WHERE outbox.event_id = candidates.event_id
         RETURNING outbox.event_id, outbox.lease_version, outbox.event`,
        [limit, workerId, leaseSeconds],
      );
      await client.query("COMMIT");
      return result.rows.map(({ event_id, lease_version, event }) => ({
        eventId: event_id,
        workerId,
        leaseVersion: Number(lease_version),
        event: jsonValue(event),
      }));
    } catch (error) {
      await rollback(client);
      throw storeFailure(error);
    } finally {
      client.release();
    }
  }

  async function completeOutbox({ eventId, workerId, leaseVersion }) {
    if (
      typeof eventId !== "string" ||
      !eventId.trim() ||
      typeof workerId !== "string" ||
      !workerId.trim() ||
      !Number.isInteger(leaseVersion) ||
      leaseVersion < 1
    ) {
      fail("INVALID_COMMAND", "Event ID, worker and lease version are required.");
    }
    const client = await connect();
    try {
      const result = await client.query(
        `UPDATE ${table("tenant_outbox")}
            SET status = 'PUBLISHED',
                published_at = now(),
                leased_by = NULL,
                lease_until = NULL,
                last_error_code = NULL
          WHERE event_id = $1
            AND leased_by = $2
            AND lease_version = $3
            AND lease_until >= now()
            AND status = 'PROCESSING'`,
        [eventId, workerId, leaseVersion],
      );
      if (result.rowCount !== 1) {
        fail("STALE_OUTBOX_LEASE", "Outbox event is not currently leased.");
      }
    } catch (error) {
      throw storeFailure(error);
    } finally {
      client.release();
    }
  }

  async function failOutbox({
    eventId,
    workerId,
    leaseVersion,
    errorCode,
    retryDelaySeconds,
  }) {
    if (
      typeof eventId !== "string" ||
      !eventId.trim() ||
      typeof workerId !== "string" ||
      !workerId.trim() ||
      !Number.isInteger(leaseVersion) ||
      leaseVersion < 1 ||
      typeof errorCode !== "string" ||
      !errorCode.trim() ||
      errorCode.length > 128 ||
      !Number.isInteger(retryDelaySeconds) ||
      retryDelaySeconds < 1 ||
      retryDelaySeconds > 3600
    ) {
      fail("INVALID_COMMAND", "Invalid outbox failure receipt.");
    }
    const client = await connect();
    try {
      const result = await client.query(
        `UPDATE ${table("tenant_outbox")}
            SET status = 'FAILED',
                available_at = now() + ($4::integer * interval '1 second'),
                leased_by = NULL,
                lease_until = NULL,
                last_error_code = $5
          WHERE event_id = $1
            AND leased_by = $2
            AND lease_version = $3
            AND lease_until >= now()
            AND status = 'PROCESSING'`,
        [
          eventId,
          workerId,
          leaseVersion,
          retryDelaySeconds,
          errorCode,
        ],
      );
      if (result.rowCount !== 1) {
        fail("STALE_OUTBOX_LEASE", "Outbox event is not currently leased.");
      }
    } catch (error) {
      throw storeFailure(error);
    } finally {
      client.release();
    }
  }

  return Object.freeze({
    runCommand,
    readTenantSnapshot,
    claimOutbox,
    completeOutbox,
    failOutbox,
  });
}
