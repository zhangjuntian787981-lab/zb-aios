import { IdentityFederationError } from "./identity-federation.mjs";

const SAFE_IDENTIFIER = /^[a-z_][a-z0-9_]*$/;

function fail(code, message) {
  throw new IdentityFederationError(code, message);
}

function jsonValue(value) {
  return typeof value === "string" ? JSON.parse(value) : value;
}

async function rollback(client) {
  try {
    await client.query("ROLLBACK");
  } catch {
    // Preserve the original storage failure.
  }
}

function outboxFailure(error) {
  if (error instanceof IdentityFederationError) return error;
  return new IdentityFederationError(
    "OUTBOX_UNAVAILABLE",
    "Identity outbox operation failed.",
  );
}

function workerId(value) {
  if (
    typeof value !== "string" ||
    !value.trim() ||
    value.length > 128
  ) {
    fail("INVALID_COMMAND", "Outbox worker ID is invalid.");
  }
}

function eventId(value) {
  if (
    typeof value !== "string" ||
    !value.trim() ||
    value.length > 128
  ) {
    fail("INVALID_COMMAND", "Outbox event ID is invalid.");
  }
}

function leaseVersion(value) {
  if (!Number.isSafeInteger(value) || value < 1) {
    fail("INVALID_COMMAND", "Outbox lease version is invalid.");
  }
}

export function createPostgresIdentityOutbox({
  pool,
  schema = "aios_core",
}) {
  if (typeof pool?.connect !== "function" || !SAFE_IDENTIFIER.test(schema)) {
    fail("INVALID_OUTBOX", "A PostgreSQL pool and safe schema are required.");
  }

  const outboxTable = `"${schema}"."identity_outbox"`;

  async function connect() {
    try {
      return await pool.connect();
    } catch (error) {
      throw outboxFailure(error);
    }
  }

  async function claimOutbox({
    workerId: selectedWorkerId,
    limit,
    leaseSeconds,
  }) {
    workerId(selectedWorkerId);
    if (
      !Number.isSafeInteger(limit) ||
      limit < 1 ||
      limit > 100 ||
      !Number.isSafeInteger(leaseSeconds) ||
      leaseSeconds < 1 ||
      leaseSeconds > 300
    ) {
      fail("INVALID_COMMAND", "Outbox claim bounds are invalid.");
    }

    const client = await connect();
    try {
      await client.query("BEGIN");
      const result = await client.query(
        `WITH candidates AS (
           SELECT event_id
             FROM ${outboxTable}
            WHERE (
                    status IN ('PENDING', 'FAILED')
                    AND available_at <= statement_timestamp()
                  )
               OR (
                    status = 'PROCESSING'
                    AND lease_until < statement_timestamp()
                  )
            ORDER BY created_at, event_id
            FOR UPDATE SKIP LOCKED
            LIMIT $1
         )
         UPDATE ${outboxTable} AS outbox
            SET status = 'PROCESSING',
                attempt_count = attempt_count + 1,
                lease_version = lease_version + 1,
                leased_by = $2,
                lease_until =
                  statement_timestamp() + ($3::integer * interval '1 second'),
                last_error_code = NULL
           FROM candidates
          WHERE outbox.event_id = candidates.event_id
         RETURNING outbox.event_id, outbox.lease_version, outbox.event`,
        [limit, selectedWorkerId, leaseSeconds],
      );
      await client.query("COMMIT");
      return result.rows.map(({ event_id, lease_version, event }) => ({
        eventId: event_id,
        workerId: selectedWorkerId,
        leaseVersion: Number(lease_version),
        event: jsonValue(event),
      }));
    } catch (error) {
      await rollback(client);
      throw outboxFailure(error);
    } finally {
      client.release();
    }
  }

  async function completeOutbox({
    eventId: selectedEventId,
    workerId: selectedWorkerId,
    leaseVersion: selectedLeaseVersion,
  }) {
    eventId(selectedEventId);
    workerId(selectedWorkerId);
    leaseVersion(selectedLeaseVersion);

    const client = await connect();
    try {
      const result = await client.query(
        `UPDATE ${outboxTable}
            SET status = 'PUBLISHED',
                leased_by = NULL,
                lease_until = NULL,
                last_error_code = NULL,
                published_at = statement_timestamp()
          WHERE event_id = $1
            AND leased_by = $2
            AND lease_version = $3
            AND lease_until >= statement_timestamp()
            AND status = 'PROCESSING'`,
        [selectedEventId, selectedWorkerId, selectedLeaseVersion],
      );
      if (result.rowCount !== 1) {
        fail("STALE_OUTBOX_LEASE", "Outbox lease is not current.");
      }
    } catch (error) {
      throw outboxFailure(error);
    } finally {
      client.release();
    }
  }

  async function failOutbox({
    eventId: selectedEventId,
    workerId: selectedWorkerId,
    leaseVersion: selectedLeaseVersion,
    errorCode,
    retryDelaySeconds,
  }) {
    eventId(selectedEventId);
    workerId(selectedWorkerId);
    leaseVersion(selectedLeaseVersion);
    if (
      typeof errorCode !== "string" ||
      !errorCode.trim() ||
      errorCode.length > 128 ||
      !Number.isSafeInteger(retryDelaySeconds) ||
      retryDelaySeconds < 1 ||
      retryDelaySeconds > 3600
    ) {
      fail("INVALID_COMMAND", "Outbox failure receipt is invalid.");
    }

    const client = await connect();
    try {
      const result = await client.query(
        `UPDATE ${outboxTable}
            SET status = 'FAILED',
                available_at =
                  statement_timestamp() +
                  ($4::integer * interval '1 second'),
                leased_by = NULL,
                lease_until = NULL,
                last_error_code = $5,
                published_at = NULL
          WHERE event_id = $1
            AND leased_by = $2
            AND lease_version = $3
            AND lease_until >= statement_timestamp()
            AND status = 'PROCESSING'`,
        [
          selectedEventId,
          selectedWorkerId,
          selectedLeaseVersion,
          retryDelaySeconds,
          errorCode,
        ],
      );
      if (result.rowCount !== 1) {
        fail("STALE_OUTBOX_LEASE", "Outbox lease is not current.");
      }
    } catch (error) {
      throw outboxFailure(error);
    } finally {
      client.release();
    }
  }

  return Object.freeze({
    claimOutbox,
    completeOutbox,
    failOutbox,
  });
}
