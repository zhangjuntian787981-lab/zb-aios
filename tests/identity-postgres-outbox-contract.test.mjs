import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { createPostgresIdentityOutbox } from "../lib/postgres-identity-outbox.mjs";

const migrationUrl = new URL(
  "../implementation/p1/c04/postgresql/0003_identity_outbox_delivery.sql",
  import.meta.url,
);

function scriptedPool(responder) {
  const queries = [];
  let connections = 0;
  const client = {
    async query(sql, parameters = []) {
      queries.push({ sql, parameters });
      return responder(sql, parameters);
    },
    release() {},
  };
  return {
    queries,
    get connections() {
      return connections;
    },
    pool: {
      async connect() {
        connections += 1;
        return client;
      },
    },
  };
}

test("the worker-only outbox module exposes three operations", () => {
  const { pool } = scriptedPool(() => ({ rows: [], rowCount: 1 }));
  const outbox = createPostgresIdentityOutbox({ pool });

  assert.deepEqual(Object.keys(outbox).sort(), [
    "claimOutbox",
    "completeOutbox",
    "failOutbox",
  ]);
});

test("the incremental migration enforces the delivery state machine", async () => {
  const sql = await readFile(migrationUrl, "utf8");

  assert.match(sql, /identity_outbox_attempt_lease_match/);
  assert.match(sql, /attempt_count::bigint = lease_version/);
  assert.match(sql, /identity_outbox_delivery_shape/);
  assert.match(sql, /OLD\.status = 'PUBLISHED'/);
  assert.match(sql, /identity_outbox_published_guard/);
  assert.match(sql, /identity_outbox_claim_guard/);
  assert.match(sql, /identity_outbox_reclaim_guard/);
  assert.match(sql, /identity_outbox_failure_guard/);
  assert.match(sql, /identity_outbox_completion_guard/);
});

test("claims are bounded, exclusive and use database time", async () => {
  const event = { id: "evt_outbox_contract" };
  const scripted = scriptedPool((sql) => {
    if (sql.includes("RETURNING outbox.event_id")) {
      return {
        rows: [
          {
            event_id: "evt_outbox_contract",
            lease_version: "3",
            event,
          },
        ],
        rowCount: 1,
      };
    }
    return { rows: [], rowCount: 1 };
  });
  const outbox = createPostgresIdentityOutbox({ pool: scripted.pool });

  const claimed = await outbox.claimOutbox({
    workerId: "identity-worker-a",
    limit: 5,
    leaseSeconds: 30,
  });
  assert.deepEqual(claimed, [
    {
      eventId: "evt_outbox_contract",
      workerId: "identity-worker-a",
      leaseVersion: 3,
      event,
    },
  ]);

  const claim = scripted.queries.find(({ sql }) =>
    sql.includes("FOR UPDATE SKIP LOCKED"),
  );
  assert.ok(claim);
  assert.match(claim.sql, /status IN \('PENDING', 'FAILED'\)/);
  assert.match(claim.sql, /status = 'PROCESSING'/);
  assert.match(claim.sql, /lease_until < statement_timestamp\(\)/);
  assert.match(claim.sql, /attempt_count = attempt_count \+ 1/);
  assert.match(claim.sql, /lease_version = lease_version \+ 1/);
  assert.deepEqual(claim.parameters, [5, "identity-worker-a", 30]);
  assert.equal(scripted.queries[0].sql, "BEGIN");
  assert.equal(scripted.queries.at(-1).sql, "COMMIT");
});

test("completion and failure are fenced by worker, version and lease time", async () => {
  const scripted = scriptedPool(() => ({ rows: [], rowCount: 1 }));
  const outbox = createPostgresIdentityOutbox({ pool: scripted.pool });

  await outbox.completeOutbox({
    eventId: "evt_outbox_contract",
    workerId: "identity-worker-a",
    leaseVersion: 4,
  });
  await outbox.failOutbox({
    eventId: "evt_outbox_retry",
    workerId: "identity-worker-b",
    leaseVersion: 7,
    errorCode: "DELIVERY_FAILED",
    retryDelaySeconds: 15,
  });

  const completion = scripted.queries.find(({ sql }) =>
    sql.includes("status = 'PUBLISHED'"),
  );
  assert.match(completion.sql, /leased_by = \$2/);
  assert.match(completion.sql, /lease_version = \$3/);
  assert.match(completion.sql, /lease_until >= statement_timestamp\(\)/);
  assert.deepEqual(completion.parameters, [
    "evt_outbox_contract",
    "identity-worker-a",
    4,
  ]);

  const failure = scripted.queries.find(({ sql }) =>
    sql.includes("status = 'FAILED'"),
  );
  assert.match(failure.sql, /available_at =[\s\S]*statement_timestamp\(\)/);
  assert.match(failure.sql, /leased_by = \$2/);
  assert.match(failure.sql, /lease_version = \$3/);
  assert.deepEqual(failure.parameters, [
    "evt_outbox_retry",
    "identity-worker-b",
    7,
    15,
    "DELIVERY_FAILED",
  ]);
});

test("invalid bounds and stale leases fail closed", async () => {
  const invalid = scriptedPool(() => ({ rows: [], rowCount: 1 }));
  const outbox = createPostgresIdentityOutbox({ pool: invalid.pool });
  await assert.rejects(
    outbox.claimOutbox({
      workerId: "identity-worker",
      limit: 1,
      leaseSeconds: 301,
    }),
    (error) => error.code === "INVALID_COMMAND",
  );
  assert.equal(invalid.connections, 0);

  const stale = scriptedPool(() => ({ rows: [], rowCount: 0 }));
  const staleOutbox = createPostgresIdentityOutbox({ pool: stale.pool });
  await assert.rejects(
    staleOutbox.completeOutbox({
      eventId: "evt_stale",
      workerId: "identity-worker",
      leaseVersion: 1,
    }),
    (error) => error.code === "STALE_OUTBOX_LEASE",
  );
});

test("database failures expose no connection details", async () => {
  const outbox = createPostgresIdentityOutbox({
    pool: {
      async connect() {
        throw new Error("secret identity database host");
      },
    },
  });

  await assert.rejects(
    outbox.claimOutbox({
      workerId: "identity-worker",
      limit: 1,
      leaseSeconds: 30,
    }),
    (error) =>
      error.code === "OUTBOX_UNAVAILABLE" &&
      !error.message.includes("secret identity database host"),
  );
});
