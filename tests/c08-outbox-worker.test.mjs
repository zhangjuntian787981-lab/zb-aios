import assert from "node:assert/strict";
import test from "node:test";
import { createMemoryAiosStateStore } from "../lib/aios-state-core.mjs";
import { createC08OutboxWorker } from "../lib/c08-outbox-worker.mjs";

const TENANT = "stn_01985000-1000-7000-8000-000000000001";
const EVENT = "evt_01985000-1000-7000-8000-000000000002";
const CASE = "cas_01985000-1000-7000-8000-000000000003";
const HASH =
  "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const OUTBOX_FIELDS = [
  "eventId",
  "state",
  "leaseVersion",
  "workerId",
  "leaseExpiresAt",
  "lastErrorCode",
  "event",
  "createdAt",
  "availableAt",
  "publishedAt",
].sort();

function scope() {
  return {
    trustSource: "C07_VERIFIED_TENANT_SCOPE",
    tenantId: TENANT,
    tenantKind: "SYNTHETIC",
    lifecycleVersion: 1,
    operationId: "C08_OUTBOX_WORKER_TEST",
    storagePath: "aios-state-core",
    correlationId: "corr-c08-outbox-worker",
    decisionId: "azd_c08_outbox_worker",
    evidenceRef: "evidence://c08/outbox-worker",
    policyVersion: "c08-outbox-worker-v1",
  };
}

async function seed(store) {
  const record = {
    eventId: EVENT,
    aggregateType: "CASE",
    aggregateId: CASE,
    aggregateVersion: 1,
    event: {
      specversion: "1.0",
      id: EVENT,
      source: "test://c08/outbox-worker",
      type: "product.aios.case-created.v1",
      subject: CASE,
      time: "2026-07-26T10:00:00.000Z",
      data: {
        tenant_id: TENANT,
        aggregate_type: "CASE",
        aggregate_id: CASE,
        aggregate_version: 1,
      },
    },
    createdAt: "2026-07-26T10:00:00.000Z",
  };
  await store.runCommand(
    scope(),
    {
      idempotencyKey: "seed-outbox-worker",
      requestHash: HASH,
      commandKind: "CREATE_CASE",
      correlationId: "corr-seed-outbox-worker",
    },
    async (tx) => {
      await tx.insertCase({
        caseId: CASE,
        tenantId: TENANT,
        tenantKind: "SYNTHETIC",
        state: "OPEN",
        version: 1,
        goalRef: "synthetic://c08/goals/outbox-worker",
        createdAt: record.createdAt,
        updatedAt: record.createdAt,
      });
      await tx.appendEvent(record);
      await tx.appendOutbox(record);
      return { caseId: CASE };
    },
  );
}

test("C08 Outbox Worker replays a durable publish acknowledgement without a duplicate effect", async () => {
  const store = createMemoryAiosStateStore();
  await seed(store);
  const accepted = new Set();
  let attempts = 0;
  const publisher = {
    async publish({ eventId }) {
      attempts += 1;
      if (!accepted.has(eventId)) {
        accepted.add(eventId);
        throw new Error("acknowledgement lost after durable accept");
      }
      return { eventId, duplicate: true };
    },
  };

  const firstWorker = createC08OutboxWorker({ store, publisher });
  const first = await firstWorker.runOnce(scope(), {
    workerId: "worker-a",
    now: "2026-07-26T10:00:00.000Z",
    leaseExpiresAt: "2026-07-26T10:01:00.000Z",
    retryAt: "2026-07-26T10:02:00.000Z",
    limit: 10,
  });
  assert.deepEqual(first, {
    claimed: 1,
    published: 0,
    requeued: 1,
    publishedEventIds: [],
    requeuedEventIds: [EVENT],
  });

  const restartedWorker = createC08OutboxWorker({ store, publisher });
  const second = await restartedWorker.runOnce(scope(), {
    workerId: "worker-b",
    now: "2026-07-26T10:02:00.000Z",
    leaseExpiresAt: "2026-07-26T10:03:00.000Z",
    retryAt: "2026-07-26T10:04:00.000Z",
    limit: 10,
  });
  assert.deepEqual(second, {
    claimed: 1,
    published: 1,
    requeued: 0,
    publishedEventIds: [EVENT],
    requeuedEventIds: [],
  });
  assert.equal(attempts, 2);
  assert.equal(accepted.size, 1);
});

test("memory Outbox Port returns one canonical shape and clears prior errors on reclaim", async () => {
  const store = createMemoryAiosStateStore();
  await seed(store);
  const claimed = await store.claimOutbox(scope(), {
    workerId: "worker-a",
    now: "2026-07-26T10:00:00.000Z",
    leaseExpiresAt: "2026-07-26T10:01:00.000Z",
    limit: 1,
  });
  assert.deepEqual(Object.keys(claimed[0]).sort(), OUTBOX_FIELDS);
  const failed = await store.failOutbox(scope(), {
    eventId: EVENT,
    workerId: "worker-a",
    leaseVersion: claimed[0].leaseVersion,
    now: "2026-07-26T10:00:30.000Z",
    retryAt: "2026-07-26T10:02:00.000Z",
    errorCode: "PUBLISH_FAILED",
  });
  assert.deepEqual(Object.keys(failed).sort(), OUTBOX_FIELDS);
  assert.equal(failed.lastErrorCode, "PUBLISH_FAILED");

  const reclaimed = await store.claimOutbox(scope(), {
    workerId: "worker-b",
    now: "2026-07-26T10:02:00.000Z",
    leaseExpiresAt: "2026-07-26T10:03:00.000Z",
    limit: 1,
  });
  assert.deepEqual(Object.keys(reclaimed[0]).sort(), OUTBOX_FIELDS);
  assert.equal(reclaimed[0].lastErrorCode, null);
  const completed = await store.completeOutbox(scope(), {
    eventId: EVENT,
    workerId: "worker-b",
    leaseVersion: reclaimed[0].leaseVersion,
    now: "2026-07-26T10:02:30.000Z",
  });
  assert.deepEqual(Object.keys(completed).sort(), OUTBOX_FIELDS);
  assert.equal(completed.lastErrorCode, null);
  assert.equal(completed.state, "PUBLISHED");
});
