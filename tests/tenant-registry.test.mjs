import assert from "node:assert/strict";
import test from "node:test";
import {
  createMemoryTenantStore,
  createSyntheticFixtureCatalog,
  createTenantRegistry,
} from "../lib/tenant-registry.mjs";
import { validateCloudEvent } from "../scripts/f03-contract-lab.mjs";

const FIXTURE_REF = Object.freeze({
  fixtureId: "synthetic-tenant-northstar-fasteners",
  sha256:
    "sha256:12693f1bed92c45128e0774ee1ea6c71b63a7edad0eff43cb988e79b6771db26",
});
const FIXTURE_CATALOG_ENTRY = Object.freeze({
  ...FIXTURE_REF,
  allowedConfigRefs: [
    "fixture://SYNTHETIC-SEED-001",
    "policy://different-policy",
  ],
});
const PROJECTIONS = [
  "AUTHORIZATION",
  "IDENTITY",
  "KNOWLEDGE",
  "SECRET_REFS",
  "STORAGE",
];
const operator = {
  actorId: "syn_prn_platform_operator",
  capabilities: ["TENANT_LIFECYCLE_MANAGE", "TENANT_LIFECYCLE_READ"],
  synthetic: true,
};
const projectionWorker = {
  actorId: "syn_svc_projection_worker",
  capabilities: ["TENANT_PROJECTION_REPORT"],
  synthetic: true,
};
const reconciler = {
  actorId: "syn_svc_tenant_reconciler",
  capabilities: ["TENANT_RECONCILE"],
  synthetic: true,
};
const clock = () => "2026-07-26T03:00:00.000Z";

function deterministicUuidFactory() {
  let counter = 0;
  return () => {
    counter += 1;
    return `01984700-0000-7000-8000-${counter.toString(16).padStart(12, "0")}`;
  };
}

function createRegistry() {
  const store = createMemoryTenantStore();
  const registry = createTenantRegistry({
    store,
    fixtureCatalog: createSyntheticFixtureCatalog([FIXTURE_CATALOG_ENTRY]),
    authorize: (context, capability) =>
      context?.synthetic === true &&
      context.capabilities?.includes(capability) === true,
    clock,
    idFactory: deterministicUuidFactory(),
  });
  return { registry, store };
}

function createCommand(overrides = {}) {
  return {
    kind: "CREATE_SYNTHETIC_TENANT",
    idempotencyKey: "create-northstar-001",
    creationKey: "p1:SYNTHETIC-SEED-001",
    fixtureRef: FIXTURE_REF,
    configRefs: ["fixture://SYNTHETIC-SEED-001"],
    correlationId: "c03-create-northstar",
    ...overrides,
  };
}

async function createAndActivate(registry) {
  const created = await registry.execute(operator, createCommand());
  let source = 0;
  for (const projection of PROJECTIONS) {
    source += 1;
    await registry.execute(projectionWorker, {
      kind: "RECORD_PROJECTION_RESULT",
      idempotencyKey: `projection-ready-${projection}`,
      tenantId: created.tenantId,
      generation: 1,
      operationId: created.operationId,
      projection,
      outcome: "SUCCEEDED",
      attempt: 1,
      sourceEventId: `projection-source-${source}`,
      correlationId: "c03-provision-northstar",
    });
  }
  const reconciled = await registry.execute(reconciler, {
    kind: "RECONCILE_TENANT",
    idempotencyKey: "reconcile-northstar-001",
    tenantId: created.tenantId,
    correlationId: "c03-reconcile-northstar",
  });
  assert.equal(reconciled.state, "ACTIVE");
  return reconciled;
}

test("concurrent duplicate creates produce one namespaced provisioning tenant", async () => {
  const { registry } = createRegistry();
  const results = await Promise.all(
    Array.from({ length: 32 }, () =>
      registry.execute(operator, createCommand()),
    ),
  );

  assert.equal(new Set(results.map(({ tenantId }) => tenantId)).size, 1);
  assert.equal(results.filter(({ duplicate }) => !duplicate).length, 1);
  assert.match(
    results[0].tenantId,
    /^stn_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
  );
  assert.equal(results[0].tenantKind, "SYNTHETIC");
  assert.equal(results[0].state, "PROVISIONING");

  const snapshot = await registry.snapshot(operator, results[0].tenantId);
  assert.equal(snapshot.synthetic, true);
  assert.match(snapshot.resourceNamespaceId, /^sns_/);
  assert.deepEqual(
    snapshot.projections.map(({ projection }) => projection),
    PROJECTIONS,
  );
  assert.ok(
    snapshot.projections.every(
      ({ desiredAction, status }) =>
        desiredAction === "PROVISION" && status === "PENDING",
    ),
  );
  assert.equal(snapshot.lifecycleEvents.length, 1);
  assert.equal(snapshot.outbox.length, 1);
  assert.equal(snapshot.outbox[0].tenantkind, "SYNTHETIC");
  assert.equal(snapshot.outbox[0].synthetic, true);
  assert.deepEqual(validateCloudEvent(snapshot.outbox[0]), {
    valid: true,
    errors: [],
  });
});

test("creation key also prevents a duplicate when the retry key changes", async () => {
  const { registry } = createRegistry();
  const first = await registry.execute(operator, createCommand());
  const retry = await registry.execute(
    operator,
    createCommand({ idempotencyKey: "create-northstar-retry-002" }),
  );

  assert.equal(retry.tenantId, first.tenantId);
  assert.equal(retry.duplicate, true);
  const snapshot = await registry.snapshot(operator, first.tenantId);
  assert.equal(snapshot.lifecycleEvents.length, 1);
  assert.equal(snapshot.outbox.length, 1);
});

test("a creation key or frozen fixture cannot be silently rebound", async () => {
  const { registry } = createRegistry();
  await registry.execute(operator, createCommand());

  await assert.rejects(
    registry.execute(
      operator,
      createCommand({
        idempotencyKey: "creation-intent-conflict",
        configRefs: ["policy://different-policy"],
      }),
    ),
    (error) => error.code === "CREATION_CONFLICT",
  );
  await assert.rejects(
    registry.execute(
      operator,
      createCommand({
        idempotencyKey: "fixture-origin-conflict",
        creationKey: "p1:different-creation-key",
      }),
    ),
    (error) => error.code === "CREATION_CONFLICT",
  );
});

test("an idempotency key cannot be reused for different content", async () => {
  const { registry } = createRegistry();
  await registry.execute(operator, createCommand());

  await assert.rejects(
    registry.execute(
      operator,
      createCommand({ correlationId: "different-command" }),
    ),
    (error) => error.code === "IDEMPOTENCY_CONFLICT",
  );
});

test("P1 rejects enterprise creation and unknown synthetic fixtures", async () => {
  const { registry } = createRegistry();

  await assert.rejects(
    registry.execute(operator, {
      kind: "CREATE_ENTERPRISE_TENANT",
      idempotencyKey: "enterprise-create-must-not-read-payload",
      enterprisePayload: {
        credentials: "must-not-be-read",
      },
    }),
    (error) => error.code === "P3_REQUIRED",
  );
  await assert.rejects(
    registry.execute(
      operator,
      createCommand({
        idempotencyKey: "unknown-fixture",
        creationKey: "p1:unknown",
        fixtureRef: {
          fixtureId: "unknown",
          sha256: `sha256:${"0".repeat(64)}`,
        },
      }),
    ),
    (error) => error.code === "UNKNOWN_SYNTHETIC_FIXTURE",
  );
});

test("P1 configuration references reject enterprise addresses and raw secret schemes", async () => {
  const { registry } = createRegistry();

  await assert.rejects(
    registry.execute(
      operator,
      createCommand({
        idempotencyKey: "enterprise-address-ref",
        creationKey: "p1:enterprise-address-ref",
        configRefs: ["https://enterprise.example/internal"],
      }),
    ),
    (error) => error.code === "SYNTHETIC_BOUNDARY_VIOLATION",
  );
  await assert.rejects(
    registry.execute(
      operator,
      createCommand({
        idempotencyKey: "raw-secret-ref",
        creationKey: "p1:raw-secret-ref",
        configRefs: ["secret://plaintext-value"],
      }),
    ),
    (error) => error.code === "SYNTHETIC_BOUNDARY_VIOLATION",
  );
  await assert.rejects(
    registry.execute(
      operator,
      createCommand({
        idempotencyKey: "unknown-fixture-ref",
        creationKey: "p1:unknown-fixture-ref",
        configRefs: ["fixture://REAL-COMPANY-DATA"],
      }),
    ),
    (error) => error.code === "UNKNOWN_SYNTHETIC_CONFIG_REF",
  );
  await assert.rejects(
    registry.execute(
      operator,
      createCommand({
        idempotencyKey: "disguised-secret-ref",
        creationKey: "p1:disguised-secret-ref",
        configRefs: ["secret-ref://plaintext-password"],
      }),
    ),
    (error) => error.code === "UNKNOWN_SYNTHETIC_CONFIG_REF",
  );
});

test("projection failure never activates a tenant", async () => {
  const { registry } = createRegistry();
  const created = await registry.execute(operator, createCommand());
  await registry.execute(projectionWorker, {
    kind: "RECORD_PROJECTION_RESULT",
    idempotencyKey: "identity-failed",
    tenantId: created.tenantId,
    generation: 1,
    operationId: created.operationId,
    projection: "IDENTITY",
    outcome: "FAILED",
    attempt: 1,
    sourceEventId: "identity-failure-source",
    errorCode: "SYNTHETIC_INJECTED_FAILURE",
    correlationId: "c03-failure-drill",
  });
  const result = await registry.execute(reconciler, {
    kind: "RECONCILE_TENANT",
    idempotencyKey: "reconcile-after-failure",
    tenantId: created.tenantId,
    correlationId: "c03-failure-drill",
  });

  assert.equal(result.state, "PROVISIONING");
  await assert.rejects(
    registry.admitNewRequest({
      tenantId: created.tenantId,
      expectedTenantKind: "SYNTHETIC",
    }),
    (error) => error.code === "TENANT_NOT_ACTIVE",
  );
});

test("a successful projection cannot be regressed by a late result", async () => {
  const { registry } = createRegistry();
  const created = await registry.execute(operator, createCommand());
  await registry.execute(projectionWorker, {
    kind: "RECORD_PROJECTION_RESULT",
    idempotencyKey: "identity-ready-first",
    tenantId: created.tenantId,
    generation: 1,
    operationId: created.operationId,
    projection: "IDENTITY",
    outcome: "SUCCEEDED",
    attempt: 1,
    sourceEventId: "identity-ready-source",
    correlationId: "c03-projection-order",
  });

  await assert.rejects(
    registry.execute(projectionWorker, {
      kind: "RECORD_PROJECTION_RESULT",
      idempotencyKey: "identity-late-failure",
      tenantId: created.tenantId,
      generation: 1,
      operationId: created.operationId,
      projection: "IDENTITY",
      outcome: "FAILED",
      attempt: 2,
      sourceEventId: "identity-old-failure-source",
      errorCode: "LATE_FAILURE",
      correlationId: "c03-projection-order",
    }),
    (error) => error.code === "PROJECTION_ALREADY_FINAL",
  );
  const snapshot = await registry.snapshot(operator, created.tenantId);
  assert.equal(
    snapshot.projections.find(
      ({ projection }) => projection === "IDENTITY",
    ).status,
    "READY",
  );
});

test("projection results are bound to the current operation and contiguous attempt", async () => {
  const { registry } = createRegistry();
  const created = await registry.execute(operator, createCommand());

  await assert.rejects(
    registry.execute(projectionWorker, {
      kind: "RECORD_PROJECTION_RESULT",
      idempotencyKey: "wrong-projection-operation",
      tenantId: created.tenantId,
      generation: 1,
      operationId: "op_01984700-0000-7000-8000-000000000999",
      projection: "IDENTITY",
      outcome: "SUCCEEDED",
      attempt: 1,
      sourceEventId: "wrong-operation-source",
      correlationId: "c03-projection-binding",
    }),
    (error) => error.code === "STALE_PROJECTION_OPERATION",
  );
  await assert.rejects(
    registry.execute(projectionWorker, {
      kind: "RECORD_PROJECTION_RESULT",
      idempotencyKey: "projection-attempt-gap",
      tenantId: created.tenantId,
      generation: 1,
      operationId: created.operationId,
      projection: "IDENTITY",
      outcome: "FAILED",
      attempt: 2,
      sourceEventId: "attempt-gap-source",
      errorCode: "ATTEMPT_ONE_MISSING",
      correlationId: "c03-projection-binding",
    }),
    (error) => error.code === "PROJECTION_RESULT_GAP",
  );
});

test("only complete current-generation projections can activate admission", async () => {
  const { registry } = createRegistry();
  const active = await createAndActivate(registry);
  const context = await registry.admitNewRequest({
    tenantId: active.tenantId,
    expectedTenantKind: "SYNTHETIC",
  });

  assert.deepEqual(context, {
    tenantId: active.tenantId,
    tenantKind: "SYNTHETIC",
    lifecycleVersion: active.lifecycleVersion,
    trustSource: "VERIFIED_SERVER_CONTEXT",
  });
});

test("suspend blocks new requests and resume requires fresh reconciliation", async () => {
  const { registry } = createRegistry();
  const active = await createAndActivate(registry);
  const suspended = await registry.execute(operator, {
    kind: "SUSPEND_TENANT",
    idempotencyKey: "suspend-northstar",
    tenantId: active.tenantId,
    expectedVersion: active.lifecycleVersion,
    reasonRef: "test://c03/suspend-drill",
    correlationId: "c03-suspend-northstar",
  });

  assert.equal(suspended.state, "SUSPENDED");
  await assert.rejects(
    registry.admitNewRequest({
      tenantId: active.tenantId,
      expectedTenantKind: "SYNTHETIC",
    }),
    (error) => error.code === "TENANT_NOT_ACTIVE",
  );
  await assert.rejects(
    registry.execute(operator, {
      kind: "RESUME_TENANT",
      idempotencyKey: "resume-with-stale-version",
      tenantId: active.tenantId,
      expectedVersion: active.lifecycleVersion,
      correlationId: "c03-resume-northstar",
    }),
    (error) => error.code === "STALE_VERSION",
  );

  const resumed = await registry.execute(operator, {
    kind: "RESUME_TENANT",
    idempotencyKey: "resume-northstar",
    tenantId: active.tenantId,
    expectedVersion: suspended.lifecycleVersion,
    correlationId: "c03-resume-northstar",
  });
  assert.equal(resumed.state, "PROVISIONING");
  assert.equal(resumed.generation, 2);
  await assert.rejects(
    registry.admitNewRequest({
      tenantId: active.tenantId,
      expectedTenantKind: "SYNTHETIC",
    }),
    (error) => error.code === "TENANT_NOT_ACTIVE",
  );
});

test("deletion remains traceable until every layer succeeds, then keeps a tombstone", async () => {
  const { registry } = createRegistry();
  const active = await createAndActivate(registry);
  const deleting = await registry.execute(operator, {
    kind: "REQUEST_TENANT_DELETION",
    idempotencyKey: "delete-northstar",
    tenantId: active.tenantId,
    expectedVersion: active.lifecycleVersion,
    reasonRef: "test://c03/delete-drill",
    correlationId: "c03-delete-northstar",
  });
  assert.equal(deleting.state, "DELETING");

  for (const projection of PROJECTIONS) {
    const failed = projection === "KNOWLEDGE";
    await registry.execute(projectionWorker, {
      kind: "RECORD_PROJECTION_RESULT",
      idempotencyKey: `delete-result-${projection}`,
      tenantId: active.tenantId,
      generation: deleting.generation,
      operationId: deleting.operationId,
      projection,
      outcome: failed ? "FAILED" : "SUCCEEDED",
      attempt: 1,
      sourceEventId: `delete-source-${projection}`,
      ...(failed ? { errorCode: "SYNTHETIC_DELETE_FAILURE" } : {}),
      correlationId: "c03-delete-northstar",
    });
  }
  let reconciled = await registry.execute(reconciler, {
    kind: "RECONCILE_TENANT",
    idempotencyKey: "reconcile-delete-failed",
    tenantId: active.tenantId,
    correlationId: "c03-delete-northstar",
  });
  assert.equal(reconciled.state, "DELETING");
  let snapshot = await registry.snapshot(operator, active.tenantId);
  assert.deepEqual(snapshot.deletionProgress, {
    completed: 4,
    failed: 1,
    pending: 0,
    total: 5,
  });

  await registry.execute(projectionWorker, {
    kind: "RECORD_PROJECTION_RESULT",
    idempotencyKey: "delete-result-knowledge-retry",
    tenantId: active.tenantId,
    generation: deleting.generation,
    operationId: deleting.operationId,
    projection: "KNOWLEDGE",
    outcome: "SUCCEEDED",
    attempt: 2,
    sourceEventId: "delete-source-knowledge-retry",
    correlationId: "c03-delete-northstar",
  });
  reconciled = await registry.execute(reconciler, {
    kind: "RECONCILE_TENANT",
    idempotencyKey: "reconcile-delete-complete",
    tenantId: active.tenantId,
    correlationId: "c03-delete-northstar",
  });
  assert.equal(reconciled.state, "DELETED");
  snapshot = await registry.snapshot(operator, active.tenantId);
  assert.equal(snapshot.state, "DELETED");
  assert.match(snapshot.resourceNamespaceId, /^sns_/);
  assert.equal(snapshot.fixtureRef.sha256, FIXTURE_REF.sha256);
  await assert.rejects(
    registry.admitNewRequest({
      tenantId: active.tenantId,
      expectedTenantKind: "SYNTHETIC",
    }),
    (error) => error.code === "TENANT_DELETED",
  );
});

test("kind mutation attempts, stale generations and unauthorized reads fail closed", async () => {
  const { registry } = createRegistry();
  const created = await registry.execute(operator, createCommand());

  await assert.rejects(
    registry.execute(operator, {
      kind: "SUSPEND_TENANT",
      idempotencyKey: "kind-mutation-attempt",
      tenantId: created.tenantId,
      tenantKind: "ENTERPRISE",
      expectedVersion: created.lifecycleVersion,
      reasonRef: "test://c03/mutation",
      correlationId: "c03-mutation",
    }),
    (error) => error.code === "INVALID_COMMAND",
  );
  await assert.rejects(
    registry.execute(projectionWorker, {
      kind: "RECORD_PROJECTION_RESULT",
      idempotencyKey: "stale-generation",
      tenantId: created.tenantId,
      generation: 0,
      operationId: created.operationId,
      projection: "IDENTITY",
      outcome: "SUCCEEDED",
      attempt: 1,
      sourceEventId: "stale-source",
      correlationId: "c03-stale",
    }),
    (error) => error.code === "STALE_PROJECTION_GENERATION",
  );
  await assert.rejects(
    registry.execute(operator, {
      kind: "RECORD_PROJECTION_RESULT",
      idempotencyKey: "manager-cannot-forge-projection",
      tenantId: created.tenantId,
      generation: 1,
      operationId: created.operationId,
      projection: "IDENTITY",
      outcome: "SUCCEEDED",
      attempt: 1,
      sourceEventId: "forged-source",
      correlationId: "c03-forged",
    }),
    (error) => error.code === "UNAUTHORIZED",
  );
  await assert.rejects(
    registry.snapshot(
      { actorId: "unknown", capabilities: [], synthetic: true },
      created.tenantId,
    ),
    (error) => error.code === "UNAUTHORIZED",
  );

  const backingStore = createMemoryTenantStore();
  let snapshotReads = 0;
  let observedRequest;
  const boundRegistry = createTenantRegistry({
    store: {
      runCommand: (...args) => backingStore.runCommand(...args),
      readTenantSnapshot: (...args) => {
        snapshotReads += 1;
        return backingStore.readTenantSnapshot(...args);
      },
    },
    fixtureCatalog: createSyntheticFixtureCatalog([FIXTURE_CATALOG_ENTRY]),
    authorize: (context, capability, request) => {
      if (capability === "TENANT_LIFECYCLE_READ") {
        observedRequest = request;
        return context.capabilities?.includes(capability) === true;
      }
      return (
        context?.synthetic === true &&
        context.capabilities?.includes(capability) === true
      );
    },
    clock,
    idFactory: deterministicUuidFactory(),
  });
  const boundCreated = await boundRegistry.execute(operator, createCommand());
  const crossTenantReader = {
    actorId: "syn_prn_other_tenant_reader",
    capabilities: ["TENANT_LIFECYCLE_READ"],
    synthetic: true,
    tenantId: "stn_01984700-0000-7000-8000-000000000999",
    authorized: true,
    scope: "TENANT_LIFECYCLE_READ:any",
  };

  await assert.rejects(
    boundRegistry.snapshot(
      crossTenantReader,
      boundCreated.tenantId,
      true,
      "TENANT_LIFECYCLE_READ:any",
    ),
    (error) => error.code === "UNAUTHORIZED",
  );
  assert.equal(snapshotReads, 0);

  const sameTenantReader = {
    ...crossTenantReader,
    tenantId: boundCreated.tenantId,
  };
  const snapshot = await boundRegistry.snapshot(
    sameTenantReader,
    boundCreated.tenantId,
  );
  assert.equal(snapshot.tenantId, boundCreated.tenantId);
  assert.equal(snapshotReads, 1);
  assert.deepEqual(observedRequest, {
    tenantId: boundCreated.tenantId,
    actor: sameTenantReader.actorId,
    action: "READ",
    scope: "TENANT_LIFECYCLE_READ",
  });
});

test("an authorizer failure is converted to a closed authorization decision", async () => {
  const registry = createTenantRegistry({
    store: createMemoryTenantStore(),
    fixtureCatalog: createSyntheticFixtureCatalog([FIXTURE_CATALOG_ENTRY]),
    authorize() {
      throw new Error("identity backend details must not escape");
    },
    clock,
    idFactory: deterministicUuidFactory(),
  });

  await assert.rejects(
    registry.execute(operator, createCommand()),
    (error) =>
      error.code === "UNAUTHORIZED" &&
      !error.message.includes("identity backend"),
  );
});
