import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  AuditEvidenceError,
  C18_GENESIS_HASH,
  assertAuditMetadataOnly,
  auditEvidenceSha256,
  canonicalizeAuditJson,
  computeAuditEventHash,
  createAuditCloudEvent,
  createAuditEvidenceService,
  createMemoryAuditEvidenceStore,
  createSyntheticAuditEvidenceCatalog,
  createSyntheticAuditEvidenceRegistry,
  verifyAuditExport,
} from "../lib/c18-audit-evidence.mjs";
import {
  createC18AuditOutboxWorker,
} from "../lib/c18-audit-outbox-worker.mjs";

const TENANT_A = "stn_018f0000-0000-7000-8000-000000000010";
const TENANT_B = "stn_01984910-3000-7000-8000-000000000002";
const TENANT_C = "stn_01984910-3000-7000-8000-000000000003";
const HUMAN = "prn_018f0000-0000-7000-8000-000000000001";
const ACTOR = "prn_018f0000-0000-7000-8000-000000000002";
const HUMAN_CHANGED =
  "prn_018f0000-0000-7000-8000-000000000003";
const DELEGATION =
  "dlg_018f0000-0000-7000-8000-000000000020";
const NOW = "2026-07-26T10:00:00.000Z";
const FAR_PAST = "2020-01-01T00:00:00.000Z";
const FAR_FUTURE = "2030-01-01T00:00:00.000Z";
const BUNDLES = new Map([
  [
    TENANT_A,
    "fixture://c18/northstar/bundles/completed-analysis-v1",
  ],
  [
    TENANT_B,
    "fixture://c18/blue-harbor/bundles/completed-analysis-v1",
  ],
  [
    TENANT_C,
    "fixture://c18/cedar/bundles/completed-analysis-v1",
  ],
]);
const catalogDocument = JSON.parse(
  await readFile(
    new URL(
      "../implementation/p1/c18/synthetic-evidence-catalog.v1.json",
      import.meta.url,
    ),
    "utf8",
  ),
);
const evidenceRegistryDocument = JSON.parse(
  await readFile(
    new URL(
      "../implementation/p1/c18/synthetic-evidence-registry.v1.json",
      import.meta.url,
    ),
    "utf8",
  ),
);
const EVIDENCE_REGISTRY = createSyntheticAuditEvidenceRegistry(
  evidenceRegistryDocument,
);
const CATALOG = createSyntheticAuditEvidenceCatalog(catalogDocument, {
  evidenceRegistry: EVIDENCE_REGISTRY,
});

function deterministicIds(start = 800) {
  let counter = start;
  return () => {
    counter += 1;
    return `018f0000-0000-7000-8000-${String(counter).padStart(12, "0")}`;
  };
}

function identity(tenantId, humanPrincipalId = HUMAN) {
  return {
    tenantId,
    tenantKind: "SYNTHETIC",
    identityAccountId: "sia_synthetic",
    identityLinkId: "lnk_synthetic",
    sessionId: "session-synthetic",
    humanSubject: {
      principalId: humanPrincipalId,
      principalType: "HUMAN",
      lifecycleVersion: 1,
      securityEpoch: 1,
    },
    workloadActor: {
      principalId: ACTOR,
      principalType: "SERVICE",
      lifecycleVersion: 1,
      securityEpoch: 1,
    },
    purposeRef: "synthetic://c18/purpose/audit",
    delegationChain: [
      {
        delegationId: DELEGATION,
        delegatorPrincipalId: humanPrincipalId,
        delegatePrincipalId: ACTOR,
        purposeRef: "synthetic://c18/purpose/audit",
        lifecycleVersion: 1,
        expiresAt: "2027-07-26T00:00:00.000Z",
      },
    ],
    trustSource:
      "VERIFIED_SESSION_IDENTITY_LINK_AND_WORKLOAD_CONTEXT",
  };
}

function scope(tenantId, correlationId = "c18-correlation") {
  const bundle = CATALOG.resolve(tenantId, BUNDLES.get(tenantId));
  return {
    trustSource: "C07_VERIFIED_TENANT_SCOPE",
    tenantId,
    tenantKind: "SYNTHETIC",
    lifecycleVersion: 2,
    correlationId,
    decisionId: bundle.authorization.decisionId,
    evidenceRef: bundle.authorization.evidenceRef,
    policyVersion: bundle.authorization.version,
  };
}

function createHarness({
  tenantId = TENANT_A,
  store,
  start = 800,
} = {}) {
  const mutable = {
    now: NOW,
    tenantActive: true,
    identitySequence: [],
  };
  const selectedStore =
    store ??
    createMemoryAuditEvidenceStore({
      clock: () => mutable.now,
    });
  const calls = [];
  const service = createAuditEvidenceService({
    store: selectedStore,
    catalog: CATALOG,
    clock: () => mutable.now,
    idFactory: deterministicIds(start),
    stablePrincipalRegistry: {
      async resolveActionIdentity() {
        calls.push("identity");
        const next = mutable.identitySequence.shift();
        return next && typeof next === "object"
          ? structuredClone(next)
          : identity(tenantId, next ?? HUMAN);
      },
    },
    tenantRegistry: {
      async admitNewRequest() {
        calls.push("tenant");
        if (!mutable.tenantActive) {
          const error = new Error("inactive");
          error.code = "TENANT_NOT_ACTIVE";
          throw error;
        }
        return {
          tenantId,
          tenantKind: "SYNTHETIC",
          lifecycleVersion: 2,
        };
      },
    },
    tenantScopeFactory({ tenant, authorization, correlationId }) {
      calls.push("scope");
      return {
        trustSource: "C07_VERIFIED_TENANT_SCOPE",
        tenantId: tenant.tenantId,
        tenantKind: tenant.tenantKind,
        lifecycleVersion: tenant.lifecycleVersion,
        correlationId,
        decisionId: authorization.decisionId,
        evidenceRef: authorization.evidenceRef,
        policyVersion: authorization.version,
      };
    },
  });
  return {
    service,
    store: selectedStore,
    mutable,
    calls,
    context() {
      return {
        synthetic: true,
        routeTrustSource: "VERIFIED_ROUTE_DESCRIPTOR",
        tenantId,
        workloadTrustSource: "VERIFIED_WORKLOAD_CONTEXT",
        workloadActorPrincipalId: ACTOR,
      };
    },
    request(suffix = "1", overrides = {}) {
      return {
        sessionToken: "synthetic-session",
        delegationId: DELEGATION,
        idempotencyKey: `c18-${tenantId.slice(-2)}-${suffix}`,
        correlationId: `c18-correlation-${suffix}`,
        evidenceBundleRef: BUNDLES.get(tenantId),
        ...overrides,
      };
    },
  };
}

function code(expected) {
  return (error) =>
    error instanceof AuditEvidenceError && error.code === expected;
}

test("RFC 8785 canonicalization is deterministic and rejects invalid JSON", () => {
  assert.equal(
    canonicalizeAuditJson({ z: -0, a: [3, true, "x"] }),
    '{"a":[3,true,"x"],"z":0}',
  );
  assert.throws(
    () => canonicalizeAuditJson({ invalid: Number.NaN }),
    code("INVALID_JSON"),
  );
  assert.throws(
    () => canonicalizeAuditJson({ invalid: "\ud800" }),
    code("INVALID_JSON"),
  );
  assert.equal(
    auditEvidenceSha256("abc"),
    "sha256:6cc43f858fbb763301637b5af970e2a46b46f461f27e5a0f41e009c59b827b25",
  );
  assert.throws(
    () => canonicalizeAuditJson(new Array(1)),
    code("INVALID_JSON"),
  );
});

test("catalog freezes exactly three Tenant-specific evidence bundles", () => {
  assert.deepEqual(CATALOG.tenantIds(), [TENANT_A, TENANT_B, TENANT_C]);
  assert.throws(
    () => CATALOG.resolve(TENANT_B, BUNDLES.get(TENANT_A)),
    code("SYNTHETIC_FIXTURE_MISMATCH"),
  );
});

test("catalog evidence resolves to frozen Tenant/type/version/digest artifacts", () => {
  const bundle = CATALOG.resolve(TENANT_A, BUNDLES.get(TENANT_A));
  const artifact = EVIDENCE_REGISTRY.resolve({
    tenantId: TENANT_A,
    evidenceType: "AUTHORIZATION",
    evidenceRef: bundle.authorization.evidenceRef,
    version: bundle.authorization.version,
    sha256: bundle.authorization.sha256,
  });
  assert.equal(artifact.tenantId, TENANT_A);
  assert.equal(artifact.evidenceType, "AUTHORIZATION");

  const tampered = structuredClone(evidenceRegistryDocument);
  tampered.entries[0].artifact.summaryCode = "TAMPERED";
  assert.throws(
    () => createSyntheticAuditEvidenceRegistry(tampered),
    code("EVIDENCE_DIGEST_MISMATCH"),
  );

  const mismatchedCatalog = structuredClone(catalogDocument);
  mismatchedCatalog.tenants[0].bundles[0].authorization.sha256 =
    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  assert.throws(
    () =>
      createSyntheticAuditEvidenceCatalog(mismatchedCatalog, {
        evidenceRegistry: EVIDENCE_REGISTRY,
      }),
    code("EVIDENCE_DIGEST_MISMATCH"),
  );
});

test("append links all required evidence through the constrained PROV graph", async () => {
  const harness = createHarness();
  const appended = await harness.service.append(
    harness.context(),
    harness.request(),
  );
  assert.equal(appended.sequence, 1);
  assert.equal(appended.previousEventHash, C18_GENESIS_HASH);
  assert.equal(appended.duplicate, false);
  assert.deepEqual(harness.calls, [
    "identity",
    "identity",
    "tenant",
    "scope",
  ]);

  const exported = await harness.store.exportChain(
    scope(TENANT_A, "c18-correlation-1"),
  );
  const [event] = exported.events;
  for (const field of [
    "identity",
    "authorization",
    "model",
    "knowledge",
    "skill",
    "tool",
    "humanDecision",
    "result",
    "c08State",
  ]) {
    assert.ok(event.payload[field]);
  }
  assert.equal(event.payload.provenance.entities.length, 9);
  assert.ok(
    event.payload.provenance.relations.some(
      (relation) => relation.type === "prov:wasGeneratedBy",
    ),
  );
  assert.ok(
    event.payload.provenance.relations.some(
      (relation) => relation.type === "prov:actedOnBehalfOf",
    ),
  );
  assert.deepEqual(verifyAuditExport(exported), {
    tenantId: TENANT_A,
    eventCount: 1,
    receiptCount: 1,
    recoverableOutboxCount: 1,
    headEventHash: event.eventHash,
  });
});

test("request and stored metadata reject body, Prompt, Tool arguments, bytes and secrets", async () => {
  const harness = createHarness();
  await assert.rejects(
    harness.service.append(
      harness.context(),
      harness.request("extra", { prompt: "do not store me" }),
    ),
    code("INVALID_INPUT"),
  );
  for (const prohibited of [
    { body: "plain text" },
    { prompt: "plain text" },
    { toolArguments: { value: 1 } },
    { fileBytes: "AAEC" },
    { safeRef: "Bearer abcdefgh" },
    { apiKey: "AIzaSyDUMMY1234567890" },
    { authorization: "Basic dXNlcjpwYXNz" },
    { safeRef: "synthetic://fixture/item?api_key=secret" },
    { version: "AKIAIOSFODNN7EXAMPLE" },
  ]) {
    assert.throws(
      () => assertAuditMetadataOnly(prohibited),
      code("PROHIBITED_AUDIT_BODY"),
    );
  }
});

test("identity change and inactive Tenant fail before persistence", async () => {
  const changed = createHarness();
  changed.mutable.identitySequence.push(HUMAN, HUMAN_CHANGED);
  await assert.rejects(
    changed.service.append(changed.context(), changed.request()),
    code("ACTION_IDENTITY_CHANGED"),
  );
  assert.equal(
    (
      await changed.store.exportChain(
        scope(TENANT_A, "c18-correlation-1"),
      )
    ).events.length,
    0,
  );

  const inactive = createHarness();
  inactive.mutable.tenantActive = false;
  await assert.rejects(
    inactive.service.append(inactive.context(), inactive.request()),
    (error) => error.code === "TENANT_NOT_ACTIVE",
  );
  assert.equal(inactive.calls.includes("scope"), false);
});

test("security-relevant Delegation changes fail the final C05 identity check", async () => {
  const harness = createHarness();
  const first = identity(TENANT_A);
  const changed = structuredClone(first);
  changed.purposeRef = "synthetic://c18/purpose/changed";
  changed.delegationChain[0].purposeRef =
    "synthetic://c18/purpose/changed";
  changed.delegationChain[0].expiresAt =
    "2028-07-26T00:00:00.000Z";
  harness.mutable.identitySequence.push(first, changed);

  await assert.rejects(
    harness.service.append(harness.context(), harness.request("purpose")),
    code("ACTION_IDENTITY_CHANGED"),
  );
});

test("idempotency returns the original event and rejects key reuse", async () => {
  const harness = createHarness();
  const first = await harness.service.append(
    harness.context(),
    harness.request("same"),
  );
  const duplicate = await harness.service.append(
    harness.context(),
    harness.request("same"),
  );
  assert.equal(duplicate.eventId, first.eventId);
  assert.equal(duplicate.duplicate, true);
  await assert.rejects(
    harness.service.append(
      harness.context(),
      harness.request("other", {
        idempotencyKey: harness.request("same").idempotencyKey,
      }),
    ),
    code("IDEMPOTENCY_CONFLICT"),
  );
});

test("concurrent appends form one continuous per-Tenant chain", async () => {
  const harness = createHarness();
  await Promise.all(
    Array.from({ length: 25 }, (_, index) =>
      harness.service.append(
        harness.context(),
        harness.request(`parallel-${index}`),
      ),
    ),
  );
  const exported = await harness.store.exportChain(
    scope(TENANT_A, "c18-correlation-parallel-0"),
  );
  assert.deepEqual(
    exported.events.map((event) => event.sequence),
    Array.from({ length: 25 }, (_, index) => index + 1),
  );
  assert.equal(verifyAuditExport(exported).eventCount, 25);
});

test("three Synthetic Tenants remain isolated even with matching local ranges", async () => {
  const store = createMemoryAuditEvidenceStore();
  const harnesses = [TENANT_A, TENANT_B, TENANT_C].map(
    (tenantId, index) =>
      createHarness({ tenantId, store, start: 1000 + index * 100 }),
  );
  await Promise.all(
    harnesses.map((harness) =>
      harness.service.append(harness.context(), harness.request()),
    ),
  );
  for (const tenantId of [TENANT_A, TENANT_B, TENANT_C]) {
    const exported = await store.exportChain(
      scope(tenantId, "c18-correlation-1"),
    );
    assert.equal(exported.events.length, 1);
    assert.equal(exported.events[0].tenantId, tenantId);
    assert.equal(exported.events[0].sequence, 1);
  }
});

test("crashed lease and lost ACK retry the same immutable CloudEvent ID", async () => {
  const harness = createHarness();
  const appended = await harness.service.append(
    harness.context(),
    harness.request(),
  );
  const tenantScope = scope(TENANT_A, "c18-correlation-1");
  harness.mutable.now = "2026-07-26T10:00:01.000Z";
  const crashed = await harness.store.claimOutbox(tenantScope, {
    workerId: "worker-crashed",
    leaseDurationSeconds: 4,
    limit: 1,
  });
  assert.equal(crashed[0].eventId, appended.eventId);
  const accepted = new Set();
  let loseAck = true;
  const worker = createC18AuditOutboxWorker({
    store: harness.store,
    publisher: {
      async publish({ eventId, event }) {
        assert.equal(event.id, eventId);
        assert.equal(
          event.type,
          "product.aios.audit-evidence-recorded.v1",
        );
        assert.equal("body" in event.data, false);
        accepted.add(eventId);
        if (loseAck) {
          loseAck = false;
          throw new Error("ACK lost");
        }
        return { eventId };
      },
    },
  });
  harness.mutable.now = "2026-07-26T10:00:06.000Z";
  const first = await worker.runOnce(tenantScope, {
    workerId: "worker-retry",
    leaseDurationSeconds: 14,
    retryDelaySeconds: 24,
    limit: 1,
  });
  assert.equal(first.requeued, 1);
  harness.mutable.now = "2026-07-26T10:00:31.000Z";
  const second = await worker.runOnce(tenantScope, {
    workerId: "worker-retry",
    leaseDurationSeconds: 19,
    retryDelaySeconds: 29,
    limit: 1,
  });
  assert.equal(second.published, 1);
  assert.deepEqual([...accepted], [appended.eventId]);
  const snapshot = await harness.store.snapshot(tenantScope);
  assert.equal(snapshot.outbox[0].attemptCount, 3);
  assert.equal(snapshot.outbox[0].status, "PUBLISHED");

  await assert.rejects(
    harness.store.claimOutbox(tenantScope, {
      workerId: "worker-invalid",
      leaseDurationSeconds: 301,
      limit: 1,
    }),
    code("INVALID_INPUT"),
  );
});

test("tampering is detected and export restores into a new verifiable store", async () => {
  const harness = createHarness();
  await harness.service.append(
    harness.context(),
    harness.request("restore-1"),
  );
  await harness.service.append(
    harness.context(),
    harness.request("restore-2"),
  );
  const tenantScope = scope(TENANT_A, "c18-correlation-restore-1");
  const exported = await harness.store.exportChain(tenantScope);
  assert.equal(exported.schemaVersion, "c18-audit-recovery.v1");
  assert.equal(exported.receipts.length, 2);
  assert.equal(exported.outbox.length, 2);
  const restored = createMemoryAuditEvidenceStore({
    restoredExports: [exported],
  });
  assert.equal(
    verifyAuditExport(await restored.exportChain(tenantScope)).eventCount,
    2,
  );
  const restoredSnapshot = await restored.snapshot(tenantScope);
  assert.equal(restoredSnapshot.receiptCount, 2);
  assert.equal(restoredSnapshot.outbox.length, 2);

  const replayHarness = createHarness({ store: restored, start: 950 });
  const replayed = await replayHarness.service.append(
    replayHarness.context(),
    replayHarness.request("restore-1"),
  );
  assert.equal(replayed.eventId, exported.events[0].eventId);
  assert.equal(replayed.duplicate, true);

  const tampered = structuredClone(exported);
  tampered.events[0].payload.summaryCode = "TAMPERED";
  assert.throws(
    () => verifyAuditExport(tampered),
    code("AUDIT_CHAIN_TAMPERED"),
  );

  const tamperedReceipt = structuredClone(exported);
  tamperedReceipt.receipts[0].requestHash =
    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  assert.throws(
    () => verifyAuditExport(tamperedReceipt),
    code("AUDIT_RECOVERY_TAMPERED"),
  );
});

test("createdAt and the closed provenance payload are part of recovery integrity", async () => {
  const harness = createHarness();
  await harness.service.append(
    harness.context(),
    harness.request("closed-payload"),
  );
  const exported = await harness.store.exportChain(
    scope(TENANT_A, "c18-correlation-closed-payload"),
  );

  const changedTime = structuredClone(exported);
  changedTime.events[0].createdAt = "2029-01-01T00:00:00.000Z";
  assert.throws(
    () => verifyAuditExport(changedTime),
    code("AUDIT_CHAIN_TAMPERED"),
  );

  const incomplete = structuredClone(exported);
  incomplete.events[0].payload = {
    retentionClass: "AUDIT_7Y",
    occurredAt: incomplete.events[0].createdAt,
  };
  incomplete.events[0].payloadSha256 = auditEvidenceSha256(
    incomplete.events[0].payload,
  );
  incomplete.events[0].eventHash = computeAuditEventHash(
    incomplete.events[0],
  );
  assert.throws(
    () => verifyAuditExport(incomplete),
    code("INVALID_AUDIT_PAYLOAD"),
  );

  const changedCloudEvent = structuredClone(exported.events[0]);
  changedCloudEvent.createdAt = "2029-01-01T00:00:00.000Z";
  assert.notEqual(
    createAuditCloudEvent(changedCloudEvent).time,
    createAuditCloudEvent(exported.events[0]).time,
  );
});

test("retention query is bounded by Tenant, sequence and occurrence time", async () => {
  const harness = createHarness();
  await harness.service.append(
    harness.context(),
    harness.request("query-1"),
  );
  harness.mutable.now = "2026-07-26T11:00:00.000Z";
  await harness.service.append(
    harness.context(),
    harness.request("query-2"),
  );
  const records = await harness.store.query(
    scope(TENANT_A, "retention-query"),
    {
      fromSequence: 2,
      toSequence: 2,
      fromOccurredAt: FAR_PAST,
      toOccurredAt: FAR_FUTURE,
      limit: 10,
    },
  );
  assert.equal(records.length, 1);
  assert.equal(records[0].sequence, 2);
  assert.equal(records[0].payload.retentionClass, "AUDIT_7Y");
});
