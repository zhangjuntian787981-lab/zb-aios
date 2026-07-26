import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  PersonalMemoryError,
  createMemoryPersonalMemoryStore,
  createPersonalMemoryService,
  createSyntheticPersonalMemoryCatalog,
} from "../lib/c09-personal-memory.mjs";

const TENANT_A = "stn_018f0000-0000-7000-8000-000000000010";
const TENANT_B = "stn_01984910-3000-7000-8000-000000000002";
const HUMAN_A = "prn_018f0000-0000-7000-8000-000000000001";
const HUMAN_B = "prn_018f0000-0000-7000-8000-000000000003";
const ACTOR = "prn_018f0000-0000-7000-8000-000000000002";
const DELEGATION_A = "dlg_018f0000-0000-7000-8000-000000000020";
const DELEGATION_B = "dlg_018f0000-0000-7000-8000-000000000021";
const CANDIDATE =
  "fixture://c09/northstar/preferences/concise";
const CORRECTED =
  "fixture://c09/northstar/preferences/corrected";
const NOW = "2026-07-26T10:00:00.000Z";
const HASH =
  "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

const CATALOG_DOCUMENT = JSON.parse(
  await readFile(
    new URL(
      "../implementation/p1/c09/synthetic-personal-memory-catalog.v1.json",
      import.meta.url,
    ),
    "utf8",
  ),
);
const CATALOG = createSyntheticPersonalMemoryCatalog(CATALOG_DOCUMENT);

function deterministicIds(start = 100) {
  let counter = start;
  return () => {
    counter += 1;
    return `018f0000-0000-7000-8000-${String(counter).padStart(12, "0")}`;
  };
}

function createHarness({
  store = createMemoryPersonalMemoryStore(),
  tenantId = TENANT_A,
} = {}) {
  const mutable = {
    tenantId,
    humanPrincipalId: HUMAN_A,
    sessionId: "session-a",
    delegationId: DELEGATION_A,
    now: NOW,
    denyMemoryIds: new Set(),
    identitySequence: [],
    decisionActorPrincipalId: null,
    decisionDelegationId: null,
  };
  const calls = [];
  const stablePrincipalRegistry = {
    async resolveActionIdentity(_context, request) {
      calls.push(`identity:${mutable.sessionId}`);
      assert.ok(request.expectedTenantId);
      const resolvedHuman =
        mutable.identitySequence.shift() ?? mutable.humanPrincipalId;
      return {
        tenantId: mutable.tenantId,
        tenantKind: "SYNTHETIC",
        identityAccountId:
          "sia_018f0000-0000-7000-8000-000000000030",
        identityLinkId:
          "lnk_018f0000-0000-7000-8000-000000000031",
        sessionId: mutable.sessionId,
        humanSubject: {
          principalId: resolvedHuman,
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
        delegationChain: [
          {
            delegationId: mutable.delegationId,
            delegatorPrincipalId: resolvedHuman,
            delegatePrincipalId: ACTOR,
            purposeRef: "synthetic://c09/purpose/personal-memory",
            lifecycleVersion: 1,
            expiresAt: "2027-07-26T00:00:00.000Z",
          },
        ],
        trustSource:
          "VERIFIED_SESSION_IDENTITY_LINK_AND_WORKLOAD_CONTEXT",
      };
    },
  };
  const authorizer = {
    async enforce({ operation, tenantId: requestedTenant, identity, resource }) {
      calls.push(`authorize:${operation}:${resource.resourceId}`);
      const allowed = !(
        operation === "C09_RECALL_ITEM" &&
        mutable.denyMemoryIds.has(resource.resourceId)
      );
      return {
        allowed,
        tenantId: requestedTenant,
        humanPrincipalId: identity.humanSubject.principalId,
        workloadActorPrincipalId:
          mutable.decisionActorPrincipalId ??
          identity.workloadActor.principalId,
        delegationId:
          mutable.decisionDelegationId ??
          identity.delegationChain.at(-1).delegationId,
        operation,
        decisionId: `decision-${operation.toLowerCase()}`,
        evidenceRef: "evidence://c09/synthetic-authorization",
        policyVersion: "c09-synthetic-policy-v1",
      };
    },
  };
  const tenantRegistry = {
    async admitNewRequest({ tenantId: requestedTenant, expectedTenantKind }) {
      calls.push("tenant");
      assert.equal(expectedTenantKind, "SYNTHETIC");
      return {
        tenantId: requestedTenant,
        tenantKind: "SYNTHETIC",
        lifecycleVersion: 1,
      };
    },
  };
  const service = createPersonalMemoryService({
    stablePrincipalRegistry,
    authorizer,
    tenantRegistry,
    catalog: CATALOG,
    store,
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
        policyVersion: authorization.policyVersion,
      };
    },
    clock: () => mutable.now,
    idFactory: deterministicIds(),
  });
  return {
    service,
    store,
    mutable,
    calls,
    context() {
      return {
        synthetic: true,
        routeTrustSource: "VERIFIED_ROUTE_DESCRIPTOR",
        tenantId: mutable.tenantId,
        workloadTrustSource: "VERIFIED_WORKLOAD_CONTEXT",
        workloadActorPrincipalId: ACTOR,
      };
    },
    request(command, overrides = {}) {
      return {
        sessionToken: `token-${mutable.sessionId}`,
        delegationId: mutable.delegationId,
        command,
        ...overrides,
      };
    },
    recall(overrides = {}) {
      return {
        sessionToken: `token-${mutable.sessionId}`,
        delegationId: mutable.delegationId,
        correlationId: "recall-correlation",
        limit: 20,
        ...overrides,
      };
    },
  };
}

function propose(idempotencyKey = "propose-1", candidateRef = CANDIDATE) {
  return {
    kind: "PROPOSE_CANDIDATE",
    candidateRef,
    idempotencyKey,
    correlationId: idempotencyKey,
  };
}

function confirm(memoryId, expectedVersion = 1, suffix = "1") {
  return {
    kind: "CONFIRM_CANDIDATE",
    memoryId,
    expectedVersion,
    explicitConfirmation: true,
    idempotencyKey: `confirm-${suffix}`,
    correlationId: `confirm-${suffix}`,
  };
}

async function confirmedMemory(harness, suffix = "1") {
  const candidate = await harness.service.execute(
    harness.context(),
    harness.request(propose(`propose-${suffix}`)),
  );
  const confirmed = await harness.service.execute(
    harness.context(),
    harness.request(confirm(candidate.memoryId, 1, suffix)),
  );
  return confirmed;
}

function assertCode(expectedCode) {
  return (error) =>
    error instanceof PersonalMemoryError && error.code === expectedCode;
}

test("catalog freezes exactly three Synthetic Tenants and prevents cross-Tenant refs", () => {
  assert.deepEqual(CATALOG.tenantIds(), [
    TENANT_A,
    TENANT_B,
    "stn_01984910-3000-7000-8000-000000000003",
  ]);
  assert.throws(
    () => CATALOG.resolve(TENANT_B, CANDIDATE),
    assertCode("SYNTHETIC_FIXTURE_MISMATCH"),
  );
});

test("model proposal remains Candidate until the same Human explicitly confirms", async () => {
  const harness = createHarness();
  const candidate = await harness.service.execute(
    harness.context(),
    harness.request(propose()),
  );
  assert.deepEqual(candidate, {
    memoryId: candidate.memoryId,
    state: "CANDIDATE",
    version: 1,
  });
  assert.deepEqual(
    (await harness.service.recall(harness.context(), harness.recall()))
      .memories,
    [],
  );
  await assert.rejects(
    harness.service.execute(
      harness.context(),
      harness.request({
        ...confirm(candidate.memoryId),
        explicitConfirmation: false,
      }),
    ),
    assertCode("EXPLICIT_CONFIRMATION_REQUIRED"),
  );
  const active = await harness.service.execute(
    harness.context(),
    harness.request(confirm(candidate.memoryId)),
  );
  assert.equal(active.state, "CONFIRMED");
  const recall = await harness.service.recall(
    harness.context(),
    harness.recall(),
  );
  assert.equal(recall.memories.length, 1);
  assert.equal(
    recall.memories[0].content,
    "Synthetic preference: concise weekly summaries.",
  );
});

test("stable Principal owns memory across Session and Delegation renewal", async () => {
  const harness = createHarness();
  const candidate = await harness.service.execute(
    harness.context(),
    harness.request(propose()),
  );
  harness.mutable.sessionId = "session-renewed";
  harness.mutable.delegationId = DELEGATION_B;
  const confirmed = await harness.service.execute(
    harness.context(),
    harness.request(confirm(candidate.memoryId)),
  );
  assert.equal(confirmed.state, "CONFIRMED");
  assert.equal(
    (await harness.service.recall(harness.context(), harness.recall()))
      .principalId,
    HUMAN_A,
  );
});

test("another Human cannot confirm or recall the owner's memory", async () => {
  const harness = createHarness();
  const candidate = await harness.service.execute(
    harness.context(),
    harness.request(propose()),
  );
  harness.mutable.humanPrincipalId = HUMAN_B;
  harness.mutable.delegationId = DELEGATION_B;
  await assert.rejects(
    harness.service.execute(
      harness.context(),
      harness.request(confirm(candidate.memoryId)),
    ),
    assertCode("MEMORY_NOT_FOUND"),
  );
  assert.deepEqual(
    (await harness.service.recall(harness.context(), harness.recall()))
      .memories,
    [],
  );
});

test("recall performs structural filtering and item C06 before reading content", async () => {
  const base = createMemoryPersonalMemoryStore();
  const order = [];
  const wrapped = {
    ...base,
    async listRecallMetadata(...args) {
      order.push("metadata");
      return base.listRecallMetadata(...args);
    },
    async readRecallContent(...args) {
      order.push("content");
      return base.readRecallContent(...args);
    },
  };
  const harness = createHarness({ store: wrapped });
  const memory = await confirmedMemory(harness);
  harness.mutable.denyMemoryIds.add(memory.memoryId);
  const recalled = await harness.service.recall(
    harness.context(),
    harness.recall(),
  );
  assert.deepEqual(recalled.memories, []);
  assert.deepEqual(order, ["metadata"]);
  assert.ok(
    harness.calls.some(
      (entry) =>
        entry === `authorize:C09_RECALL_ITEM:${memory.memoryId}`,
    ),
  );
});

test("profile pause suppresses recall and resume restores it", async () => {
  const harness = createHarness();
  await confirmedMemory(harness);
  const paused = await harness.service.execute(
    harness.context(),
    harness.request({
      kind: "CHANGE_PROFILE_STATE",
      expectedProfileVersion: 1,
      state: "PAUSED",
      idempotencyKey: "pause-1",
      correlationId: "pause-1",
    }),
  );
  assert.equal(paused.state, "PAUSED");
  assert.deepEqual(
    (await harness.service.recall(harness.context(), harness.recall()))
      .memories,
    [],
  );
  await harness.service.execute(
    harness.context(),
    harness.request({
      kind: "CHANGE_PROFILE_STATE",
      expectedProfileVersion: 2,
      state: "ACTIVE",
      idempotencyKey: "resume-1",
      correlationId: "resume-1",
    }),
  );
  assert.equal(
    (await harness.service.recall(harness.context(), harness.recall()))
      .memories.length,
    1,
  );
});

test("natural expiry filters recall and explicit expiration scrubs content", async () => {
  const harness = createHarness();
  const candidate = await harness.service.execute(
    harness.context(),
    harness.request(
      propose(
        "propose-expiring",
        "fixture://c09/northstar/work-state/catalog",
      ),
    ),
  );
  const active = await harness.service.execute(
    harness.context(),
    harness.request(confirm(candidate.memoryId, 1, "expiring")),
  );
  harness.mutable.now = "2026-08-27T00:00:00.000Z";
  assert.deepEqual(
    (await harness.service.recall(harness.context(), harness.recall()))
      .memories,
    [],
  );
  const expired = await harness.service.execute(
    harness.context(),
    harness.request({
      kind: "EXPIRE_MEMORY",
      memoryId: active.memoryId,
      expectedVersion: active.version,
      idempotencyKey: "expire-1",
      correlationId: "expire-1",
    }),
  );
  assert.equal(expired.state, "EXPIRED");
  const snapshot = await harness.store.exportRecoverySnapshot();
  assert.equal(
    snapshot.memories.find((item) => item.memoryId === active.memoryId)
      .content,
    null,
  );
});

test("correction atomically deletes old content and confirms the replacement", async () => {
  const harness = createHarness();
  const active = await confirmedMemory(harness);
  const checkpoint = await harness.service.execute(
    harness.context(),
    harness.request({
      kind: "SAVE_CHECKPOINT",
      checkpointId: null,
      expectedVersion: 0,
      threadRef: "synthetic://c08/thread/personal-memory",
      stateRef: "fixture://c09/checkpoint/state-1",
      stateSha256: HASH,
      memoryIds: [active.memoryId],
      idempotencyKey: "checkpoint-1",
      correlationId: "checkpoint-1",
    }),
  );
  const corrected = await harness.service.execute(
    harness.context(),
    harness.request({
      kind: "CORRECT_MEMORY",
      memoryId: active.memoryId,
      expectedVersion: active.version,
      replacementCandidateRef: CORRECTED,
      explicitConfirmation: true,
      idempotencyKey: "correct-1",
      correlationId: "correct-1",
    }),
  );
  assert.equal(corrected.state, "CONFIRMED");
  const recall = await harness.service.recall(
    harness.context(),
    harness.recall(),
  );
  assert.deepEqual(
    recall.memories.map((memory) => memory.content),
    ["Synthetic preference: corrected daily summaries."],
  );
  const readCheckpoint = await harness.service.readCheckpoint(
    harness.context(),
    {
      sessionToken: "token-session-a",
      delegationId: DELEGATION_A,
      checkpointId: checkpoint.checkpointId,
      correlationId: "read-checkpoint-1",
    },
  );
  assert.deepEqual(readCheckpoint.memoryIds, []);
  const snapshot = await harness.store.exportRecoverySnapshot();
  const old = snapshot.memories.find(
    (memory) => memory.memoryId === active.memoryId,
  );
  assert.equal(old.state, "DELETED");
  assert.equal(old.content, null);
});

test("explicit deletion propagates to Checkpoint and survives recovery", async () => {
  const harness = createHarness();
  const active = await confirmedMemory(harness);
  const checkpoint = await harness.service.execute(
    harness.context(),
    harness.request({
      kind: "SAVE_CHECKPOINT",
      checkpointId: null,
      expectedVersion: 0,
      threadRef: "synthetic://c08/thread/delete-propagation",
      stateRef: "fixture://c09/checkpoint/delete-propagation",
      stateSha256: HASH,
      memoryIds: [active.memoryId],
      idempotencyKey: "checkpoint-delete",
      correlationId: "checkpoint-delete",
    }),
  );
  await harness.service.execute(
    harness.context(),
    harness.request({
      kind: "DELETE_MEMORY",
      memoryId: active.memoryId,
      expectedVersion: active.version,
      idempotencyKey: "delete-1",
      correlationId: "delete-1",
    }),
  );
  const recovery = await harness.store.exportRecoverySnapshot();
  assert.equal(JSON.stringify(recovery).includes("concise weekly"), false);
  const recoveredStore = createMemoryPersonalMemoryStore({
    snapshot: recovery,
  });
  const recovered = createHarness({ store: recoveredStore });
  assert.deepEqual(
    (await recovered.service.recall(
      recovered.context(),
      recovered.recall(),
    )).memories,
    [],
  );
  const recoveredCheckpoint = await recovered.service.readCheckpoint(
    recovered.context(),
    {
      sessionToken: "token-session-a",
      delegationId: DELEGATION_A,
      checkpointId: checkpoint.checkpointId,
      correlationId: "read-after-recovery",
    },
  );
  assert.deepEqual(recoveredCheckpoint.memoryIds, []);
});

test("same replay returns one effect and conflicting replay is rejected", async () => {
  const harness = createHarness();
  const command = propose("same-replay");
  const first = await harness.service.execute(
    harness.context(),
    harness.request(command),
  );
  const replay = await harness.service.execute(
    harness.context(),
    harness.request(command),
  );
  assert.deepEqual(replay, first);
  assert.equal(
    (await harness.store.inspectForTest()).events.length,
    1,
  );
  await assert.rejects(
    harness.service.execute(
      harness.context(),
      harness.request({
        ...propose("same-replay"),
        candidateRef: "fixture://c09/northstar/work-state/catalog",
      }),
    ),
    assertCode("IDEMPOTENCY_CONFLICT"),
  );
});

test("concurrent confirmations allow exactly one current-version transition", async () => {
  const harness = createHarness();
  const candidate = await harness.service.execute(
    harness.context(),
    harness.request(propose()),
  );
  const settled = await Promise.allSettled([
    harness.service.execute(
      harness.context(),
      harness.request(confirm(candidate.memoryId, 1, "concurrent-a")),
    ),
    harness.service.execute(
      harness.context(),
      harness.request(confirm(candidate.memoryId, 1, "concurrent-b")),
    ),
  ]);
  assert.equal(
    settled.filter((entry) => entry.status === "fulfilled").length,
    1,
  );
  const rejected = settled.find((entry) => entry.status === "rejected");
  assert.ok(
    ["STALE_VERSION", "INVALID_STATE"].includes(rejected.reason.code),
  );
});

test("cross-Tenant candidate, route and scope attempts fail closed", async () => {
  const harness = createHarness();
  await assert.rejects(
    harness.service.execute(
      harness.context(),
      harness.request(
        propose(
          "cross-tenant-candidate",
          "fixture://c09/cedar/preferences/evidence-first",
        ),
      ),
    ),
    assertCode("SYNTHETIC_FIXTURE_MISMATCH"),
  );
  await assert.rejects(
    harness.service.execute(
      { ...harness.context(), tenantId: TENANT_B },
      harness.request(propose("route-mismatch")),
    ),
    assertCode("IDENTITY_BINDING_INVALID"),
  );
});

test("arbitrary content and forbidden business categories cannot enter through the model API", async () => {
  const harness = createHarness();
  await assert.rejects(
    harness.service.execute(
      harness.context(),
      harness.request({
        ...propose("arbitrary"),
        content: "real order fact",
        category: "ORDER",
      }),
    ),
    assertCode("INVALID_INPUT"),
  );
  const forbidden = structuredClone(CATALOG_DOCUMENT);
  forbidden.tenants[0].candidates[0].category = "KPI";
  assert.throws(
    () => createSyntheticPersonalMemoryCatalog(forbidden),
    assertCode("FORBIDDEN_MEMORY_CATEGORY"),
  );
});

test("a C05 identity switch after C06 authorization fails before admission", async () => {
  const harness = createHarness();
  harness.mutable.identitySequence.push(HUMAN_A, HUMAN_B);
  await assert.rejects(
    harness.service.execute(
      harness.context(),
      harness.request(propose("identity-switch")),
    ),
    assertCode("IDENTITY_CHANGED"),
  );
  assert.equal(harness.calls.includes("tenant"), false);
  assert.deepEqual((await harness.store.inspectForTest()).memories, []);
});

test("a C06 decision bound to another Actor fails before the final C05 check", async () => {
  const harness = createHarness();
  harness.mutable.decisionActorPrincipalId = HUMAN_B;
  await assert.rejects(
    harness.service.execute(
      harness.context(),
      harness.request(propose("actor-switch")),
    ),
    assertCode("FORBIDDEN"),
  );
  assert.deepEqual(harness.calls.slice(0, 2), [
    "identity:session-a",
    `authorize:C09_PROPOSE_CANDIDATE:${HUMAN_A}`,
  ]);
  assert.equal(harness.calls.filter((entry) => entry.startsWith("identity:")).length, 1);
  assert.deepEqual((await harness.store.inspectForTest()).memories, []);
});

test("C05 identity, C06 authorization, C03 admission and C07 scope run in order", async () => {
  const harness = createHarness();
  await harness.service.execute(
    harness.context(),
    harness.request(propose()),
  );
  assert.deepEqual(harness.calls.slice(0, 4), [
    "identity:session-a",
    `authorize:C09_PROPOSE_CANDIDATE:${HUMAN_A}`,
    "identity:session-a",
    "tenant",
  ]);
  assert.deepEqual(harness.calls.slice(4, 5), [
    "scope",
  ]);
});
