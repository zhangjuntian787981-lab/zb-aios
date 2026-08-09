import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  PersonalMemoryError,
  createMemoryPersonalMemoryStore,
  createPersonalMemoryRetentionWorker,
  createPersonalMemoryService,
  createSyntheticHumanConsentAuthority,
  createSyntheticPersonalMemoryCatalog,
  personalMemorySha256,
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
  humanConsentStore = null,
} = {}) {
  const { issuer: consentIssuer, consentStore } =
    createSyntheticHumanConsentAuthority();
  const mutable = {
    tenantId,
    humanPrincipalId: HUMAN_A,
    sessionId: "session-a",
    delegationId: DELEGATION_A,
    now: NOW,
    denyMemoryIds: new Set(),
    identitySequence: [],
    itemDecisionSequence: [],
    decisionActorPrincipalId: null,
    decisionDelegationId: null,
    afterAuthorize: null,
  };
  const calls = [];
  const stablePrincipalRegistry = {
    async resolveActionIdentity(_context, request) {
      calls.push(`identity:${mutable.sessionId}`);
      assert.ok(request.expectedTenantId);
      const nextIdentity = mutable.identitySequence.shift();
      const identityOverride = typeof nextIdentity === "string"
        ? { humanPrincipalId: nextIdentity }
        : nextIdentity ?? {};
      const resolvedHuman =
        identityOverride.humanPrincipalId ?? mutable.humanPrincipalId;
      const resolvedActor =
        identityOverride.workloadActorPrincipalId ?? ACTOR;
      const resolvedDelegation =
        identityOverride.delegationId ?? mutable.delegationId;
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
          lifecycleVersion:
            identityOverride.humanLifecycleVersion ?? 1,
          securityEpoch: identityOverride.humanSecurityEpoch ?? 1,
        },
        workloadActor: {
          principalId: resolvedActor,
          principalType: "SERVICE",
          lifecycleVersion:
            identityOverride.workloadLifecycleVersion ?? 1,
          securityEpoch:
            identityOverride.workloadSecurityEpoch ?? 1,
        },
        delegationChain: identityOverride.delegationChain ?? [
          {
            delegationId: resolvedDelegation,
            delegatorPrincipalId: resolvedHuman,
            delegatePrincipalId: resolvedActor,
            purposeRef:
              identityOverride.delegationPurposeRef ??
              "synthetic://c09/purpose/personal-memory",
            lifecycleVersion:
              identityOverride.delegationLifecycleVersion ?? 1,
            expiresAt:
              identityOverride.delegationExpiresAt ??
              "2027-07-26T00:00:00.000Z",
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
      const decisionOverride = operation === "C09_RECALL_ITEM"
        ? mutable.itemDecisionSequence.shift() ?? {}
        : {};
      const decision = {
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
        decisionId:
          decisionOverride.decisionId ??
          `decision-${operation.toLowerCase()}`,
        evidenceRef:
          decisionOverride.evidenceRef ??
          "evidence://c09/synthetic-authorization",
        policyVersion:
          decisionOverride.policyVersion ?? "c09-synthetic-policy-v1",
      };
      mutable.afterAuthorize?.({
        operation,
        identity: structuredClone(identity),
        resource: structuredClone(resource),
      });
      return decision;
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
    humanConsentStore: humanConsentStore ?? consentStore,
    clock: () => mutable.now,
    idFactory: deterministicIds(),
  });
  return {
    service,
    store,
    consentIssuer,
    consentStore,
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

function issueConsent(
  harness,
  {
    memoryId,
    expectedVersion = 1,
    candidateRef = CANDIDATE,
    purpose = "CONFIRM_PERSONAL_MEMORY",
  },
) {
  return harness.consentIssuer.issue({
    tenantId: harness.mutable.tenantId,
    humanPrincipalId: harness.mutable.humanPrincipalId,
    memoryId,
    expectedVersion,
    contentSha256: CATALOG.resolve(
      harness.mutable.tenantId,
      candidateRef,
    ).contentSha256,
    expiresAt: "2026-07-26T11:00:00.000Z",
    purpose,
  });
}

function confirm(
  harness,
  memoryId,
  expectedVersion = 1,
  suffix = "1",
  candidateRef = CANDIDATE,
) {
  return {
    kind: "CONFIRM_CANDIDATE",
    memoryId,
    expectedVersion,
    humanConsentToken: issueConsent(harness, {
      memoryId,
      expectedVersion,
      candidateRef,
    }),
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
    harness.request(confirm(harness, candidate.memoryId, 1, suffix)),
  );
  return confirmed;
}

function assertCode(expectedCode) {
  return (error) =>
    error instanceof PersonalMemoryError && error.code === expectedCode;
}

test("personal memory service exposes only governed operations", () => {
  const harness = createHarness();
  assert.deepEqual(Object.keys(harness.service).sort(), [
    "execute",
    "readCheckpoint",
    "recall",
  ]);
});

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

test("model proposal remains Candidate until a trusted Human consent artifact is consumed", async () => {
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
        kind: "CONFIRM_CANDIDATE",
        memoryId: candidate.memoryId,
        expectedVersion: 1,
        humanConsentToken:
          "hct_018f0000-0000-7000-8000-000000000099",
        idempotencyKey: "confirm-unissued",
        correlationId: "confirm-unissued",
      }),
    ),
    assertCode("HUMAN_CONSENT_INVALID"),
  );
  const active = await harness.service.execute(
    harness.context(),
    harness.request(confirm(harness, candidate.memoryId)),
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

test("Human consent is content-bound, expiring, one-time and replay-safe", async () => {
  const harness = createHarness();
  const candidate = await harness.service.execute(
    harness.context(),
    harness.request(propose("propose-consent-properties")),
  );
  const mismatchedToken = issueConsent(harness, {
    memoryId: candidate.memoryId,
    candidateRef: CORRECTED,
  });
  await assert.rejects(
    harness.service.execute(
      harness.context(),
      harness.request({
        kind: "CONFIRM_CANDIDATE",
        memoryId: candidate.memoryId,
        expectedVersion: 1,
        humanConsentToken: mismatchedToken,
        idempotencyKey: "confirm-content-mismatch",
        correlationId: "confirm-content-mismatch",
      }),
    ),
    assertCode("HUMAN_CONSENT_BINDING_MISMATCH"),
  );
  const expiredToken = harness.consentIssuer.issue({
    tenantId: TENANT_A,
    humanPrincipalId: HUMAN_A,
    memoryId: candidate.memoryId,
    expectedVersion: 1,
    contentSha256: CATALOG.resolve(TENANT_A, CANDIDATE).contentSha256,
    expiresAt: NOW,
    purpose: "CONFIRM_PERSONAL_MEMORY",
  });
  await assert.rejects(
    harness.service.execute(
      harness.context(),
      harness.request({
        kind: "CONFIRM_CANDIDATE",
        memoryId: candidate.memoryId,
        expectedVersion: 1,
        humanConsentToken: expiredToken,
        idempotencyKey: "confirm-expired-consent",
        correlationId: "confirm-expired-consent",
      }),
    ),
    assertCode("HUMAN_CONSENT_EXPIRED"),
  );

  const token = issueConsent(harness, { memoryId: candidate.memoryId });
  const command = {
    kind: "CONFIRM_CANDIDATE",
    memoryId: candidate.memoryId,
    expectedVersion: 1,
    humanConsentToken: token,
    idempotencyKey: "confirm-one-time",
    correlationId: "confirm-one-time",
  };
  const active = await harness.service.execute(
    harness.context(),
    harness.request(command),
  );
  assert.deepEqual(
    await harness.service.execute(
      harness.context(),
      harness.request(command),
    ),
    active,
  );
  const secondCandidate = await harness.service.execute(
    harness.context(),
    harness.request(propose("propose-token-reuse")),
  );
  await assert.rejects(
    harness.service.execute(
      harness.context(),
      harness.request({
        ...command,
        memoryId: secondCandidate.memoryId,
        idempotencyKey: "confirm-token-reuse",
        correlationId: "confirm-token-reuse",
      }),
    ),
    assertCode("HUMAN_CONSENT_ALREADY_CONSUMED"),
  );
  const event = (await harness.store.inspectForTest()).events.find(
    ({ eventType }) => eventType === "MEMORY_CONFIRMED",
  );
  assert.equal(event.humanConsentEvidence.memoryId, candidate.memoryId);
  assert.equal(event.humanConsentEvidence.expectedVersion, 1);
  assert.equal(
    event.humanConsentEvidence.contentSha256,
    CATALOG.resolve(TENANT_A, CANDIDATE).contentSha256,
  );
  assert.equal(JSON.stringify(event).includes(token), false);
});

test("Human consent evidence rejects token, content and secret fields", async (t) => {
  for (const unsupportedField of [
    "token",
    "humanConsentToken",
    "content",
    "secret",
  ]) {
    await t.test(unsupportedField, async () => {
      const humanConsentStore = {
        async consume({ token, expected, now }) {
          return {
            ...expected,
            expiresAt: "2026-07-26T11:00:00.000Z",
            tokenSha256: personalMemorySha256(token),
            consumedAt: now,
            [unsupportedField]: "must-not-persist",
          };
        },
      };
      const harness = createHarness({ humanConsentStore });
      const candidate = await harness.service.execute(
        harness.context(),
        harness.request(propose(`propose-malicious-${unsupportedField}`)),
      );
      await assert.rejects(
        harness.service.execute(
          harness.context(),
          harness.request({
            kind: "CONFIRM_CANDIDATE",
            memoryId: candidate.memoryId,
            expectedVersion: candidate.version,
            humanConsentToken:
              "hct_018f0000-0000-7000-8000-000000000099",
            idempotencyKey: `confirm-malicious-${unsupportedField}`,
            correlationId: `confirm-malicious-${unsupportedField}`,
          }),
        ),
        assertCode("INVALID_INPUT"),
      );
      const state = await harness.store.inspectForTest();
      assert.equal(
        state.memories.find(
          ({ memoryId }) => memoryId === candidate.memoryId,
        ).state,
        "CANDIDATE",
      );
      assert.equal(
        JSON.stringify(state).includes("must-not-persist"),
        false,
      );
    });
  }
});

test("committed confirmation replays after service and consent restart", async () => {
  const store = createMemoryPersonalMemoryStore();
  const first = createHarness({ store });
  const candidate = await first.service.execute(
    first.context(),
    first.request(propose("propose-restart-replay")),
  );
  const command = confirm(
    first,
    candidate.memoryId,
    candidate.version,
    "restart-replay",
  );
  const confirmed = await first.service.execute(
    first.context(),
    first.request(command),
  );

  const restarted = createHarness({ store });
  assert.deepEqual(
    await restarted.service.execute(
      restarted.context(),
      restarted.request(command),
    ),
    confirmed,
  );
});

test("uncommitted consent fails closed after service restart", async () => {
  const store = createMemoryPersonalMemoryStore();
  const first = createHarness({ store });
  const candidate = await first.service.execute(
    first.context(),
    first.request(propose("propose-uncommitted-restart")),
  );
  const command = confirm(
    first,
    candidate.memoryId,
    candidate.version,
    "uncommitted-restart",
  );

  const restarted = createHarness({ store });
  await assert.rejects(
    restarted.service.execute(
      restarted.context(),
      restarted.request(command),
    ),
    assertCode("HUMAN_CONSENT_INVALID"),
  );
});

test("stale consent target fails before consuming Human consent", async () => {
  const harness = createHarness();
  const candidate = await harness.service.execute(
    harness.context(),
    harness.request(propose("propose-stale-consent")),
  );
  const token = issueConsent(harness, {
    memoryId: candidate.memoryId,
    expectedVersion: 2,
  });
  const command = {
    kind: "CONFIRM_CANDIDATE",
    memoryId: candidate.memoryId,
    expectedVersion: 2,
    humanConsentToken: token,
    idempotencyKey: "confirm-stale-consent",
    correlationId: "confirm-stale-consent",
  };

  await assert.rejects(
    harness.service.execute(
      harness.context(),
      harness.request(command),
    ),
    assertCode("STALE_VERSION"),
  );
  await harness.consentStore.consume({
    token,
    expected: {
      tenantId: TENANT_A,
      humanPrincipalId: HUMAN_A,
      memoryId: candidate.memoryId,
      expectedVersion: 2,
      contentSha256: CATALOG.resolve(TENANT_A, CANDIDATE).contentSha256,
      purpose: "CONFIRM_PERSONAL_MEMORY",
    },
    now: NOW,
    requestHash: personalMemorySha256("manual-consent-check"),
  });
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
    harness.request(confirm(harness, candidate.memoryId)),
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
      harness.request(confirm(harness, candidate.memoryId)),
    ),
    assertCode("MEMORY_NOT_FOUND"),
  );
  assert.deepEqual(
    (await harness.service.recall(harness.context(), harness.recall()))
      .memories,
    [],
  );
});

test("Memory Store rejects a same-Tenant Principal replacement", async () => {
  const store = createMemoryPersonalMemoryStore();
  const ownerScope = {
    trustSource: "C07_VERIFIED_TENANT_SCOPE",
    tenantId: TENANT_A,
    tenantKind: "SYNTHETIC",
    principalId: HUMAN_A,
  };
  await assert.rejects(
    store.readProfile(ownerScope, {
      tenantId: TENANT_A,
      principalId: HUMAN_B,
    }),
    assertCode("IDENTITY_BINDING_INVALID"),
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

  const postReadBase = createMemoryPersonalMemoryStore();
  let revokeAfterRead = () => {};
  const postReadStore = {
    ...postReadBase,
    async readRecallContent(...args) {
      const postReadMemory = await postReadBase.readRecallContent(...args);
      revokeAfterRead();
      return postReadMemory;
    },
  };
  const postReadHarness = createHarness({ store: postReadStore });
  const postReadMemory = await confirmedMemory(
    postReadHarness,
    "post-read-revocation",
  );
  revokeAfterRead = () => {
    postReadHarness.mutable.denyMemoryIds.add(postReadMemory.memoryId);
  };

  const postReadResult = await postReadHarness.service.recall(
    postReadHarness.context(),
    postReadHarness.recall(),
  );

  assert.deepEqual(postReadResult.memories, []);

  for (const [name, tamper] of [
    ["tenant", (entry) => ({ ...entry, tenantId: TENANT_B })],
    ["principal", (entry) => ({ ...entry, principalId: HUMAN_B })],
    [
      "memory ID",
      (entry) => ({
        ...entry,
        memoryId: "mem_018f0000-0000-7000-8000-000000009999",
      }),
    ],
    ["category", (entry) => ({ ...entry, category: "WORK_STATE" })],
    ["state", (entry) => ({ ...entry, state: "CANDIDATE" })],
    ["version", (entry) => ({ ...entry, version: entry.version - 1 })],
    [
      "declared content hash",
      (entry) => ({ ...entry, contentSha256: HASH }),
    ],
    [
      "plaintext content",
      (entry) => ({ ...entry, content: "tampered plaintext" }),
    ],
  ]) {
    const bindingBase = createMemoryPersonalMemoryStore();
    const bindingStore = {
      ...bindingBase,
      async readRecallContent(...args) {
        const bindingMemory = await bindingBase.readRecallContent(...args);
        return tamper(bindingMemory);
      },
    };
    const bindingHarness = createHarness({ store: bindingStore });
    await confirmedMemory(
      bindingHarness,
      `binding-${name.replaceAll(" ", "-")}`,
    );

    await assert.rejects(
      bindingHarness.service.recall(
        bindingHarness.context(),
        bindingHarness.recall(),
      ),
      assertCode("INTEGRITY_VIOLATION"),
      name,
    );
  }

  const evidenceBase = createMemoryPersonalMemoryStore();
  let contentReads = 0;
  const evidenceStore = {
    ...evidenceBase,
    async readRecallContent(...args) {
      contentReads += 1;
      return evidenceBase.readRecallContent(...args);
    },
  };
  const evidenceHarness = createHarness({ store: evidenceStore });
  const evidenceMemory = await confirmedMemory(
    evidenceHarness,
    "final-evidence",
  );
  const resources = [];
  evidenceHarness.mutable.itemDecisionSequence.push(
    {
      decisionId: "decision-c09-recall-item-before-read",
      evidenceRef: "evidence://c09/recall-item-before-read",
      policyVersion: "c09-recall-item-before-read-v1",
    },
    {
      decisionId: "decision-c09-recall-item-after-read",
      evidenceRef: "evidence://c09/recall-item-after-read",
      policyVersion: "c09-recall-item-after-read-v1",
    },
  );
  evidenceHarness.mutable.afterAuthorize = ({ operation, resource }) => {
    if (operation === "C09_RECALL_ITEM") resources.push(resource);
  };

  const evidenceResult = await evidenceHarness.service.recall(
    evidenceHarness.context(),
    evidenceHarness.recall(),
  );

  assert.equal(contentReads, 1);
  assert.deepEqual(resources, [
    {
      resourceType: "personal_memory",
      resourceId: evidenceMemory.memoryId,
      category: "PREFERENCE",
      version: evidenceMemory.version,
    },
    {
      resourceType: "personal_memory",
      resourceId: evidenceMemory.memoryId,
      category: "PREFERENCE",
      version: evidenceMemory.version,
      contentSha256: CATALOG.resolve(TENANT_A, CANDIDATE).contentSha256,
    },
  ]);
  assert.deepEqual(evidenceResult.memories[0].authorizationEvidence, {
    decisionId: "decision-c09-recall-item-after-read",
    evidenceRef: "evidence://c09/recall-item-after-read",
    policyVersion: "c09-recall-item-after-read-v1",
    humanPrincipalId: HUMAN_A,
    workloadActorPrincipalId: ACTOR,
    delegationId: DELEGATION_A,
  });
});

test("recall drops an item when C05 identity changes during item C06", async (t) => {
  for (const [name, identityOverride] of [
    ["actor", { workloadActorPrincipalId: HUMAN_B }],
    ["delegation", { delegationId: DELEGATION_B }],
    ["human lifecycle", { humanLifecycleVersion: 2 }],
    ["human security epoch", { humanSecurityEpoch: 2 }],
    ["workload lifecycle", { workloadLifecycleVersion: 2 }],
    ["workload epoch", { workloadSecurityEpoch: 2 }],
    ["delegation lifecycle", { delegationLifecycleVersion: 2 }],
    [
      "delegation expiry",
      { delegationExpiresAt: "2027-07-27T00:00:00.000Z" },
    ],
    [
      "delegation chain",
      {
        delegationPurposeRef:
          "synthetic://c09/purpose/changed-personal-memory",
      },
    ],
  ]) {
    await t.test(name, async () => {
      const base = createMemoryPersonalMemoryStore();
      let contentReads = 0;
      const store = {
        ...base,
        async readRecallContent(...args) {
          contentReads += 1;
          return base.readRecallContent(...args);
        },
      };
      const harness = createHarness({ store });
      await confirmedMemory(harness);
      harness.mutable.afterAuthorize = ({ operation }) => {
        if (operation === "C09_RECALL_ITEM") {
          harness.mutable.identitySequence.push(identityOverride);
          harness.mutable.afterAuthorize = null;
        }
      };
      const result = await harness.service.recall(
        harness.context(),
        harness.recall(),
      );
      assert.deepEqual(result.memories, []);
      assert.equal(contentReads, 0);

      const postReadBase = createMemoryPersonalMemoryStore();
      let changeIdentityAfterRead = () => {};
      const postReadStore = {
        ...postReadBase,
        async readRecallContent(...args) {
          const postReadMemory = await postReadBase.readRecallContent(...args);
          changeIdentityAfterRead();
          return postReadMemory;
        },
      };
      const postReadHarness = createHarness({ store: postReadStore });
      await confirmedMemory(
        postReadHarness,
        `post-read-identity-${name.replaceAll(" ", "-")}`,
      );
      changeIdentityAfterRead = () => {
        postReadHarness.mutable.identitySequence.push(identityOverride);
      };

      const postReadResult = await postReadHarness.service.recall(
        postReadHarness.context(),
        postReadHarness.recall(),
      );

      assert.deepEqual(postReadResult.memories, []);
    });
  }
});

test("profile pause suppresses recall, checkpoint and recovery content until resume", async () => {
  const harness = createHarness();
  const active = await confirmedMemory(harness);
  const checkpoint = await harness.service.execute(
    harness.context(),
    harness.request({
      kind: "SAVE_CHECKPOINT",
      checkpointId: null,
      expectedVersion: 0,
      threadRef: "synthetic://c08/thread/pause",
      stateRef: "fixture://c09/checkpoint/pause",
      stateSha256: HASH,
      memoryIds: [active.memoryId],
      idempotencyKey: "checkpoint-pause",
      correlationId: "checkpoint-pause",
    }),
  );
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
  await assert.rejects(
    harness.service.readCheckpoint(harness.context(), {
      sessionToken: "token-session-a",
      delegationId: DELEGATION_A,
      checkpointId: checkpoint.checkpointId,
      correlationId: "read-paused-checkpoint",
    }),
    assertCode("PROFILE_PAUSED"),
  );
  const pausedRecovery = await harness.store.exportRecoverySnapshot({
    asOf: harness.mutable.now,
  });
  assert.equal(
    JSON.stringify(pausedRecovery).includes("concise weekly"),
    false,
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

test("natural expiry filters reads and materialization atomically scrubs recovery and checkpoints", async () => {
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
    harness.request(
      confirm(
        harness,
        candidate.memoryId,
        1,
        "expiring",
        "fixture://c09/northstar/work-state/catalog",
      ),
    ),
  );
  const checkpoint = await harness.service.execute(
    harness.context(),
    harness.request({
      kind: "SAVE_CHECKPOINT",
      checkpointId: null,
      expectedVersion: 0,
      threadRef: "synthetic://c08/thread/expiry",
      stateRef: "fixture://c09/checkpoint/expiry",
      stateSha256: HASH,
      memoryIds: [active.memoryId],
      idempotencyKey: "checkpoint-expiry",
      correlationId: "checkpoint-expiry",
    }),
  );
  harness.mutable.now = "2026-08-27T00:00:00.000Z";
  assert.deepEqual(
    (await harness.service.recall(harness.context(), harness.recall()))
      .memories,
    [],
  );
  assert.deepEqual(
    (
      await harness.service.readCheckpoint(harness.context(), {
        sessionToken: "token-session-a",
        delegationId: DELEGATION_A,
        checkpointId: checkpoint.checkpointId,
        correlationId: "read-expired-checkpoint",
      })
    ).memoryIds,
    [],
  );
  const recoveryBeforeWorker = await harness.store.exportRecoverySnapshot({
    asOf: harness.mutable.now,
  });
  assert.equal(
    recoveryBeforeWorker.memories.find(
      (item) => item.memoryId === active.memoryId,
    ).content,
    null,
  );
  const materialize = {
    kind: "MATERIALIZE_EXPIRY",
    memoryId: active.memoryId,
    expectedVersion: active.version,
    idempotencyKey: "materialize-expiry-1",
    correlationId: "materialize-expiry-1",
  };
  const [expired, replay] = await Promise.all([
    harness.service.execute(
      harness.context(),
      harness.request(materialize),
    ),
    harness.service.execute(
      harness.context(),
      harness.request(materialize),
    ),
  ]);
  assert.deepEqual(replay, expired);
  assert.equal(
    (await harness.store.inspectForTest()).events.filter(
      (event) =>
        event.memoryId === active.memoryId &&
        event.eventType === "MEMORY_EXPIRED",
    ).length,
    1,
  );
  assert.equal(expired.state, "EXPIRED");
  const snapshot = await harness.store.exportRecoverySnapshot({
    asOf: harness.mutable.now,
  });
  assert.equal(
    snapshot.memories.find((item) => item.memoryId === active.memoryId)
      .content,
    null,
  );
  const recovered = createHarness({
    store: createMemoryPersonalMemoryStore({ snapshot }),
  });
  assert.deepEqual(
    (
      await recovered.service.readCheckpoint(
        recovered.context(),
        {
          sessionToken: "token-session-a",
          delegationId: DELEGATION_A,
          checkpointId: checkpoint.checkpointId,
          correlationId: "read-expired-after-restart",
        },
      )
    ).memoryIds,
    [],
  );
});

test("retention worker materializes only due memory without returning plaintext", async () => {
  const harness = createHarness();
  const candidate = await harness.service.execute(
    harness.context(),
    harness.request(
      propose(
        "propose-retention-worker",
        "fixture://c09/northstar/work-state/catalog",
      ),
    ),
  );
  await harness.service.execute(
    harness.context(),
    harness.request({
      kind: "CHANGE_PROFILE_STATE",
      expectedProfileVersion: 1,
      state: "PAUSED",
      idempotencyKey: "pause-retention-worker",
      correlationId: "pause-retention-worker",
    }),
  );
  harness.mutable.now = "2026-08-27T00:00:00.000Z";
  const retentionIdentity = {
    trustSource: "C05_VERIFIED_WORKLOAD_IDENTITY",
    tenantId: TENANT_A,
    tenantKind: "SYNTHETIC",
    principalId: ACTOR,
    principalKind: "SERVICE",
    lifecycleVersion: 1,
    securityEpoch: 1,
  };
  const workloadIdentitySequence = [];
  const worker = createPersonalMemoryRetentionWorker({
    store: harness.store,
    clock: () => harness.mutable.now,
    idFactory: deterministicIds(4000),
    workloadIdentityProvider: {
      async resolve() {
        return structuredClone(
          workloadIdentitySequence.shift() ?? retentionIdentity,
        );
      },
    },
    authorizer: {
      async enforce({ tenantId, operation, identity, resource }) {
        return {
          allowed: true,
          tenantId,
          operation,
          actorPrincipalId: identity.principalId,
          resourceId: resource.resourceId,
          expectedVersion: resource.expectedVersion,
          decisionId: "decision-c09-retention-worker",
          evidenceRef: "policy://c09/retention-worker",
          policyVersion: "c09-retention-worker-v1",
        };
      },
    },
    tenantRegistry: {
      async admitNewRequest({ tenantId }) {
        return {
          tenantId,
          tenantKind: "SYNTHETIC",
          lifecycleVersion: 1,
        };
      },
    },
    async tenantScopeFactory({ tenant, authorization, correlationId }) {
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
  });
  assert.deepEqual(Object.keys(worker), ["materializeExpiry"]);
  const command = {
    tenantId: TENANT_A,
    memoryId: candidate.memoryId,
    expectedVersion: candidate.version,
    idempotencyKey: "retention-worker-expiry",
    correlationId: "retention-worker-expiry",
  };
  const first = await worker.materializeExpiry(command);
  const replay = await worker.materializeExpiry(command);
  assert.deepEqual(replay, first);
  assert.deepEqual(first, {
    memoryId: candidate.memoryId,
    state: "EXPIRED",
    version: 2,
  });
  assert.equal(JSON.stringify(first).includes("Synthetic work state"), false);
  const state = await harness.store.inspectForTest();
  const expired = state.memories.find(
    ({ memoryId }) => memoryId === candidate.memoryId,
  );
  assert.equal(expired.content, null);
  assert.equal(
    state.events.filter(
      ({ memoryId, eventType }) =>
        memoryId === candidate.memoryId &&
        eventType === "MEMORY_EXPIRED",
    ).length,
    1,
  );
  for (const [field, value] of [
    ["principalId", HUMAN_B],
    ["lifecycleVersion", 2],
    ["securityEpoch", 2],
  ]) {
    workloadIdentitySequence.push(
      retentionIdentity,
      { ...retentionIdentity, [field]: value },
    );
    await assert.rejects(
      worker.materializeExpiry({
        ...command,
        idempotencyKey: `retention-identity-race-${field}`,
        correlationId: `retention-identity-race-${field}`,
      }),
      assertCode("IDENTITY_CHANGED"),
    );
  }
  assert.equal(
    (await harness.store.inspectForTest()).events.length,
    state.events.length,
  );
  await assert.rejects(
    worker.materializeExpiry({ ...command, operation: "DELETE_MEMORY" }),
    assertCode("INVALID_INPUT"),
  );
});

test("Memory retention Store rejects forged actor, evidence and envelope bindings", async (t) => {
  const harness = createHarness();
  const candidate = await harness.service.execute(
    harness.context(),
    harness.request(
      propose(
        "retention-store-binding",
        "fixture://c09/northstar/work-state/catalog",
      ),
    ),
  );
  harness.mutable.now = "2026-08-27T00:00:00.000Z";
  const command = {
    operation: "MATERIALIZE_EXPIRY",
    tenantId: TENANT_A,
    memoryId: candidate.memoryId,
    expectedVersion: candidate.version,
    idempotencyKey: "retention-store-materialize-binding",
    correlationId: "retention-store-binding",
  };
  const envelope = {
    ...command,
    tenantKind: "SYNTHETIC",
    eventId: "mev_018f0000-0000-7000-8000-000000008888",
    requestHash: personalMemorySha256({
      ...command,
      actorPrincipalId: ACTOR,
      actorLifecycleVersion: 1,
      actorSecurityEpoch: 1,
    }),
    now: harness.mutable.now,
  };
  const authorizationEvidence = {
    tenantId: TENANT_A,
    operation: "C09_RETENTION_MATERIALIZE_EXPIRY",
    actorPrincipalId: ACTOR,
    actorLifecycleVersion: 1,
    actorSecurityEpoch: 1,
    resourceId: candidate.memoryId,
    expectedVersion: candidate.version,
    decisionId: "decision-retention-store-binding",
    evidenceRef: "evidence://c09/retention-store-binding",
    policyVersion: "c09-retention-store-binding-v1",
  };
  const scope = {
    trustSource: "C09_VERIFIED_RETENTION_SCOPE",
    tenantId: TENANT_A,
    tenantKind: "SYNTHETIC",
    lifecycleVersion: 1,
    correlationId: command.correlationId,
    decisionId: authorizationEvidence.decisionId,
    evidenceRef: authorizationEvidence.evidenceRef,
    policyVersion: authorizationEvidence.policyVersion,
    operation: authorizationEvidence.operation,
    memoryId: candidate.memoryId,
    expectedVersion: candidate.version,
    actorPrincipalId: ACTOR,
    actorLifecycleVersion: 1,
    actorSecurityEpoch: 1,
    authorizationEvidence,
  };
  for (const [name, mutate, code] of [
    [
      "actor",
      (value) => {
        value.scope.actorPrincipalId = HUMAN_B;
      },
      "TENANT_SCOPE_VIOLATION",
    ],
    [
      "actor lifecycle",
      (value) => {
        value.scope.actorLifecycleVersion = 0;
      },
      "INVALID_INPUT",
    ],
    [
      "actor security epoch",
      (value) => {
        value.scope.actorSecurityEpoch = "1";
      },
      "INVALID_INPUT",
    ],
    [
      "valid but forged actor identity versions",
      (value) => {
        value.scope.actorLifecycleVersion = 2;
        value.scope.actorSecurityEpoch = 2;
      },
      "TENANT_SCOPE_VIOLATION",
    ],
    [
      "valid but forged actor identity hash binding",
      (value) => {
        value.scope.actorLifecycleVersion = 2;
        value.scope.actorSecurityEpoch = 2;
        value.scope.authorizationEvidence.actorLifecycleVersion = 2;
        value.scope.authorizationEvidence.actorSecurityEpoch = 2;
      },
      "TENANT_SCOPE_VIOLATION",
    ],
    [
      "authorization evidence",
      (value) => {
        value.scope.authorizationEvidence.secret = "forbidden";
      },
      "INVALID_INPUT",
    ],
    [
      "envelope hash",
      (value) => {
        value.envelope.idempotencyKey = "retention-store-binding-changed";
      },
      "TENANT_SCOPE_VIOLATION",
    ],
  ]) {
    await t.test(name, async () => {
      const value = {
        scope: structuredClone(scope),
        envelope: structuredClone(envelope),
      };
      mutate(value);
      await assert.rejects(
        harness.store.materializeExpiry(value.scope, value.envelope),
        assertCode(code),
      );
      const state = await harness.store.inspectForTest();
      assert.equal(
        state.memories.find(
          ({ memoryId }) => memoryId === candidate.memoryId,
        ).state,
        "CANDIDATE",
      );
      assert.equal(
        state.events.some(
          ({ memoryId, eventType }) =>
            memoryId === candidate.memoryId &&
            eventType === "MEMORY_EXPIRED",
        ),
        false,
      );
    });
  }
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
      humanConsentToken: issueConsent(harness, {
        memoryId: active.memoryId,
        expectedVersion: active.version,
        candidateRef: CORRECTED,
        purpose: "CORRECT_PERSONAL_MEMORY",
      }),
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
  const snapshot = await harness.store.exportRecoverySnapshot({
    asOf: harness.mutable.now,
  });
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
  const deletedState = await harness.store.inspectForTest();
  assert.equal(
    deletedState.memories.filter(
      (memory) =>
        memory.memoryId === active.memoryId &&
        ["CANDIDATE", "CONFIRMED"].includes(memory.state),
    ).length,
    0,
  );
  assert.equal(
    deletedState.memories.filter(
      (memory) =>
        memory.memoryId === active.memoryId &&
        memory.content !== null,
    ).length,
    0,
  );
  assert.equal(
    deletedState.checkpoints.filter((item) =>
      item.memoryIds.includes(active.memoryId)
    ).length,
    0,
  );
  assert.equal(
    JSON.stringify({
      events: deletedState.events,
      receipts: deletedState.receipts,
    }).includes("Synthetic preference: concise weekly summaries."),
    false,
  );
  assert.deepEqual(
    (
      await harness.service.recall(
        harness.context(),
        harness.recall(),
      )
    ).memories.filter(
      (memory) => memory.memoryId === active.memoryId,
    ),
    [],
  );
  const recovery = await harness.store.exportRecoverySnapshot({
    asOf: harness.mutable.now,
  });
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
  const recoveredState = await recoveredStore.inspectForTest();
  assert.equal(
    recoveredState.memories.filter(
      (memory) =>
        memory.memoryId === active.memoryId &&
        memory.content !== null,
    ).length,
    0,
  );
  assert.equal(
    recoveredState.checkpoints.filter((item) =>
      item.memoryIds.includes(active.memoryId)
    ).length,
    0,
  );
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
      harness.request(
        confirm(harness, candidate.memoryId, 1, "concurrent-a"),
      ),
    ),
    harness.service.execute(
      harness.context(),
      harness.request(
        confirm(harness, candidate.memoryId, 1, "concurrent-b"),
      ),
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
